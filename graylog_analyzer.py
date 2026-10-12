#!/usr/bin/env python3
"""
graylog_analyzer.py
Graylog 異常日誌自動分析工具，串接 LLM（預設 DGX vLLM qwen3.8-flash-next，可切換 Ollama）

使用方式：
  python graylog_analyzer.py                        # 分析過去 24 小時（逐小時模式）
  python graylog_analyzer.py --output file          # 同時儲存報告檔案
  python graylog_analyzer.py --range 3600           # 快速模式：只查過去 1 小時（單次分析）
  python graylog_analyzer.py --no-hourly            # 停用逐小時，改回單次大查詢
  python graylog_analyzer.py --schedule             # 定時排程模式
"""

import argparse
import json
import os
import sys
import time
import yaml
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_BASE_DIR, ".env"))
load_dotenv(r"C:\Users\inno\Documents\graylog-mcp\.env")  # 舊路徑（若存在，不覆蓋上面的值）

from graylog import GraylogClient
from preprocessor import (preprocess, extract_stats, merge_stats, format_structured_report_slice,
                          format_device_summary, find_unknown_identifiers, classify_devices,
                          format_priority_table, heading_device_ids, normalize_device_headings)
from llm import LLMClient
from mask import Masker
from output import send_output


def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        print(f"[ERROR] 找不到設定檔 {path}，請先複製 config.example.yaml 為 config.yaml 並填入實際位址")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def make_llm(config: dict) -> LLMClient:
    cfg = config["llm"]
    key_env = cfg.get("api_key_env", "")
    api_key = os.getenv(key_env, "") if key_env else ""
    if cfg.get("provider", "openai") != "ollama" and not api_key:
        print(f"[WARN] 找不到 {key_env}，將不帶 API Key 呼叫 LLM")
    return LLMClient(cfg, api_key)


def require_graylog_token() -> str:
    token = os.getenv("GRAYLOG_TOKEN")
    if not token:
        print("[ERROR] 找不到 GRAYLOG_TOKEN，請確認專案資料夾的 .env")
        sys.exit(1)
    return token


def deliver(report: str, config: dict, output_methods: list[str]):
    print(f"[輸出] 方式：{', '.join(output_methods)}")
    report_dir = config["output"].get("report_dir", "./reports")
    for method in output_methods:
        send_output(
            method, report, report_dir=report_dir,
            smtp_host=os.getenv("SMTP_HOST", ""),
            smtp_port=int(os.getenv("SMTP_PORT", 465)),
            sender=os.getenv("SMTP_SENDER", ""),
            password=os.getenv("SMTP_PASSWORD", ""),
            recipients=os.getenv("SMTP_RECIPIENTS", "").split(","),
            line_token=os.getenv("LINE_NOTIFY_TOKEN", ""),
        )


def _today_label() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d")


def build_report(config: dict, accumulated_stats: dict, title: str, range_label: str,
                 anomaly_hours: int, total_hours: int) -> str:
    """
    分批（並行）送 LLM 分析每台設備，另以全設備摘要產生總覽與優先表，
    最後自動檢核報告中的 IP / 介面名稱是否存在於統計資料。
    """
    if not accumulated_stats:
        return f"# {title}\n\n{range_label}：無異常事件，所有設備運作正常。"

    llm = make_llm(config)
    batch_size = config["llm"].get("batch_size", 30)
    concurrency = max(1, config["llm"].get("concurrency", 3))

    # 去識別化：送出的統計資料改用代號，報告回來後在本機換回
    masker = Masker() if config["llm"].get("mask") else None
    work_stats = masker.mask_stats(accumulated_stats) if masker else accumulated_stats
    if masker:
        print(f"[遮罩] 已去識別化：{masker.summary()}")

    # 優先分級由程式依規則判定；設備分析依 P0 → P1 → P2、筆數多到少排序
    # 以原始資料分級（報告用真實名稱），送給模型的表格另行遮罩
    classified = classify_devices(accumulated_stats, config.get("priority"))
    priority_table = format_priority_table(classified)
    priority_table_llm = masker.mask_text(priority_table) if masker else priority_table
    counts = {p: sum(1 for c in classified if c["priority"] == p) for p in ("P0", "P1", "P2")}
    print(f"[分級] P0 {counts['P0']} 台、P1 {counts['P1']} 台、P2 {counts['P2']} 台")
    work_id = (lambda d: masker.forward[d]) if masker else (lambda d: d)
    sorted_devices = [(work_id(c["device"]), work_stats[work_id(c["device"])]) for c in classified]
    total_devices = len(sorted_devices)
    batches = [sorted_devices[i:i + batch_size] for i in range(0, total_devices, batch_size)]
    total_batches = len(batches)
    print(f"[彙整] 共 {total_devices} 台設備，分 {total_batches} 批送 {llm.label}"
          f"（每批 {batch_size} 台，並行 {concurrency}）＋ 1 次總覽...")

    def run_batch(idx: int, batch: list) -> str:
        chunk = format_structured_report_slice(batch, total_devices, total_hours)
        t0 = time.time()
        section = llm.analyze_batch(chunk, idx, total_batches)
        first_line = section.splitlines()[0][:50] if section else "[WARN]"
        print(f"  [批次 {idx}/{total_batches}] {len(chunk)} 字 → {time.time() - t0:.0f}s  {first_line}", flush=True)
        return section

    def run_final() -> str:
        summary = format_device_summary(work_stats, total_hours)
        t0 = time.time()
        result = llm.analyze_final(priority_table_llm, summary, total_devices, range_label)
        print(f"  [總覽] {len(summary)} 字 → {time.time() - t0:.0f}s", flush=True)
        return result

    def missing_devices(sections: list[str]) -> list:
        # 只要設備代號 / IP 出現在任一 ### 標題列即視為已覆蓋（容許模型標題格式不一）
        covered = heading_device_ids("\n".join(sections))
        return [(d, s) for d, s in sorted_devices if d not in covered]

    t_start = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        final_future = pool.submit(run_final)
        batch_futures = [pool.submit(run_batch, idx, b) for idx, b in enumerate(batches, 1)]
        batch_sections = [f.result() for f in batch_futures]

        # 覆蓋率檢查：回應被截斷或漏掉的設備，補送一輪（預覽模式不補送）
        missing = [] if llm.dry_run_path else missing_devices(batch_sections)
        if missing:
            retry_batches = [missing[i:i + batch_size] for i in range(0, len(missing), batch_size)]
            print(f"[覆蓋] {len(missing)} 台設備未出現在分析結果，補送 {len(retry_batches)} 批...", flush=True)
            retry_futures = [pool.submit(run_batch, f"補{idx}", b) for idx, b in enumerate(retry_batches, 1)]
            batch_sections += [f.result() for f in retry_futures]

        overview = final_future.result()
    print(f"[彙整] LLM 分析完成，耗時 {time.time() - t_start:.0f}s")

    still_missing = [] if llm.dry_run_path else missing_devices(batch_sections)
    if still_missing:
        ips = ", ".join(d for d, _ in still_missing)
        print(f"[覆蓋] 仍有 {len(still_missing)} 台設備缺少分析")
        batch_sections.append(f"### ⚠ 以下 {len(still_missing)} 台設備未取得 LLM 分析，請參考原始統計：\n{ips}")

    model_note = f"{llm.label}（已去識別化送出：{masker.summary()}）" if masker else llm.label
    report = (
        f"# {title}\n\n"
        f"- 時間範圍：{range_label}\n"
        f"- 受影響設備：{total_devices} 台，有異常小時：{anomaly_hours}/{total_hours}\n"
        f"- 分析模型：{model_note}\n\n"
        f"{overview}\n\n"
        f"## 優先處理順序\n\n{priority_table}\n\n"
        f"## 各設備分析\n\n"
        + "\n\n".join(batch_sections)
    )

    if masker:
        report = masker.unmask(report)
        leftovers = masker.leftover_tokens(report)
        if leftovers:
            print(f"[遮罩] 報告中有 {len(leftovers)} 個無法還原的代號（模型自行產生）")
            report += f"\n\n## ⚠ 無法還原的代號\n模型輸出了對照表中不存在的代號，請人工確認：{', '.join(leftovers)}\n"

    # 設備標題統一由程式改寫為「【IP】主機名稱」
    report = normalize_device_headings(report, accumulated_stats)

    unknown = find_unknown_identifiers(report, accumulated_stats)
    if unknown["ips"] or unknown["interfaces"]:
        print(f"[檢核] 發現資料中不存在的 IP {len(unknown['ips'])} 個、介面 {len(unknown['interfaces'])} 個")
        report += (
            "\n\n## ⚠ 自動檢核\n"
            "以下項目出現在報告中，但原始統計資料中找不到，可能是模型改寫或捏造，請人工確認：\n"
        )
        if unknown["ips"]:
            report += f"- IP：{', '.join(unknown['ips'])}\n"
        if unknown["interfaces"]:
            report += f"- 介面：{', '.join(unknown['interfaces'])}\n"
    else:
        print("[檢核] 報告中的 IP / 介面名稱皆可在統計資料中找到 [OK]")

    return report


def run_hourly_analysis(config: dict, output_methods: list[str], hours: int = 24,
                        fetch_only: bool = False, date: str = None):
    """逐小時撈取並統計（不呼叫 LLM），最後彙整為日報告；fetch_only 時只存快取。
    指定 date（YYYY-MM-DD，台灣時間）時分析該日 00:00~24:00。"""
    if date:
        day_start_tw = datetime.strptime(date, "%Y-%m-%d")
        now = (day_start_tw + timedelta(days=1) - timedelta(hours=8)).replace(tzinfo=timezone.utc)
        hours = 24
    else:
        now = datetime.now(timezone.utc)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 開始逐小時分析（共 {hours} 小時）...")

    graylog = GraylogClient(config["graylog"]["url"], require_graylog_token())

    accumulated_stats = {}
    anomaly_hours = 0
    range_label = (f"{(now - timedelta(hours=hours) + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')} ~ "
                   f"{(now + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M')}（台灣時間）")

    for i in range(hours - 1, -1, -1):
        to_dt = now - timedelta(hours=i)
        from_dt = to_dt - timedelta(hours=1)
        hour_label = (from_dt + timedelta(hours=8)).strftime("%m/%d %H:00")

        print(f"  [{hours - i:02d}/{hours}] 查詢 {hour_label}...", end=" ", flush=True)
        messages = graylog.fetch_anomalies_by_hour(from_dt, to_dt,
                                                   limit=config["query"]["limit"],
                                                   max_total=config["query"].get("max_per_hour", 10000))

        if not messages:
            print("無異常")
            continue

        anomaly_hours += 1
        # 結構化統計（保證精確 IP + interface）
        hour_stats = extract_stats(messages, hour_label)
        merge_stats(accumulated_stats, hour_stats)
        print(f"{len(messages)} 筆 / {len(hour_stats)} 台設備")

    # 儲存快取，供 --batch-only 使用
    cache_path = os.path.join(config["output"].get("report_dir", "./reports"), "accumulated_stats.json")
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"anomaly_hours": anomaly_hours, "hours": hours, "range_label": range_label,
                   "stats": accumulated_stats}, f, ensure_ascii=False, default=str)
    print(f"[快取] 已儲存至 {cache_path}")
    if date:
        dated_path = cache_path.replace(".json", f"_{date.replace('-', '')}.json")
        with open(dated_path, "w", encoding="utf-8") as f:
            json.dump({"anomaly_hours": anomaly_hours, "hours": hours, "range_label": range_label,
                       "stats": accumulated_stats}, f, ensure_ascii=False, default=str)
        print(f"[快取] 另存日期副本 {dated_path}")

    if fetch_only:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 撈取完成（--fetch-only，未呼叫 LLM）[OK]")
        return

    print(f"\n[彙整] 有異常的小時：{anomaly_hours}/{hours}")
    report = build_report(config, accumulated_stats, f"Graylog 異常分析日報告 — {date or _today_label()}",
                          range_label, anomaly_hours, hours)
    deliver(report, config, output_methods)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 分析完成 [OK]")


def run_batch_only(config: dict, output_methods: list[str]):
    """從快取 accumulated_stats.json 直接執行 LLM 彙整，跳過撈取階段"""
    cache_path = os.path.join(config["output"].get("report_dir", "./reports"), "accumulated_stats.json")
    if not os.path.exists(cache_path):
        print(f"[ERROR] 找不到快取檔案 {cache_path}，請先執行完整分析")
        sys.exit(1)

    with open(cache_path, "r", encoding="utf-8") as f:
        cache = json.load(f)

    accumulated_stats = cache["stats"]
    anomaly_hours = cache["anomaly_hours"]
    hours = cache["hours"]
    print(f"[快取] 載入 {len(accumulated_stats)} 台設備資料（anomaly_hours={anomaly_hours}/{hours}）")

    range_label = cache.get("range_label", f"快取 accumulated_stats.json（{hours} 小時）")
    title_date = range_label[:10] if "range_label" in cache else _today_label()
    report = build_report(config, accumulated_stats, f"Graylog 異常分析日報告 — {title_date}",
                          range_label, anomaly_hours, hours)
    deliver(report, config, output_methods)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 彙整完成 [OK]")


def run_analysis(config: dict, output_methods: list[str], range_seconds: int = None):
    """單次分析（快速模式 / --no-hourly）"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 開始分析...")

    query_range = range_seconds or config["query"]["range_seconds"]
    query_limit = config["query"]["limit"]

    print(f"[1/4] 查詢 Graylog（過去 {query_range // 3600} 小時）...")
    graylog = GraylogClient(config["graylog"]["url"], require_graylog_token())
    messages = graylog.fetch_anomalies(query_range, query_limit)
    print(f"      撈到 {len(messages)} 筆異常日誌")

    if not messages:
        print("      [OK] 本次查詢無異常，結束分析")
        return

    llm = make_llm(config)
    print("[2/4] 前處理（去重、分組）...")
    log_summary = preprocess(messages, max_devices=100, max_chars=llm.max_batch_chars)

    print(f"[3/4] 送交 {llm.label} 分析...")
    report = llm.analyze(log_summary)

    print(f"[4/4] 輸出結果（{', '.join(output_methods)}）...")
    deliver(report, config, output_methods)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 分析完成 [OK]")


HOURLY_CACHE_RETAIN_DAYS = 8


def run_fetch_hour(config: dict):
    """撈前一小時的 log，存入 hourly_cache/YYYY-MM-DD_HH.json，不呼叫 LLM。
    自動清除超過 HOURLY_CACHE_RETAIN_DAYS 天的舊快取。"""
    graylog_token = require_graylog_token()

    now = datetime.now(timezone.utc)
    to_dt = now.replace(minute=0, second=0, microsecond=0)
    from_dt = to_dt - timedelta(hours=1)
    local_hour = (from_dt + timedelta(hours=8))
    hour_label = local_hour.strftime("%m/%d %H:00")
    cache_key = local_hour.strftime("%Y-%m-%d_%H")

    report_dir = config["output"].get("report_dir", "./reports")
    cache_dir = os.path.join(report_dir, "hourly_cache")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{cache_key}.json")

    if os.path.exists(cache_file):
        print(f"[快取] {cache_key}.json 已存在，跳過（刪除後可重新撈取）")
    else:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 撈取 {hour_label}...", end=" ", flush=True)
        graylog = GraylogClient(config["graylog"]["url"], graylog_token)
        messages = graylog.fetch_anomalies_by_hour(from_dt, to_dt, limit=config["query"]["limit"],
                                                   max_total=config["query"].get("max_per_hour", 10000))

        if not messages:
            print("無異常")
            stats = {}
        else:
            stats = extract_stats(messages, hour_label)
            print(f"{len(messages)} 筆 / {len(stats)} 台設備")

        fetched_at = (now + timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%S+08:00")
        payload = {
            "fetched_at": fetched_at,
            "hour_label": hour_label,
            "from_dt": from_dt.isoformat(),
            "to_dt": to_dt.isoformat(),
            "stats": stats,
        }
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, default=str)
        print(f"[快取] 已儲存 {cache_file}")

    # 清除超過保留天數的舊快取
    cutoff = (now + timedelta(hours=8)) - timedelta(days=HOURLY_CACHE_RETAIN_DAYS)
    removed = 0
    for fname in os.listdir(cache_dir):
        if not fname.endswith(".json"):
            continue
        try:
            file_dt = datetime.strptime(fname[:13], "%Y-%m-%d_%H").replace(tzinfo=timezone.utc)
            if file_dt < cutoff:
                os.remove(os.path.join(cache_dir, fname))
                removed += 1
        except ValueError:
            pass
    if removed:
        print(f"[清理] 已刪除 {removed} 個超過 {HOURLY_CACHE_RETAIN_DAYS} 天的舊快取")


def run_from_cache(config: dict, output_methods: list[str], hours: int = 24,
                   start: str = None, end: str = None):
    """從 hourly_cache/ 彙整指定時間段的快取，不重新查 Graylog。
    優先使用 --start/--end（本地時間，格式 'YYYY-MM-DD HH' 或 'YYYY-MM-DD HH:MM'）；
    未指定則彙整最近 hours 小時。"""
    report_dir = config["output"].get("report_dir", "./reports")
    cache_dir = os.path.join(report_dir, "hourly_cache")

    TW = timedelta(hours=8)

    if start or end:
        # 解析本地時間（台灣時間）→ 產生整點清單
        def parse_local(s):
            for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H"):
                try:
                    return datetime.strptime(s, fmt)
                except ValueError:
                    pass
            raise ValueError(f"無法解析時間：{s}，格式需為 'YYYY-MM-DD HH' 或 'YYYY-MM-DD HH:MM'")

        now_local = datetime.now(timezone.utc) + TW
        start_local = parse_local(start).replace(minute=0) if start else (now_local - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
        end_local   = parse_local(end).replace(minute=0)   if end   else now_local.replace(minute=0, second=0, microsecond=0)
        range_label = f"{start_local.strftime('%Y-%m-%d %H:00')} ~ {end_local.strftime('%Y-%m-%d %H:00')}"
        hour_slots = []
        cur = start_local
        while cur < end_local:
            hour_slots.append(cur)
            cur += timedelta(hours=1)
    else:
        now = datetime.now(timezone.utc)
        end_hour = now.replace(minute=0, second=0, microsecond=0)
        hour_slots = [(end_hour - timedelta(hours=i) + TW) for i in range(hours, 0, -1)]
        range_label = f"最近 {hours} 小時"

    total_slots = len(hour_slots)
    accumulated_stats = {}
    loaded_hours = 0
    anomaly_hours = 0

    print(f"[{datetime.now().strftime('%H:%M:%S')}] 從快取彙整 {range_label}（共 {total_slots} 小時）...")
    for idx, local_hour in enumerate(hour_slots, 1):
        cache_key = local_hour.strftime("%Y-%m-%d_%H")
        cache_file = os.path.join(cache_dir, f"{cache_key}.json")

        if not os.path.exists(cache_file):
            print(f"  [{idx:03d}/{total_slots}] {local_hour.strftime('%m/%d %H:00')} — 無快取，跳過")
            continue

        with open(cache_file, "r", encoding="utf-8") as f:
            payload = json.load(f)

        hour_stats = payload.get("stats", {})
        hour_label = payload.get("hour_label", cache_key)
        loaded_hours += 1
        if hour_stats:
            anomaly_hours += 1
            merge_stats(accumulated_stats, hour_stats)
        print(f"  [{idx:03d}/{total_slots}] {hour_label} — {len(hour_stats)} 台設備")

    print(f"\n[彙整] 載入 {loaded_hours}/{total_slots} 小時快取，有異常：{anomaly_hours} 小時，設備：{len(accumulated_stats)} 台")

    report = build_report(config, accumulated_stats, f"Graylog 異常分析報告 — {range_label}",
                          range_label, anomaly_hours, total_slots)
    deliver(report, config, output_methods)
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 彙整完成 [OK]")


def run_schedule(config: dict, output_methods: list[str], use_hourly: bool):
    try:
        import schedule
    except ImportError:
        print("[ERROR] 請先安裝 schedule：pip install schedule")
        sys.exit(1)

    cron_str = config.get("schedule", {}).get("cron", "0 8 * * *")
    parts = cron_str.split()
    minute, hour = parts[0], parts[1]
    run_time = f"{int(hour):02d}:{int(minute):02d}"
    print(f"[排程模式] 每天 {run_time} 自動執行分析")

    if use_hourly:
        schedule.every().day.at(run_time).do(
            run_hourly_analysis, config=config, output_methods=output_methods
        )
    else:
        schedule.every().day.at(run_time).do(
            run_analysis, config=config, output_methods=output_methods
        )

    while True:
        schedule.run_pending()
        time.sleep(60)


def main():
    parser = argparse.ArgumentParser(description="Graylog 異常日誌自動分析工具")
    parser.add_argument("--output", "-o", action="append",
                        choices=["terminal", "file", "pdf", "email", "line"],
                        help="輸出方式（可指定多次）")
    parser.add_argument("--range", "-r", type=int,
                        help="查詢時間範圍（秒）；指定此參數時自動切換為單次模式")
    parser.add_argument("--hours", type=int, default=24,
                        help="逐小時模式分析幾小時（預設 24）")
    parser.add_argument("--no-hourly", action="store_true",
                        help="停用逐小時模式，改回單次大查詢")
    parser.add_argument("--batch-only", action="store_true",
                        help="跳過撈取階段，直接從快取 accumulated_stats.json 執行 LLM 彙整")
    parser.add_argument("--date", type=str, default=None,
                        help="分析指定日期（台灣時間 YYYY-MM-DD 00:00~24:00），可搭配 --fetch-only")
    parser.add_argument("--fetch-only", action="store_true",
                        help="逐小時撈取 --hours 小時並存入 accumulated_stats.json，不呼叫 LLM（之後可用 --batch-only 產生報告）")
    parser.add_argument("--fetch-hour", action="store_true",
                        help="撈前一小時 log 存入 hourly_cache/，不呼叫 LLM（適合每小時排程）")
    parser.add_argument("--from-cache", action="store_true",
                        help="從 hourly_cache/ 彙整快取，不重新查 Graylog")
    parser.add_argument("--start", type=str, default=None,
                        help="彙整起始時間（台灣時間），格式：'YYYY-MM-DD HH'，與 --from-cache 搭配")
    parser.add_argument("--end", type=str, default=None,
                        help="彙整結束時間（台灣時間），格式：'YYYY-MM-DD HH'，與 --from-cache 搭配")
    parser.add_argument("--schedule", "-s", action="store_true",
                        help="啟用定時排程模式")
    parser.add_argument("--llm-profile", type=str, default=None,
                        help="改用 config.yaml 中 llm_profiles 的設定檔（例如 external）")
    parser.add_argument("--dry-run", action="store_true",
                        help="預覽模式：不呼叫 LLM，只把實際要送出的請求內容寫入 reports/send_preview_*.txt")
    parser.add_argument("--config", "-c",default=os.path.join(_BASE_DIR, "config.yaml"),
                        help="設定檔路徑（預設為程式所在資料夾的 config.yaml）")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.llm_profile:
        profiles = config.get("llm_profiles", {})
        if args.llm_profile not in profiles:
            print(f"[ERROR] config.yaml 中找不到 llm_profiles.{args.llm_profile}")
            sys.exit(1)
        config["llm"].update(profiles[args.llm_profile])
        print(f"[設定] 使用 LLM 設定檔：{args.llm_profile}（{config['llm']['url']}，mask={config['llm'].get('mask', False)}）")
    if args.dry_run:
        report_dir = config["output"].get("report_dir", "./reports")
        os.makedirs(report_dir, exist_ok=True)
        config["llm"]["dry_run_path"] = os.path.join(
            report_dir, datetime.now().strftime("send_preview_%Y%m%d_%H%M%S.txt"))
        print(f"[預覽] 不會送出任何請求，內容寫入 {config['llm']['dry_run_path']}")
    output_methods = args.output or [config["output"].get("default", "terminal")]
    use_hourly = not args.no_hourly and args.range is None

    if args.schedule:
        run_schedule(config, output_methods, use_hourly)
    elif args.fetch_hour:
        run_fetch_hour(config)
    elif args.from_cache:
        run_from_cache(config, output_methods, hours=args.hours, start=args.start, end=args.end)
    elif args.batch_only:
        run_batch_only(config, output_methods)
    elif use_hourly or args.fetch_only or args.date:
        run_hourly_analysis(config, output_methods, hours=args.hours, fetch_only=args.fetch_only,
                            date=args.date)
    else:
        run_analysis(config, output_methods, range_seconds=args.range)


if __name__ == "__main__":
    main()
