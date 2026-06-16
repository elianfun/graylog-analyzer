#!/usr/bin/env python3
"""
graylog_analyzer.py
Graylog 異常日誌自動分析工具，串接本地 Ollama LLM

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
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv(r"D:\claude\graylog-mcp\.env")

from graylog import GraylogClient
from preprocessor import preprocess, extract_stats, merge_stats, format_structured_report, format_structured_report_slice
from ollama import OllamaClient
from output import send_output


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_hourly_analysis(config: dict, output_methods: list[str], hours: int = 24):
    """逐小時分析，最後彙整為日報告"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 開始逐小時分析（共 {hours} 小時）...")

    graylog_token = os.getenv("GRAYLOG_TOKEN")
    if not graylog_token:
        print("[ERROR] 找不到 GRAYLOG_TOKEN，請確認 .env 檔案路徑")
        sys.exit(1)

    graylog = GraylogClient(config["graylog"]["url"], graylog_token)
    ollama = OllamaClient(config["ollama"]["url"], config["ollama"]["model"])

    now = datetime.now(timezone.utc)
    accumulated_stats = {}
    anomaly_hours = 0

    for i in range(hours - 1, -1, -1):
        to_dt = now - timedelta(hours=i)
        from_dt = to_dt - timedelta(hours=1)
        hour_label = (from_dt + timedelta(hours=8)).strftime("%m/%d %H:00")

        print(f"  [{hours - i:02d}/{hours}] 查詢 {hour_label}...", end=" ", flush=True)
        messages = graylog.fetch_anomalies_by_hour(from_dt, to_dt,
                                                   limit=config["query"]["limit"])

        if not messages:
            print("無異常")
            continue

        anomaly_hours += 1
        # 結構化統計（保證精確 IP + interface）
        hour_stats = extract_stats(messages, hour_label)
        merge_stats(accumulated_stats, hour_stats)

        # 進度顯示：用 preprocess 取得簡短文字摘要給 Ollama 做小時摘要
        log_summary = preprocess(messages)
        device_count = len(hour_stats)
        total_count = len(messages)
        print(f"{total_count} 筆 / {device_count} 台設備", end=" → ", flush=True)

        summary = ollama.analyze_hourly(hour_label, log_summary)
        first_line = summary.splitlines()[0][:60] if summary else "[WARN]"
        print(first_line)
        time.sleep(10)

    # 儲存快取，供 --batch-only 使用
    cache_path = os.path.join(config["output"].get("report_dir", "./reports"), "accumulated_stats.json")
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump({"anomaly_hours": anomaly_hours, "hours": hours, "stats": accumulated_stats}, f, ensure_ascii=False, default=str)
    print(f"[快取] 已儲存至 {cache_path}")

    print(f"\n[彙整] 有異常的小時：{anomaly_hours}/{hours}，Python 彙整精確數據...")

    if not accumulated_stats:
        report = "今日無異常事件，所有設備運作正常。"
    else:
        BATCH_SIZE = 8
        sorted_devices = sorted(accumulated_stats.items(), key=lambda x: -x[1]["total"])
        total_devices = len(sorted_devices)
        batches = [sorted_devices[i:i+BATCH_SIZE] for i in range(0, total_devices, BATCH_SIZE)]
        total_batches = len(batches)
        print(f"[彙整] 共 {total_devices} 台設備，分 {total_batches} 批送 Ollama（每批 {BATCH_SIZE} 台）...")

        batch_sections = []
        for idx, batch in enumerate(batches, 1):
            chunk = format_structured_report_slice(batch, total_devices)
            print(f"  [批次 {idx}/{total_batches}] {len(chunk)} 字...", end=" ", flush=True)
            section = ollama.analyze_batch(chunk, idx, total_batches)
            first_line = section.splitlines()[0][:60] if section else "[WARN]"
            print(first_line)
            batch_sections.append(section)
            if idx < total_batches:
                time.sleep(10)

        now_str = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d")
        report = (
            f"# Graylog 異常分析日報告 — {now_str}\n\n"
            f"受影響設備：{total_devices} 台，有異常小時：{anomaly_hours}/{hours}\n\n"
            + "\n\n".join(batch_sections)
        )

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

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 分析完成 [OK]")


def run_batch_only(config: dict, output_methods: list[str]):
    """從快取 accumulated_stats.json 直接執行 Ollama 批次彙整，跳過撈取階段"""
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

    ollama = OllamaClient(config["ollama"]["url"], config["ollama"]["model"])

    BATCH_SIZE = 8
    sorted_devices = sorted(accumulated_stats.items(), key=lambda x: -x[1]["total"])
    total_devices = len(sorted_devices)
    batches = [sorted_devices[i:i+BATCH_SIZE] for i in range(0, total_devices, BATCH_SIZE)]
    total_batches = len(batches)
    print(f"[彙整] 共 {total_devices} 台設備，分 {total_batches} 批送 Ollama（每批 {BATCH_SIZE} 台）...")

    batch_sections = []
    for idx, batch in enumerate(batches, 1):
        chunk = format_structured_report_slice(batch, total_devices)
        print(f"  [批次 {idx}/{total_batches}] {len(chunk)} 字...", end=" ", flush=True)
        section = ollama.analyze_batch(chunk, idx, total_batches)
        first_line = section.splitlines()[0][:60] if section else "[WARN]"
        print(first_line)
        batch_sections.append(section)
        if idx < total_batches:
            time.sleep(10)

    now_str = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d")
    report = (
        f"# Graylog 異常分析日報告 — {now_str}\n\n"
        f"受影響設備：{total_devices} 台，有異常小時：{anomaly_hours}/{hours}\n\n"
        + "\n\n".join(batch_sections)
    )

    report_dir = config["output"].get("report_dir", "./reports")
    for method in output_methods:
        send_output(method, report, report_dir=report_dir,
                    smtp_host=os.getenv("SMTP_HOST", ""),
                    smtp_port=int(os.getenv("SMTP_PORT", 465)),
                    sender=os.getenv("SMTP_SENDER", ""),
                    password=os.getenv("SMTP_PASSWORD", ""),
                    recipients=os.getenv("SMTP_RECIPIENTS", "").split(","),
                    line_token=os.getenv("LINE_NOTIFY_TOKEN", ""))

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 彙整完成 [OK]")


def run_analysis(config: dict, output_methods: list[str], range_seconds: int = None):
    """單次分析（快速模式 / --no-hourly）"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 開始分析...")

    graylog_token = os.getenv("GRAYLOG_TOKEN")
    if not graylog_token:
        print("[ERROR] 找不到 GRAYLOG_TOKEN，請確認 .env 檔案路徑")
        sys.exit(1)

    query_range = range_seconds or config["query"]["range_seconds"]
    query_limit = config["query"]["limit"]

    print(f"[1/4] 查詢 Graylog（過去 {query_range // 3600} 小時）...")
    graylog = GraylogClient(config["graylog"]["url"], graylog_token)
    messages = graylog.fetch_anomalies(query_range, query_limit)
    print(f"      撈到 {len(messages)} 筆異常日誌")

    if not messages:
        print("      [OK] 本次查詢無異常，結束分析")
        return

    print("[2/4] 前處理（去重、分組）...")
    log_summary = preprocess(messages)

    print(f"[3/4] 送交 Ollama（{config['ollama']['model']}）分析...")
    ollama = OllamaClient(config["ollama"]["url"], config["ollama"]["model"])
    report = ollama.analyze(log_summary)

    print(f"[4/4] 輸出結果（{', '.join(output_methods)}）...")
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

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 分析完成 [OK]")


HOURLY_CACHE_RETAIN_DAYS = 8


def run_fetch_hour(config: dict):
    """撈前一小時的 log，存入 hourly_cache/YYYY-MM-DD_HH.json，不呼叫 Ollama。
    自動清除超過 HOURLY_CACHE_RETAIN_DAYS 天的舊快取。"""
    graylog_token = os.getenv("GRAYLOG_TOKEN")
    if not graylog_token:
        print("[ERROR] 找不到 GRAYLOG_TOKEN，請確認 .env 檔案路徑")
        sys.exit(1)

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
        messages = graylog.fetch_anomalies_by_hour(from_dt, to_dt, limit=config["query"]["limit"])

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

    if not accumulated_stats:
        report = "快取期間無異常事件，所有設備運作正常。"
    else:
        ollama = OllamaClient(config["ollama"]["url"], config["ollama"]["model"])
        BATCH_SIZE = 8
        sorted_devices = sorted(accumulated_stats.items(), key=lambda x: -x[1]["total"])
        total_devices = len(sorted_devices)
        batches = [sorted_devices[i:i+BATCH_SIZE] for i in range(0, total_devices, BATCH_SIZE)]
        total_batches = len(batches)
        print(f"[彙整] 共 {total_devices} 台設備，分 {total_batches} 批送 Ollama（每批 {BATCH_SIZE} 台）...")

        batch_sections = []
        for idx, batch in enumerate(batches, 1):
            chunk = format_structured_report_slice(batch, total_devices)
            print(f"  [批次 {idx}/{total_batches}] {len(chunk)} 字...", end=" ", flush=True)
            section = ollama.analyze_batch(chunk, idx, total_batches)
            first_line = section.splitlines()[0][:60] if section else "[WARN]"
            print(first_line)
            batch_sections.append(section)
            if idx < total_batches:
                time.sleep(10)

        report = (
            f"# Graylog 異常分析報告 — {range_label}\n\n"
            f"受影響設備：{total_devices} 台，有異常小時：{anomaly_hours}/{total_slots}\n\n"
            + "\n\n".join(batch_sections)
        )

    print(f"[輸出] 方式：{', '.join(output_methods)}")
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
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 彙整完成 [OK]")


def run_schedule(config: dict, output_methods: list[str], use_hourly: bool):
    try:
        import schedule
        import time
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
                        choices=["terminal", "file", "email", "line"],
                        help="輸出方式（可指定多次）")
    parser.add_argument("--range", "-r", type=int,
                        help="查詢時間範圍（秒）；指定此參數時自動切換為單次模式")
    parser.add_argument("--hours", type=int, default=24,
                        help="逐小時模式分析幾小時（預設 24）")
    parser.add_argument("--no-hourly", action="store_true",
                        help="停用逐小時模式，改回單次大查詢")
    parser.add_argument("--batch-only", action="store_true",
                        help="跳過撈取階段，直接從快取 accumulated_stats.json 執行 Ollama 批次彙整")
    parser.add_argument("--fetch-hour", action="store_true",
                        help="撈前一小時 log 存入 hourly_cache/，不呼叫 Ollama（適合每小時排程）")
    parser.add_argument("--from-cache", action="store_true",
                        help="從 hourly_cache/ 彙整快取，不重新查 Graylog")
    parser.add_argument("--start", type=str, default=None,
                        help="彙整起始時間（台灣時間），格式：'YYYY-MM-DD HH'，與 --from-cache 搭配")
    parser.add_argument("--end", type=str, default=None,
                        help="彙整結束時間（台灣時間），格式：'YYYY-MM-DD HH'，與 --from-cache 搭配")
    parser.add_argument("--schedule", "-s", action="store_true",
                        help="啟用定時排程模式")
    parser.add_argument("--config", "-c", default="config.yaml",
                        help="設定檔路徑（預設 config.yaml）")
    args = parser.parse_args()

    config = load_config(args.config)
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
    elif use_hourly:
        run_hourly_analysis(config, output_methods, hours=args.hours)
    else:
        run_analysis(config, output_methods, range_seconds=args.range)


if __name__ == "__main__":
    main()
