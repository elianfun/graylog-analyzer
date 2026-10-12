import re
from collections import defaultdict
from datetime import datetime, timedelta

LEVEL_MAP = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

_IF_RE = re.compile(r'\b([gxe][et]-\d+/\d+/\d+(?:\.\d+)?|[Gg]igabitEthernet\d+/\d+(?:/\d+)?)\b')
_SYSLOG_PRI_RE = re.compile(r'^<(\d+)>')
_VAR_RE = re.compile(
    r'\b(LBA=\d+|status=\w+|error=\w+|offset=\d+|length=\d+|0x[0-9a-fA-F]+|\d{4}-\d{2}-\d{2}T[\d:.Z]+)\b'
)

# syslog 標頭：<PRI>[序號:] 時間戳 [主機名稱]，例：
#   <2>Jun 14 22:53:11 SW02-EX46-56.16 /kernel: ...
#   <189>123: *Jun 14 22:53:11.123 UTC: %LINK-3-UPDOWN: ...
_HEADER_RE = re.compile(
    r'^<\d+>\s*(?:\d+:\s*)?'
    r'(?:\*?[A-Z][a-z]{2}\s+\d+\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Z]{2,4})?:?\s+'
    r'(?:(?!%)\S+\s+(?=\S))?)?'   # 主機名稱只在有時間戳時才去除
)
_IPV4_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')

FLAP_WINDOW = timedelta(minutes=5)
FLAP_THRESHOLD = 10   # 同一介面 5 分鐘內 up/down 超過此次數才視為異常

_LINK_EVENT_RE = re.compile(r'SNMP_TRAP_LINK_(DOWN|UP)', re.IGNORECASE)
_LINK_DOWN_RE = re.compile(r'SNMP_TRAP_LINK_DOWN', re.IGNORECASE)


def _is_link_event(message: str) -> bool:
    return bool(_LINK_EVENT_RE.search(message))


def _parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize(message: str) -> str:
    # 去掉 syslog 標頭（每筆時間戳不同，會讓相同訊息無法歸併）
    msg = _HEADER_RE.sub("", message, count=1)
    msg = _VAR_RE.sub("*", msg)
    msg = re.sub(r'\[\d+\]', '[*]', msg)   # 行程 PID，例：sshd[97388]
    msg = re.sub(r'\*(\s*\*)+', '*', msg)
    return msg.strip()


def _top_patterns(pattern_counts: dict, n: int = 5) -> list[tuple[str, int]]:
    """重新正規化後歸併計數（相容舊快取中含 syslog 標頭的樣式），取前 n 名"""
    merged: dict[str, int] = defaultdict(int)
    for pattern, count in pattern_counts.items():
        merged[_normalize(pattern)] += count
    return sorted(merged.items(), key=lambda x: -x[1])[:n]


def _detect_flapping(logs: list[dict]) -> dict[str, list[dict]]:
    """針對 SNMP_TRAP_LINK_DOWN/UP 事件做 flapping 偵測。
    DOWN + UP 配對才算一次 up/down，同一介面在 FLAP_WINDOW 內
    min(DOWN次數, UP次數) >= FLAP_THRESHOLD 才視為異常。"""
    by_if_down: dict[str, list[datetime]] = defaultdict(list)
    by_if_up:   dict[str, list[datetime]] = defaultdict(list)

    for log in logs:
        msg = log.get("message", "")
        if not _is_link_event(msg):
            continue
        ts = _parse_ts(log.get("timestamp", ""))
        if not ts:
            continue
        is_down = bool(_LINK_DOWN_RE.search(msg))
        for iface in _IF_RE.findall(msg):
            if is_down:
                by_if_down[iface].append(ts)
            else:
                by_if_up[iface].append(ts)

    all_ifaces = set(by_if_down) | set(by_if_up)

    flapping = {}
    for iface in all_ifaces:
        # 合併並排序，標記 DOWN/UP
        events: list[tuple[datetime, str]] = (
            [(ts, "DOWN") for ts in by_if_down.get(iface, [])] +
            [(ts, "UP")   for ts in by_if_up.get(iface, [])]
        )
        events.sort(key=lambda x: x[0])

        windows = []
        i = 0
        while i < len(events):
            window_end = events[i][0] + FLAP_WINDOW
            j = i
            while j < len(events) and events[j][0] <= window_end:
                j += 1
            window_events = events[i:j]

            # 配對數 = min(DOWN次數, UP次數)
            down_n = sum(1 for _, s in window_events if s == "DOWN")
            up_n   = sum(1 for _, s in window_events if s == "UP")
            pairs  = min(down_n, up_n)

            if pairs >= FLAP_THRESHOLD:
                windows.append({
                    "window_start": events[i][0].strftime("%H:%M"),
                    "window_end":   events[j - 1][0].strftime("%H:%M"),
                    "count": pairs,
                    "down": down_n,
                    "up":   up_n,
                })
                i = j
            else:
                i += 1

        if windows:
            flapping[iface] = windows

    return flapping


def _valid_messages(logs: list[dict]) -> tuple[list[dict], dict]:
    """有效訊息 = 非 link 事件 + 已確認 flapping 介面的 link 事件；
    正常開關機（非 flapping 介面的零星 link down/up）直接過濾。"""
    link_msgs = [m for m in logs if _is_link_event(m.get("message", ""))]
    other_msgs = [m for m in logs if not _is_link_event(m.get("message", ""))]
    raw_flapping = _detect_flapping(logs)
    flapping_ifaces = set(raw_flapping.keys())
    valid_link_msgs = [
        m for m in link_msgs
        if flapping_ifaces.intersection(_IF_RE.findall(m.get("message", "")))
    ]
    return other_msgs + valid_link_msgs, raw_flapping


def extract_stats(messages: list[dict], hour_label: str = "") -> dict:
    """
    從原始 log 萃取每台設備的結構化統計，供跨小時彙整使用。
    回傳格式：
    {
      "10.0.56.16": {
        "hostname": "SW02-EX46-56.16",
        "hours": ["06/14 21:00"],
        "total": 638,
        "pattern_counts": {"WRITE_DMA FAILURE *": 638},
        "flapping": {"ge-0/0/0": [{"hour": "06/15 03:00", "window": "03:04~03:07", "count": 6}]},
        "max_level": 2,
      }
    }
    """
    grouped: dict[str, list[dict]] = defaultdict(list)
    for msg in messages:
        grouped[msg.get("source", "unknown")].append(msg)

    stats = {}
    for device, logs in grouped.items():
        # 嘗試從 log 取 hostname
        hostname = ""
        for log in logs:
            m = re.search(r'>\w{3}\s+\d+ \d+:\d+:\d+ (\S+)', log.get("message", ""))
            if m:
                hostname = m.group(1)
                break

        # Flapping 偵測並過濾正常開關機的 link 事件
        valid_msgs, raw_flapping = _valid_messages(logs)

        # 整台設備若無任何真實異常則略過
        if not valid_msgs:
            continue

        # 最嚴重的 level（只看有效訊息）
        max_level = 7
        for log in valid_msgs:
            lvl = log.get("level", -1)
            if lvl < 0:
                pri_m = _SYSLOG_PRI_RE.match(log.get("message", ""))
                lvl = int(pri_m.group(1)) % 8 if pri_m else 7
            if lvl < max_level:
                max_level = lvl

        # 訊息樣式統計（只計有效訊息）
        pattern_counts: dict[str, int] = defaultdict(int)
        for log in valid_msgs:
            raw = log.get("message", "")
            pattern = _normalize(raw)
            # 保留 interface 名稱，截斷過長
            if len(pattern) > 150:
                pattern = pattern[:150] + "..."
            pattern_counts[pattern] += 1

        flapping_with_hour = {}
        for iface, windows in raw_flapping.items():
            flapping_with_hour[iface] = [
                {"hour": hour_label, "window": f"{w['window_start']}~{w['window_end']}",
                 "count": w["count"], "down": w["down"], "up": w["up"]}
                for w in windows
            ]

        stats[device] = {
            "hostname": hostname,
            "hours": [hour_label] if hour_label else [],
            "total": len(valid_msgs),
            "pattern_counts": dict(pattern_counts),
            "flapping": flapping_with_hour,
            "max_level": max_level,
        }

    return stats


def merge_stats(accumulated: dict, hour_stats: dict) -> None:
    """將單小時 stats 合併進 24 小時累積 dict（in-place）"""
    for device, s in hour_stats.items():
        if device not in accumulated:
            accumulated[device] = {
                "hostname": s["hostname"],
                "hours": [],
                "total": 0,
                "pattern_counts": defaultdict(int),
                "flapping": {},
                "max_level": 7,
            }

        acc = accumulated[device]
        if s["hostname"] and not acc["hostname"]:
            acc["hostname"] = s["hostname"]
        acc["hours"].extend(s["hours"])
        acc["total"] += s["total"]
        for pattern, count in s["pattern_counts"].items():
            acc["pattern_counts"][pattern] += count
        for iface, windows in s["flapping"].items():
            if iface not in acc["flapping"]:
                acc["flapping"][iface] = []
            acc["flapping"][iface].extend(windows)
        if s["max_level"] < acc["max_level"]:
            acc["max_level"] = s["max_level"]


def format_structured_report_slice(devices_slice: list, total_devices: int,
                                   total_hours: int = 24, top_n_patterns: int = 5,
                                   max_flap_lines: int = 10) -> str:
    """
    將指定的設備切片格式化為結構化文字（供分批送 LLM 使用）。
    devices_slice: list of (device_ip, stats_dict)
    """
    lines = []
    lines.append(f"以下是網路設備異常精確統計（共 {total_devices} 台設備，本批顯示 {len(devices_slice)} 台）：\n")

    for device, s in devices_slice:
        level_name = LEVEL_MAP.get(s["max_level"], "UNKNOWN")
        hostname = s["hostname"] or ""
        hour_count = len(set(s["hours"]))
        lines.append(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"【{device}】{hostname}  最高等級:{level_name}  出現:{hour_count}/{total_hours} 小時  總計:{s['total']} 筆")

        if s["flapping"]:
            flap_lines = []
            for iface, windows in s["flapping"].items():
                for w in windows:
                    detail = f"DOWN:{w.get('down', '?')} UP:{w.get('up', '?')}"
                    flap_lines.append(f"  ⚠ Flapping {iface}：{w['hour']} {w['window']} 共 {w['count']} 次 up/down（{detail}）")
            lines.extend(flap_lines[:max_flap_lines])
            if len(flap_lines) > max_flap_lines:
                lines.append(f"  ⚠ （另有 {len(flap_lines) - max_flap_lines} 筆 Flapping 紀錄未列出）")

        for pattern, count in _top_patterns(s["pattern_counts"], top_n_patterns):
            lines.append(f"  x{count:5d}  {pattern}")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


def format_device_summary(accumulated: dict, total_hours: int = 24) -> str:
    """全設備精簡摘要（每台一列），供最終總覽與優先排序使用"""
    lines = ["IP | 設備名稱 | 最高等級 | 出現小時 | 總筆數 | Flapping 介面 | 最多的訊息樣式"]
    for device, s in sorted(accumulated.items(), key=lambda x: -x[1]["total"]):
        level_name = LEVEL_MAP.get(s["max_level"], "UNKNOWN")
        hour_count = len(set(s["hours"]))
        flaps = ", ".join(f"{iface}({sum(w['count'] for w in ws)}次)"
                          for iface, ws in s["flapping"].items()) or "-"
        top = _top_patterns(s["pattern_counts"], 1)
        top_text = f"x{top[0][1]} {top[0][0][:100]}" if top else "-"
        lines.append(f"{device} | {s['hostname'] or '-'} | {level_name} | {hour_count}/{total_hours} | "
                     f"{s['total']} | {flaps} | {top_text}")
    return "\n".join(lines)


DEFAULT_PRIORITY_RULES = {
    "p0": {"flap": 100, "if_events": 300, "hw_critical_min": 10},
    "p1": {"flap": 20, "if_events": 50, "total": 100, "error_total": 50, "hw_warning_min": 10},
    "hw_critical_keywords": ["NOT spinning", "WRITE_DMA", "PSU", "Power Supply", "Temp Too Hot",
                             "Major alarm set", "storm", "loop detect"],
    "hw_warning_keywords": ["Too Warm", "too Warm", "Minor alarm set", "receive power low",
                            "RTC ERROR", "get failed", "is down"],
}


def _short_reason(pattern: str, limit: int = 110) -> str:
    """精簡訊息樣式供判定原因使用：去掉行程前綴，有 reason= 時只取原因"""
    text = re.sub(r'^[\w./-]+(?:\[\*\])?:\s*', '', pattern)
    m = re.search(r'reason=(.+)$', text)
    if m:
        text = m.group(1)
    return text[:limit] + ("…" if len(text) > limit else "")


def _device_metrics(s: dict, rules: dict) -> dict:
    """計算分級用指標：最大介面 Flapping、最大介面事件數、硬體關鍵字筆數"""
    flap_by_if = {iface: sum(w["count"] for w in ws) for iface, ws in s["flapping"].items()}
    events_by_if: dict[str, int] = defaultdict(int)
    hw_crit: dict[str, int] = defaultdict(int)
    hw_warn: dict[str, int] = defaultdict(int)
    def has_keyword(pattern: str, keywords: list[str]) -> bool:
        # 以完整字詞比對，避免 "PSU" 誤中 "URL_PSUWeb" 之類的名稱
        return any(re.search(r'(?<!\w)' + re.escape(k) + r'(?!\w)', pattern) for k in keywords)

    for pattern, count in _top_patterns(s["pattern_counts"], 10 ** 6):
        for iface in set(_IF_RE.findall(pattern)):
            events_by_if[iface] += count
        if has_keyword(pattern, rules["hw_critical_keywords"]):
            hw_crit[pattern] += count
        elif has_keyword(pattern, rules["hw_warning_keywords"]):
            hw_warn[pattern] += count
    top_flap = max(flap_by_if.items(), key=lambda x: x[1], default=("", 0))
    top_if = max(events_by_if.items(), key=lambda x: x[1], default=("", 0))
    return {
        "top_flap": top_flap, "top_if": top_if,
        "hw_crit": sorted(hw_crit.items(), key=lambda x: -x[1]),
        "hw_warn": sorted(hw_warn.items(), key=lambda x: -x[1]),
    }


def classify_devices(stats: dict, rules: dict | None = None) -> list[dict]:
    """
    依規則將設備分為 P0 / P1 / P2，回傳依（等級, -總筆數）排序的清單：
    [{"device", "hostname", "priority", "reasons": [...], "total", "max_level"}]
    """
    r = {**DEFAULT_PRIORITY_RULES, **(rules or {})}
    p0, p1 = r["p0"], r["p1"]
    result = []
    for device, s in stats.items():
        m = _device_metrics(s, r)
        hw_crit_total = sum(c for _, c in m["hw_crit"])
        hw_warn_total = sum(c for _, c in m["hw_warn"])
        flap_if, flap = m["top_flap"]
        ev_if, events = m["top_if"]

        p0_reasons, p1_reasons = [], []
        if hw_crit_total >= p0["hw_critical_min"]:
            p0_reasons.append(f"硬體異常：{_short_reason(m['hw_crit'][0][0])}（{hw_crit_total} 筆）")
        if flap >= p0["flap"]:
            p0_reasons.append(f"{flap_if} Flapping {flap} 次")
        if events >= p0["if_events"] and ev_if != flap_if:
            p0_reasons.append(f"{ev_if} 介面事件 {events} 筆")
        if not p0_reasons:
            if hw_crit_total:
                p1_reasons.append(f"硬體異常：{_short_reason(m['hw_crit'][0][0])}（{hw_crit_total} 筆）")
            if hw_warn_total >= p1["hw_warning_min"]:
                p1_reasons.append(f"硬體/服務警告：{_short_reason(m['hw_warn'][0][0])}（{hw_warn_total} 筆）")
            if flap >= p1["flap"]:
                p1_reasons.append(f"{flap_if} Flapping {flap} 次")
            if events >= p1["if_events"] and ev_if != flap_if:
                p1_reasons.append(f"{ev_if} 介面事件 {events} 筆")
            if s["total"] >= p1["total"] and not p1_reasons:
                p1_reasons.append(f"總異常 {s['total']} 筆")
            if s["max_level"] <= 3 and s["total"] >= p1["error_total"] and not p1_reasons:
                p1_reasons.append(f"{LEVEL_MAP.get(s['max_level'])} 等級共 {s['total']} 筆")

        if p0_reasons:
            priority, reasons = "P0", p0_reasons
        elif p1_reasons:
            priority, reasons = "P1", p1_reasons
        else:
            priority = "P2"
            top = _top_patterns(s["pattern_counts"], 1)
            reasons = [f"{top[0][0][:60]}（{top[0][1]} 筆）"] if top else []
        result.append({"device": device, "hostname": s.get("hostname") or "-", "priority": priority,
                       "reasons": reasons, "total": s["total"], "max_level": s["max_level"]})

    order = {"P0": 0, "P1": 1, "P2": 2}
    return sorted(result, key=lambda x: (order[x["priority"]], -x["total"]))


def format_priority_table(classified: list[dict], p2_limit: int = 10) -> str:
    """產生 Markdown 優先處理表：P0、P1 全列，P2 列前 p2_limit 台"""
    counts = {p: sum(1 for c in classified if c["priority"] == p) for p in ("P0", "P1", "P2")}
    lines = [f"P0 {counts['P0']} 台、P1 {counts['P1']} 台、P2 {counts['P2']} 台"
             f"（分級依 config.yaml 的 priority 規則，由程式判定）\n",
             "| 等級 | IP 位址 | 設備名稱 | 總筆數 | 判定原因 |",
             "|---|---|---|---|---|"]
    p2_shown = 0
    for c in classified:
        if c["priority"] == "P2":
            if p2_shown >= p2_limit:
                continue
            p2_shown += 1
        reason = "；".join(c["reasons"]).replace("|", "/")
        lines.append(f"| {c['priority']} | {c['device']} | {c['hostname']} | {c['total']} | {reason} |")
    if counts["P2"] > p2_limit:
        lines.append(f"| P2 | — | 其餘 {counts['P2'] - p2_limit} 台 | — | 零星介面事件，觀察即可 |")
    return "\n".join(lines)


_HEADING_ID_RE = re.compile(r'DEV-\d{3,}|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


def heading_device_ids(text: str) -> set[str]:
    """取出所有 ### 標題列中出現的設備代號 / IP（容許模型標題格式不一）"""
    ids: set[str] = set()
    for line in text.splitlines():
        if line.lstrip().startswith("###"):
            ids.update(_HEADING_ID_RE.findall(line))
    return ids


def normalize_device_headings(text: str, stats: dict) -> str:
    """將設備分析的 ### 標題統一改寫為「### 【IP】主機名稱」（不依賴模型輸出格式）"""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("###"):
            ids = [i for i in _HEADING_ID_RE.findall(line) if i in stats]
            if ids:
                device = ids[0]
                line = f"### 【{device}】{stats[device].get('hostname') or ''}".rstrip()
        out.append(line)
    return "\n".join(out)


def find_unknown_identifiers(report: str, accumulated: dict) -> dict[str, list[str]]:
    """
    比對 LLM 報告中出現的 IP / 介面名稱是否存在於統計資料，
    回傳 {"ips": [...], "interfaces": [...]} 為資料中找不到的項目（可能是模型捏造或改寫）。
    """
    known_ips: set[str] = set()
    known_ifs: set[str] = set()
    for device, s in accumulated.items():
        known_ips.update(_IPV4_RE.findall(device))
        known_ips.update(_IPV4_RE.findall(s.get("hostname", "") or ""))
        known_ifs.update(s["flapping"].keys())
        for pattern in s["pattern_counts"]:
            known_ips.update(_IPV4_RE.findall(pattern))
            known_ifs.update(_IF_RE.findall(pattern))

    report_ips = set(_IPV4_RE.findall(report))
    report_ifs = set(_IF_RE.findall(report))
    return {
        "ips": sorted(report_ips - known_ips),
        "interfaces": sorted(report_ifs - known_ifs),
    }


def format_structured_report(accumulated: dict, top_n: int = 30) -> str:
    """
    Python 層格式化精確報告，保證 IP 和 interface 名稱不被模糊化。
    回傳給 Ollama 的結構化文字。
    """
    # 依總筆數排序，取前 top_n
    sorted_devices = sorted(accumulated.items(), key=lambda x: -x[1]["total"])[:top_n]

    lines = []
    lines.append(f"以下是 24 小時網路設備異常精確統計（共 {len(accumulated)} 台設備，顯示前 {len(sorted_devices)} 台）：\n")

    for device, s in sorted_devices:
        level_name = LEVEL_MAP.get(s["max_level"], "UNKNOWN")
        hostname = s["hostname"] or device
        hour_count = len(set(s["hours"]))
        lines.append(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"【{device}】{hostname}  最高等級:{level_name}  出現:{hour_count}/24 小時  總計:{s['total']} 筆")

        # Flapping
        if s["flapping"]:
            for iface, windows in s["flapping"].items():
                for w in windows:
                    detail = f"DOWN:{w.get('down', '?')} UP:{w.get('up', '?')}"
                    lines.append(f"  ⚠ Flapping {iface}：{w['hour']} {w['window']} 共 {w['count']} 次 up/down（{detail}）")

        # 前 5 大訊息樣式
        for pattern, count in _top_patterns(s["pattern_counts"], 5):
            lines.append(f"  x{count:5d}  {pattern}")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


def preprocess(messages: list[dict], max_patterns_per_device: int = 5,
               max_devices: int = 30, max_chars: int = 4000) -> str:
    """單次 preprocess（向下相容，供 analyze_hourly 使用）"""
    if not messages:
        return "（本次查詢無異常日誌）"

    grouped: dict[str, list[dict]] = defaultdict(list)
    for msg in messages:
        grouped[msg.get("source", "unknown")].append(msg)

    sorted_devices = sorted(grouped.items(), key=lambda x: -len(x[1]))
    if len(sorted_devices) > max_devices:
        sorted_devices = sorted_devices[:max_devices]

    lines = []
    lines.append(f"共收到 {len(messages)} 筆異常日誌，涉及 {len(grouped)} 台設備"
                 f"（報告顯示前 {len(sorted_devices)} 台）\n")
    lines.append("=" * 60)

    for device, logs in sorted_devices:
        # 過濾：link 事件只保留真正 flapping 的介面
        valid_logs, flapping = _valid_messages(logs)
        if not valid_logs:
            continue

        lines.append(f"\n【設備】{device}（共 {len(valid_logs)} 筆）")

        if flapping:
            lines.append("  ⚠ Flapping 偵測：")
            for iface, windows in flapping.items():
                for w in windows:
                    detail = f"DOWN:{w.get('down', '?')} UP:{w.get('up', '?')}"
                    lines.append(f"    🔴 {iface}：{w['window_start']}～{w['window_end']} 內 {w['count']} 次 up/down（{detail}）")

        pattern_count: dict[str, int] = defaultdict(int)
        level_map_local: dict[str, int] = {}

        for log in valid_logs:
            raw_msg = log.get("message", "")
            pattern = _normalize(raw_msg)
            if len(pattern) > 200:
                pattern = pattern[:200] + "..."
            pattern_count[pattern] += 1
            lvl = log.get("level", -1)
            if lvl < 0:
                m = _SYSLOG_PRI_RE.match(raw_msg)
                lvl = int(m.group(1)) % 8 if m else 7
            if lvl < level_map_local.get(pattern, 7):
                level_map_local[pattern] = lvl

        sorted_patterns = sorted(pattern_count.items(), key=lambda x: -x[1])
        if len(sorted_patterns) > max_patterns_per_device:
            lines.append(f"  （共 {len(sorted_patterns)} 種訊息樣式，僅顯示前 {max_patterns_per_device} 種）")
            sorted_patterns = sorted_patterns[:max_patterns_per_device]

        for pattern, count in sorted_patterns:
            lvl = level_map_local.get(pattern, 7)
            lvl_name = LEVEL_MAP.get(lvl, "UNKNOWN")
            lines.append(f"  [{lvl_name:9s}] x{count:4d}  {pattern}")

    lines.append("\n" + "=" * 60)
    result = "\n".join(lines)

    if len(result) > max_chars:
        result = result[:max_chars] + "\n...(已達字數上限)"

    return result
