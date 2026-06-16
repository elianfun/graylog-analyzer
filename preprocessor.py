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

FLAP_WINDOW = timedelta(minutes=5)
FLAP_THRESHOLD = 5


def _parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize(message: str) -> str:
    msg = _VAR_RE.sub("*", message)
    msg = re.sub(r'\*(\s*\*)+', '*', msg)
    return msg.strip()


def _detect_flapping(logs: list[dict]) -> dict[str, list[dict]]:
    by_if: dict[str, list[datetime]] = defaultdict(list)
    for log in logs:
        ts = _parse_ts(log.get("timestamp", ""))
        for iface in _IF_RE.findall(log.get("message", "")):
            if ts:
                by_if[iface].append(ts)

    flapping = {}
    for iface, times in by_if.items():
        times.sort()
        windows = []
        i = 0
        while i < len(times):
            window_end = times[i] + FLAP_WINDOW
            j = i
            while j < len(times) and times[j] <= window_end:
                j += 1
            count = j - i
            if count >= FLAP_THRESHOLD:
                windows.append({
                    "window_start": times[i].strftime("%H:%M"),
                    "window_end": times[j - 1].strftime("%H:%M"),
                    "count": count,
                })
                i = j
            else:
                i += 1
        if windows:
            flapping[iface] = windows

    return flapping


def extract_stats(messages: list[dict], hour_label: str = "") -> dict:
    """
    從原始 log 萃取每台設備的結構化統計，供跨小時彙整使用。
    回傳格式：
    {
      "192.168.56.16": {
        "hostname": "SM02-EX46-56.16",
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

        # 最嚴重的 level
        max_level = 7
        for log in logs:
            lvl = log.get("level", -1)
            if lvl < 0:
                pri_m = _SYSLOG_PRI_RE.match(log.get("message", ""))
                lvl = int(pri_m.group(1)) % 8 if pri_m else 7
            if lvl < max_level:
                max_level = lvl

        # 訊息樣式統計
        pattern_counts: dict[str, int] = defaultdict(int)
        for log in logs:
            raw = log.get("message", "")
            pattern = _normalize(raw)
            # 保留 interface 名稱，截斷過長
            if len(pattern) > 150:
                pattern = pattern[:150] + "..."
            pattern_counts[pattern] += 1

        # Flapping 偵測
        raw_flapping = _detect_flapping(logs)
        flapping_with_hour = {}
        for iface, windows in raw_flapping.items():
            flapping_with_hour[iface] = [
                {"hour": hour_label, "window": f"{w['window_start']}~{w['window_end']}", "count": w["count"]}
                for w in windows
            ]

        stats[device] = {
            "hostname": hostname,
            "hours": [hour_label] if hour_label else [],
            "total": len(logs),
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


def format_structured_report_slice(devices_slice: list, total_devices: int) -> str:
    """
    將指定的設備切片格式化為結構化文字（供分批送 Ollama 使用）。
    devices_slice: list of (device_ip, stats_dict)
    """
    lines = []
    lines.append(f"以下是網路設備異常精確統計（共 {total_devices} 台設備，本批顯示 {len(devices_slice)} 台）：\n")

    for device, s in devices_slice:
        level_name = LEVEL_MAP.get(s["max_level"], "UNKNOWN")
        hostname = s["hostname"] or device
        hour_count = len(set(s["hours"]))
        lines.append(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append(f"【{device}】{hostname}  最高等級:{level_name}  出現:{hour_count}/24 小時  總計:{s['total']} 筆")

        if s["flapping"]:
            for iface, windows in s["flapping"].items():
                for w in windows:
                    lines.append(f"  ⚠ Flapping {iface}：{w['hour']} {w['window']} 共 {w['count']} 次")

        top_patterns = sorted(s["pattern_counts"].items(), key=lambda x: -x[1])[:5]
        for pattern, count in top_patterns:
            lines.append(f"  x{count:5d}  {pattern}")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


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
                    lines.append(f"  ⚠ Flapping {iface}：{w['hour']} {w['window']} 共 {w['count']} 次")

        # 前 5 大訊息樣式
        top_patterns = sorted(s["pattern_counts"].items(), key=lambda x: -x[1])[:5]
        for pattern, count in top_patterns:
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
        lines.append(f"\n【設備】{device}（共 {len(logs)} 筆）")

        flapping = _detect_flapping(logs)
        if flapping:
            lines.append("  ⚠ Flapping 偵測：")
            for iface, windows in flapping.items():
                for w in windows:
                    lines.append(f"    🔴 {iface}：{w['window_start']}～{w['window_end']} 內 {w['count']} 次")

        pattern_count: dict[str, int] = defaultdict(int)
        level_map_local: dict[str, int] = {}

        for log in logs:
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
