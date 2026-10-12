"""
去識別化：送外部 LLM 前，將 IP、主機名稱、帳號、MAC 換成代號；報告回來後在本機換回。
對照表只存在本機記憶體（可選擇寫入本機檔案供檢查），不會送出。
"""
import copy
import re

_IPV4_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
_MAC_RE = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b')
# 常見登入/帳號樣式：user root、user 'admin'、User=admin、for invalid user test、username: xxx、
# Authentication error for admin from 1.2.3.4（for 後面須接 from 才視為帳號，避免誤遮 "failed for port 12"）
_USER_RE = re.compile(r"(?i)\b(user(?:name)?\s*[=:]?\s*'?|for\s+(?:invalid\s+)?user\s+|for\s+(?=\S+\s+from\s))"
                      r"([A-Za-z0-9_.\-@\\]{2,64})")
_USER_SKIP = {"from", "to", "on", "the", "invalid", "user", "unknown", "root"}  # root 為通用帳號，保留
# 伺服器 / 服務群組 / 角色等名稱（如 A10 SLB：server web01p、group URL_AppWeb_443；VPN：Role=xxx）
_NAME_RE = re.compile(r"(?i)\b(server|service-group|group|virtual-server|vserver|vip|pool|role|realm)"
                      r"(\s*[=:]?\s*'?)([A-Za-z][\w.\-]{1,63})")
_NAME_SKIP = {"shutdown", "is", "down", "up", "start", "started", "stop", "stopped", "local", "error",
              "failed", "the", "of", "for", "status", "port", "health", "state", "timeout"}
TOKEN_RE = re.compile(r'\b(?:DEV|HOST|IP|USER|MAC|NAME)-\d{3,}\b')
_ABBR_RE = re.compile(r'\b(DEV|HOST|IP|USER|MAC|NAME)-(\d{3})((?:/\d{3})+)\b')


class Masker:
    def __init__(self):
        self.forward: dict[str, str] = {}   # 原值 → 代號
        self.counters: dict[str, int] = {}

    def _token(self, kind: str, value: str) -> str:
        if value not in self.forward:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.forward[value] = f"{kind}-{self.counters[kind]:03d}"
        return self.forward[value]

    def mask_text(self, text: str) -> str:
        # 主機名稱較長，先替換，避免其中的部分 IP 片段被拆開
        for name in sorted((k for k, v in self.forward.items() if v.startswith("HOST-")),
                           key=len, reverse=True):
            text = text.replace(name, self.forward[name])
        text = _IPV4_RE.sub(lambda m: self.forward.get(m.group(0)) or self._token("IP", m.group(0)), text)
        text = _MAC_RE.sub(lambda m: self._token("MAC", m.group(0)), text)

        def name_sub(m):
            name = m.group(3)
            if name.lower() in _NAME_SKIP or TOKEN_RE.fullmatch(name):
                return m.group(0)
            return m.group(1) + m.group(2) + self._token("NAME", name)
        text = _NAME_RE.sub(name_sub, text)

        def user_sub(m):
            name = m.group(2)
            if name.lower() in _USER_SKIP or TOKEN_RE.fullmatch(name):
                return m.group(0)
            return m.group(1) + self._token("USER", name)
        return _USER_RE.sub(user_sub, text)

    def mask_stats(self, stats: dict) -> dict:
        """回傳去識別化後的統計資料副本（設備 key、hostname、訊息樣式皆替換）"""
        # 先登記設備與主機名稱，代號依總筆數排序，DEV-001 為最多異常的設備
        for device, s in sorted(stats.items(), key=lambda x: -x[1]["total"]):
            self._token("DEV", device)
            if s.get("hostname") and s["hostname"] != device:
                self._token("HOST", s["hostname"])

        masked = {}
        for device, s in stats.items():
            m = copy.deepcopy(s)
            # 主機名稱代號對分析無用且易讓模型混淆標題，送出時留空（報告回來後由程式補回真實名稱）
            m["hostname"] = ""
            m["pattern_counts"] = {}
            for pattern, count in s["pattern_counts"].items():
                key = self.mask_text(pattern)
                m["pattern_counts"][key] = m["pattern_counts"].get(key, 0) + count
            masked[self.forward[device]] = m
        return masked

    def unmask(self, text: str) -> str:
        reverse = {v: k for k, v in self.forward.items()}
        # 模型常把代號縮寫成 DEV-003/006/008，先展開成完整代號再還原
        text = _ABBR_RE.sub(lambda m: "、".join(
            f"{m.group(1)}-{n}" for n in [m.group(2)] + m.group(3).strip("/").split("/")), text)
        return TOKEN_RE.sub(lambda m: reverse.get(m.group(0), m.group(0)), text)

    def repair_abbreviated(self, text: str) -> str:
        """修復已還原報告中的縮寫殘留：例如「10.0.0.1/006/008」→ 展開為各設備 IP"""
        reverse = {v: k for k, v in self.forward.items()}

        def sub(m):
            token = self.forward.get(m.group(1), "")
            if not token.startswith("DEV-"):
                return m.group(0)
            nums = m.group(2).strip("/").split("/")
            return "、".join([m.group(1)] + [reverse.get(f"DEV-{n}", f"DEV-{n}") for n in nums])
        # /NNN 後面不可接數字或「.」，避免把「1.2.3.4/192.168.5.6」誤判為縮寫
        return re.sub(r'((?:\d{1,3}\.){3}\d{1,3})((?:/\d{3}(?![\d.]))+)', sub, text)

    def leftover_tokens(self, text: str) -> list[str]:
        """unmask 後仍殘留的代號（模型自行捏造、對照表中不存在）"""
        return sorted(set(TOKEN_RE.findall(text)))

    def summary(self) -> str:
        return "、".join(f"{k} {v} 個" for k, v in sorted(self.counters.items()))
