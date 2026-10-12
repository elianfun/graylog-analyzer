import re
import threading
import time
import requests

try:
    # 使用 Windows 憑證存放區驗證 HTTPS（院內 SSL 檢查設備的根憑證不在 certifi 清單中）
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass


SYSTEM_PROMPT = """你是一位專業的網路設備日誌分析師，負責分析 Juniper 與 Cisco 交換器的 syslog 異常。
請使用繁體中文回答，格式簡潔清楚，避免冗長。"""

_THINK_RE = re.compile(r"<think>.*?</think>", flags=re.DOTALL)


def _truncate(text: str, limit: int) -> str:
    if len(text) > limit:
        return text[:limit] + "\n...(已截斷)"
    return text


class LLMClient:
    """
    LLM 呼叫封裝，支援：
      - openai：OpenAI 相容 API（vLLM、LiteLLM），POST {url}/chat/completions
      - ollama：Ollama 原生 API，POST {url}/api/chat
    """

    def __init__(self, cfg: dict, api_key: str = ""):
        self.provider = cfg.get("provider", "openai")
        self.url = cfg["url"].rstrip("/")
        self.model = cfg["model"]
        self.api_key = api_key
        self.temperature = cfg.get("temperature", 0.1)
        self.max_tokens = cfg.get("max_tokens", 16384)
        self.timeout = cfg.get("timeout", 600)
        self.retries = cfg.get("retries", 2)
        self.max_batch_chars = cfg.get("max_batch_chars", 60000)
        self.max_final_chars = cfg.get("max_final_chars", 120000)
        self.batch_thinking = cfg.get("batch_thinking", True)
        self.final_thinking = cfg.get("final_thinking", True)
        self.thinking_control = cfg.get("thinking_control", True)  # 是否送 enable_thinking 參數（僅 vLLM/Qwen 支援）
        self.dry_run_path =cfg.get("dry_run_path", "")   # 設定時只把請求內容寫入檔案，不送出
        self._dry_run_lock = threading.Lock()

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"

    def _post_openai(self, messages: list[dict], thinking: bool) -> tuple[str, str]:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if not thinking and self.thinking_control:
            # vLLM / Qwen chat template：關閉思考過程
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = requests.post(f"{self.url}/chat/completions", json=payload,
                             headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        choice = resp.json()["choices"][0]
        # 只取正式回答；思考過程在 reasoning / reasoning_content 欄位，不採用
        content = choice["message"].get("content") or ""
        return content, choice.get("finish_reason", "")

    def _post_ollama(self, messages: list[dict], thinking: bool) -> tuple[str, str]:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "think": thinking,
            "keep_alive": 0,   # 回應後立即卸載模型，避免記憶體累積
            "options": {"temperature": self.temperature, "num_ctx": 16384},
        }
        resp = requests.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data["message"].get("content", ""), data.get("done_reason", "")

    def chat(self, messages: list[dict], thinking: bool = True) -> str:
        """呼叫 LLM；例外或空白回應時重試，最終失敗回傳 [ERROR]/[WARN] 字串。"""
        if self.dry_run_path:
            with self._dry_run_lock, open(self.dry_run_path, "a", encoding="utf-8") as f:
                f.write(f"\n{'#' * 80}\n# 請求 → {self.url}/chat/completions  model={self.model}  thinking={thinking}\n{'#' * 80}\n")
                for m in messages:
                    f.write(f"\n----- [{m['role']}] -----\n{m['content']}\n")
            return "（預覽模式：未送出）"
        post =self._post_ollama if self.provider == "ollama" else self._post_openai
        last_problem = ""
        for attempt in range(self.retries + 1):
            try:
                content, finish = post(messages, thinking)
                content = _THINK_RE.sub("", content).strip()
                if content:
                    if finish == "length":
                        content += "\n\n（[WARN] 回應達 max_tokens 上限，內容可能不完整）"
                    return content
                last_problem = f"空白回應（finish_reason={finish}）"
                if finish == "length" and thinking:
                    # 思考過程耗盡 token 額度：改為關閉思考再試，避免重複同樣的失敗
                    print(f"  [LLM] 思考耗盡 max_tokens，改以關閉思考重試", flush=True)
                    thinking = False
            except (requests.exceptions.RequestException, KeyError, IndexError, ValueError) as e:
                last_problem = str(e)
            if attempt < self.retries:
                time.sleep(5 * (attempt + 1))
        if last_problem.startswith("空白回應"):
            return f"[WARN] 模型未回傳分析結果：{last_problem}"
        return f"[ERROR] LLM 呼叫失敗（{self.label}）：{last_problem}"

    def analyze_batch(self, structured_report: str, batch_num: int, total_batches: int) -> str:
        """分析一批設備，回傳該批的分析段落"""
        structured_report = _truncate(structured_report, self.max_batch_chars)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"以下是 Python 精確統計的網路設備異常數據（第 {batch_num}/{total_batches} 批），"
                    f"IP 位址、介面名稱（如 ge-0/0/25）、筆數均為精確值，請原封不動保留，不可推測或捏造。\n\n"
                    f"{structured_report}\n\n"
                    f"請針對本批**每一台**設備輸出繁體中文分析，依資料順序，格式：\n"
                    f"### 【IP位址】設備名稱（直接照抄資料中該設備【】那一行的【】內容，不可改寫或省略）\n"
                    f"- 問題描述（引用精確數據：筆數、介面名稱、出現小時數）\n"
                    f"- 可能原因\n"
                    f"- 建議處置\n"
                    f"只輸出設備分析段落，不要加前言或總結。請直接開始："
                ),
            },
        ]
        return self.chat(messages, thinking=self.batch_thinking)

    def analyze_final(self, priority_table: str, device_summary: str, total_devices: int,
                      range_label: str) -> str:
        """
        接收 Python 判定的優先處理表與全設備摘要，只輸出「異常總覽」段落（分級不交給模型）。
        """
        device_summary = _truncate(device_summary, self.max_final_chars)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"以下是 Python 精確統計的網路設備異常資料（{range_label}，共 {total_devices} 台設備）。"
                    f"IP 位址、介面名稱、筆數均為精確值，請原封不動保留，不可推測或捏造。\n\n"
                    f"【優先處理表】（等級已由程式依規則判定，不可更改）\n{priority_table}\n\n"
                    f"【全設備摘要】（依總筆數排序）\n{device_summary}\n\n"
                    f"請只輸出以下一段（繁體中文、Markdown），不要重複輸出表格：\n"
                    f"## 異常總覽\n"
                    f"4~8 點：主要問題類型與台數、P0 設備最需要先處理的事項（分類歸納，例如硬體故障、介面 flapping）、"
                    f"P1 需排程處理的重點、整體建議。\n"
                    f"提到設備時每個 IP / 代號都要完整寫出（例如 DEV-003、DEV-006），"
                    f"不可縮寫成 DEV-003/006，也不可用「～」表示範圍。\n"
                    f"請直接開始："
                ),
            },
        ]
        return self.chat(messages, thinking=self.final_thinking)

    def analyze(self, log_summary: str) -> str:
        """單次分析（快速模式 / --no-hourly）"""
        log_summary = _truncate(log_summary, self.max_batch_chars)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"以下是網路設備異常日誌，請直接輸出繁體中文分析報告：\n\n"
                    f"{log_summary}\n\n請直接開始寫報告："
                ),
            },
        ]
        return self.chat(messages, thinking=self.final_thinking)
