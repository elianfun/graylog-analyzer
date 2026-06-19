import re
import time
import requests


SYSTEM_PROMPT = """你是一位專業的網路設備日誌分析師，負責分析 Juniper 與 Cisco 交換器的 syslog 異常。
請使用繁體中文回答，格式簡潔清楚，避免冗長。"""


def _unload_model(url: str, model: str) -> None:
    """強制 Ollama 卸載模型，釋放記憶體。"""
    try:
        requests.post(f"{url}/api/generate",
                      json={"model": model, "keep_alive": 0},
                      timeout=10)
    except Exception:
        pass


def _call_ollama(url: str, model: str, messages: list[dict], timeout: int = 120) -> str:
    """共用的 Ollama chat 呼叫。content 空白時 retry 一次，強制輸出。"""
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "keep_alive": 0,   # 回應後立即卸載，釋放記憶體
        "think": False,    # 停用 Qwen3 思考模式，避免生成大量推理 token 拖慢速度
        "options": {"temperature": 0.1, "num_ctx": 16384},
    }

    def _extract(data: dict) -> str:
        content = data["message"].get("content", "").strip()
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        return content

    max_retries = 2
    retry_delay = 5  # 秒

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(f"{url}/api/chat", json=payload, timeout=timeout)
            resp.raise_for_status()
            content = _extract(resp.json())

            # content 空白：retry，在 user message 末尾強制要求立即輸出
            if not content:
                retry_messages = messages[:-1] + [{
                    "role": messages[-1]["role"],
                    "content": messages[-1]["content"] + "\n\n（請立即輸出結果，不要思考過程）",
                }]
                payload["messages"] = retry_messages
                resp2 = requests.post(f"{url}/api/chat", json=payload, timeout=timeout)
                resp2.raise_for_status()
                content = _extract(resp2.json())

            return content or "[WARN] 模型未回傳分析結果"

        except requests.exceptions.RequestException as e:
            if attempt < max_retries:
                print(f"    [WARN] Ollama 連線失敗（第 {attempt}/{max_retries} 次），{retry_delay} 秒後重試... ({e})")
                time.sleep(retry_delay)
            else:
                return f"[ERROR] Ollama 失敗（已重試 {max_retries} 次）: {e}"


class OllamaClient:
    def __init__(self, url: str, model: str):
        self.url = url.rstrip("/")
        self.model = model

    def analyze_hourly(self, hour_label: str, log_summary: str) -> str:
        """分析單一小時的 log，輸出 3~8 行簡短摘要"""
        if len(log_summary) > 3000:
            log_summary = log_summary[:3000] + "\n...(已截斷)"

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"以下是 {hour_label} 這一小時的網路設備異常日誌：\n\n"
                    f"{log_summary}\n\n"
                    f"請直接輸出 3~8 行繁體中文摘要，格式：\n"
                    f"- [設備IP/名稱] 問題描述（筆數）\n"
                    f"若無異常請回覆「無異常」。請直接開始："
                ),
            },
        ]
        return _call_ollama(self.url, self.model, messages, timeout=120)

    def analyze_batch(self, structured_report: str, batch_num: int, total_batches: int) -> str:
        """分析一批設備（分批送 Ollama 使用），回傳該批的分析段落"""
        if len(structured_report) > 6000:
            structured_report = structured_report[:6000] + "\n...(已截斷)"

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"以下是 Python 精確統計的網路設備異常數據（第 {batch_num}/{total_batches} 批），"
                    f"IP 位址、介面名稱（如 ge-0/0/25）、筆數均為精確值，請原封不動保留。\n\n"
                    f"{structured_report}\n\n"
                    f"請針對本批每台設備輸出繁體中文分析，格式：\n"
                    f"### 【IP位址】設備名稱\n"
                    f"- 問題描述（引用精確數據）\n"
                    f"- 可能原因\n"
                    f"- 建議處置\n"
                    f"請直接開始："
                ),
            },
        ]
        return _call_ollama(self.url, self.model, messages, timeout=120)

    def analyze_final(self, structured_report: str) -> str:
        """
        接收 Python 已彙整的精確結構化統計，
        Ollama 只補充每台設備的可能原因與建議處置，不得更改 IP、介面名稱、筆數。
        """
        if len(structured_report) > 8000:
            structured_report = structured_report[:8000] + "\n...(已截斷)"

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"以下是 Python 精確統計的 24 小時網路設備異常數據（前 20 台），"
                    f"IP 位址、介面名稱（如 ge-0/0/25）、筆數均為精確值，請原封不動保留。\n\n"
                    f"{structured_report}\n\n"
                    f"請根據以上精確數據，僅輸出優先處理順序表格（P0/P1/P2），格式：\n"
                    f"| 等級 | IP 位址 | 設備名稱 | 原因摘要 |\n"
                    f"每台設備一列，必須使用精確 IP。請直接輸出表格："
                ),
            },
        ]
        return _call_ollama(self.url, self.model, messages, timeout=120)

    def analyze(self, log_summary: str) -> str:
        """單次分析（向下相容）"""
        if len(log_summary) > 3000:
            log_summary = log_summary[:3000] + "\n...(已截斷)"

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
        return _call_ollama(self.url, self.model, messages)
