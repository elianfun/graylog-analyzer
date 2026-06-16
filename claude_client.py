import os
import anthropic


FINAL_SYSTEM_PROMPT = """你是一位專業的網路設備日誌分析師，負責分析 Juniper 與 Cisco 交換器的 syslog 異常。
請使用繁體中文回答，格式簡潔清楚，避免冗長。"""


def analyze_final_with_claude(structured_report: str, model: str = "claude-haiku-4-5-20251001") -> str:
    """
    使用 Claude API 彙整完整結構化報告。
    支援最大 200K token context，可直接處理完整 45,966 字資料。
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return "[ERROR] 找不到 ANTHROPIC_API_KEY，請在 .env 中設定"

    client = anthropic.Anthropic(api_key=api_key)

    prompt = (
        f"以下是 Python 精確統計的 24 小時網路設備異常數據，"
        f"IP 位址、介面名稱（如 ge-0/0/25）、筆數均為精確值，請原封不動保留。\n\n"
        f"{structured_report}\n\n"
        f"請根據以上完整精確數據，輸出繁體中文日報告，格式如下：\n"
        f"## 1. 今日異常總覽\n"
        f"（設備數、嚴重等級分佈、主要問題類型）\n\n"
        f"## 2. 每台設備分析（所有設備，依嚴重性排序）\n"
        f"### 【IP位址】設備名稱\n"
        f"- 問題描述（引用精確數據：筆數、介面名稱、出現小時數）\n"
        f"- 可能原因\n"
        f"- 建議處置\n\n"
        f"## 3. 優先處理順序（P0/P1/P2，含精確 IP）\n"
        f"| 等級 | IP 位址 | 設備名稱 | 原因摘要 |\n"
        f"請直接開始寫報告："
    )

    try:
        message = client.messages.create(
            model=model,
            max_tokens=4096,
            system=FINAL_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except Exception as e:
        return f"[ERROR] Claude API 失敗: {e}"
