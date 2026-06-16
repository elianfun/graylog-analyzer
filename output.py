import os
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def output_terminal(report: str, **kwargs):
    """直接印在終端機"""
    print("\n" + "=" * 60)
    print("Graylog 異常分析報告")
    print("=" * 60)
    print(report)
    print("=" * 60 + "\n")


def output_file(report: str, report_dir: str = "./reports", **kwargs):
    """存成文字檔"""
    os.makedirs(report_dir, exist_ok=True)
    filename = datetime.now().strftime("report_%Y%m%d_%H%M%S.txt")
    filepath = os.path.join(report_dir, filename)

    header = (
        f"Graylog 異常分析報告\n"
        f"產生時間：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'=' * 60}\n\n"
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(header + report)

    print(f"[OK] 報告已儲存：{filepath}")
    return filepath


def output_email(report: str, smtp_host: str, smtp_port: int,
                 sender: str, password: str, recipients: list[str], **kwargs):
    """寄送 Email"""
    subject = f"【Graylog 異常報告】{datetime.now().strftime('%Y-%m-%d %H:%M')}"

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(report, "plain", "utf-8"))

    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(sender, password)
            server.sendmail(sender, recipients, msg.as_string())
        print(f"[OK] Email 已寄出至：{recipients}")
    except Exception as e:
        print(f"[ERROR] Email 寄送失敗: {e}")


def output_line(report: str, line_token: str, **kwargs):
    """推送 Line Notify"""
    import requests
    headers = {"Authorization": f"Bearer {line_token}"}
    # Line Notify 單則訊息上限 1000 字，超過則截斷
    message = report[:950] + "...\n（完整報告請查看檔案）" if len(report) > 950 else report
    payload = {"message": f"\nGraylog 異常分析\n\n{message}"}
    try:
        resp = requests.post(
            "https://notify-api.line.me/api/notify",
            headers=headers,
            data=payload,
            timeout=10,
        )
        if resp.status_code == 200:
            print("[✅] Line Notify 推送成功")
        else:
            print(f"[ERROR] Line Notify 失敗: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[ERROR] Line Notify 失敗: {e}")


OUTPUT_HANDLERS = {
    "terminal": output_terminal,
    "file": output_file,
    "email": output_email,
    "line": output_line,
}


def send_output(method: str, report: str, **kwargs):
    handler = OUTPUT_HANDLERS.get(method)
    if handler:
        handler(report, **kwargs)
    else:
        print(f"[WARN] 未知的輸出方式：{method}，改用 terminal")
        output_terminal(report)
