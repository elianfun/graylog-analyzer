import os
import re
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


def output_pdf(report: str, report_dir: str = "./reports", **kwargs):
    """存成 PDF 檔（使用 ReportLab + 微軟正黑體）"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError:
        print("[ERROR] 請安裝 reportlab：pip install reportlab")
        return

    font_reg = r"C:\Windows\Fonts\msjh.ttc"
    font_bold = r"C:\Windows\Fonts\msjhbd.ttc"
    try:
        pdfmetrics.registerFont(TTFont("MSJhengHei", font_reg, subfontIndex=0))
        pdfmetrics.registerFont(TTFont("MSJhengHei-Bold", font_bold, subfontIndex=0))
    except Exception:
        pass  # already registered on repeated calls

    os.makedirs(report_dir, exist_ok=True)
    filename = datetime.now().strftime("report_%Y%m%d_%H%M%S.pdf")
    filepath = os.path.join(report_dir, filename)

    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        rightMargin=20 * mm, leftMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=20 * mm,
    )

    h1_style = ParagraphStyle("H1", fontName="MSJhengHei-Bold", fontSize=16,
                               spaceAfter=6, textColor=colors.HexColor("#1a1a2e"))
    h3_style = ParagraphStyle("H3", fontName="MSJhengHei-Bold", fontSize=11,
                               spaceBefore=12, spaceAfter=4,
                               textColor=colors.HexColor("#2c3e50"),
                               backColor=colors.HexColor("#ecf0f1"),
                               leftIndent=4, borderPadding=(3, 4, 3, 4))
    body_style = ParagraphStyle("Body", fontName="MSJhengHei", fontSize=9.5,
                                 spaceAfter=3, leading=16, leftIndent=8)
    meta_style = ParagraphStyle("Meta", fontName="MSJhengHei", fontSize=10,
                                 spaceAfter=10, textColor=colors.HexColor("#555"))

    def _to_xml(text: str) -> str:
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
        return text

    story = []
    for line in report.splitlines():
        s = line.strip()
        if not s:
            story.append(Spacer(1, 3))
        elif s.startswith("# "):
            story.append(Paragraph(_to_xml(s[2:]), h1_style))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=colors.HexColor("#2c3e50"), spaceAfter=6))
        elif s.startswith("## "):
            story.append(Paragraph(_to_xml(s[3:]), h3_style))
        elif s.startswith("### "):
            story.append(Paragraph(_to_xml(s[4:]), h3_style))
        elif s.startswith("- "):
            story.append(Paragraph("• " + _to_xml(s[2:]), body_style))
        else:
            story.append(Paragraph(_to_xml(s), meta_style))

    doc.build(story)
    print(f"[OK] PDF 報告已儲存：{filepath}")
    return filepath


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
    "pdf": output_pdf,
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
