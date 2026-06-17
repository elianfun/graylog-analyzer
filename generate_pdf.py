"""
將 graylog-analyzer 產出的 .txt 報告轉換為精美 PDF（reportlab 版）
用法：python generate_pdf.py <report.txt>  或不帶參數自動選最新報告
"""
import sys
import re
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus.flowables import Flowable

# ── 字型：優先用系統內建中文字型 ──────────────────────────────────────
FONT_PATHS = [
    r"C:\Windows\Fonts\msjh.ttc",       # 微軟正黑體
    r"C:\Windows\Fonts\mingliu.ttc",    # 細明體
    r"C:\Windows\Fonts\kaiu.ttf",       # 標楷體
    r"C:\Windows\Fonts\simsun.ttc",     # 新細明體
]
FONT_NAME = "ZH"
FONT_BOLD = "ZH"

for fp in FONT_PATHS:
    if Path(fp).exists():
        try:
            pdfmetrics.registerFont(TTFont("ZH", fp, subfontIndex=0))
            pdfmetrics.registerFont(TTFont("ZH-Bold", fp, subfontIndex=0))
            FONT_BOLD = "ZH-Bold"
            break
        except Exception:
            continue

# ── 顏色定義 ──────────────────────────────────────────────────────────
C_CRITICAL = colors.HexColor("#C53030")
C_ERROR    = colors.HexColor("#C05621")
C_WARNING  = colors.HexColor("#B7791F")
C_INFO     = colors.HexColor("#2B6CB0")
C_HEADER   = colors.HexColor("#1A365D")
C_SUBHEADER= colors.HexColor("#2D3748")
C_BG_LIGHT = colors.HexColor("#F7FAFC")
C_BORDER   = colors.HexColor("#E2E8F0")
C_TEXT     = colors.HexColor("#2D3748")
C_MUTED    = colors.HexColor("#718096")
C_WHITE    = colors.white


SEV_COLOR = {
    "critical": C_CRITICAL,
    "error":    C_ERROR,
    "warning":  C_WARNING,
    "info":     C_INFO,
}
SEV_BG = {
    "critical": colors.HexColor("#FFF5F5"),
    "error":    colors.HexColor("#FFFAF0"),
    "warning":  colors.HexColor("#FFFFF0"),
    "info":     colors.HexColor("#EBF8FF"),
}
SEV_LABEL = {
    "critical": "CRITICAL",
    "error":    "ERROR",
    "warning":  "WARNING",
    "info":     "INFO",
}


# ── 解析報告 ──────────────────────────────────────────────────────────
def parse_report(txt):
    lines = txt.splitlines()
    generated_at, subtitle, summary = "", "", ""
    for line in lines:
        if line.startswith("產生時間："):
            generated_at = line.replace("產生時間：", "").strip()
        elif line.startswith("# Graylog"):
            subtitle = line.lstrip("# ").strip()
        elif line.startswith("受影響設備"):
            summary = line.strip()

    devices = []
    current = None
    for line in lines:
        m = re.match(r"^### 【(.+?)】(.+)$", line)
        if m:
            if current:
                devices.append(current)
            current = {"ip": m.group(1), "name": m.group(2), "items": []}
        elif current is not None and line.startswith("- "):
            current["items"].append(line[2:].strip())
    if current:
        devices.append(current)

    return subtitle, generated_at, summary, devices


def severity_class(items):
    text = " ".join(items).upper()
    if any(k in text for k in ["CRITICAL", "FAILURE", "WRITE_DMA", "EMERG", "RTC ERROR"]):
        return "critical"
    if any(k in text for k in ["ERROR", "FAN", "NOT SPINNING", "ALARM", "TOO HOT", "TOO WARM"]):
        return "error"
    if any(k in text for k in ["WARNING", "FLAPPING", "LINK DOWN", "KAFKA", "DOWN"]):
        return "warning"
    return "info"


def strip_md(text):
    """移除 **bold** 和 `code` markdown 標記"""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"`(.+?)`", r"[\1]", text)
    return text


# ── 自訂 Flowable：色塊標題列 ─────────────────────────────────────────
class ColorBar(Flowable):
    def __init__(self, width, height, fill_color, text, text_color=C_WHITE, font=FONT_NAME, fontsize=9):
        super().__init__()
        self.width = width
        self.height = height
        self.fill_color = fill_color
        self.text = text
        self.text_color = text_color
        self.font = font
        self.fontsize = fontsize

    def draw(self):
        self.canv.setFillColor(self.fill_color)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        self.canv.setFillColor(self.text_color)
        self.canv.setFont(self.font, self.fontsize)
        self.canv.drawString(6, (self.height - self.fontsize) / 2 + 1, self.text)


# ── 建立 PDF ──────────────────────────────────────────────────────────
def build_pdf(out_path, subtitle, generated_at, summary, devices):
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        topMargin=18*mm, bottomMargin=18*mm,
        leftMargin=18*mm, rightMargin=18*mm,
    )

    W = A4[0] - 36*mm  # 可用寬度

    # ── Styles ──
    def sty(name, font=FONT_NAME, size=9, color=C_TEXT, leading=14, **kw):
        return ParagraphStyle(name, fontName=font, fontSize=size,
                              textColor=color, leading=leading, **kw)

    s_title    = sty("title",   font=FONT_BOLD, size=16, color=C_WHITE,  leading=20)
    s_subtitle = sty("sub",     font=FONT_NAME, size=10, color=colors.HexColor("#BEE3F8"), leading=14)
    s_body     = sty("body",    size=9,  leading=14, spaceAfter=2)
    s_muted    = sty("muted",   size=8,  color=C_MUTED, leading=12)
    s_ip       = sty("ip",      font=FONT_BOLD, size=10, color=C_SUBHEADER, leading=14)
    s_devname  = sty("devname", size=9,  color=C_MUTED,  leading=14)
    s_item     = sty("item",    size=9,  color=C_TEXT,   leading=14, leftIndent=8, spaceAfter=3)
    s_label    = sty("label",   font=FONT_BOLD, size=8,  color=C_WHITE, leading=12)
    s_stat_num = sty("statnum", font=FONT_BOLD, size=20, color=C_WHITE, leading=24, alignment=1)
    s_stat_lbl = sty("statlbl", size=8,  color=colors.HexColor("#E2E8F0"), leading=10, alignment=1)
    s_sec      = sty("sec",     font=FONT_BOLD, size=11, color=C_SUBHEADER, leading=16, spaceBefore=6, spaceAfter=8)

    story = []

    # ── 頁首色塊 ──
    hdr_data = [[
        Paragraph("GRAYLOG Analytics Report", s_title),
        Paragraph(f"產生時間：{generated_at}<br/>分析引擎：Ollama / qwen3.5:4b", s_muted),
    ]]
    hdr_table = Table(hdr_data, colWidths=[W * 0.62, W * 0.38])
    hdr_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_HEADER),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING",(0,0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (0,  -1), 14),
        ("RIGHTPADDING",(1, 0), (1,  -1), 14),
        ("TEXTCOLOR",   (1, 0), (1,  -1), C_MUTED),
        ("ALIGN",       (1, 0), (1,  -1), "RIGHT"),
    ]))
    story.append(hdr_table)

    # 副標題列
    sub_data = [[Paragraph(f"{subtitle}　　{summary}", s_subtitle)]]
    sub_table = Table(sub_data, colWidths=[W])
    sub_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_SUBHEADER),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("LEFTPADDING",  (0, 0), (-1, -1), 14),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 10))

    # ── 統計卡片 ──
    counts = {k: 0 for k in ("critical", "error", "warning", "info")}
    for d in devices:
        counts[severity_class(d["items"])] += 1

    def stat_cell(num, lbl, bg):
        return [Paragraph(str(num), s_stat_num), Paragraph(lbl, s_stat_lbl)]

    stat_data = [[
        *[Table([[Paragraph(str(counts[k]), s_stat_num)],
                 [Paragraph(SEV_LABEL[k], s_stat_lbl)]],
                colWidths=[W / 5 - 4]) for k in ("critical", "error", "warning", "info")],
        Table([[Paragraph(str(len(devices)), s_stat_num)],
               [Paragraph("受影響設備", s_stat_lbl)]],
              colWidths=[W / 5 - 4]),
    ]]

    stat_table = Table([
        [
            Table([[Paragraph(str(counts["critical"]), s_stat_num),
                    Paragraph("CRITICAL", s_stat_lbl)]], colWidths=[W/5-3]),
            Table([[Paragraph(str(counts["error"]),    s_stat_num),
                    Paragraph("ERROR",    s_stat_lbl)]], colWidths=[W/5-3]),
            Table([[Paragraph(str(counts["warning"]),  s_stat_num),
                    Paragraph("WARNING",  s_stat_lbl)]], colWidths=[W/5-3]),
            Table([[Paragraph(str(counts["info"]),     s_stat_num),
                    Paragraph("INFO",     s_stat_lbl)]], colWidths=[W/5-3]),
            Table([[Paragraph(str(len(devices)),       s_stat_num),
                    Paragraph("受影響設備", s_stat_lbl)]], colWidths=[W/5-3]),
        ]
    ], colWidths=[W/5]*5)

    bg_list = [C_CRITICAL, C_ERROR, C_WARNING, C_INFO, C_SUBHEADER]
    stat_ts = TableStyle([("TOPPADDING", (0,0),(-1,-1), 8),
                          ("BOTTOMPADDING",(0,0),(-1,-1),8),
                          ("ALIGN",(0,0),(-1,-1),"CENTER"),
                          ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                          ("ROUNDEDCORNERS",[4]),])
    for i, bg in enumerate(bg_list):
        stat_ts.add("BACKGROUND", (i,0),(i,0), bg)
    stat_table.setStyle(stat_ts)
    story.append(stat_table)
    story.append(Spacer(1, 14))

    # ── 設備清單 ──
    story.append(Paragraph("異常設備分析（依嚴重等級排序）", s_sec))

    # 先排序：critical > error > warning > info
    order = {"critical": 0, "error": 1, "warning": 2, "info": 3}
    sorted_devices = sorted(devices, key=lambda d: order[severity_class(d["items"])])

    for i, d in enumerate(sorted_devices, 1):
        cls  = severity_class(d["items"])
        clr  = SEV_COLOR[cls]
        bg   = SEV_BG[cls]
        lbl  = SEV_LABEL[cls]

        # 標題列
        hdr_row = Table([[
            Paragraph(f"#{i:02d}", s_muted),
            Paragraph(d["ip"], s_ip),
            Paragraph(d["name"], s_devname),
            Paragraph(lbl, s_label),
        ]], colWidths=[10*mm, 38*mm, W - 10*mm - 38*mm - 20*mm, 20*mm])
        hdr_row.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), bg),
            ("BOX",          (0,0), (-1,-1), 0.5, clr),
            ("LINEBEFORE",   (0,0), (0,-1),  3,   clr),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("LEFTPADDING",  (0,0), (0,-1),  6),
            ("BACKGROUND",   (3,0), (3,-1),  clr),
            ("ALIGN",        (3,0), (3,-1),  "CENTER"),
        ]))

        # 內容列（問題/原因/建議）
        item_paras = []
        for item in d["items"]:
            item_paras.append(Paragraph(f"• {strip_md(item)}", s_item))

        body_table = Table([[item_paras]], colWidths=[W])
        body_table.setStyle(TableStyle([
            ("BOX",          (0,0),(-1,-1), 0.5, C_BORDER),
            ("LINEBEFORE",   (0,0),(0,-1),  3,   clr),
            ("TOPPADDING",   (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ("LEFTPADDING",  (0,0),(-1,-1), 10),
            ("BACKGROUND",   (0,0),(-1,-1), C_WHITE),
        ]))

        story.append(KeepTogether([hdr_row, body_table, Spacer(1, 6)]))

    # ── 頁尾 ──
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width=W, color=C_BORDER))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Graylog Analytics Report　|　{generated_at}　|　共 {len(devices)} 台設備",
        sty("footer", size=8, color=C_MUTED, alignment=1)
    ))

    doc.build(story)


# ── 主程式 ────────────────────────────────────────────────────────────
def main():
    reports_dir = Path(__file__).parent / "reports"

    if len(sys.argv) > 1:
        txt_path = Path(sys.argv[1])
    else:
        files = sorted(reports_dir.glob("report_*.txt"), reverse=True)
        if not files:
            print("找不到報告檔案")
            sys.exit(1)
        txt_path = files[0]

    print(f"讀取報告：{txt_path}")
    txt = txt_path.read_text(encoding="utf-8")

    subtitle, generated_at, summary, devices = parse_report(txt)
    print(f"解析完成：{len(devices)} 台設備")

    pdf_path = txt_path.with_suffix(".pdf")
    build_pdf(pdf_path, subtitle, generated_at, summary, devices)
    print(f"PDF 已產出：{pdf_path}")


if __name__ == "__main__":
    main()
