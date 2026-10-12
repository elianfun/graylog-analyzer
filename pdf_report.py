"""
將 Markdown 格式的分析報告轉為 PDF 日報表（reportlab，使用微軟正黑體）。
支援：# / ## / ### 標題、- 項目符號、| 表格 |、**粗體**、一般段落。
"""
import os
import re
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

_FONT_CANDIDATES = [
    ("C:/Windows/Fonts/msjh.ttc", "C:/Windows/Fonts/msjhbd.ttc"),   # 微軟正黑體
    ("C:/Windows/Fonts/mingliu.ttc", "C:/Windows/Fonts/mingliub.ttc"),
]
FONT, FONT_BOLD = "CJK", "CJK-Bold"

PRIMARY = colors.HexColor("#1F3A5F")
MUTED = colors.HexColor("#5B6573")
RULE = colors.HexColor("#D5DAE1")
LEVEL_COLORS = {
    "P0": colors.HexColor("#FDE2E1"),
    "P1": colors.HexColor("#FFF1D6"),
    "P2": colors.HexColor("#E8F1FB"),
}


def _register_fonts():
    if FONT in pdfmetrics.getRegisteredFontNames():
        return
    for regular, bold in _FONT_CANDIDATES:
        if os.path.exists(regular):
            pdfmetrics.registerFont(TTFont(FONT, regular, subfontIndex=0))
            pdfmetrics.registerFont(TTFont(FONT_BOLD, bold if os.path.exists(bold) else regular,
                                           subfontIndex=0))
            pdfmetrics.registerFontFamily(FONT, normal=FONT, bold=FONT_BOLD,
                                          italic=FONT, boldItalic=FONT_BOLD)
            return
    raise RuntimeError("找不到中文字型（msjh.ttc / mingliu.ttc）")


def _styles() -> dict:
    base = dict(fontName=FONT, leading=15, fontSize=10, alignment=TA_LEFT, wordWrap="CJK")
    return {
        "title": ParagraphStyle("title", **{**base, "fontName": FONT_BOLD, "fontSize": 20,
                                            "leading": 26, "textColor": PRIMARY, "spaceAfter": 6}),
        "h2": ParagraphStyle("h2", **{**base, "fontName": FONT_BOLD, "fontSize": 14, "leading": 20,
                                      "textColor": PRIMARY, "spaceBefore": 12, "spaceAfter": 6}),
        "h3": ParagraphStyle("h3", **{**base, "fontName": FONT_BOLD, "fontSize": 11, "leading": 16,
                                      "textColor": PRIMARY, "spaceBefore": 8, "spaceAfter": 2}),
        "body": ParagraphStyle("body", **{**base, "spaceAfter": 3}),
        "bullet": ParagraphStyle("bullet", **{**base, "leftIndent": 12, "bulletIndent": 2,
                                              "spaceAfter": 2}),
        "meta": ParagraphStyle("meta", **{**base, "fontSize": 9.5, "textColor": MUTED}),
        "cell": ParagraphStyle("cell", **{**base, "fontSize": 8.5, "leading": 11.5}),
        "cell_head": ParagraphStyle("cell_head", **{**base, "fontName": FONT_BOLD, "fontSize": 8.5,
                                                    "leading": 11.5, "textColor": colors.white}),
    }


def _inline(text: str) -> str:
    """跳脫 XML 後處理 **粗體** 與 `程式碼`"""
    text = escape(text.strip())
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`(.+?)`", r"\1", text)
    return text


def _parse_table(lines: list[str], st: dict, width: float) -> Table:
    rows = []
    for line in lines:
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            continue  # 分隔列 |---|---|
        rows.append(cells)
    ncols = max(len(r) for r in rows)
    rows = [r + [""] * (ncols - len(r)) for r in rows]

    data = [[Paragraph(_inline(c), st["cell_head"] if i == 0 else st["cell"]) for c in r]
            for i, r in enumerate(rows)]

    # 欄寬：短欄（等級、IP、設備名稱）依實際文字寬度給足不換行，剩餘寬度依比例分給長欄
    pad = 16   # 左右 padding 各 6pt + 邊框餘裕
    natural = [max(pdfmetrics.stringWidth(re.sub(r"\*\*", "", r[c]), FONT_BOLD, 8.5) for r in rows) + pad
               for c in range(ncols)]
    short = [n <= width * 0.3 for n in natural]
    fixed = sum(n for n, s in zip(natural, short) if s)
    long_total = sum(n for n, s in zip(natural, short) if not s)
    if long_total and fixed < width:
        col_widths = [n if s else (width - fixed) * n / long_total for n, s in zip(natural, short)]
    else:
        col_widths = [width * n / sum(natural) for n in natural]

    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, r in enumerate(rows[1:], 1):
        level = next((k for k in LEVEL_COLORS if r[0].startswith(k)), None)
        if level:
            style.append(("BACKGROUND", (0, i), (-1, i), LEVEL_COLORS[level]))
        elif i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F6F8FA")))
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle(style))
    return table


def markdown_to_story(report: str, st: dict, width: float) -> list:
    story = []
    lines = report.splitlines()
    i = 0
    pending_device: list = []   # ### 設備段落：標題與內容盡量不跨頁

    def flush_device():
        if pending_device:
            story.append(KeepTogether(list(pending_device)))
            pending_device.clear()

    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()
        target = pending_device if pending_device else story

        if not stripped:
            i += 1
            continue
        if stripped.startswith("|"):
            block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i])
                i += 1
            flush_device()
            story.append(_parse_table(block, st, width))
            story.append(Spacer(1, 6))
            continue
        if stripped.startswith("# "):
            flush_device()
            story.append(Paragraph(_inline(stripped[2:]), st["title"]))
        elif stripped.startswith("## "):
            flush_device()
            story.append(Paragraph(_inline(stripped[3:]), st["h2"]))
            story.append(Table([[""]], colWidths=[width], rowHeights=[1],
                               style=[("LINEABOVE", (0, 0), (-1, -1), 0.8, PRIMARY)]))
            story.append(Spacer(1, 4))
        elif stripped.startswith("### "):
            flush_device()
            pending_device.append(Paragraph(_inline(stripped[4:]), st["h3"]))
        elif re.match(r"^[-*]\s+", stripped):
            target.append(Paragraph(_inline(re.sub(r"^[-*]\s+", "", stripped)), st["bullet"],
                                    bulletText="•"))
        elif re.match(r"^\d+\.\s+", stripped):
            num = stripped.split(".", 1)[0]
            target.append(Paragraph(_inline(stripped.split(".", 1)[1]), st["bullet"],
                                    bulletText=f"{num}."))
        elif set(stripped) <= {"=", "-", "━"}:
            pass  # 分隔線
        else:
            target.append(Paragraph(_inline(stripped), st["body"]))
        i += 1
    flush_device()
    return story


def build_pdf(report: str, pdf_path: str, title: str = "Graylog 異常分析日報告") -> str:
    _register_fonts()
    st = _styles()
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont(FONT, 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, 10 * mm, f"{title}　產生時間：{generated}")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"第 {doc.page} 頁")
        canvas.setStrokeColor(PRIMARY)
        canvas.setLineWidth(2)
        canvas.line(doc.leftMargin, A4[1] - 12 * mm, A4[0] - doc.rightMargin, A4[1] - 12 * mm)
        canvas.restoreState()

    doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm, title=title,
                            author="graylog-analyzer")
    story = markdown_to_story(report, st, doc.width)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return pdf_path
