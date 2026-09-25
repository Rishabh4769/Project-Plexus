"""Shared helpers for PLEXUS PDF report templates."""

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.graphics.shapes import Drawing, Rect, String, Line

PAGE_W, PAGE_H = A4


def p(style_name, font="Helvetica", size=9, color=colors.black,
      align=0, leading=None, bold=False, space_after=4, space_before=0):
    return ParagraphStyle(
        style_name, fontName=(font + "-Bold") if bold else font,
        fontSize=size, textColor=color, alignment=align,
        leading=leading or size * 1.35,
        spaceAfter=space_after, spaceBefore=space_before,
    )


def para(text, style):
    return Paragraph(text, style)


def hbar_chart(items, width=7.0 * inch, bar_h=14, gap=6,
               bar_color=colors.HexColor("#3A7BD5"),
               label_color=colors.HexColor("#1E2533"),
               value_color=colors.HexColor("#5D6D7E"),
               font_size=8, max_items=8):
    """Horizontal bar chart as a Drawing. items = [(label, value), ...]."""
    items = items[:max_items]
    if not items:
        return Drawing(width, 10)
    max_v = max(v for _, v in items) or 1
    label_w = 1.3 * inch
    value_w = 0.8 * inch
    bar_area = width - label_w - value_w
    row_h = bar_h + gap
    d = Drawing(width, row_h * len(items))
    for i, (label, value) in enumerate(items):
        y = d.height - (i + 1) * row_h + gap / 2
        d.add(String(label_w - 8, y + 2, str(label)[:18],
                     fontName="Helvetica", fontSize=font_size,
                     fillColor=label_color, textAnchor="end"))
        bw = max(2, bar_area * (value / max_v))
        d.add(Rect(label_w, y, bw, bar_h, fillColor=bar_color,
                   strokeColor=bar_color))
        d.add(String(label_w + bw + 6, y + 2, f"{value:,}",
                     fontName="Helvetica", fontSize=font_size,
                     fillColor=value_color))
    return d


def kpi_strip(stats, box_bg, num_color, label_color, num_size=22):
    """stats = [(label, value), ...] -> one-row Table of KPI boxes."""
    n = len(stats)
    col_w = (7.0 * inch) / n
    cells = []
    for label, value in stats:
        inner = [
            [para(f"<b>{value}</b>",
                  p(f"kpi_n_{label}", size=num_size, color=num_color, bold=True,
                    align=1, space_after=2))],
            [para(label.upper(),
                  p(f"kpi_l_{label}", size=7.5, color=label_color, align=1,
                    space_after=0))],
        ]
        t = Table(inner, colWidths=[col_w - 12])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), box_bg),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        cells.append(t)
    outer = Table([cells], colWidths=[col_w] * n, spaceBefore=6, spaceAfter=6)
    outer.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return outer


def vbar_chart(items, width=7.0 * inch, height=2.8 * inch,
               bar_color=colors.HexColor("#3A7BD5"),
               label_color=colors.HexColor("#1E2533"),
               value_color=colors.HexColor("#5D6D7E"),
               font_size=8, max_items=8):
    """Vertical bar chart as a Drawing. items = [(label, value), ...]."""
    items = items[:max_items]
    if not items:
        return Drawing(width, 10)
    max_v = max(v for _, v in items) or 1
    n = len(items)
    slot = width / n
    bar_w = min(slot * 0.55, 0.65 * inch)
    label_area = 0.42 * inch
    value_area = 0.30 * inch
    chart_h = height - label_area - value_area
    d = Drawing(width, height)
    for i, (label, value) in enumerate(items):
        cx = slot * i + slot / 2
        bh = max(3, chart_h * (value / max_v))
        x = cx - bar_w / 2
        y = label_area
        d.add(Rect(x, y, bar_w, bh, fillColor=bar_color,
                   strokeColor=bar_color))
        d.add(String(cx, y + bh + 7, f"{value:,}",
                     fontName="Helvetica", fontSize=font_size,
                     fillColor=value_color, textAnchor="middle"))
        d.add(String(cx, y - 13, str(label)[:14],
                     fontName="Helvetica", fontSize=font_size,
                     fillColor=label_color, textAnchor="middle"))
    d.add(Line(0, label_area, width, label_area,
               strokeColor=label_color, strokeWidth=0.75))
    return d


def severity_of(alert_type):
    t = (alert_type or "").lower()
    if "flood" in t or "anomaly" in t or "ml " in t:
        return "critical"
    return "normal"


def doc_template(buffer, bg_painter=None, footer=None,
                 left=0.75 * inch, right=0.75 * inch,
                 top=0.85 * inch, bottom=0.75 * inch):
    def _on_page(canvas, doc):
        canvas.saveState()
        if bg_painter:
            bg_painter(canvas)
        if footer:
            footer(canvas, doc)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=left, rightMargin=right,
        topMargin=top, bottomMargin=bottom,
        title="PLEXUS Network Traffic Report", author="PLEXUS NIDS",
    )
    # NB: ReportLab 5.x ignores onFirstPage/onLaterPages passed to the
    # constructor — they must go to build(). Return both.
    return doc, _on_page


def build(generate_fn):
    """Wrap a template's element-builder into generate(data) -> bytes."""
    def generate(data):
        buffer = io.BytesIO()
        elements, doc_kwargs = generate_fn(data)
        doc, on_page = doc_template(buffer, **doc_kwargs)
        doc.build(elements, onFirstPage=on_page, onLaterPages=on_page)
        return buffer.getvalue()
    return generate
