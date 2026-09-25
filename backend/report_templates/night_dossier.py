"""Template 5 — 'Night Dossier': hybrid.

Theme  → SOC Dark (1): dark analyst-console palette, red masthead accents.
Design → Forensic Dossier (3): case-file structure — metadata table,
         F-01 findings, numbered evidence log, stamped verdict,
         chain-of-custody footer, examiner's note.
Cards  → dark panels with highlight accents (from Pulse stat-card idea).
"""

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, KeepTogether

from .base import (p, para, vbar_chart, severity_of, build, PAGE_W, PAGE_H)

TEMPLATE_ID = "night_dossier"
TEMPLATE_NAME = "Night Dossier"
TEMPLATE_DESC = ("Hybrid: SOC-dark theme + dossier case-file design + "
                 "dark highlight stat cards.")

# ── Theme (from SOC Dark) ───────────────────────────────────────────── #
BG     = colors.HexColor("#0B0E14")
PANEL  = colors.HexColor("#131926")
PANEL2 = colors.HexColor("#1A2233")
RED    = colors.HexColor("#FF4D4D")
AMBER  = colors.HexColor("#FFB020")
TEAL   = colors.HexColor("#35D0BA")
TXT    = colors.HexColor("#E6EAF2")
MUTED  = colors.HexColor("#8B94A7")
GRID   = colors.HexColor("#232D42")


def _bg(canvas):
    canvas.setFillColor(BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)


def _footer(canvas, doc):
    canvas.setFillColor(MUTED)
    canvas.setFont("Courier", 7)
    canvas.drawString(0.75 * inch, 0.5 * inch,
                      "PLEXUS NIDS  •  SESSION EVIDENCE REPORT")
    canvas.drawRightString(PAGE_W - 0.75 * inch, 0.5 * inch,
                           f"PAGE {doc.page}")


# ── Design (from Dossier): stamped verdict ──────────────────────────── #
def _stamp(data):
    crit = any(severity_of(a["alert_type"]) == "critical"
               for a in data["alerts"])
    if data["alerts"]:
        txt = "THREATS DETECTED" if crit else "ADVISORIES NOTED"
        col = RED if crit else AMBER
    else:
        txt, col = "NO THREATS FOUND", TEAL
    inner = Table([[para(f"<b>{txt}</b>",
                         p("st", size=13, color=col, bold=True, align=1,
                           font="Courier", space_after=0))]],
                  colWidths=[2.6 * inch])
    inner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 2, col),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, col),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return inner


# ── Design (from Dossier): case metadata ────────────────────────────── #
def _meta_table(data):
    rows = [
        ("CASE NO.", data["session_id"]),
        ("OPENED", data["started_at"]),
        ("CLOSED", data["ended_at"]),
        ("EXAMINER", "PLEXUS NIDS (automated)"),
        ("SOURCE", data["iface"]),
        ("EXHIBITS", f"{data['packet_count']:,} packets / {data['alert_count']} alerts"),
    ]
    body = [[para(f"<b>{k}</b>", p("k", size=8, color=MUTED, bold=True,
                                   font="Courier")),
             para(v, p("v", size=8.5, color=TXT, font="Courier"))]
            for k, v in rows]
    t = Table(body, colWidths=[1.6 * inch, 5.4 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.75, GRID),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, GRID),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


# ── Cards: dark panels, highlight accents ───────────────────────────── #
def _stat_cards(data):
    crit = sum(1 for a in data["alerts"]
               if severity_of(a["alert_type"]) == "critical")
    cards = [
        (f"{data['packet_count']:,}", "PACKETS", TEAL),
        (str(data["alert_count"]), "ALERTS", AMBER),
        (str(crit), "CRITICAL", RED),
    ]
    n = len(cards)
    col_w = (7.0 * inch) / n
    cells = []
    for val, label, accent in cards:
        inner = Table([
            [para(f"<b>{val}</b>",
                  p("n", size=24, color=accent, bold=True, align=1,
                    space_after=1))],
            [para(label, p("l", size=7.5, color=MUTED, align=1,
                           space_after=0))],
        ], colWidths=[col_w - 14])
        inner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("LINEABOVE", (0, 0), (-1, 0), 3, accent),
            ("BOX", (0, 0), (-1, -1), 0.75, GRID),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        cells.append(inner)
    t = Table([cells], colWidths=[col_w] * n, spaceBefore=4, spaceAfter=4)
    t.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


# ── Design (from Dossier): F-01 findings, dark ──────────────────────── #
def _findings(data):
    rows = []
    for i, a in enumerate(data["alerts"], 1):
        sev = severity_of(a["alert_type"])
        sev_c = RED if sev == "critical" else AMBER
        rows.append([
            para(f"<b>F-{i:02d}</b>", p("c", size=8, color=TXT, bold=True,
                                        font="Courier")),
            para(f"<b>{a['alert_type']}</b><br/>"
                 f"<font color=\"{sev_c.hexval()}\">{sev.upper()}</font>",
                 p("c", size=8, color=TXT)),
            para(a["description"], p("c", size=8, color=MUTED)),
            para(f"{a['src_ip']}<br/><font color=\"#8B94A7\">"
                 f"{a['timestamp'][11:]}</font>",
                 p("c", size=7.5, color=TXT, font="Courier")),
        ])
    if not rows:
        return para("No findings recorded.", p("nf", size=9, color=MUTED))
    t = Table(rows, colWidths=[0.6 * inch, 1.4 * inch, 3.2 * inch, 1.8 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.75, GRID),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [PANEL, colors.HexColor("#101623")]),
    ]))
    return t


# ── Design (from Dossier): evidence log, dark ───────────────────────── #
def _evidence_log(packets):
    rows = [[
        para("<b>EXHIBIT</b>", p("h", size=7.5, color=MUTED, bold=True,
                                 font="Courier")),
        para("<b>TIMESTAMP</b>", p("h", size=7.5, color=MUTED, bold=True,
                                   font="Courier")),
        para("<b>SOURCE</b>", p("h", size=7.5, color=MUTED, bold=True,
                                font="Courier")),
        para("<b>DESTINATION</b>", p("h", size=7.5, color=MUTED, bold=True,
                                     font="Courier")),
        para("<b>PROTO/LEN</b>", p("h", size=7.5, color=MUTED, bold=True,
                                   font="Courier")),
    ]]
    for i, x in enumerate(packets[:100], 1):
        rows.append([
            para(f"<b>EX-{i:03d}</b>", p("c", size=7.5, color=TEAL, bold=True,
                                         font="Courier")),
            para(x["timestamp"], p("c", size=7, color=TXT, font="Courier")),
            para(f"{x['src_ip']}:{x['src_port']}",
                 p("c", size=7, color=TXT, font="Courier")),
            para(f"{x['dst_ip']}:{x['dst_port']}",
                 p("c", size=7, color=TEAL, font="Courier")),
            para(f"{x['protocol']}/{x['length']}",
                 p("c", size=7, color=MUTED, font="Courier")),
        ])
    t = Table(rows, colWidths=[0.75 * inch, 1.5 * inch, 1.75 * inch,
                               1.75 * inch, 1.25 * inch],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL2),
        ("BACKGROUND", (0, 1), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.75, GRID),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, GRID),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def _section(title, accent):
    return para(f'<font color="{accent.hexval()}">▮</font>  {title}',
                p("sec", size=12, color=TXT, bold=True,
                  space_before=10, space_after=6))


def _elements(data):
    el = []
    # Masthead: dossier layout, dark theme
    el.append(para("PLEXUS // CASE FILE",
                   p("mast", size=9, color=RED, bold=True,
                     font="Courier", space_after=2)))
    head = Table([
        [para("Network Intrusion Examination",
              p("ti", size=22, color=TXT, bold=True, space_after=0)),
         _stamp(data)]
    ], colWidths=[4.2 * inch, 2.8 * inch])
    head.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    el.append(head)
    el.append(para("Automated findings — session evidence package",
                   p("su", size=9, color=MUTED, space_after=8)))

    el.append(_meta_table(data))
    el.append(Spacer(1, 0.08 * inch))

    # Dark highlight stat cards
    el.append(_stat_cards(data))
    el.append(Spacer(1, 0.05 * inch))

    # Dossier findings, dark
    el.append(_section("FINDINGS", RED))
    el.append(_findings(data))
    el.append(para("<b>Examiner's note:</b> rule-based findings (port scan, "
                   "flood) are heuristic. ML-flagged flows include an XGBoost "
                   "confidence and, where available, a Laya second-opinion "
                   "note marked beta. Corroborate before action.",
                   p("nt", size=7.5, color=MUTED, space_before=6,
                     space_after=2, leading=10)))

    # SOC-dark port chart — vertical bars (kept with its header)
    el.append(KeepTogether([
        _section("PORT ACTIVITY", TEAL),
        vbar_chart(
            [(f":{r['dst_port']}", r["count"]) for r in data["port_usage"]],
            bar_color=TEAL, label_color=TXT, value_color=MUTED),
    ]))

    # Dossier evidence log, dark — first 100 exhibits
    el.append(_section("EVIDENCE LOG — PACKET EXHIBITS (first 100)", MUTED))
    el.append(_evidence_log(data["packets"]))
    return el


def _generate(data):
    return _elements(data), {"bg_painter": _bg, "footer": _footer}


generate = build(_generate)
