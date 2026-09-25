"""Template 3 — 'Forensic Dossier': case-file / evidence-log aesthetic."""

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from .base import (p, para, severity_of, build, PAGE_W, PAGE_H)

TEMPLATE_ID = "dossier"
TEMPLATE_NAME = "Forensic Dossier"
TEMPLATE_DESC = "Case-file styling. Evidence log, findings, stamped verdict, chain-of-custody footer."

PAPER   = colors.HexColor("#F7F3E9")
INK     = colors.HexColor("#2B2620")
MUTED   = colors.HexColor("#7A7264")
RULE    = colors.HexColor("#D8CFB8")
STAMP_R = colors.HexColor("#B3372E")
STAMP_G = colors.HexColor("#2E7D4F")
EVID_BG = colors.HexColor("#FFFFFF")


def _bg(canvas):
    canvas.setFillColor(PAPER)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)


def _footer(canvas, doc):
    canvas.setFillColor(MUTED)
    canvas.setFont("Courier", 7)
    canvas.drawString(0.75 * inch, 0.5 * inch,
                      "PLEXUS NIDS  •  SESSION EVIDENCE REPORT")
    canvas.drawRightString(PAGE_W - 0.75 * inch, 0.5 * inch,
                           f"PAGE {doc.page}")


def _stamp(data):
    crit = any(severity_of(a["alert_type"]) == "critical"
               for a in data["alerts"])
    if data["alerts"]:
        txt, col = ("THREATS DETECTED" if crit else "ADVISORIES NOTED"), \
                   (STAMP_R if crit else colors.HexColor("#B07A1E"))
    else:
        txt, col = "NO THREATS FOUND", STAMP_G
    inner = Table([[para(f"<b>{txt}</b>",
                         p("st", size=13, color=col, bold=True, align=1,
                           font="Courier", space_after=0))]],
                  colWidths=[2.6 * inch])
    inner.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 2, col),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, col),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return inner


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
             para(v, p("v", size=8.5, color=INK, font="Courier"))]
            for k, v in rows]
    t = Table(body, colWidths=[1.6 * inch, 5.4 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), EVID_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, RULE),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _findings(data):
    rows = []
    for i, a in enumerate(data["alerts"], 1):
        sev = severity_of(a["alert_type"])
        sev_c = "#B3372E" if sev == "critical" else "#B07A1E"
        rows.append([
            para(f"<b>F-{i:02d}</b>", p("c", size=8, color=INK, bold=True,
                                        font="Courier")),
            para(f"<b>{a['alert_type']}</b><br/><font color=\"{sev_c}\">"
                 f"{sev.upper()}</font>",
                 p("c", size=8, color=INK)),
            para(a["description"], p("c", size=8, color=INK)),
            para(f"{a['src_ip']}<br/><font color=\"#7A7264\">"
                 f"{a['timestamp'][11:]}</font>",
                 p("c", size=7.5, color=INK, font="Courier")),
        ])
    if not rows:
        return para("No findings recorded.", p("nf", size=9, color=MUTED))
    t = Table(rows, colWidths=[0.6 * inch, 1.4 * inch, 3.2 * inch, 1.8 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), EVID_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, RULE),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _evidence_log(packets):
    rows = []
    for i, x in enumerate(packets[:50], 1):
        rows.append([
            para(f"{i:03d}", p("c", size=7, color=MUTED, font="Courier")),
            para(x["timestamp"], p("c", size=7, color=INK, font="Courier")),
            para(f"{x['src_ip']}:{x['src_port']}",
                 p("c", size=7, color=INK, font="Courier")),
            para(f"{x['dst_ip']}:{x['dst_port']}",
                 p("c", size=7, color=INK, font="Courier")),
            para(f"{x['protocol']}/{x['length']}",
                 p("c", size=7, color=MUTED, font="Courier")),
        ])
    t = Table(rows, colWidths=[0.5 * inch, 1.5 * inch, 1.9 * inch,
                               1.9 * inch, 1.2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), EVID_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, RULE),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _elements(data):
    el = []
    el.append(para("DIGITAL FORENSICS  •  NETWORK DIVISION",
                   p("eb", size=8, color=MUTED, bold=True, font="Courier",
                     space_after=2)))
    head = Table([
        [para("CASE FILE", p("ti", size=28, color=INK, bold=True,
                             font="Courier", space_after=0)),
         _stamp(data)]
    ], colWidths=[4.2 * inch, 2.8 * inch])
    head.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    el.append(head)
    el.append(para("Network intrusion examination — automated findings",
                   p("su", size=10, color=MUTED, space_after=10)))

    el.append(_meta_table(data))
    el.append(Spacer(1, 0.15 * inch))

    el.append(para("FINDINGS", p("s1", size=12, color=INK, bold=True,
                                 font="Courier", space_before=6,
                                 space_after=6)))
    el.append(_findings(data))
    el.append(Spacer(1, 0.12 * inch))

    el.append(para("EVIDENCE LOG — PACKET EXHIBITS (first 50)",
                   p("s2", size=12, color=INK, bold=True, font="Courier",
                     space_before=6, space_after=6)))
    el.append(_evidence_log(data["packets"]))

    el.append(para("Examiner's note: rule-based findings (port scan, flood) "
                   "are heuristic. ML-flagged flows include an XGBoost "
                   "confidence and, where available, a Laya second-opinion "
                   "note marked beta. Corroborate before action.",
                   p("nt", size=8, color=MUTED, space_before=12,
                     leading=11)))
    return el


def _generate(data):
    return _elements(data), {"bg_painter": _bg, "footer": _footer}


generate = build(_generate)
