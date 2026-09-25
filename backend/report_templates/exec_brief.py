"""Template 2 — 'Executive Brief': minimal, whitespace-heavy one-pager style."""

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, HRFlowable

from .base import (p, para, kpi_strip, severity_of, build, PAGE_W, PAGE_H)

TEMPLATE_ID = "exec_brief"
TEMPLATE_NAME = "Executive Brief"
TEMPLATE_DESC = "Minimal boardroom style. Verdict banner, KPI cards, auto key findings."

INK      = colors.HexColor("#1A2332")
MUTED    = colors.HexColor("#6B778C")
LINE     = colors.HexColor("#E3E8F0")
CARD_BG  = colors.HexColor("#F6F8FB")
RED      = colors.HexColor("#D64545")
RED_BG   = colors.HexColor("#FDECEC")
AMBER    = colors.HexColor("#C98A12")
AMBER_BG = colors.HexColor("#FFF7E0")
GREEN    = colors.HexColor("#1E8E5A")
GREEN_BG = colors.HexColor("#E9F7F0")
TEAL     = colors.HexColor("#0E7C7B")


def _footer(canvas, doc):
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(0.75 * inch, 0.55 * inch,
                      "PLEXUS Network Intrusion Detection System  •  Confidential")
    canvas.drawRightString(PAGE_W - 0.75 * inch, 0.55 * inch,
                           f"{doc.page}")


def _verdict(data):
    crit = [a for a in data["alerts"]
            if severity_of(a["alert_type"]) == "critical"]
    if crit:
        bg, fg, label = RED_BG, RED, \
            f"{len(crit)} CRITICAL THREAT{'S' if len(crit) != 1 else ''} DETECTED"
    elif data["alerts"]:
        bg, fg, label = AMBER_BG, AMBER, \
            f"{len(data['alerts'])} ADVISORY ALERT{'S' if len(data['alerts']) != 1 else ''}"
    else:
        bg, fg, label = GREEN_BG, GREEN, "NO THREATS DETECTED"
    t = Table([[para(f"<b>{label}</b>",
                     p("v", size=11, color=fg, bold=True, align=1,
                       space_after=0))]],
              colWidths=[7.0 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.75, fg),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _findings(data):
    items = []
    for a in data["alerts"]:
        sev = severity_of(a["alert_type"])
        dot = ("<font color=\"#D64545\">●</font>" if sev == "critical"
               else "<font color=\"#C98A12\">●</font>")
        items.append(
            f"{dot}&nbsp;&nbsp;<b>{a['alert_type']}</b> from "
            f"<b>{a['src_ip']}</b> — {a['description']} "
            f"<font color=\"#6B778C\">({a['timestamp']})</font>")
    if not items:
        items = ["No anomalous activity observed during this session."]
    rows = [[para(f"{i + 1}.&nbsp;&nbsp;{txt}",
                  p("f", size=9, color=INK, space_after=5,
                    leading=13))] for i, txt in enumerate(items)]
    t = Table(rows, colWidths=[7.0 * inch])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def _alert_rows(data):
    rows = []
    for a in data["alerts"]:
        sev = severity_of(a["alert_type"])
        sev_c = "#D64545" if sev == "critical" else "#C98A12"
        rows.append([
            para(a["timestamp"], p("c", size=8, color=MUTED)),
            para(a["src_ip"], p("c", size=8, color=INK)),
            para(a["alert_type"], p("c", size=8, color=INK, bold=True)),
            para(f'<font color="{sev_c}"><b>{sev.upper()}</b></font>',
                 p("c", size=8, bold=True)),
            para(a["description"], p("c", size=8, color=MUTED)),
        ])
    t = Table(rows, colWidths=[1.3 * inch, 1.0 * inch, 1.2 * inch,
                               0.8 * inch, 2.7 * inch])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _elements(data):
    el = []
    # Eyebrow + title
    el.append(para("PLEXUS &nbsp;·&nbsp; NETWORK INTRUSION DETECTION",
                   p("eb", size=8, color=TEAL, bold=True, space_after=4)))
    el.append(para("Threat Brief",
                   p("ti", size=30, color=INK, bold=True, space_after=2)))
    el.append(para(f"Session {data['session_id']} &nbsp;·&nbsp; "
                   f"{data['started_at']} → {data['ended_at']} &nbsp;·&nbsp; "
                   f"{data['iface']}",
                   p("me", size=9, color=MUTED, space_after=10)))

    el.append(_verdict(data))
    el.append(Spacer(1, 0.15 * inch))

    el.append(kpi_strip([
        ("Packets inspected", f"{data['packet_count']:,}"),
        ("Alerts raised", str(data["alert_count"])),
        ("Unique sources", str(len({x['src_ip'] for x in data["packets"][:200]}))),
    ], CARD_BG, INK, MUTED, num_size=24))
    el.append(Spacer(1, 0.1 * inch))

    el.append(para("Key findings", p("s1", size=13, color=INK, bold=True,
                                    space_before=6, space_after=6)))
    el.append(HRFlowable(width="100%", thickness=1, color=LINE,
                         spaceAfter=8))
    el.append(_findings(data))

    el.append(para("Alert detail", p("s2", size=13, color=INK, bold=True,
                                    space_before=10, space_after=4)))
    el.append(HRFlowable(width="100%", thickness=1, color=LINE,
                         spaceAfter=4))
    el.append(_alert_rows(data))

    el.append(para("Scope note",
                   p("sn", size=8, color=MUTED, space_before=14)))
    el.append(para("This brief summarises automated NIDS findings for the "
                   "session window above. ML-flagged anomalies carry a Laya "
                   "second-opinion note (beta). Packet-level evidence is "
                   "retained in the session archive.",
                   p("sn2", size=8, color=MUTED, leading=11)))
    return el


def _generate(data):
    return _elements(data), {"footer": _footer}


generate = build(_generate)
