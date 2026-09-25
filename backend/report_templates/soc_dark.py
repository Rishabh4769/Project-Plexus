"""Template 1 — 'SOC Dark': dark analyst-console threat report."""

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from .base import (p, para, hbar_chart, kpi_strip, severity_of, build,
                   PAGE_W, PAGE_H)

TEMPLATE_ID = "soc_dark"
TEMPLATE_NAME = "SOC Dark"
TEMPLATE_DESC = "Dark analyst-console theme. Red alert accents, KPI strip, port bar chart."

BG        = colors.HexColor("#0B0E14")
PANEL     = colors.HexColor("#131926")
PANEL2    = colors.HexColor("#1A2233")
RED       = colors.HexColor("#FF4D4D")
AMBER     = colors.HexColor("#FFB020")
TEAL      = colors.HexColor("#35D0BA")
TXT       = colors.HexColor("#E6EAF2")
MUTED     = colors.HexColor("#8B94A7")
GRID      = colors.HexColor("#232D42")


def _bg(canvas):
    canvas.setFillColor(BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)


def _footer(canvas, doc):
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(0.75 * inch, 0.5 * inch,
                      "PLEXUS NIDS  •  INTERNAL — ANALYST EYES ONLY")
    canvas.drawRightString(PAGE_W - 0.75 * inch, 0.5 * inch,
                           f"PAGE {doc.page}")


def _alert_table(alerts):
    rows = [[
        para("<b>TIME</b>", p("h", size=8, color=MUTED, bold=True)),
        para("<b>SOURCE</b>", p("h", size=8, color=MUTED, bold=True)),
        para("<b>TYPE</b>", p("h", size=8, color=MUTED, bold=True)),
        para("<b>SEVERITY</b>", p("h", size=8, color=MUTED, bold=True)),
        para("<b>DETAIL</b>", p("h", size=8, color=MUTED, bold=True)),
    ]]
    for a in alerts:
        sev = severity_of(a["alert_type"])
        sev_c = RED if sev == "critical" else AMBER
        rows.append([
            para(a["timestamp"], p("c", size=7.5, color=TXT, font="Courier")),
            para(a["src_ip"], p("c", size=7.5, color=TXT, font="Courier")),
            para(a["alert_type"], p("c", size=7.5, color=TXT)),
            para(f"<b>{sev.upper()}</b>", p("c", size=7.5, color=sev_c, bold=True)),
            para(a["description"], p("c", size=7.5, color=MUTED)),
        ])
    t = Table(rows, colWidths=[1.25 * inch, 1.05 * inch, 1.15 * inch,
                               0.85 * inch, 2.7 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL2),
        ("BACKGROUND", (0, 1), (-1, -1), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL, colors.HexColor("#101623")]),
    ]))
    return t


def _packet_table(packets):
    rows = [[para(f"<b>{h}</b>", p("h", size=7.5, color=MUTED, bold=True))
             for h in ("TIME", "SRC", "DST", "SPORT", "DPORT", "LEN", "PROTO", "FLAGS")]]
    for x in packets[:60]:
        rows.append([
            para(x["timestamp"][11:], p("c", size=7, color=MUTED, font="Courier")),
            para(x["src_ip"], p("c", size=7, color=TXT, font="Courier")),
            para(x["dst_ip"], p("c", size=7, color=TXT, font="Courier")),
            para(str(x["src_port"]), p("c", size=7, color=MUTED, font="Courier")),
            para(str(x["dst_port"]), p("c", size=7, color=TEAL, font="Courier")),
            para(str(x["length"]), p("c", size=7, color=MUTED, font="Courier")),
            para(x["protocol"], p("c", size=7, color=TXT, font="Courier")),
            para(x["flags"] or "—", p("c", size=7, color=MUTED, font="Courier")),
        ])
    t = Table(rows, colWidths=[0.75 * inch, 1.15 * inch, 1.15 * inch, 0.6 * inch,
                               0.6 * inch, 0.55 * inch, 0.6 * inch, 0.6 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL2),
        ("BACKGROUND", (0, 1), (-1, -1), PANEL),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _elements(data):
    el = []
    # Masthead
    el.append(para("PLEXUS // THREAT REPORT",
                   p("mast", size=9, color=RED, bold=True,
                     font="Courier", space_after=2)))
    el.append(para("Network Intrusion Detection — Session Summary",
                   p("sub", size=20, color=TXT, bold=True, space_after=2)))
    el.append(para(f"Session <b>{data['session_id']}</b>  •  "
                   f"{data['iface']}  •  "
                   f"{data['started_at']} → {data['ended_at']}",
                   p("meta", size=8.5, color=MUTED, font="Courier",
                     space_after=8)))

    # KPI strip
    crit = sum(1 for a in data["alerts"]
               if severity_of(a["alert_type"]) == "critical")
    el.append(kpi_strip([
        ("Packets", f"{data['packet_count']:,}"),
        ("Alerts", str(data["alert_count"])),
        ("Critical", str(crit)),
        ("Top port", str(data["port_usage"][0]["dst_port"])),
    ], PANEL, TXT, MUTED))
    el.append(Spacer(1, 0.1 * inch))

    # Alerts
    el.append(para('<font color="#FF4D4D">▮</font>  ALERTS',
                   p("s1", size=12, color=TXT, bold=True,
                     space_before=8, space_after=6)))
    el.append(_alert_table(data["alerts"]))
    el.append(Spacer(1, 0.15 * inch))

    # Port activity chart
    el.append(para('<font color="#35D0BA">▮</font>  PORT ACTIVITY',
                   p("s2", size=12, color=TXT, bold=True,
                     space_before=8, space_after=6)))
    el.append(hbar_chart(
        [(f":{r['dst_port']} {r['protocol']}", r["count"])
         for r in data["port_usage"]],
        bar_color=TEAL, label_color=TXT, value_color=MUTED))
    el.append(Spacer(1, 0.15 * inch))

    # Packet sample
    el.append(para('<font color="#8B94A7">▮</font>  PACKET SAMPLE (latest 60)',
                   p("s3", size=12, color=TXT, bold=True,
                     space_before=8, space_after=6)))
    el.append(_packet_table(data["packets"]))
    return el


def _generate(data):
    return _elements(data), {"bg_painter": _bg, "footer": _footer}


generate = build(_generate)
