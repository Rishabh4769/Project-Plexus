"""incidents.py — correlate raw alerts into analyst-facing incidents.

SOC-analyst rationale: a lone port scan is noise, but a scan followed by
a SYN flood and DNS tunneling from the same host is one attack story.
Grouping alerts by attacker (and by time window) turns a flood of rows
into a handful of incidents with a severity worth paging someone for.

Pure function, no DB, stdlib only.
"""

from datetime import datetime

_TS_FORMAT = "%Y-%m-%d %H:%M:%S"  # matches sniffer alert timestamps

_CRITICAL_TYPES = {"ARP Spoofing"}
_HIGH_TYPES = {"DNS Tunneling", "SYN Flood"}
_MEDIUM_TYPES = {"Port Scanning", "Flooding"}


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, _TS_FORMAT)
    except (ValueError, TypeError):
        return None


def _severity(alert_types) -> str:
    types = set(alert_types)
    if len(types) >= 3 or types & _CRITICAL_TYPES:
        return "critical"
    if len(types) >= 2 or types & _HIGH_TYPES:
        return "high"
    if types & _MEDIUM_TYPES:
        return "medium"
    return "low"


def _build(src_ip: str, alerts: list) -> dict:
    types = sorted({a[2] for a in alerts})
    stamps = [a[0] for a in alerts]
    return {
        "src_ip": src_ip,
        "alert_types": types,
        "count": len(alerts),
        "first_seen": min(stamps),
        "last_seen": max(stamps),
        "severity": _severity(types),
    }


def correlate(alerts, window: int = 300) -> list:
    """Group alert tuples into incidents.

    alerts: iterable of (timestamp, src_ip, alert_type, description, session_id).
    window: max seconds between consecutive alerts from one IP before a new
            incident is opened.
    Returns a list of dicts:
        {src_ip, alert_types, count, first_seen, last_seen, severity}
    """
    by_ip: dict[str, list] = {}
    for alert in alerts:
        by_ip.setdefault(alert[1], []).append((alert, _parse_ts(alert[0])))

    incidents = []
    for src_ip, items in by_ip.items():
        items.sort(key=lambda it: (it[1] is None, it[1]))
        current: list = []
        last_dt = None
        for alert, dt in items:
            if (current and dt is not None and last_dt is not None
                    and (dt - last_dt).total_seconds() > window):
                incidents.append(_build(src_ip, current))
                current = []
            current.append(alert)
            last_dt = dt
        if current:
            incidents.append(_build(src_ip, current))

    incidents.sort(key=lambda inc: inc["first_seen"])
    return incidents
