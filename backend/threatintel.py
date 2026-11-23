"""threatintel.py — local blocklist enrichment for alerts.

No API keys, no network calls: a static blocklist of known-bad IPs
(documentation / TEST-NET ranges only — never real addresses) is checked
against every alert's source IP. Pure stdlib; degrades to a no-op when the
data file is missing.
"""

from pathlib import Path

_BLOCKLIST_PATH = Path(__file__).resolve().parent / "data" / "blocklist.txt"
_BLOCKLISTED_TAG = " [blocklisted]"


def _load_blocklist() -> set[str]:
    ips: set[str] = set()
    try:
        for line in _BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    except OSError:
        pass  # missing file -> empty blocklist, enrichment degrades to no-op
    return ips


_BLOCKLISTED_IPS: set[str] = _load_blocklist()


def is_blocklisted(ip: str) -> bool:
    """True when ip appears on the local blocklist."""
    return ip in _BLOCKLISTED_IPS


def enrich_alert(alert: tuple):
    """Tag an alert tuple when its source IP is blocklisted.

    Returns (alert_tuple, flagged). The description gains a
    " [blocklisted]" suffix when flagged; otherwise the tuple is
    returned unchanged.
    """
    ts, src_ip, alert_type, description, session_id = alert
    if is_blocklisted(src_ip):
        description = f"{description}{_BLOCKLISTED_TAG}"
        return (ts, src_ip, alert_type, description, session_id), True
    return alert, False
