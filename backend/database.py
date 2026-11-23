"""
database.py — SQLite layer for PLEXUS.
All queries use parameterised statements to prevent SQL injection.
"""

import sqlite3
import datetime
import os
import numpy as np
from pathlib import Path

# Overridable via PLEXUS_DB_PATH so the docker image can persist the
# database on a mounted volume (compose sets /data/network_traffic.db).
DB_PATH = Path(os.environ.get("PLEXUS_DB_PATH", Path(__file__).parent.parent / "network_traffic.db"))


# Alert severity for graph dot coloring (single source of truth).
#   critical -> red dot   (active attack: flood, ML-confirmed anomaly)
#   normal   -> yellow dot (reconnaissance: port scan)
# Unknown future alert types default to "normal".
ALERT_SEVERITY = {
    "Flooding":        "critical",
    "ML NIDS Anomaly": "critical",
    "Port Scanning":   "normal",
}


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT    NOT NULL,
                src_ip     TEXT    NOT NULL,
                dst_ip     TEXT    NOT NULL DEFAULT '',
                src_port   INTEGER NOT NULL DEFAULT 0,
                dst_port   INTEGER NOT NULL DEFAULT 0,
                length     INTEGER NOT NULL DEFAULT 0,
                protocol   TEXT    NOT NULL DEFAULT 'IP',
                flags      TEXT    NOT NULL DEFAULT '',
                ttl        INTEGER NOT NULL DEFAULT 0,
                checksum   INTEGER NOT NULL DEFAULT 0,
                payload    TEXT    NOT NULL DEFAULT '',
                session_id TEXT    NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                src_ip      TEXT    NOT NULL,
                alert_type  TEXT    NOT NULL,
                description TEXT    NOT NULL,
                session_id  TEXT    NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    NOT NULL UNIQUE,
                password_hash TEXT   NOT NULL,
                created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                last_login   TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS app_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT    NOT NULL DEFAULT (datetime('now')),
                source     TEXT    NOT NULL,
                level      TEXT    NOT NULL DEFAULT 'INFO',
                category   TEXT    NOT NULL DEFAULT 'general',
                message    TEXT    NOT NULL,
                detail     TEXT    NOT NULL DEFAULT '',
                session_id TEXT    NOT NULL DEFAULT '',
                username   TEXT    NOT NULL DEFAULT ''
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        # Indexes for common query patterns
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_source    ON app_logs(source)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_level     ON app_logs(level)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_ts        ON app_logs(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session  ON alerts(session_id)")
        # --- v3.2.0: events table (SIEM common schema; benchmarked against
        # ECS / OCSF / Wazuh / Splunk CIM — see docs/schema-benchmark-professional-siem.md)
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                event_uid      TEXT    NOT NULL UNIQUE,
                timestamp      TEXT    NOT NULL,
                ingested_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                schema_version TEXT    NOT NULL DEFAULT '1.0',
                event_category TEXT    NOT NULL CHECK (event_category IN
                    ('authentication','iam','system','host','network','process','file','configuration','application')),
                event_action   TEXT    NOT NULL,
                event_type     TEXT    CHECK (event_type IN
                    ('access','admin','change','connection','creation','deletion','denied','end','error','info','start','user')),
                outcome        TEXT    CHECK (outcome IN ('success','failure','unknown')),
                severity_id    INTEGER NOT NULL DEFAULT 1 CHECK (severity_id BETWEEN 0 AND 5),
                source_type    TEXT    NOT NULL,
                app            TEXT,
                user_name      TEXT,
                src_user_name  TEXT,
                user_id        INTEGER REFERENCES users(id),
                src_ip         TEXT,
                src_port       INTEGER CHECK (src_port BETWEEN 0 AND 65535),
                dst_ip         TEXT,
                dst_port       INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
                host_name      TEXT,
                session_id     TEXT,
                message        TEXT,
                raw            TEXT,
                raw_hash       TEXT,
                detail         TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_cat_act  ON events(event_category, event_action, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events(src_ip, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_user     ON events(user_name, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity_id, timestamp)")
        # --- v3.2.0: alerts lifecycle + rule identity + pivot columns (additive, idempotent)
        _alert_cols = {row[1] for row in c.execute("PRAGMA table_info(alerts)")}
        for _name, _ddl in (
            ("ingested_at",         "ingested_at TEXT"),
            ("severity_id",         "severity_id INTEGER CHECK (severity_id BETWEEN 0 AND 5)"),
            ("rule_id",             "rule_id TEXT"),
            ("rule_name",           "rule_name TEXT"),
            ("rule_groups",         "rule_groups TEXT"),
            ("dst_ip",              "dst_ip TEXT"),
            ("dst_port",            "dst_port INTEGER"),
            ("user_name",           "user_name TEXT"),
            ("host_name",           "host_name TEXT"),
            ("event_id",            "event_id INTEGER REFERENCES events(id)"),
            ("event_count",         "event_count INTEGER NOT NULL DEFAULT 1"),
            ("first_seen",          "first_seen TEXT"),
            ("last_seen",           "last_seen TEXT"),
            ("mitre_tactic",        "mitre_tactic TEXT"),
            ("mitre_technique_id",  "mitre_technique_id TEXT CHECK (mitre_technique_id IS NULL OR mitre_technique_id GLOB 'T[0-9][0-9][0-9][0-9]*')"),
            ("mitre_technique_name","mitre_technique_name TEXT"),
            ("status",              "status TEXT NOT NULL DEFAULT 'open'"),
            ("notes",               "notes TEXT NOT NULL DEFAULT ''"),
            ("resolved_at",         "resolved_at TEXT"),
            ("acknowledged_by",     "acknowledged_by TEXT"),
            ("resolved_by",         "resolved_by TEXT"),
        ):
            if _name not in _alert_cols:
                c.execute(f"ALTER TABLE alerts ADD COLUMN {_ddl}")
        conn.commit()


def log_packet(data: tuple) -> None:
    """data = (timestamp, src_ip, dst_ip, src_port, dst_port, length, protocol, flags, ttl, checksum, payload, session_id)"""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, length, protocol, flags, ttl, checksum, payload, session_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            data,
        )
        conn.commit()


def log_alert(data: tuple) -> None:
    """data = (timestamp, src_ip, alert_type, description, session_id)"""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO alerts (timestamp, src_ip, alert_type, description, session_id) "
            "VALUES (?, ?, ?, ?, ?)",
            data,
        )
        conn.commit()


_EVENT_COLUMNS = (
    "event_uid", "timestamp", "ingested_at", "schema_version",
    "event_category", "event_action", "event_type", "outcome", "severity_id",
    "source_type", "app", "user_name", "src_user_name", "user_id",
    "src_ip", "src_port", "dst_ip", "dst_port", "host_name",
    "session_id", "message", "raw", "raw_hash", "detail",
)


def log_event(data: dict) -> int:
    """Insert one normalized event into the events table; returns the row id.

    Required keys: timestamp (ISO-8601 UTC), event_category, event_action,
    source_type. event_uid / ingested_at / schema_version / severity_id are
    filled with writer-side defaults when absent (schema discipline: UUID4
    identity, UTC ingest time, OCSF severity 0-5)."""
    import uuid
    from datetime import datetime, timezone

    row = {col: data.get(col) for col in _EVENT_COLUMNS}
    if not row["event_uid"]:
        row["event_uid"] = str(uuid.uuid4())
    if not row["ingested_at"]:
        row["ingested_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if not row["schema_version"]:
        row["schema_version"] = "1.0"
    if row["severity_id"] is None:
        row["severity_id"] = 1
    cols = ", ".join(_EVENT_COLUMNS)
    marks = ", ".join("?" for _ in _EVENT_COLUMNS)
    with get_connection() as conn:
        cur = conn.execute(
            f"INSERT INTO events ({cols}) VALUES ({marks})",
            tuple(row[col] for col in _EVENT_COLUMNS),
        )
        conn.commit()
        return cur.lastrowid


def get_sessions() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT session_id,
                   MIN(timestamp) AS started_at,
                   COUNT(*)       AS packet_count
            FROM packets
            GROUP BY session_id
            ORDER BY started_at DESC
        """).fetchall()
    return [dict(r) for r in rows]


def get_packets(session_id: str, limit: int = 500, offset: int = 0) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, length, protocol, flags, ttl, checksum, payload "
            "FROM packets WHERE session_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (session_id, limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def search_packets(
    session_id: str,
    protocol: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    flags: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """
    Multi-field search — all params are AND-ed together.
    Empty/None params are ignored (Wireshark-style behavior).
    """
    clauses = ["session_id = ?"]
    params  = [session_id]

    if protocol:
        clauses.append("LOWER(protocol) = LOWER(?)")
        params.append(protocol)
    if src_ip:
        clauses.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")
    if dst_ip:
        clauses.append("dst_ip LIKE ?")
        params.append(f"%{dst_ip}%")
    if src_port is not None:
        clauses.append("src_port = ?")
        params.append(src_port)
    if dst_port is not None:
        clauses.append("dst_port = ?")
        params.append(dst_port)
    if flags:
        clauses.append("flags LIKE ?")
        params.append(f"%{flags}%")

    sql = (
        "SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, length, protocol, flags, ttl, checksum, payload "
        "FROM packets WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ?"
    )
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_alerts(session_id: str, limit: int = 200, offset: int = 0) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp, src_ip, alert_type, description "
            "FROM alerts WHERE session_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (session_id, limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def get_port_usage(session_id: str) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT dst_port, protocol, COUNT(*) AS count "
            "FROM packets WHERE session_id = ? "
            "GROUP BY dst_port, protocol ORDER BY count DESC LIMIT 50",
            (session_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_talkers(session_id: str, limit: int = 10) -> list[dict]:
    """Return top source IPs by packet count and total bytes."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT src_ip, COUNT(*) AS packet_count, SUM(length) AS total_bytes "
            "FROM packets WHERE session_id = ? "
            "GROUP BY src_ip ORDER BY packet_count DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_graph_data(session_id: str) -> dict:
    with get_connection() as conn:
        pkt_rows = conn.execute(
            "SELECT timestamp FROM packets WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        ).fetchall()
        alert_rows = conn.execute(
            "SELECT timestamp, alert_type FROM alerts WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        ).fetchall()

    def to_epoch(ts: str) -> float | None:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.datetime.strptime(ts, fmt).timestamp()
            except ValueError:
                continue
        return None

    pkt_times   = [t for t in (to_epoch(r["timestamp"]) for r in pkt_rows)   if t is not None]
    alert_times = []
    alert_sevs  = []
    for r in alert_rows:
        t = to_epoch(r["timestamp"])
        if t is not None:
            alert_times.append(t)
            alert_sevs.append(ALERT_SEVERITY.get(r["alert_type"], "normal"))

    if not pkt_times and not alert_times:
        return {"labels": [], "packets": [], "alerts": [], "alert_severity": []}

    all_times = pkt_times + alert_times
    min_ts, max_ts = min(all_times), max(all_times)
    duration = max_ts - min_ts
    buckets = 1 if duration == 0 else min(60, max(5, int(duration) + 1))
    edges = np.linspace(min_ts, max_ts + 1, buckets + 1)

    pkt_counts   = np.histogram(pkt_times,   bins=edges)[0] if pkt_times   else np.zeros(buckets, dtype=int)
    alert_counts = np.histogram(alert_times, bins=edges)[0] if alert_times else np.zeros(buckets, dtype=int)

    labels = [
        datetime.datetime.fromtimestamp(edges[i]).strftime("%H:%M:%S")
        for i in range(buckets)
    ]

    # Per-bucket severity for dot coloring: critical wins over normal,
    # None where the bucket has no alerts.
    sev_per_bucket = [None] * buckets
    if alert_times:
        bucket_idx = np.clip(np.digitize(alert_times, edges) - 1, 0, buckets - 1)
        for i, s in zip(bucket_idx, alert_sevs):
            i = int(i)
            if s == "critical":
                sev_per_bucket[i] = "critical"
            elif sev_per_bucket[i] is None:
                sev_per_bucket[i] = "normal"

    return {
        "labels":  labels,
        "packets": pkt_counts.tolist(),
        "alerts":  alert_counts.tolist(),
        "alert_severity": sev_per_bucket,
    }


def get_session_summary(session_id: str) -> dict:
    with get_connection() as conn:
        pkt_count = conn.execute(
            "SELECT COUNT(*) FROM packets WHERE session_id = ?", (session_id,)
        ).fetchone()[0]
        alert_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE session_id = ?", (session_id,)
        ).fetchone()[0]
        started = conn.execute(
            "SELECT MIN(timestamp) FROM packets WHERE session_id = ?", (session_id,)
        ).fetchone()[0]
    return {
        "session_id":   session_id,
        "packet_count": pkt_count,
        "alert_count":  alert_count,
        "started_at":   started,
    }


# ── Session management (persistent, multi-worker safe) ────────────────── #

def create_session_row(token_hash: str, username: str, expires_at: float) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)",
            (token_hash, username, expires_at),
        )
        conn.commit()


def get_session_row(token_hash: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
    return dict(row) if row else None


def touch_session(token_hash: str, expires_at: float) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (expires_at, token_hash),
        )
        conn.commit()


def delete_session_row(token_hash: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()


def purge_expired_sessions(now: float) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.commit()


# ── User management ───────────────────────────────────────────────────── #

def create_user(username: str, password_hash: str) -> bool:
    """
    Insert a new user. Returns True on success, False if username already exists.
    password_hash must be a bcrypt hash — never store plaintext.
    """
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def create_first_user(username: str, password_hash: str) -> tuple[bool, str]:
    """
    Atomically create the very first user. The user_count check and the
    INSERT run inside one IMMEDIATE transaction, so two concurrent
    /api/auth/setup requests cannot both succeed.
    Returns (ok, message).
    """
    conn = get_connection()
    try:
        conn.isolation_level = None  # autocommit; we manage BEGIN/COMMIT ourselves
        conn.execute("BEGIN IMMEDIATE")
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count > 0:
            conn.execute("ROLLBACK")
            return False, "Setup already complete"
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
        except sqlite3.IntegrityError:
            conn.execute("ROLLBACK")
            return False, "Username already taken"
        conn.execute("COMMIT")
        return True, "Account created"
    finally:
        conn.close()


def get_user(username: str) -> dict | None:
    """Return the user row or None if not found."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, created_at, last_login "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def update_last_login(username: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET last_login = datetime('now') WHERE username = ?",
            (username,),
        )
        conn.commit()


def list_users() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, username, created_at, last_login FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def user_count() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# ── App log functions ─────────────────────────────────────────────────── #

def write_log(
    source: str,
    level: str,
    category: str,
    message: str,
    detail: str = "",
    session_id: str = "",
    username: str = "",
) -> None:
    """
    Persist a log entry to app_logs.
    source   : 'backend' | 'frontend'
    level    : 'INFO' | 'WARNING' | 'ERROR' | 'DEBUG'
    category : 'auth' | 'capture' | 'sniffer' | 'api' | 'ui' | 'general'
    """
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO app_logs (source, level, category, message, detail, session_id, username) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (source, level.upper(), category, message, detail, session_id, username),
        )
        conn.commit()


def get_logs(
    source: str | None = None,
    level: str | None = None,
    category: str | None = None,
    session_id: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    clauses = []
    params: list = []

    if source:
        clauses.append("source = ?")
        params.append(source.lower())
    if level:
        clauses.append("UPPER(level) = UPPER(?)")
        params.append(level)
    if category:
        clauses.append("category = ?")
        params.append(category.lower())
    if session_id:
        clauses.append("session_id = ?")
        params.append(session_id)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        f"SELECT id, timestamp, source, level, category, message, detail, session_id, username "
        f"FROM app_logs {where} ORDER BY id DESC LIMIT ? OFFSET ?"
    )
    params += [limit, offset]

    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_log_stats() -> dict:
    """Return counts grouped by source and level for the summary cards."""
    with get_connection() as conn:
        by_source = conn.execute(
            "SELECT source, COUNT(*) AS cnt FROM app_logs GROUP BY source"
        ).fetchall()
        by_level = conn.execute(
            "SELECT level, COUNT(*) AS cnt FROM app_logs GROUP BY level"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM app_logs").fetchone()[0]
    return {
        "total": total,
        "by_source": {r["source"]: r["cnt"] for r in by_source},
        "by_level":  {r["level"]:  r["cnt"] for r in by_level},
    }
