import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import tableStyles from "./DataTable.module.css";
import styles from "./AlertsPage.module.css";

const SEVERITY_LABELS = ["Unknown", "Low", "Medium", "High", "Critical", "Fatal"];
const STATUSES = ["open", "acknowledged", "resolved", "false_positive"];
const STATUS_LABELS = {
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
};

function severityTagClass(sev) {
  if (sev >= 4) return tableStyles.tagDanger;
  if (sev === 3) return tableStyles.tagWarning;
  return tableStyles.tagIp;
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState("queue");
  const [severityFilter, setSeverityFilter] = useState("");
  const [q, setQ] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [noteDrafts, setNoteDrafts] = useState({});

  async function load() {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (statusFilter !== "queue" && statusFilter !== "all") {
        params.set("status", statusFilter);
      }
      if (severityFilter !== "") params.set("severity_id", severityFilter);
      params.set("limit", "200");
      const res = await api.get(`/alerts?${params.toString()}`);
      if (!res.ok) throw new Error(`Failed to load alerts (${res.status})`);
      setAlerts(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [statusFilter, severityFilter]);

  const rows = useMemo(() => {
    let out = alerts;
    if (statusFilter === "queue") {
      out = out.filter((a) => a.status === "open" || a.status === "acknowledged");
    }
    if (q.trim()) {
      const lq = q.trim().toLowerCase();
      out = out.filter(
        (a) =>
          a.src_ip?.toLowerCase().includes(lq) ||
          a.alert_type?.toLowerCase().includes(lq) ||
          a.description?.toLowerCase().includes(lq)
      );
    }
    return out;
  }, [alerts, statusFilter, q]);

  async function patchAlert(id, patch) {
    setBusyId(id);
    setError("");
    try {
      const res = await api.patch(`/alerts/${id}`, patch);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `Update failed (${res.status})`);
      }
      const updated = await res.json();
      setAlerts((prev) => prev.map((a) => (a.id === id ? updated : a)));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className={tableStyles.container}>
      <div className={tableStyles.toolbar}>
        <span className={tableStyles.title}>Alerts</span>
        <select
          className={styles.select}
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          aria-label="Filter by status"
        >
          <option value="queue">Working queue (open + acknowledged)</option>
          <option value="all">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{STATUS_LABELS[s]}</option>
          ))}
        </select>
        <select
          className={styles.select}
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEVERITY_LABELS.map((label, i) => (
            <option key={i} value={i}>{label}</option>
          ))}
        </select>
        <input
          className={tableStyles.search}
          type="search"
          placeholder="Filter by IP, type, description…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="Search alerts"
        />
        <button className={styles.refresh} onClick={load} disabled={loading}>
          Refresh
        </button>
        <span className={tableStyles.count}>{rows.length.toLocaleString()} alerts</span>
      </div>

      {error && <div className={styles.error} role="alert">{error}</div>}

      <div className={tableStyles.tableWrap}>
        <table className={tableStyles.table}>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Status</th>
              <th>Alert Type</th>
              <th>Source IP</th>
              <th>MITRE</th>
              <th>Count</th>
              <th>First Seen</th>
              <th>Last Seen</th>
              <th>Description</th>
              <th>Analyst Notes</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={10} className={tableStyles.empty}>Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={10} className={tableStyles.empty}>No alerts match the current filters.</td></tr>
            )}
            {!loading && rows.map((a) => (
              <tr key={a.id}>
                <td>
                  <span className={`${tableStyles.tag} ${severityTagClass(a.severity_id ?? 1)}`}>
                    {SEVERITY_LABELS[a.severity_id ?? 1] ?? "Low"}
                  </span>{" "}
                  <select
                    className={styles.miniSelect}
                    value={a.severity_id ?? 1}
                    disabled={busyId === a.id}
                    onChange={(e) => patchAlert(a.id, { severity_id: Number(e.target.value) })}
                    aria-label="Set severity"
                  >
                    {SEVERITY_LABELS.map((label, i) => (
                      <option key={i} value={i}>{i} · {label}</option>
                    ))}
                  </select>
                </td>
                <td>
                  <select
                    className={styles.miniSelect}
                    value={a.status}
                    disabled={busyId === a.id}
                    onChange={(e) => patchAlert(a.id, { status: e.target.value })}
                    aria-label="Set status"
                  >
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                    ))}
                  </select>
                </td>
                <td>{a.alert_type}</td>
                <td className={tableStyles.mono}>{a.src_ip}</td>
                <td className={tableStyles.mono}>
                  {a.mitre_technique_id
                    ? `${a.mitre_technique_id} ${a.mitre_technique_name ?? ""}`
                    : "—"}
                </td>
                <td className={tableStyles.mono}>{a.event_count ?? 1}</td>
                <td className={tableStyles.mono}>{a.first_seen ?? a.timestamp}</td>
                <td className={tableStyles.mono}>{a.last_seen ?? a.timestamp}</td>
                <td className={tableStyles.desc}>{a.description}</td>
                <td>
                  <div className={styles.noteCell}>
                    <input
                      className={styles.noteInput}
                      type="text"
                      value={noteDrafts[a.id] ?? a.notes ?? ""}
                      onChange={(e) =>
                        setNoteDrafts((d) => ({ ...d, [a.id]: e.target.value }))
                      }
                      placeholder="Add note…"
                      aria-label="Analyst note"
                    />
                    <button
                      className={styles.saveBtn}
                      disabled={busyId === a.id}
                      onClick={() =>
                        patchAlert(a.id, { notes: noteDrafts[a.id] ?? a.notes ?? "" })
                      }
                    >
                      Save
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
