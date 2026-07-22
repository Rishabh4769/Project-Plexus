import React, { useEffect, useState } from "react";
import styles from "./Dashboard.module.css";

const API = "/api";

export default function Dashboard({
  capturing,
  sessionId,
  iface,
  packetTotal,
  alertTotal,
  packets,
  alerts,
}) {
  const [talkers, setTalkers] = useState([]);

  // Fetch top-talkers when session changes
  useEffect(() => {
    if (!sessionId) return;
    fetch(`${API}/sessions/${encodeURIComponent(sessionId)}/top-talkers?limit=8`)
      .then((r) => (r.ok ? r.json() : []))
      .then(setTalkers)
      .catch(() => {});
  }, [sessionId, packetTotal]); // re-fetch as packets grow

  // Protocol breakdown from in-memory live packets
  const protocolMap = {};
  for (const p of packets) {
    protocolMap[p.protocol] = (protocolMap[p.protocol] ?? 0) + 1;
  }
  const protocols = Object.entries(protocolMap).sort((a, b) => b[1] - a[1]);
  const totalBytes = packets.reduce((s, p) => s + (p.length ?? 0), 0);

  return (
    <div className={styles.container}>
      {/* ── Top Section: Hero Scanner Console & Stat Grid ───────────────── */}
      <div className={styles.heroRow}>
        {/* Scanner Radar Hero Card */}
        <div className={`${styles.card} ${styles.heroCard} ${capturing ? styles.heroActive : ""}`}>
          <div className={styles.radarLayout}>
            <div className={styles.radarVisual}>
              <div className={`${styles.radarCircle} ${capturing ? styles.pulse1 : ""}`} />
              <div className={`${styles.radarCircle} ${styles.delay1} ${capturing ? styles.pulse2 : ""}`} />
              <div className={`${styles.radarCircle} ${styles.delay2} ${capturing ? styles.pulse3 : ""}`} />
              <div className={styles.radarHub}>
                <svg
                  className={`${styles.radarIcon} ${capturing ? styles.spinning : ""}`}
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                >
                  <circle cx="12" cy="12" r="10" strokeDasharray="4 4" />
                  <circle cx="12" cy="12" r="6" />
                  <line x1="12" y1="2" x2="12" y2="22" strokeOpacity="0.3" />
                  <line x1="2" y1="12" x2="22" y2="12" strokeOpacity="0.3" />
                  <path d="M12 12 L12 2" strokeWidth="2.5" strokeLinecap="round" />
                </svg>
              </div>
            </div>
            <div className={styles.heroInfo}>
              <div className={styles.heroStatus}>
                <span className={`${styles.statusBadge} ${capturing ? styles.statusActive : styles.statusIdle}`}>
                  {capturing ? "SCANNING ACTIVE" : "SCANNER STANDBY"}
                </span>
              </div>
              <h2 className={styles.heroTitle}>
                {capturing ? "Monitoring Interface" : "Security Scanner Ready"}
              </h2>
              <div className={styles.heroMetadata}>
                <div className={styles.metaRow}>
                  <span className={styles.metaLabel}>Interface:</span>
                  <span className={styles.metaVal}>{iface || "all interfaces"}</span>
                </div>
                {sessionId && (
                  <div className={styles.metaRow}>
                    <span className={styles.metaLabel}>Session:</span>
                    <span className={`${styles.metaVal} ${styles.mono}`}>{sessionId}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Small Stats Grid */}
        <div className={styles.statsCol}>
          <StatCard
            label="Packets Logged"
            value={packetTotal.toLocaleString()}
            color="blue"
            icon={<IcPacket />}
            desc="Network packet frames captured"
          />
          <StatCard
            label="Security Alerts"
            value={alertTotal.toLocaleString()}
            color={alertTotal > 0 ? "red" : "gray"}
            icon={<IcAlert />}
            desc="Flagged traffic anomalies"
            pulse={alertTotal > 0}
          />
          <StatCard
            label="Volume Captured"
            value={fmtBytes(totalBytes)}
            color="teal"
            icon={<IcBytes />}
            desc="Total data throughput size"
          />
        </div>
      </div>

      {/* ── Middle Section: Protocols & Top Talkers ─────────────────────── */}
      <div className={styles.grid}>
        {/* Protocol distribution */}
        <div className={`${styles.card} ${styles.span2}`}>
          <div className={styles.cardHead}>
            <span>Protocol Distribution</span>
            <span className={styles.headDesc}>Ratio of captured frame protocols</span>
          </div>
          {protocols.length === 0 ? (
            <div className={styles.empty}>
              <span className={styles.emptyIcon}></span>
              <p>No packets captured yet. Start the scanner to inspect traffic.</p>
            </div>
          ) : (
            <div className={styles.protoList}>
              {protocols.map(([proto, count]) => {
                const pct = packetTotal ? Math.round((count / packetTotal) * 100) : 0;
                return (
                  <div key={proto} className={styles.protoRow}>
                    <span className={`${styles.protoBadge} ${styles[`proto_${proto.toLowerCase()}`]}`}>
                      {proto}
                    </span>
                    <div className={styles.barTrack}>
                      <div
                        className={`${styles.barFill} ${styles[`bar_${proto.toLowerCase()}`]}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className={styles.protoCount}>{count.toLocaleString()}</span>
                    <span className={styles.protoPct}>{pct}%</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Top Talkers */}
        <div className={`${styles.card} ${styles.span2}`}>
          <div className={styles.cardHead}>
            <span>Top Traffic Sources</span>
            <span className={styles.headDesc}>IP addresses generating highest bandwidth</span>
          </div>
          {talkers.length === 0 ? (
            <div className={styles.empty}>
              <span className={styles.emptyIcon}></span>
              <p>Waiting for top talkers data...</p>
            </div>
          ) : (
            <div className={styles.tableContainer}>
              <table className={styles.miniTable}>
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Source IP Address</th>
                    <th>Packets</th>
                    <th style={{ textAlign: "right" }}>Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {talkers.slice(0, 5).map((t, i) => (
                    <tr key={t.src_ip} className={styles.talkerRow}>
                      <td className={styles.rank}>0{i + 1}</td>
                      <td className={styles.mono}>{t.src_ip}</td>
                      <td className={styles.mono}>{t.packet_count?.toLocaleString()}</td>
                      <td className={`${styles.mono} ${styles.valRight}`}>{fmtBytes(t.total_bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent Packets Card List */}
        <div className={styles.card}>
          <div className={styles.cardHead}>
            <span>Live Packet Stream</span>
            <span className={styles.headDesc}>Latest captured packets rolling</span>
          </div>
          {packets.length === 0 ? (
            <div className={styles.empty}>
              <span className={styles.emptyIcon}></span>
              <p>Waiting for network packets...</p>
            </div>
          ) : (
            <div className={styles.streamList}>
              {packets.slice(0, 5).map((p, i) => (
                <div key={i} className={styles.streamItem}>
                  <div className={styles.streamHead}>
                    <span className={`${styles.miniProto} ${styles[`proto_${p.protocol?.toLowerCase()}`]}`}>
                      {p.protocol}
                    </span>
                    <span className={styles.streamTime}>{p.timestamp?.slice(11)}</span>
                  </div>
                  <div className={styles.streamBody}>
                    <span className={styles.streamIP} title={p.src_ip}>
                      {p.src_ip}
                    </span>
                    <span className={styles.streamArrow}>→</span>
                    <span className={styles.streamIP} title={p.dst_ip}>
                      {p.dst_ip || "—"}
                    </span>
                  </div>
                  <div className={styles.streamFoot}>
                    <span>Port: <code className={styles.mono}>{p.dst_port}</code></span>
                    <span>Size: <code className={styles.mono}>{p.length} B</code></span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Alerts Card List */}
        <div className={styles.card}>
          <div className={styles.cardHead}>
            <span>Security Alerts Log</span>
            <span className={styles.headDesc}>Most recent intrusion warnings</span>
          </div>
          {alerts.length === 0 ? (
            <div className={styles.empty}>
              <span className={styles.emptyIcon}></span>
              <p>No alerts logged. System secure.</p>
            </div>
          ) : (
            <div className={styles.streamList}>
              {alerts.slice(0, 5).map((a, i) => (
                <div key={i} className={`${styles.streamItem} ${styles.alertItem}`}>
                  <div className={styles.streamHead}>
                    <span className={a.alert_type === "Port Scanning" ? styles.badgeDanger : styles.badgeWarn}>
                      ⚠️ {a.alert_type}
                    </span>
                    <span className={styles.streamTime}>{a.timestamp?.slice(11)}</span>
                  </div>
                  <div className={styles.alertSrc}>
                    Source IP: <code className={styles.mono}>{a.src_ip}</code>
                  </div>
                  <p className={styles.alertDesc}>{a.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Helpers ─────────────────────────────────────────────────────────── */
function fmtBytes(n) {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function StatCard({ label, value, color, icon, desc, pulse }) {
  return (
    <div
      className={`${styles.statCard} ${styles[`accent_${color}`]} ${
        pulse ? styles.pulsingCard : ""
      }`}
    >
      <span className={styles.statIcon}>{icon}</span>
      <div className={styles.statContent}>
        <div className={styles.statLabel}>{label}</div>
        <div className={styles.statValue}>{value}</div>
        <div className={styles.statDesc}>{desc}</div>
      </div>
    </div>
  );
}

function IcPacket() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
    >
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}
function IcAlert() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
    >
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}
function IcBytes() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
    >
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </svg>
  );
}
