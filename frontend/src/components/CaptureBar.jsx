import React, { useState, useEffect } from "react";
import styles from "./CaptureBar.module.css";

const FILTERS = [
  { value: null,   label: "All traffic" },
  { value: "tcp",  label: "TCP only"    },
  { value: "udp",  label: "UDP only"    },
  { value: "icmp", label: "ICMP only"   },
  { value: "ip",   label: "IP only"     },
];

export default function CaptureBar({
  capturing, sessionId, packetTotal, alertTotal,
  settings, interfaces, onStart, onStop, onApplySettings, onClearLogs, onExportPdf,
}) {
  const [localSettings, setLocalSettings] = useState(settings);
  const [settingsOpen,  setSettingsOpen]  = useState(false);

  // The default interface is auto-selected after /api/interfaces loads —
  // sync it into the form so the picker reflects the active value.
  useEffect(() => {
    if (settings.iface) {
      setLocalSettings((prev) => ({ ...prev, iface: settings.iface }));
    }
  }, [settings.iface]);

  function handleStart() { onStart(localSettings); }

  function handleApply(e) {
    e.preventDefault();
    onApplySettings(localSettings);
    setSettingsOpen(false);
  }

  const set = (k, v) => setLocalSettings((p) => ({ ...p, [k]: v }));

  return (
    <header className={styles.captureBar}>
      <div className={styles.row}>
        {/* Left: primary actions */}
        <div className={styles.actions}>
          {!capturing ? (
            <button className={`${styles.btn} ${styles.primary}`} onClick={handleStart}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
                <polygon points="6 3 20 12 6 21 6 3"/>
              </svg>
              Start Capture
            </button>
          ) : (
            <button className={`${styles.btn} ${styles.danger}`} onClick={onStop}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
                <rect x="6" y="6" width="12" height="12" rx="2"/>
              </svg>
              Stop
            </button>
          )}

          <button
            className={`${styles.btn} ${styles.ghost} ${settingsOpen ? styles.open : ""}`}
            onClick={() => setSettingsOpen((v) => !v)}
            aria-expanded={settingsOpen}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            Capture Settings
          </button>

          <button className={`${styles.btn} ${styles.ghost}`} onClick={onClearLogs}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
              <path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
            </svg>
            Clear Screen
          </button>

          {sessionId && (
            <button className={`${styles.btn} ${styles.ghost}`} onClick={onExportPdf}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Generate PDF Report
            </button>
          )}
        </div>

        {/* Right: live status banner */}
        <div className={styles.stats}>
          <div className={styles.activeDetails}>
            {sessionId && (
              <span className={styles.activeSession}>
                Session: <code className={styles.mono}>{sessionId}</code>
              </span>
            )}
            <div className={styles.statusGroup}>
              <span className={`${styles.statusDot} ${capturing ? styles.dotLive : styles.dotIdle}`} />
              <span className={styles.statusLabel}>{capturing ? "Active Sniffer" : "Standby"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Detection settings panel */}
      {settingsOpen && (
        <form className={`${styles.panel} animate-slide-up`} onSubmit={handleApply}>
          <h3 className={styles.panelTitle}>Anomaly Detection Thresholds</h3>
          <p className={styles.panelSubtitle}>Configure rule-based scanner sensitivity thresholds. Changes apply dynamically.</p>
          <div className={styles.panelGrid}>
            <FormField
              label="Network Interface"
              description="Interface to sniff — loopback, LAN (Ethernet) and Wi-Fi are listed separately. Applies on next start."
            >
              <select
                value={localSettings.iface ?? ""}
                onChange={(e) => set("iface", e.target.value || null)}
              >
                <option value="">All interfaces</option>
                {(interfaces ?? []).map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name} ({i.iface_type})
                  </option>
                ))}
              </select>
            </FormField>

            <FormField 
              label="Capture Filter"
              description="Applies BPF filtering (e.g. TCP only) at kernel level to capture matching packets."
            >
              <select
                value={localSettings.filter ?? ""}
                onChange={(e) => set("filter", e.target.value || null)}
              >
                {FILTERS.map((f) => (
                  <option key={f.label} value={f.value ?? ""}>{f.label}</option>
                ))}
              </select>
            </FormField>
            
            <FormField 
              label="Time Window (seconds)"
              description="Rolling evaluation interval (in seconds) used to detect scans and flood thresholds."
            >
              <input type="number" min="1" max="3600" value={localSettings.time_window}
                onChange={(e) => set("time_window", Number(e.target.value))} />
            </FormField>
            
            <FormField 
              label="Port Scan Threshold"
              description="Alert triggers if a source IP touches more than this number of distinct ports within the window."
            >
              <input type="number" min="1" max="65535" value={localSettings.max_ports_scanned}
                onChange={(e) => set("max_ports_scanned", Number(e.target.value))} />
            </FormField>
            
            <FormField 
              label="Flood Threshold (packets)"
              description="Alert triggers if a source IP transmits more packets than this limit within the window."
            >
              <input type="number" min="1" max="1000000" value={localSettings.max_packets_flood}
                onChange={(e) => set("max_packets_flood", Number(e.target.value))} />
            </FormField>

            <FormField
              label="Packet Limit"
              description="Auto-stop capture after this many packets (e.g. 1500 for an ML batch). Blank = unlimited."
            >
              <input type="number" min="1" max="1000000"
                value={localSettings.max_packets ?? ""}
                placeholder="Unlimited"
                onChange={(e) => set("max_packets", e.target.value ? Number(e.target.value) : null)} />
            </FormField>
          </div>
          <div className={styles.panelActions}>
            <button type="submit" className={`${styles.btn} ${styles.primary}`}>Apply Changes</button>
            <button type="button" className={`${styles.btn} ${styles.ghost}`}
              onClick={() => setSettingsOpen(false)}>Dismiss</button>
          </div>
        </form>
      )}
    </header>
  );
}

function FormField({ label, description, children }) {
  return (
    <label className={styles.formField}>
      <span className={styles.formFieldLabel}>{label}</span>
      {children}
      {description && <span className={styles.formFieldDesc}>{description}</span>}
    </label>
  );
}
