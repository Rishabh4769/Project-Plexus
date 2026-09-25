import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "../api";

const MAX_ROWS = 500;

const DEFAULT_SETTINGS = {
  filter:            null,
  iface:             null,
  time_window:       10,
  max_ports_scanned: 5,
  max_packets_flood: 1500,
  max_packets:       null, // packet limit for auto-stop; null = unlimited
};

export function useCapture(onMessage) {
  const [capturing,   setCapturing]   = useState(false);
  const [sessionId,   setSessionId]   = useState(null);
  const [packetTotal, setPacketTotal] = useState(0);
  const [alertTotal,  setAlertTotal]  = useState(0);
  const [packets,     setPackets]     = useState([]);
  const [alerts,      setAlerts]      = useState([]);
  const [settings,    setSettings]    = useState(DEFAULT_SETTINGS);
  const [interfaces,  setInterfaces]  = useState([]);
  const [error,       setError]       = useState(null);

  // Signatures of alerts already shown this session. Safety net against
  // duplicate delivery (e.g. two sockets briefly alive during reconnect):
  // the same alert can never render twice. Cleared on start/clear.
  const seenAlerts = useRef(new Set());
  const alertSig = (a) =>
    `${a.timestamp}|${a.src_ip}|${a.alert_type}|${a.description}`;

  // Load available interfaces once (token may not exist on first paint)
  useEffect(() => {
    api.get("/interfaces")
      .then((r) => r.ok ? r.json() : [])
      .then((data) => {
        setInterfaces(data);
        if (Array.isArray(data) && data.length > 0) {
          const first = data.find((i) => i.iface_type !== "Loopback");
          if (first) setSettings((p) => ({ ...p, iface: first.name }));
        }
      })
      .catch(() => {});
  }, []);

  const handleMessage = useCallback((msg) => {
    if (msg.type === "status") {
      setCapturing(msg.capturing);
      setSessionId(msg.session_id);
      setPacketTotal(msg.packet_total ?? 0);
      setAlertTotal(msg.alert_total ?? 0);
      if (msg.settings) setSettings((p) => ({ ...p, ...msg.settings }));
    } else if (msg.type === "packet") {
      setPackets((prev) => [msg.data, ...prev].slice(0, MAX_ROWS));
      setPacketTotal(msg.packet_total);
    } else if (msg.type === "alert") {
      setAlerts((prev) => [msg.data, ...prev].slice(0, MAX_ROWS));
      setAlertTotal(msg.alert_total);
    } else if (msg.type === "update") {
      setPacketTotal(msg.packet_total);
      setAlertTotal(msg.alert_total);
      // Backend may omit these on some broadcasts — never clobber with undefined.
      if (typeof msg.capturing === "boolean") setCapturing(msg.capturing);
      if (msg.session_id) setSessionId(msg.session_id);
      // Backend sends batches oldest→newest; the UI keeps newest-first.
      if (Array.isArray(msg.packets) && msg.packets.length > 0) {
        setPackets((prev) => msg.packets.slice().reverse().concat(prev).slice(0, MAX_ROWS));
      }
      if (Array.isArray(msg.alerts) && msg.alerts.length > 0) {
        const fresh = [];
        for (const a of msg.alerts) {
          const s = alertSig(a);
          if (seenAlerts.current.has(s)) continue;
          seenAlerts.current.add(s);
          fresh.push(a);
        }
        if (fresh.length > 0) {
          setAlerts((prev) => fresh.slice().reverse().concat(prev).slice(0, MAX_ROWS));
        }
      }
    }
    onMessage?.(msg);
  }, [onMessage]);

  const startCapture = useCallback(async (overrides = {}) => {
    setError(null);
    const res = await api.post("/capture/start", { ...settings, ...overrides });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || "Failed to start capture");
    }
    const data = await res.json();
    setSessionId(data.session_id);
    setCapturing(true);
    setPackets([]);
    setAlerts([]);
    seenAlerts.current.clear();
  }, [settings]);

  const stopCapture = useCallback(async () => {
    setError(null);
    const res = await api.post("/capture/stop");
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || "Failed to stop capture");
    }
    setCapturing(false);
  }, []);

  const applySettings = useCallback(async (newSettings) => {
    setSettings((prev) => ({ ...prev, ...newSettings }));
    if (capturing) {
      await api.post("/capture/settings", newSettings).catch(() => {});
    }
  }, [capturing]);

  const clearLogs = useCallback(() => {
    setPackets([]);
    setAlerts([]);
    seenAlerts.current.clear();
  }, []);

  // Auto-stop the capture once the configured packet limit is reached.
  // Quiet on failure — the WS status broadcast is the source of truth.
  useEffect(() => {
    if (capturing && settings.max_packets && packetTotal >= settings.max_packets) {
      api.post("/capture/stop").catch(() => {});
    }
  }, [capturing, packetTotal, settings.max_packets]);

  return {
    capturing, sessionId, packetTotal, alertTotal,
    packets, alerts, settings, interfaces, error, setError,
    handleMessage, startCapture, stopCapture, applySettings, clearLogs,
  };
}
