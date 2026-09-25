/**
 * useWebSocket.js
 * One live WebSocket per browser tab to the PLEXUS backend.
 *
 * Design notes (2026-09-24 duplicate-alert fix):
 *  - onMessage is consumed through a ref so parent re-renders never
 *    re-trigger the effect (re-running the effect used to pile up sockets,
 *    and every socket received the same broadcast → N duplicate alerts).
 *  - Each effect run owns a `cancelled` flag + its reconnect timer, so a
 *    stale socket's onclose can never schedule a zombie reconnect after
 *    the effect re-ran.
 *  - Reconnects only when `authKey` changes (login/logout). The token
 *    travels as a query param because browsers can't set headers on the
 *    WS handshake.
 */

import { useEffect, useRef } from "react";
import { getToken } from "../api.js";

const WS_URL = "ws://127.0.0.1:8000/ws/stream";
const MAX_BACKOFF_MS = 30_000;

export function useWebSocket(onMessage, authKey) {
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    let cancelled = false;
    let ws = null;
    let timer = null;
    let backoff = 1_000;

    // v3.0.0: the stream requires auth. No token yet (pre-login) → stay
    // disconnected; the authKey change after login re-runs this effect.
    const token = getToken();
    if (!token) return undefined;

    function connect() {
      if (cancelled) return;
      // One live socket per tab — never open a second while one is alive.
      if (ws && (ws.readyState === WebSocket.OPEN ||
                 ws.readyState === WebSocket.CONNECTING)) {
        return;
      }

      ws = new WebSocket(`${WS_URL}?token=${encodeURIComponent(token)}`);

      ws.onopen = () => {
        backoff = 1_000; // reset back-off on successful connect
      };

      ws.onmessage = (event) => {
        try {
          onMessageRef.current(JSON.parse(event.data));
        } catch {
          // Ignore malformed frames
        }
      };

      ws.onclose = (event) => {
        if (cancelled) return;
        if (event.code === 4401) {
          // Backend rejected our token — bounce to the login screen.
          window.dispatchEvent(new Event("ns:unauthorized"));
          return;
        }
        backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
        timer = setTimeout(connect, backoff);
      };

      ws.onerror = () => {
        try { ws.close(); } catch { /* already closed */ }
      };
    }

    connect();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      try { ws?.close(); } catch { /* already closed */ }
      ws = null;
    };
  }, [authKey]);
}
