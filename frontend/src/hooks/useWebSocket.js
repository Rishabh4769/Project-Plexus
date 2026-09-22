/**
 * useWebSocket.js
 * Manages a WebSocket connection to the PLEXUS backend.
 * Auto-reconnects with exponential back-off on unexpected disconnection.
 */

import { useEffect, useRef, useCallback } from "react";
import { getToken } from "../api.js";

const WS_URL = "ws://127.0.0.1:8000/ws/stream";
const MAX_BACKOFF_MS = 30_000;

export function useWebSocket(onMessage) {
  const wsRef        = useRef(null);
  const backoffRef   = useRef(1_000);
  const unmountedRef = useRef(false);

  const connect = useCallback(() => {
    if (unmountedRef.current) return;

    // v3.0.0: the stream now requires auth — the token travels as a query
    // param because browsers can't set custom headers on WS handshakes.
    const ws = new WebSocket(`${WS_URL}?token=${encodeURIComponent(getToken())}`);
    wsRef.current = ws;

    ws.onopen = () => {
      backoffRef.current = 1_000; // reset back-off on successful connect
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch {
        // Ignore malformed frames
      }
    };

    ws.onclose = (event) => {
      if (unmountedRef.current) return;
      if (event.code === 4401) {
        // Backend rejected our token — bounce to the login screen.
        window.dispatchEvent(new Event("ns:unauthorized"));
        return;
      }
      const delay = backoffRef.current;
      backoffRef.current = Math.min(delay * 2, MAX_BACKOFF_MS);
      setTimeout(connect, delay);
    };

    ws.onerror = () => ws.close();
  }, [onMessage]);

  useEffect(() => {
    unmountedRef.current = false;
    connect();
    return () => {
      unmountedRef.current = true;
      wsRef.current?.close();
    };
  }, [connect]);
}
