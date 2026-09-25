# PLEXUS — Detection Workflows & Data Flow

How packets become alerts in PLEXUS v3.0.x. Two detection paths run in
parallel: a **fast rule-based path** (port scan / flood) and a **slower
ML path** (XGBoost → Laya second opinion).

---

## 1. System overview

```
                    ┌─────────────────────────────────────────────┐
                    │              NETWORK INTERFACE              │
                    └──────────────────────┬──────────────────────┘
                                           │ Scapy sniff()
                                           ▼
                    ┌─────────────────────────────────────────────┐
                    │        PacketSniffer._packet_callback       │
                    │  (one thread, per-packet, synchronous)      │
                    └──────┬──────────────────────────┬───────────┘
                           │                          │
              ┌────────────▼──────────┐    ┌──────────▼──────────────┐
              │  RULE-BASED DETECTOR  │    │    FlowAggregator       │
              │  · port-scan count    │    │  (bidirectional flows,  │
              │  · flood count        │    │   20 statistical feats) │
              └────────────┬──────────┘    └──────────┬──────────────┘
                           │                          │ flow complete
                           │                 ┌────────▼─────────┐
                           │                 │ XGBoost predict  │
                           │                 └────────┬─────────┘
                           │                          │ attack?
                           │                 ┌────────▼─────────┐
                           │                 │ Laya 2nd opinion │
                           │                 │ (beta, optional) │
                           │                 └────────┬─────────┘
                           └────────────┬─────────────┘
                                        │ alert tuples
                                        ▼
                    ┌─────────────────────────────────────────────┐
                    │   state.alert_queue  /  state.packet_queue   │
                    │   (thread-safe Queue, shared with backend)  │
                    └──────────────────────┬──────────────────────┘
                                           │ _queue_broadcaster
                                           │ (every 0.5 s, when capturing)
                                           ▼
                    ┌─────────────────────────────────────────────┐
                    │  SQLite (log_packet / log_alert) + desktop  │
                    │  notify() → WS broadcast {type:"update"}   │
                    └──────────────────────┬──────────────────────┘
                                           │ ws://127.0.0.1:8000/ws/stream
                                           ▼
                    ┌─────────────────────────────────────────────┐
                    │  React: useWebSocket → useCapture            │
                    │  packets/alerts tables, TrafficChart,      │
                    │  toast + sidebar badge                      │
                    └─────────────────────────────────────────────┘
```

---

## 2. Workflow A — Rule-based detection (fast path)

Runs **inside `_packet_callback`**, so it fires the moment the offending
packet is seen. No ML involved.

```
packet arrives
  │
  ├─ extract src_ip, dst_port
  ├─ _connections[src_ip].add(dst_port)      # distinct ports per source
  ├─ _packet_counts[src_ip] += 1             # packets per source
  │
  ├─ PORT SCAN?  len(ports) > max_ports_scanned (default 5)
  │              AND src_ip not already alerted this window
  │              → alert_queue.put("Port Scanning", …)
  │
  ├─ FLOOD?      count > max_packets_flood (default 1500)
  │              AND src_ip not already alerted this window
  │              → alert_queue.put("Flooding", …)
  │
  ├─ every time_window (default 10 s): clear counters + alerted sets
  │
  └─ packet → packet_queue  (+ feed FlowAggregator for the ML path)
```

**Defaults:** `time_window=10`, `max_ports_scanned=5` (6th distinct port
triggers), `max_packets_flood=1500` (>1500 packets from one source in 10 s
≈ >150 pkt/s).

---

## 3. Workflow B — ML detection (XGBoost → Laya)

Runs on **completed flows**, not individual packets — inherently slower
than the rule path.

```
FlowAggregator emits flow (15 s timeout, TCP FIN/RST, or ~15 packets)
  │
  ├─ 20 features → StandardScaler → XGBoost predict
  │
  ├─ benign → drop
  │
  └─ attack → Laya second_opinion(flow)   [beta, PLEXUS_DISABLE_LAYA=1 skips]
              │
              ├─ lazy-loads convaiinnovations/laya-typed-decisions
              │  (ModernBERT-large, 421M params) on first flagged flow
              ├─ returns: attack P% + category
              │  (port_scan | flood | brute_force | benign)
              └─ alert_queue.put("ML NIDS Anomaly",
                                 description + "Laya second opinion (beta): …")
```

Laya never replaces XGBoost — it only adds a second-opinion note to
ML-flagged flows, labelled **beta/experimental**. If Laya fails to load
or score, the original XGBoost alert is still emitted.

---

## 4. Workflow C — Broadcast & frontend rendering

```
_queue_broadcaster  (asyncio task, 1 per backend process)
  every 0.5 s, only while capturing:
    drain ≤50 packets → log_packet() → SQLite
    drain ≤20 alerts  → log_alert()  → SQLite + desktop notify()
    _broadcast({type:"update", packets, alerts,
                packet_total, alert_total, session_id, capturing})
      → every socket in state.ws_clients (each socket gets one copy)

React frontend
  useWebSocket(handleMessage, user)   # exactly ONE socket per tab
    └─ ws.onmessage → handleMessage("update")
         ├─ packets: newest-first, capped at 500 rows
         ├─ alerts:  deduped by signature
         │           (timestamp|src_ip|type|description), capped at 500
         ├─ totals + capturing state
         └─ TrafficChart: alert dots ONLY where alert count ≠ 0
```

### Alert severity → graph colour

| Alert type      | Severity | Graph dot |
|-----------------|----------|-----------|
| Port Scanning   | normal   | yellow ■  |
| Flooding        | critical | red ■     |
| ML NIDS Anomaly | critical | red ■     |
| (future types)  | normal   | yellow ■  |

Critical wins if a time bucket contains both severities.

---

## 5. Measured latency (2026-09-24)

| Path | End-to-end | Breakdown |
|------|-----------|-----------|
| Port-scan alert | **~0.5 s** after scan ends | rule check: instant (in packet callback) → broadcaster poll: ≤0.5 s → WS push + render: instant |
| Flood alert | ~0.5 s | same as above |
| ML anomaly alert | seconds | flow completion (up to 15 s) + XGBoost (ms) + Laya (seconds on cold start, model load is lazy) + broadcaster poll |

The 0.5 s floor on the fast path is the broadcaster's `asyncio.sleep(0.5)`.
Lower it for a snappier demo, raise it to save CPU.

---

## 6. Session lifecycle

```
POST /api/capture/start
  ├─ 409 if already capturing
  ├─ drain packet/alert queues (fresh session)
  ├─ new session_id, reset totals
  ├─ PacketSniffer(iface, filter, time_window,
  │                 max_ports_scanned, max_packets_flood)
  ├─ sniffer.start() → background thread
  └─ frontend clears tables + alert-dedup set

POST /api/capture/stop
  ├─ 409 if not capturing
  └─ sniffer.stop() → thread exits on next packet (stop_filter)
```

The backend refuses a second concurrent capture (`409 Capture already
running`); the frontend keeps exactly one WebSocket per tab, so each
alert is delivered — and rendered — once.
