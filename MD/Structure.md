# Project Structure: PLEXUS + NIDS Model Integration

**Stack:** FastAPI + Scapy (backend) · React (frontend) · SQLite · scikit-learn/XGBoost (model, planned)
**Status:** Scanner implemented (capture, auth, WebSocket streaming, PDF reports, rule-based alerts). Model + integration planned — see PRD.md.

---

## Top-level layout (actual, post-cleanup)

```
PLEXUS/
├── backend/                   # FastAPI + Scapy — implemented
├── frontend/                  # React — implemented
├── ml/                        # NEW — model training + inference (not yet created)
├── data/                      # NEW — CICIDS2017 subset, sample PCAPs (not yet created)
├── MD/
│   ├── PRD.md
│   └── Structure.md
├── PLEXUS.sh                  # one-command launcher (starts backend + frontend)
├── start_backend.sh
├── start_frontend.sh
├── README.md
└── .gitignore
```

**Removed in cleanup:** `.venv/`, `frontend/node_modules/`, `frontend/dist/`, `__pycache__/`, `.DS_Store`, `network_traffic.db` (all regenerated/reinstalled locally — none belong in the repo), and the legacy `plexus.py` (old Tkinter version, deleted per decision — no longer preserved anywhere). All internal "NetScope" naming renamed to PLEXUS for consistency (scripts, README, docstrings, frontend meta tags).

---

## backend/ (FastAPI + Scapy) — implemented, flat layout

```
backend/
├── __init__.py
├── main.py                    # FastAPI app: REST endpoints, WebSocket (/ws/stream), lifespan/session mgmt
├── sniffer.py                 # PacketSniffer — Scapy capture loop + existing rule-based alerts
├── database.py                # SQLite layer, all queries parameterised — tables: packets, alerts, users, app_logs
├── auth.py                    # Token-based auth (bcrypt), login/register/revoke/validate
├── interfaces.py              # Network interface discovery + whitelist validation
├── report.py                  # PDF report generation (ReportLab)
├── logger.py                  # App-level logging → app_logs table
└── requirements.txt
```

There is no `routes/`, `capture/`, or `storage/` subpackage — `main.py` holds the endpoints directly, importing from the flat modules above. Any NIDS integration should follow this same flat convention rather than introducing new subfolders that don't match the existing style.

**Planned integration touchpoints:**
- `sniffer.py` — extend `_packet_callback`'s existing per-source-IP tracking into a proper flow aggregator (see PRD §8.2), call the trained model, push predictions to the same `alert_queue` the rule-based alerts already use.
- `main.py` — one new route for batch PCAP analysis (upload/select → run model → return summary).

---

## frontend/ (React) — implemented, flat layout

```
frontend/
├── src/
│   ├── main.jsx
│   ├── App.jsx
│   ├── App.module.css
│   ├── api.js                 # single API client module (not split per-resource)
│   ├── components/
│   │   ├── Sidebar.jsx
│   │   ├── CaptureBar.jsx     # capture controls + settings
│   │   ├── Dashboard.jsx      # stat cards, recent activity
│   │   ├── PacketTable.jsx    # live packet table + filtering
│   │   ├── PacketDetail.jsx   # packet detail pane
│   │   ├── AlertTable.jsx     # alert table — WILL surface model alerts automatically, no changes needed for v1
│   │   ├── FilterBar.jsx
│   │   ├── TrafficChart.jsx   # Chart.js traffic chart
│   │   └── Sessions.jsx       # historical session browser
│   ├── context/
│   │   ├── AuthContext.jsx
│   │   └── ThemeContext.jsx
│   ├── hooks/
│   │   ├── useCapture.js      # capture state + API calls
│   │   └── useWebSocket.js    # auto-reconnecting WS client
│   ├── pages/
│   │   └── LoginPage.jsx
│   └── styles/
│       └── globals.css
├── index.html
├── package.json
└── vite.config.js
```

**Planned integration touchpoints:**
- **None required for v1.** `AlertTable.jsx` already renders whatever rows land in the `alerts` table — model-generated alerts show up automatically once the backend emits them, no new component needed.
- Optional stretch: small visual badge on `AlertTable` distinguishing rule-based vs. model-based alerts (needs a `source` column — see PRD §11 open question).

---

## ml/ (NEW — to be created) — training + inference

```
ml/
├── train/
│   ├── preprocess.py           # CICIDS2017 loading, cleaning (Infinity/NaN, dupes, ID columns)
│   ├── feature_selection.py    # throwaway RF → importance ranking → top 15-20 features
│   ├── train_model.py          # RF/XGBoost training + cross-validation on reduced feature set
│   └── evaluate.py             # F1, precision, recall, confusion matrix
├── features/
│   ├── flow_aggregator.py      # extends sniffer.py's connection tracking into full flow stats
│   └── feature_spec.py         # canonical list of the selected ~15-20 features
├── inference/
│   ├── model_loader.py         # loads serialized model + scaler/encoder together
│   ├── predict_realtime.py     # called from backend/sniffer.py per completed flow
│   └── predict_batch.py        # called from the new batch-analysis route in backend/main.py
├── artifacts/                  # gitignored — model.joblib, scaler.joblib, metrics.json
└── notebooks/
    └── eda.ipynb                # EDA + cleaning exploration, kept out of the production path
```

- `ml/` stays a standalone Python package — no FastAPI/React imports inside it. `backend/` imports *from* `ml/`, never the reverse.
- `flow_aggregator.py` is shared by both real-time and batch inference — one implementation, not two.

---

## data/ (NEW — to be created)

```
data/
├── cicids2017/
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv   # or PortScan variant
├── sample_pcaps/                # fixtures for testing the flow aggregator + batch inference
└── captured/                    # gitignored — real live-captured .pcap exports
```

---

## Naming & convention notes

- Repo/product name is **PLEXUS**, consistently, everywhere — scripts, docstrings, frontend meta tags, README.
- Backend and frontend both use **flat** module/component layout by convention — don't introduce nested subpackages for the ML integration; keep `ml/` as the one new top-level package instead of scattering NIDS logic into new backend subfolders.
- Everything generated (venv, node_modules, dist, db, model artifacts, captured pcaps) is gitignored — nothing generated should ever be committed again.

---
*Pairs with PRD.md — milestones M3–M5 map directly onto `ml/features/`, `ml/inference/`, and the two integration touchpoints in `sniffer.py`/`main.py` above.*
