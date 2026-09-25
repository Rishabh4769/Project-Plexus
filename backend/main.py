"""
main.py — FastAPI application entry point for PLEXUS.

Security:
  - CORS locked to localhost:5173 only
  - All protected routes require X-Auth-Token header (server-side sessions)
  - BPF filter / iface whitelist-validated in sniffer / interfaces modules
  - All DB queries parameterised (see database.py)
  - Pydantic bounds on every numeric field
"""

import asyncio
import json
import re
import time
from contextlib import asynccontextmanager
from queue import Empty, Queue
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from scapy.all import PcapReader, IP  # type: ignore
from ml.features.flow_aggregator import FlowAggregator
from ml.inference.model_loader import NIDSModelLoader
import tempfile
import os
from backend.notifications import notify


from backend.auth import login, register_first_user, revoke_token, validate_token
from backend.ratelimit import is_rate_limited, record_failed_attempt, reset_attempts
from backend.database import (
    get_alerts,
    get_graph_data,
    get_logs,
    get_log_stats,
    get_packets,
    get_port_usage,
    get_session_summary,
    get_sessions,
    get_top_talkers,
    init_db,
    log_alert,
    log_packet,
    search_packets,
    user_count,
    write_log,
)
from backend.interfaces import get_interfaces, is_valid_interface
from backend.logger import log as applog
from backend.report import generate_pdf
from backend.sniffer import VALID_BPF_FILTERS, PacketSniffer

# ── Lifespan ──────────────────────────────────────────────────────────── #

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(_queue_broadcaster())
    yield
    task.cancel()
    if state.sniffer and state.capturing:
        state.sniffer.stop()


# ── App ───────────────────────────────────────────────────────────────── #

app = FastAPI(
    title="PLEXUS API",
    version="3.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Auth-Token"],
)

# ── Upload limits ───────────────────────────────────────────────────────── #
MAX_PCAP_BYTES = 100 * 1024 * 1024  # 100 MB — streamed to disk in chunks

# ── Application state ─────────────────────────────────────────────────── #

class _AppState:
    sniffer:      Optional[PacketSniffer] = None
    packet_queue: Queue       = Queue()
    alert_queue:  Queue       = Queue()
    session_id:   str         = ""
    iface:        str         = ""
    capturing:    bool        = False
    packet_total: int         = 0
    alert_total:  int         = 0
    ws_clients:   set[WebSocket] = set()

state = _AppState()

# ── Auth dependency ───────────────────────────────────────────────────── #

def require_auth(x_token: str = Header(..., alias="X-Auth-Token")) -> str:
    username = validate_token(x_token)
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    return username

# ── Pydantic schemas ──────────────────────────────────────────────────── #

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)

class SetupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8, max_length=128)

class CaptureStartRequest(BaseModel):
    filter:            Optional[str] = Field(None)
    iface:             Optional[str] = Field(None)
    time_window:       int = Field(10,  ge=1, le=3600)
    max_ports_scanned: int = Field(5,   ge=1, le=65535)
    max_packets_flood: int = Field(1500, ge=1, le=1_000_000)

    @field_validator("filter")
    @classmethod
    def _chk_filter(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        c = v.strip().lower()
        if c not in VALID_BPF_FILTERS:
            raise ValueError(f"filter must be one of {sorted(VALID_BPF_FILTERS)}")
        return c

    @field_validator("iface")
    @classmethod
    def _chk_iface(cls, v: Optional[str]) -> Optional[str]:
        if not v or not v.strip():
            return None
        name = v.strip()
        if not is_valid_interface(name):
            raise ValueError(f"Interface '{name}' not found on this system")
        return name

class SettingsUpdateRequest(BaseModel):
    filter:            Optional[str] = None
    time_window:       Optional[int] = Field(None, ge=1, le=3600)
    max_ports_scanned: Optional[int] = Field(None, ge=1, le=65535)
    max_packets_flood: Optional[int] = Field(None, ge=1, le=1_000_000)

    @field_validator("filter")
    @classmethod
    def _chk_filter(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        c = v.strip().lower()
        if c not in VALID_BPF_FILTERS:
            raise ValueError(f"filter must be one of {sorted(VALID_BPF_FILTERS)}")
        return c

# ── WS broadcaster ────────────────────────────────────────────────────── #

async def _broadcast(message: dict) -> None:
    dead: set[WebSocket] = set()
    data = json.dumps(message)
    for ws in state.ws_clients:
        try:
            await ws.send_text(data)
        except Exception:
            dead.add(ws)
    state.ws_clients -= dead


async def _queue_broadcaster() -> None:
    while True:
        await asyncio.sleep(0.5)
        if not state.capturing:
            continue

        packets_batch: list[dict] = []
        for _ in range(50):
            try:
                pkt = state.packet_queue.get_nowait()
            except Empty:
                break
            log_packet(pkt)
            state.packet_total += 1
            ts, src_ip, dst_ip, src_port, dst_port, length, protocol, flags, ttl, checksum, payload, _sid = pkt
            packets_batch.append({
                "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "length": length, "protocol": protocol,
                "flags": flags, "ttl": ttl,
                "checksum": checksum, "payload": payload,
            })

        alerts_batch: list[dict] = []
        for _ in range(20):
            try:
                alert = state.alert_queue.get_nowait()
            except Empty:
                break
            log_alert(alert)
            state.alert_total += 1
            ts, src_ip, alert_type, description, _sid = alert
            alerts_batch.append({
                "timestamp": ts, "src_ip": src_ip,
                "alert_type": alert_type, "description": description,
            })
            # Trigger cross-platform native desktop notification
            try:
                notify(
                    title=f"🚨 PLEXUS NIDS: {alert_type}",
                    message=description
                )
            except Exception as notify_err:
                print(f"[PLEXUS/Alert] Notification failed: {notify_err}")



        if packets_batch or alerts_batch:
            await _broadcast({
                "type": "update",
                "packets": packets_batch,
                "alerts": alerts_batch,
                "packet_total": state.packet_total,
                "alert_total": state.alert_total,
                "session_id": state.session_id,
                "capturing": state.capturing,
            })

# ═══════════════════════════════════════════════════════════════════════
# PUBLIC ENDPOINTS (no auth)
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/auth/status")
async def auth_status():
    return {"setup_required": user_count() == 0}


@app.post("/api/auth/setup")
async def auth_setup(body: SetupRequest):
    ok, msg = register_first_user(body.username, body.password)
    if not ok:
        applog.warning("auth", f"Setup failed: {msg}", username=body.username)
        raise HTTPException(status_code=400, detail=msg)
    applog.info("auth", "First admin account created", username=body.username)
    return {"message": msg}


@app.post("/api/auth/login")
async def auth_login(body: LoginRequest, request: Request):
    # Brute-force throttle: 5 failed attempts per minute, keyed by client IP + username.
    client_ip = request.client.host if request.client else "unknown"
    rl_key = f"{client_ip}:{body.username.strip().lower()}"
    if is_rate_limited(rl_key):
        applog.warning("auth", "Login rate-limited", username=body.username)
        raise HTTPException(status_code=429, detail="Too many attempts — try again in a minute")
    ok, result = login(body.username, body.password)
    if not ok:
        record_failed_attempt(rl_key)
        applog.warning("auth", "Failed login attempt", username=body.username, detail=result)
        raise HTTPException(status_code=401, detail=result)
    reset_attempts(rl_key)
    applog.info("auth", "User logged in", username=body.username)
    return {"token": result, "username": body.username}


# ═══════════════════════════════════════════════════════════════════════
# PROTECTED ENDPOINTS (require X-Auth-Token)
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/auth/logout")
async def auth_logout(
    x_token: str = Header(..., alias="X-Auth-Token"),
    _username: str = Depends(require_auth),
):
    applog.info("auth", "User logged out", username=_username)
    revoke_token(x_token)
    return {"message": "Logged out"}


@app.get("/api/auth/me")
async def auth_me(username: str = Depends(require_auth)):
    return {"username": username}


# ── WebSocket origins allowed to open a stream (browsers always send Origin
# on the WS handshake; rejecting anything else stops random websites from
# siphoning the live packet feed via ws://127.0.0.1:8000).
ALLOWED_WS_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}

# Close codes: 4401 = unauthorized, 4403 = forbidden origin.
# NOTE: we accept() first, then close with a code. Closing *before* accept
# makes Starlette answer HTTP 403, which hides the reason from the client.
# Nothing is transmitted between accept and close, so no data leaks.
@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket, token: str = Query("")):
    await websocket.accept()
    origin = websocket.headers.get("origin")
    if origin and origin not in ALLOWED_WS_ORIGINS:
        await websocket.close(code=4403)
        return
    # Browsers can't set custom headers on a WS handshake, so the session
    # token travels as a query param.
    username = validate_token(token) if token else None
    if username is None:
        await websocket.close(code=4401)
        return
    state.ws_clients.add(websocket)
    await websocket.send_text(json.dumps({
        "type": "status",
        "capturing": state.capturing,
        "session_id": state.session_id,
        "iface": state.iface,
        "packet_total": state.packet_total,
        "alert_total": state.alert_total,
    }))
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        pass
    finally:
        state.ws_clients.discard(websocket)


# ── Capture ───────────────────────────────────────────────────────────── #

@app.post("/api/capture/start")
async def start_capture(
    body: CaptureStartRequest,
    _: str = Depends(require_auth),
):
    if state.capturing:
        raise HTTPException(status_code=409, detail="Capture already running")
    while not state.packet_queue.empty():
        state.packet_queue.get_nowait()
    while not state.alert_queue.empty():
        state.alert_queue.get_nowait()

    session_id         = time.strftime("%Y%m%d_%H%M%S")
    state.session_id   = session_id
    state.iface        = body.iface or "all"
    state.packet_total = 0
    state.alert_total  = 0
    state.capturing    = True

    state.sniffer = PacketSniffer(
        packet_queue      = state.packet_queue,
        alert_queue       = state.alert_queue,
        session_id        = session_id,
        filter_exp        = body.filter,
        iface             = body.iface,
        time_window       = body.time_window,
        max_ports_scanned = body.max_ports_scanned,
        max_packets_flood = body.max_packets_flood,
    )
    state.sniffer.start()
    applog.info("capture", f"Capture started on interface '{state.iface}'",
                session_id=session_id, username=_)
    await _broadcast({"type": "status", "capturing": True, "session_id": session_id,
                      "iface": state.iface, "packet_total": 0, "alert_total": 0})
    return {"status": "started", "session_id": session_id, "iface": state.iface}


@app.post("/api/capture/stop")
async def stop_capture(_: str = Depends(require_auth)):
    if not state.capturing:
        raise HTTPException(status_code=409, detail="No capture is running")
    state.sniffer.stop()
    state.capturing = False
    applog.info("capture", f"Capture stopped — {state.packet_total} packets, {state.alert_total} alerts",
                session_id=state.session_id, username=_)
    await _broadcast({"type": "status", "capturing": False,
                      "session_id": state.session_id,
                      "packet_total": state.packet_total,
                      "alert_total": state.alert_total})
    return {"status": "stopped", "session_id": state.session_id}


@app.post("/api/capture/settings")
async def update_settings(
    body: SettingsUpdateRequest,
    _: str = Depends(require_auth),
):
    if not state.sniffer:
        raise HTTPException(status_code=409, detail="No sniffer instance exists")
    state.sniffer.update_settings(
        filter_exp        = body.filter,
        time_window       = body.time_window,
        max_ports_scanned = body.max_ports_scanned,
        max_packets_flood = body.max_packets_flood,
    )
    return {"status": "settings updated"}


@app.get("/api/capture/status")
async def capture_status(_: str = Depends(require_auth)):
    return {
        "capturing":    state.capturing,
        "session_id":   state.session_id,
        "iface":        state.iface,
        "packet_total": state.packet_total,
        "alert_total":  state.alert_total,
    }


@app.post("/api/capture/analyze-pcap")
async def analyze_pcap(
    file: UploadFile = File(...),
    _: str = Depends(require_auth),
):
    """
    Accepts a PCAP upload, processes its packet streams into network flows,
    and runs the trained XGBoost classifier to detect threats.

    Uploads are streamed to disk in chunks and capped at MAX_PCAP_BYTES —
    the whole file is never held in RAM.
    """
    filename = file.filename or ""
    if not filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only standard .pcap or .pcapng files are supported")

    # Save to a temporary file, streaming in chunks with a hard size cap
    temp_fd, temp_path = tempfile.mkstemp(suffix=".pcap")
    try:
        size = 0
        with os.fdopen(temp_fd, "wb") as tmp:
            while True:
                chunk = await file.read(1024 * 1024)  # 1 MB chunks
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_PCAP_BYTES:
                    raise HTTPException(status_code=413, detail="PCAP too large (max 100 MB)")
                tmp.write(chunk)

        aggregator = FlowAggregator(flow_timeout=999999.0)  # High timeout for file processing
        model_loader = NIDSModelLoader()
        
        total_packets = 0
        analyzed_flows = {}
        anomalies = []

        # Read packets using Scapy PcapReader (streaming, memory-safe)
        with PcapReader(temp_path) as pcap:
            for pkt in pcap:
                if IP not in pkt:
                    continue
                total_packets += 1
                
                # Flow Aggregator processes each packet
                # We use the packet time if available, otherwise current time
                pkt_time = float(pkt.time) if hasattr(pkt, "time") else time.time()
                res = aggregator.process_packet(pkt, pkt_time)
                if res:
                    flow_key, features = res
                    # Keep latest extracted features for each flow
                    analyzed_flows[flow_key] = features

        # For any remaining active flows that did not hit threshold or connection teardown, get final metrics
        for flow_key, flow in aggregator.flows.items():
            src_ip, dst_ip, sport, dport, proto = flow_key
            key_str = f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto})"
            if key_str not in analyzed_flows:
                analyzed_flows[key_str] = flow.get_features()

        # Run inference on all extracted flows
        normal_count = 0
        attack_count = 0
        
        for flow_key, features in analyzed_flows.items():
            is_attack, prob = model_loader.predict(features)
            if is_attack:
                attack_count += 1
                anomalies.append({
                    "flow": flow_key,
                    "confidence": round(prob * 100, 2),
                    "features": features
                })
            else:
                normal_count += 1

        return {
            "filename": file.filename,
            "total_packets": total_packets,
            "total_flows": len(analyzed_flows),
            "normal_flows": normal_count,
            "attack_flows": attack_count,
            "anomalies": anomalies
        }

    except Exception as e:
        applog.error("capture", f"PCAP Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to analyze PCAP: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)



@app.get("/api/interfaces")
async def list_interfaces(_: str = Depends(require_auth)):
    return get_interfaces()


# ── Logs endpoints ────────────────────────────────────────────────────── #

class FrontendLogEntry(BaseModel):
    level:      str = Field("INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")
    category:   str = Field("ui",   max_length=32)
    message:    str = Field(...,    max_length=512)
    detail:     str = Field("",     max_length=1024)
    session_id: str = Field("",     max_length=64)

    @field_validator("category", "level")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip().lower() if v else v


@app.post("/api/logs")
async def ingest_frontend_log(
    body: FrontendLogEntry,
    username: str = Depends(require_auth),
):
    """Receive a log entry from the React frontend and persist it."""
    write_log(
        source     = "frontend",
        level      = body.level.upper(),
        category   = body.category,
        message    = body.message,
        detail     = body.detail,
        session_id = body.session_id,
        username   = username,
    )
    return {"status": "logged"}


@app.get("/api/logs")
async def query_logs(
    source:     Optional[str] = None,
    level:      Optional[str] = None,
    category:   Optional[str] = None,
    session_id: Optional[str] = None,
    limit:      int = 200,
    offset:     int = 0,
    _: str = Depends(require_auth),
):
    return get_logs(
        source     = source,
        level      = level,
        category   = category,
        session_id = session_id,
        limit      = min(limit, 1000),
        offset     = offset,
    )


@app.get("/api/logs/stats")
async def logs_stats(_: str = Depends(require_auth)):
    return get_log_stats()


# ── Sessions ──────────────────────────────────────────────────────────── #

@app.get("/api/sessions")
async def list_sessions(_: str = Depends(require_auth)):
    return get_sessions()


@app.get("/api/sessions/{session_id}/summary")
async def session_summary(session_id: str, _: str = Depends(require_auth)):
    data = get_session_summary(session_id)
    if data["packet_count"] == 0 and data["alert_count"] == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    return data


@app.get("/api/sessions/{session_id}/packets")
async def session_packets(
    session_id: str,
    limit: int = 500,
    offset: int = 0,
    _: str = Depends(require_auth),
):
    return get_packets(session_id, limit=min(limit, 1000), offset=offset)


@app.get("/api/sessions/{session_id}/packets/search")
async def search_session_packets(
    session_id: str,
    protocol:  Optional[str] = None,
    src_ip:    Optional[str] = None,
    dst_ip:    Optional[str] = None,
    src_port:  Optional[int] = None,
    dst_port:  Optional[int] = None,
    flags:     Optional[str] = None,
    limit:     int = 500,
    _: str = Depends(require_auth),
):
    def _clean(v: Optional[str]) -> Optional[str]:
        return v.strip()[:64] if v else None
    return search_packets(
        session_id,
        protocol  = _clean(protocol),
        src_ip    = _clean(src_ip),
        dst_ip    = _clean(dst_ip),
        src_port  = src_port,
        dst_port  = dst_port,
        flags     = _clean(flags),
        limit     = min(limit, 1000),
    )


@app.get("/api/sessions/{session_id}/alerts")
async def session_alerts(
    session_id: str,
    limit: int = 200,
    offset: int = 0,
    _: str = Depends(require_auth),
):
    return get_alerts(session_id, limit=min(limit, 500), offset=offset)


@app.get("/api/sessions/{session_id}/port-usage")
async def session_port_usage(session_id: str, _: str = Depends(require_auth)):
    return get_port_usage(session_id)


@app.get("/api/sessions/{session_id}/graph")
async def session_graph(session_id: str, _: str = Depends(require_auth)):
    return get_graph_data(session_id)


@app.get("/api/sessions/{session_id}/top-talkers")
async def session_top_talkers(
    session_id: str,
    limit: int = 10,
    _: str = Depends(require_auth),
):
    return get_top_talkers(session_id, limit=min(limit, 50))


@app.get("/api/sessions/{session_id}/report")
async def session_report(session_id: str, _: str = Depends(require_auth)):
    # Strict allowlist: the id is interpolated into Content-Disposition,
    # so anything outside [A-Za-z0-9_-] is rejected outright.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    summary = get_session_summary(session_id)
    if summary["packet_count"] == 0 and summary["alert_count"] == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    pdf_bytes = generate_pdf(session_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="plexus_{session_id}.pdf"'},
    )


# ── Entry point ───────────────────────────────────────────────────────── #

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
