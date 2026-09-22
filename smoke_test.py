"""Smoke test for PLEXUS v3.0.0 security fixes. Run while uvicorn is up."""
import asyncio
import json
import urllib.request

BASE = "http://127.0.0.1:8123"
passed, failed = [], []

# NOTE: the shell deletes network_traffic.db before booting the server,
# making each run hermetic. Do NOT delete it here — the running server
# would recreate an empty file with no tables.

def check(name, cond, detail=""):
    (passed if cond else failed).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))

def post(path, data, token=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

import urllib.error

# 1. Setup + login
s, _ = post("/api/auth/setup", {"username": "smokeadmin", "password": "testpassword123"})
check("setup creates first user", s == 200, f"got {s}")
s, body = post("/api/auth/login", {"username": "smokeadmin", "password": "testpassword123"})
token = json.loads(body).get("token", "") if s == 200 else ""
check("login succeeds", s == 200 and len(token) == 64, f"got {s}")
check("sessions table has 1 row (persistent sessions)",
      __import__("sqlite3").connect("network_traffic.db").execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1)

# 2. WebSocket auth
async def ws_test():
    import websockets
    results = {}
    GOOD_ORIGIN = "http://localhost:5173"
    # no token -> 4401
    try:
        async with websockets.connect("ws://127.0.0.1:8123/ws/stream", origin=GOOD_ORIGIN) as ws:
            await ws.recv()
            results["no_token"] = "accepted?!"
    except websockets.exceptions.ConnectionClosed as e:
        results["no_token"] = e.code
    # bad token -> 4401
    try:
        async with websockets.connect("ws://127.0.0.1:8123/ws/stream?token=" + "z"*64, origin=GOOD_ORIGIN) as ws:
            await ws.recv()
            results["bad_token"] = "accepted?!"
    except websockets.exceptions.ConnectionClosed as e:
        results["bad_token"] = e.code
    # valid token, evil origin -> 4403
    try:
        async with websockets.connect(
            f"ws://127.0.0.1:8123/ws/stream?token={token}",
            origin="http://evil.com") as ws:
            await ws.recv()
            results["evil_origin"] = "accepted?!"
    except websockets.exceptions.ConnectionClosed as e:
        results["evil_origin"] = e.code
    # valid token, legit origin -> accepted
    try:
        async with websockets.connect(
            f"ws://127.0.0.1:8123/ws/stream?token={token}",
            origin=GOOD_ORIGIN) as ws:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            results["good"] = msg.get("type")
    except Exception as e:
        results["good"] = f"error: {e}"
    return results

r = asyncio.run(ws_test())
check("WS without token -> 4401", r["no_token"] == 4401, f"got {r['no_token']}")
check("WS bad token -> 4401", r["bad_token"] == 4401, f"got {r['bad_token']}")
check("WS evil origin -> 4403", r["evil_origin"] == 4403, f"got {r['evil_origin']}")
check("WS valid token+origin accepted", r["good"] == "status", f"got {r['good']}")

# 3. Header injection on report endpoint
s, _ = get("/api/sessions/abc%0d%0aX-Injected:%20yes/report", token)
check("malicious session_id rejected (404)", s == 404, f"got {s}")

# 4. Rate limiting — 6 bad logins, LAST so the 429 doesn't block other tests
codes = [post("/api/auth/login", {"username": "smokeadmin", "password": "wrong"})[0] for _ in range(6)]
check("5 bad logins -> 401", codes[:5] == [401]*5, f"got {codes[:5]}")
check("6th bad login -> 429", codes[5] == 429, f"got {codes[5]}")

print(f"\n{len(passed)} passed, {len(failed)} failed")
raise SystemExit(1 if failed else 0)
