"""
Tests for threshold floors and waivers, and for the alert channels of production monitoring.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_model_governance
"""
import json
import os
import random
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

os.environ["ASTRA_SECRET_KEY"] = Fernet.generate_key().decode()
os.environ["ASTRA_REPO_ALLOW_PRIVATE_HOSTS"] = "1"

import model_alerts                                             # noqa: E402
from db.models import AlertChannel, ApiKey, ModelMonitor, ThresholdFloors   # noqa: E402
from db.session import SessionLocal                              # noqa: E402
from main import app                                             # noqa: E402
from tests._auth import authed_client                            # noqa: E402
from tests.test_agent_registry import cleanup                    # noqa: E402

model_alerts.HOST_CHECK = lambda host: None

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


received = []
status_to_send = [200]


class Hook(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        self.send_response(status_to_send[0])
        self.end_headers()


server = HTTPServer(("127.0.0.1", 0), Hook)
threading.Thread(target=server.serve_forever, daemon=True).start()
HOOK = f"http://127.0.0.1:{server.server_address[1]}/services/T000/SECRET-TOKEN-xyz"

rng = random.Random(23)
NAME = "zz-test-governed-model"
BODY = {"name": NAME, "task": "generative", "baseline_target": 100, "features": [{"name": "topic", "kind": "categorical"}], "output": {"name": "reply", "kind": "categorical"}}


def keyed(token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def tidy():
    with SessionLocal() as s:
        for m in s.query(ModelMonitor).filter(ModelMonitor.key.like("zz-test%")).all():
            s.delete(m)
        s.query(AlertChannel).filter(AlertChannel.name.like("zz-test%")).delete(synchronize_session=False)
        s.query(ThresholdFloors).delete(synchronize_session=False)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()
    cleanup()


def rec(at, flags=None):
    r = {"inputs": {"topic": rng.choice(["a", "b", "c"])}, "output": "ok", "latency_ms": 100, "at": at.isoformat()}
    if flags:
        r["flags"] = flags
    return r


def post(c, key, records):
    return c.post(f"/api/model-monitor/{key}/records", content=json.dumps({"records": records}), headers={"content-type": "application/json"})


def wait_for_alerts():
    for t in list(model_alerts.PENDING):
        t.join(10)


try:
    with authed_client("admin", "Compliance lead") as api, authed_client("engineer", "Model owner") as eng, authed_client("auditor") as aud:
        tidy()
        col = keyed(api.post("/api/keys", json={"name": "zz-test-serving", "role": "collector"}).json()["key"])
        key = api.post("/api/model-monitor", json=BODY).json()["key"]

        # ── floors
        f = api.get("/api/model-monitor/floors").json()
        check("no floors to begin with, and the governed thresholds are listed with their direction", f["floors"] == {} and f["governed"]["model"]["psi_drift"] == "lower" and f["governed"]["model"]["parity_breach"] == "higher", f)
        check("an auditor can read the floors", aud.get("/api/model-monitor/floors").status_code == 200)
        check("a model owner cannot set the floors", eng.put("/api/model-monitor/floors", json={"floors": {"model": {"psi_drift": 0.2}}}).status_code == 403)
        check("an operational threshold cannot have a floor", api.put("/api/model-monitor/floors", json={"floors": {"model": {"min_n": 5}}}).status_code == 422 and api.put("/api/model-monitor/floors", json={"floors": {"nope": {}}}).status_code == 422)
        r = api.put("/api/model-monitor/floors", json={"floors": {"model": {"psi_drift": 0.2, "parity_breach": 0.8}, "decisions": {"perfunctory_seconds": 5}}})
        check("compliance sets the floors, recorded under their name", r.status_code == 200 and r.json()["floors"]["model"]["psi_drift"] == 0.2 and r.json()["updated_by"] == "Compliance lead", r.text)

        d = api.get(f"/api/model-monitor/{key}").json()
        check("a floor stricter than the default applies to a monitor that never set the threshold", d["thresholds"]["psi_drift"] == 0.2 and d["floors"]["psi_drift"] == 0.2 and d["waivers"] == [])

        # ── the owner tunes within the floor
        r = eng.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.4}})
        check("the owner cannot loosen past the floor, and is told which", r.status_code == 403 and "psi_drift" in r.json()["detail"] and "floor 0.2" in r.json()["detail"], r.text)
        r = eng.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.12, "error_drift": 0.2}})
        check("the owner can tighten, and tune a threshold with no floor", r.status_code == 200 and r.json()["thresholds"]["psi_drift"] == 0.12 and r.json()["thresholds"]["error_drift"] == 0.2, r.text)

        # ── a waiver
        r = api.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.4}})
        check("compliance must give a reason to loosen", r.status_code == 422, r.text)
        r = api.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.4}, "waiver_reason": "Seasonal traffic makes this input swing; reviewed weekly."})
        w = r.json().get("waivers") or []
        check("with a reason it is allowed and recorded as a waiver", r.status_code == 200 and len(w) == 1 and w[0]["by"] == "Compliance lead" and w[0]["floor"] == 0.2 and "Seasonal" in w[0]["reason"] and r.json()["thresholds"]["psi_drift"] == 0.4, r.text)
        r = eng.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.4, "error_drift": 0.1}})
        check("the owner can keep changing other thresholds while the waiver stands", r.status_code == 200 and len(r.json()["waivers"]) == 1, r.text)
        check("but not move the waived one to another loose value", eng.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.5}}).status_code == 403)
        r = eng.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.15}})
        check("tightening back inside the floor ends the waiver", r.status_code == 200 and r.json()["waivers"] == [], r.text)

        api.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.3}, "waiver_reason": "Temporary while the new data feed settles."})
        api.put("/api/model-monitor/floors", json={"floors": {"model": {"psi_drift": 0.1}, "decisions": {"perfunctory_seconds": 5}}})
        d = api.get(f"/api/model-monitor/{key}").json()
        check("a waived value survives a tighter floor", d["thresholds"]["psi_drift"] == 0.3 and len(d["waivers"]) == 1)
        eng.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.1}})
        api.put("/api/model-monitor/floors", json={"floors": {"model": {"psi_drift": 0.05}, "decisions": {"perfunctory_seconds": 5}}})
        d = api.get(f"/api/model-monitor/{key}").json()
        check("when the floor is tightened later, a value now looser than it is held to it", d["thresholds"]["psi_drift"] == 0.05 and d["custom_thresholds"]["psi_drift"] == 0.1, d["thresholds"])

        # ── decision thresholds follow the same rule
        r = eng.put(f"/api/model-monitor/{key}/decision-settings", json={"thresholds": {"perfunctory_seconds": 2}})
        check("the same floor applies to how review is judged", r.status_code == 403 and "perfunctory_seconds" in r.text, r.text)
        r = api.put(f"/api/model-monitor/{key}/decision-settings", json={"thresholds": {"perfunctory_seconds": 2}, "waiver_reason": "Experts review these in seconds by design."})
        check("compliance can waive it with a reason", r.status_code == 200 and len(r.json()["waivers"]) == 1 and r.json()["thresholds"]["perfunctory_seconds"] == 2.0, r.text)

        # ── alert channels
        check("an auditor can list channels, a model owner cannot add one", aud.get("/api/model-monitor/alerts/channels").status_code == 200 and eng.post("/api/model-monitor/alerts/channels", json={"name": "zz-test-ch", "url": HOOK}).status_code == 403)
        for what, url in [("an http address to a non-private host is refused when private hosts are not allowed", None), ("a user name in the address", "https://bob:pw@example.com/x"), ("not an address", "hello"), ("ftp", "ftp://example.com/x")]:
            if url is None:
                continue
            check(f"refused: {what}", api.post("/api/model-monitor/alerts/channels", json={"name": "zz-test-ch", "url": url}).status_code == 422)
        r = api.post("/api/model-monitor/alerts/channels", json={"name": "zz-test-high", "url": HOOK, "min_severity": 3})
        check("an administrator adds a channel; only its host is shown, never the address", r.status_code == 201 and r.json()["host"] == "127.0.0.1" and "SECRET-TOKEN" not in r.text, r.text)
        cid = r.json()["id"]
        r2 = api.post("/api/model-monitor/alerts/channels", json={"name": "zz-test-critical-only", "url": HOOK + "-b", "min_severity": 5})
        check("the listing never carries the address either", "SECRET-TOKEN" not in api.get("/api/model-monitor/alerts/channels").text)
        with SessionLocal() as s:
            stored = s.get(AlertChannel, __import__("uuid").UUID(cid)).url_sealed
        check("the address is stored encrypted", "SECRET-TOKEN" not in stored and "127.0.0.1" not in stored)
        t = api.post(f"/api/model-monitor/alerts/channels/{cid}/test")
        check("a test message is delivered and says so", t.status_code == 200 and t.json()["ok"] is True and received and received[-1][0].endswith("SECRET-TOKEN-xyz") and "test from ASTRA" in received[-1][1]["text"], t.text)
        received.clear()

        # ── an incident reaches the channels, once, and only those it qualifies for
        now = datetime.now(timezone.utc)
        post(col, key, [rec(now - timedelta(hours=30, seconds=i)) for i in range(120)])
        wait_for_alerts()
        check("quiet traffic sends nothing", received == [])
        post(col, key, [rec(now - timedelta(minutes=10, seconds=i), {"secret_in_prompt": True} if i == 3 else None) for i in range(150)])
        api.get(f"/api/model-monitor/{key}")
        wait_for_alerts()
        check("a credential going out sends one alert to a channel whose minimum it reaches", len(received) == 1 and "Data leaving the organisation" in received[0][1]["text"] and received[0][1]["astra"]["severity"] >= 3 and "Advice only" in received[0][1]["text"], received)
        check("it names the incident and carries no records", received[0][1]["astra"]["incident"].startswith("MON-") and "topic" not in json.dumps(received[0][1]))
        n = len(received)
        api.get(f"/api/model-monitor/{key}")
        post(col, key, [rec(now - timedelta(minutes=5, seconds=i)) for i in range(20)])
        wait_for_alerts()
        check("the same open incident is not alerted again", len(received) == n)
        chans = {c["name"]: c for c in api.get("/api/model-monitor/alerts/channels").json()}
        check("the channel records what happened, and the critical-only one was not used", chans["zz-test-high"]["last_status"].startswith("delivered") and chans["zz-test-critical-only"]["last_status"] is None, chans)

        status_to_send[0] = 500
        t = api.post(f"/api/model-monitor/alerts/channels/{cid}/test")
        check("a failing channel is reported, not raised", t.status_code == 200 and t.json()["ok"] is False and "500" in t.json()["status"], t.text)
        status_to_send[0] = 200
        check("a channel can be paused and removed", api.patch(f"/api/model-monitor/alerts/channels/{cid}", json={"active": False}).json()["active"] is False and api.delete(f"/api/model-monitor/alerts/channels/{cid}").status_code == 204)
        check("an unknown channel is a 404", api.delete(f"/api/model-monitor/alerts/channels/{cid}").status_code == 404 and api.delete("/api/model-monitor/alerts/channels/nope").status_code == 404)
finally:
    try:
        tidy()
    except Exception as exc:
        print("cleanup failed", exc)
    server.shutdown()
sys.exit(1 if fails else 0)
