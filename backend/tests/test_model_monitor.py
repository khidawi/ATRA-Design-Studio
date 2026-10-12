"""
Tests for model_monitor.py: plugging a production model in, learning its baseline, noticing drift, bias and bad inputs, and raising incidents.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_model_monitor
"""
import json
import random
import sys
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import model_monitor as mm
from db.models import ApiKey, Design, ModelIncident, ModelMonitor, ModelWindow
from db.session import SessionLocal
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


rng = random.Random(11)
NAME = "zz-test-credit-model"
SECRET_TEXT = "PATIENT-SECRET-NOTE-9f3"


def rec(age_mu=45, plans=(0.6, 0.3, 0.1), approve=0.5, correct=0.92, fa=None, ma=None, bad_age=0.0, at=None, uid=None):
    g = rng.choice(["F", "M"])
    p = {"F": fa, "M": ma}[g] if fa is not None else approve
    d = "approve" if rng.random() < p else "deny"
    age = rng.gauss(age_mu, 8)
    if bad_age and rng.random() < bad_age:
        age = rng.choice([-10, 200])
    r = {"inputs": {"age": age, "plan": rng.choices(["a", "b", "c"], plans)[0], "ref": uid or f"user-{rng.randrange(10**6)}", "note": SECRET_TEXT + "x" * 20, "unused": "ignored"},
         "output": d, "confidence": min(0.99, max(0.05, rng.gauss(0.8, 0.1))), "latency_ms": abs(rng.gauss(60, 12)),
         "label": d if rng.random() < correct else ("deny" if d == "approve" else "approve"), "segments": {"gender": g}, "extra_field": "ignored"}
    if at is not None:
        r["at"] = at.isoformat()
    return r


def post(c, key, records):
    return c.post(f"/api/model-monitor/{key}/records", content=json.dumps({"records": records}), headers={"content-type": "application/json"})


def keyed(token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


BODY = {"name": NAME, "task": "classification", "baseline_target": 300,
        "features": [{"name": "age", "kind": "numeric", "min": 18, "max": 100}, {"name": "plan", "kind": "categorical"}, {"name": "ref", "kind": "categorical"}, {"name": "note", "kind": "text"}],
        "output": {"name": "decision", "kind": "categorical", "positive": "approve"}, "segments": ["gender"]}


def tidy():
    with SessionLocal() as s:
        for m in s.query(ModelMonitor).filter(ModelMonitor.key.like("zz-test%")).all():
            s.delete(m)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()
    cleanup()


try:
    with authed_client("admin", "Compliance lead") as api, authed_client("auditor") as aud:
        tidy()
        k = api.post("/api/keys", json={"name": "zz-test-serving", "role": "collector"}).json()
        col = keyed(k["key"])

        # ── creating
        check("capabilities", api.get("/api/model-monitor/capabilities").json()["thresholds"]["psi_drift"] == 0.25)
        inf = api.post("/api/model-monitor/infer-schema", json={"inputs": {"age": 41, "plan": "gold", "ok": True, "bio": "x" * 100}, "output": "approve", "segments": {"gender": "F"}}).json()
        check("a schema is suggested from one example", {f["name"]: f["kind"] for f in inf["features"]} == {"age": "numeric", "plan": "categorical", "ok": "boolean", "bio": "text"} and inf["output"]["kind"] == "categorical" and inf["segments"] == ["gender"], inf)
        check("an auditor cannot create a monitor, and can read the list", aud.post("/api/model-monitor", json=BODY).status_code == 403 and aud.get("/api/model-monitor").status_code == 200)
        for what, change in [("a bad kind", {"features": [{"name": "a", "kind": "image"}]}), ("two features with one name", {"features": [{"name": "a", "kind": "numeric"}, {"name": "a", "kind": "numeric"}]}),
                             ("an unknown threshold", {"thresholds": {"nope": 1}}), ("a model design that does not exist", {"design_key": "d-nothere"}), ("a baseline that is too small", {"baseline_target": 5}), ("no features", {"features": []})]:
            check(f"refused: {what}", api.post("/api/model-monitor", json={**BODY, **change}).status_code == 422)
        r = api.post("/api/model-monitor", json=BODY)
        check("create a monitor", r.status_code == 201 and r.json()["status"] == "LEARNING" and r.json()["ingest_path"].endswith("/records"), r.text)
        key = r.json()["key"]
        check("the same name twice is refused", api.post("/api/model-monitor", json=BODY).status_code == 409)

        # ── who may send
        check("no key, no entry", TestClient(app).post(f"/api/model-monitor/{key}/records", json={"records": [rec()]}).status_code == 401)
        check("a collector key can send records and read nothing else", post(col, key, [rec()]).status_code == 200 and col.get("/api/model-monitor").status_code == 403 and col.get(f"/api/model-monitor/{key}").status_code == 403)
        check("an auditor cannot send", post(aud, key, [rec()]).status_code == 403)
        check("an unknown monitor is a 404", post(col, "zz-test-nothing", [rec()]).status_code == 404)
        check("a batch over the limit is refused", post(col, key, [rec() for _ in range(mm.MAX_BATCH + 1)]).status_code == 422)
        check("a body over the size limit is refused", col.post(f"/api/model-monitor/{key}/records", content=b"x" * (mm.MAX_BODY + 10), headers={"content-type": "application/json"}).status_code == 413)
        check("a malformed body is a 422 with a reason", col.post(f"/api/model-monitor/{key}/records", content=b"{nope", headers={"content-type": "application/json"}).status_code == 422 and post(col, key, []).status_code == 422)

        # ── learning
        out = post(col, key, [rec() for _ in range(100)]).json()
        check("while learning it reports progress", out["status"] == "LEARNING" and out["learning"]["records"] >= 100 and out["learning"]["target"] == 300 and not out["baseline_frozen"], out)
        d = api.get(f"/api/model-monitor/{key}").json()
        check("the monitor says it is learning", d["status"] == "LEARNING" and d["evaluation"]["status"] == "LEARNING" and d["baseline"] is None)
        old = datetime.now(timezone.utc) - timedelta(days=60)
        mix = post(col, key, [rec(at=old), rec(at=datetime.now(timezone.utc) + timedelta(hours=2)), rec()]).json()
        check("a timestamp outside the retention window or in the future is rejected, not believed", mix["rejected"] == 2 and mix["accepted"] == 1, mix)
        out = post(col, key, [rec() for _ in range(250)]).json()
        check("the baseline is frozen when enough has been seen", out["baseline_frozen"] is True and out["status"] in ("LOW_VOLUME", "NO_DATA", "OK"), out)
        d = api.get(f"/api/model-monitor/{key}").json()
        check("the baseline is described", d["baseline"]["n"] >= 300 and d["baseline"]["source"] == "learned" and d["baseline"]["performance"].get("accuracy", 0) > 0.8)

        # ── normal traffic, then each kind of trouble
        post(col, key, [rec() for _ in range(500)])
        d = api.get(f"/api/model-monitor/{key}").json()
        check("traffic like the baseline is OK, with no signal and no incident", d["status"] == "OK" and not any(d["signals"].values()) and api.get(f"/api/model-monitor/{key}/incidents").json() == [], d["evaluation"].get("reasons"))
        check("the detail shows each feature against its baseline", {f["name"] for f in d["evaluation"]["features"]} == {"age", "plan", "ref", "note"} and d["evaluation"]["output"]["dist"]["labels"])

        past = datetime.now(timezone.utc) - timedelta(hours=3)
        post(col, key, [rec(age_mu=70, at=past) for _ in range(900)])
        d = api.get(f"/api/model-monitor/{key}").json()
        check("a shifted input is DRIFT, with the drift signal", d["status"] == "DRIFT" and d["signals"]["drift_detected"] is True and d["signals"]["drift_type"] == "DATA_DRIFT", d["reasons"])
        incs = api.get(f"/api/model-monitor/{key}/incidents").json()
        check("and an incident is opened for a person", len(incs) == 1 and incs[0]["type"] == "DRIFT_DETECTION" and incs[0]["status"] == "OPEN" and incs[0]["severity"] >= 3 and incs[0]["id"].startswith("MON-"), incs)
        post(col, key, [rec(age_mu=70, at=past) for _ in range(300)])
        api.get(f"/api/model-monitor/{key}")
        check("more of the same does not open another", len(api.get(f"/api/model-monitor/{key}/incidents").json()) == 1)

        post(col, key, [rec(fa=0.7, ma=0.2, at=past) for _ in range(900)])
        d = api.get(f"/api/model-monitor/{key}").json()
        check("unequal outcomes by group are a bias breach signal", d["signals"]["bias_breach_detected"] is True and any(f["attribute"] == "gender" and f["ratio"] < 0.8 for f in d["evaluation"]["fairness"]), d["evaluation"]["fairness"])
        post(col, key, [rec(bad_age=0.3, at=past) for _ in range(300)])
        d = api.get(f"/api/model-monitor/{key}").json()
        check("values outside the declared range are a domain violation signal", d["signals"]["domain_violation_occurred"] is True)
        kinds = {i["type"] for i in api.get(f"/api/model-monitor/{key}/incidents").json()}
        check("each kind raises its own incident", {"DRIFT_DETECTION", "BIAS_BREACH", "MODEL_FAILURE"} <= kinds, kinds)

        # ── the history
        s = api.get(f"/api/model-monitor/{key}/series?hours=48").json()
        check("the history gives each bucket's volume, PSI per feature, error rate and latency", s["step_hours"] == 1 and s["buckets"] and "age" in s["buckets"][-1]["psi"] and s["thresholds"]["psi_drift"] == 0.25 and s["buckets"][-1]["p95"], s["buckets"][-1:])

        # ── what is stored
        with SessionLocal() as sess:
            m = sess.query(ModelMonitor).filter(ModelMonitor.key == key).one()
            blob = json.dumps([w.acc for w in sess.query(ModelWindow).filter(ModelWindow.monitor_id == m.id).all()]) + json.dumps(m.baseline) + json.dumps(m.buffer)
            cat = [w.acc["features"]["ref"] for w in sess.query(ModelWindow).filter(ModelWindow.monitor_id == m.id).all()]
        check("no record, no text and no field outside the schema is stored", SECRET_TEXT not in blob and "ignored" not in blob and "extra_field" not in blob)
        check("a free identifier is capped, not stored", all(len(c["cat"]) <= 50 for c in cat) and sum(c["other"] for c in cat) > 100)

        # ── recovery: the person decides
        api.patch(f"/api/model-monitor/{key}", json={"thresholds": {"eval_hours": 1}})
        post(col, key, [rec() for _ in range(400)])
        d = api.get(f"/api/model-monitor/{key}").json()
        check("when traffic recovers the signals clear, but the incidents stay for a person", d["status"] in ("OK", "WATCH") and not any(d["signals"].values()), (d["status"], d["reasons"]))
        incs = api.get(f"/api/model-monitor/{key}/incidents").json()
        check("each incident notes that its signal has gone", all(i["recovered_at"] for i in incs) and all(i["status"] == "OPEN" for i in incs), incs)
        one = incs[0]
        check("a person closes an incident, and is recorded", api.patch(f"/api/model-monitor/incidents/{one['uuid']}", json={"status": "RESOLVED"}).json()["status"] == "RESOLVED"
              and next(i for i in api.get(f"/api/model-monitor/{key}/incidents").json() if i["uuid"] == one["uuid"])["resolved_by"] == "Compliance lead" and api.patch(f"/api/model-monitor/incidents/{one['uuid']}", json={"status": "NOPE"}).status_code == 422)

        # ── tied to a model design
        dd = api.post("/api/designs", json={"name": "zz-test model", "domain": "GENERAL", "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1}})
        design_key = dd.json()["design_key"] if dd.status_code == 201 else None
        if design_key:
            check("a monitor can be tied to a model design", api.patch(f"/api/model-monitor/{key}", json={"design_key": design_key}).json()["design_key"] == design_key and api.patch(f"/api/model-monitor/{key}", json={"design_key": "d-none"}).status_code == 422)
            post(col, key, [rec(age_mu=75, at=datetime.now(timezone.utc) - timedelta(minutes=1)) for _ in range(900)])
            api.patch(f"/api/model-monitor/{key}", json={"thresholds": {"eval_hours": 24}})
            api.get(f"/api/model-monitor/{key}")
            sg = api.get(f"/api/model-monitor/signals?design_key={design_key}").json()
            check("the model design gets the signals the score understands, and the incidents", sg["signals"]["drift_detected"] is True and sg["signals"]["drift_type"] == "DATA_DRIFT" and sg["monitors"][0]["key"] == key and any(i["id"].startswith("MON-") for i in sg["incidents"]), sg["signals"])
            check("a design with no monitor has no signals", not any(api.get("/api/model-monitor/signals?design_key=d-none").json()["signals"].values()))

        # ── the baseline can be supplied, reset and frozen by hand
        d = api.get(f"/api/model-monitor/{key}").json()
        with SessionLocal() as sess:
            base = sess.query(ModelMonitor).filter(ModelMonitor.key == key).one().baseline
        check("a malformed baseline is refused", api.put(f"/api/model-monitor/{key}/baseline", json={"profile": {"features": {}, "output": {}}}).status_code == 422)
        sup = api.put(f"/api/model-monitor/{key}/baseline", json={"profile": base})
        check("a baseline supplied from the training data is accepted and starts a clean history", sup.status_code == 200 and sup.json()["baseline"]["source"] == "supplied" and sup.json()["status"] == "NO_DATA", sup.text[:200])
        post(col, key, [rec() for _ in range(60)])
        check("a few records are not judged", api.get(f"/api/model-monitor/{key}").json()["status"] == "LOW_VOLUME")
        rs = api.post(f"/api/model-monitor/{key}/baseline/reset").json()
        check("a reset forgets the baseline and learns again", rs["status"] == "LEARNING" and rs["baseline"] is None)
        check("freezing needs enough records", api.post(f"/api/model-monitor/{key}/baseline/freeze").status_code == 409)
        post(col, key, [rec() for _ in range(120)])
        fz = api.post(f"/api/model-monitor/{key}/baseline/freeze")
        check("the baseline can be frozen by hand once there are enough", fz.status_code == 200 and fz.json()["baseline"]["n"] >= 120 and api.post(f"/api/model-monitor/{key}/baseline/freeze").status_code == 409)

        # ── limits
        saved = mm.RECORDS_PER_MINUTE
        mm.RECORDS_PER_MINUTE = 50
        mm._window.clear()
        r = post(col, key, [rec() for _ in range(80)])
        mm.RECORDS_PER_MINUTE = saved
        mm._window.clear()
        check("too many records: 429 with Retry-After", r.status_code == 429 and int(r.headers["retry-after"]) >= 1, (r.status_code, r.headers))
        check("a threshold can be changed, an unknown one is refused", api.patch(f"/api/model-monitor/{key}", json={"thresholds": {"psi_drift": 0.4}}).json()["thresholds"]["psi_drift"] == 0.4 and api.patch(f"/api/model-monitor/{key}", json={"thresholds": {"x": 1}}).status_code == 422)
        check("deleting a monitor removes its history", api.delete(f"/api/model-monitor/{key}").status_code == 204 and api.get(f"/api/model-monitor/{key}").status_code == 404)
        with SessionLocal() as sess:
            check("nothing is left behind", sess.query(ModelWindow).count() == 0 and sess.query(ModelIncident).count() == 0)
finally:
    tidy()

sys.exit(1 if fails else 0)
