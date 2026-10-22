"""
Tests that a model's production monitors go when the model goes: deleting a model design, removing a model from the organisation, and clearing the platform.
A runtime that outlives its model is a stale row in the Connected runtimes list.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_monitor_cleanup     # a scratch database: see tests/_guard.py
"""
import json
import sys
from datetime import datetime, timedelta, timezone

from db.models import ApiKey, Design, ModelMonitor, ModelWindow
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_company import body
from tests.test_removal import ORG, wipe_all

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


def tidy():
    wipe_all()
    with SessionLocal() as s:
        for m in s.query(ModelMonitor).filter(ModelMonitor.key.like("zz-test%")).all():
            s.delete(m)
        s.query(Design).filter(Design.name.like("zz-test%")).delete(synchronize_session=False)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()


BODY = {"task": "classification", "baseline_target": 100, "features": [{"name": "a", "kind": "numeric"}], "output": {"name": "o", "kind": "categorical"}}


def make(api, name, design_key=None):
    r = api.post("/api/model-monitor", json={**BODY, "name": name, "design_key": design_key})
    assert r.status_code == 201, r.text
    api.post(f"/api/model-monitor/{r.json()['key']}/records", content=json.dumps({"records": [{"inputs": {"a": i}, "output": "x", "at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()} for i in range(120)]}),
             headers={"content-type": "application/json"})
    return r.json()["key"]


def keys(api):
    return {m["key"] for m in api.get("/api/model-monitor").json()}


def windows(key):
    with SessionLocal() as s:
        m = s.query(ModelMonitor).filter(ModelMonitor.key == key).first()
        return None if m is None else s.query(ModelWindow).filter(ModelWindow.monitor_id == m.id).count()


try:
    with authed_client("admin", "Alice Admin") as api:
        tidy()
        domain = api.get("/api/domains").json()[0]["domain_id"]
        mk = lambda n: api.post("/api/designs", json={"name": n, "domain": domain, "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1}}).json()["design_key"]   # noqa: E731

        # ── deleting a model design
        d1, d2 = mk("zz-test model one"), mk("zz-test model two")
        k1, k2, korphan = make(api, "zz-test-runtime-one", d1), make(api, "zz-test-runtime-two", d2), make(api, "zz-test-runtime-unlinked")
        check("the runtimes exist", {k1, k2, korphan} <= keys(api))
        check("deleting a model design removes its runtime", api.delete(f"/api/designs/{d1}").status_code == 204 and k1 not in keys(api) and api.get(f"/api/model-monitor/{k1}").status_code == 404)
        check("and its stored history with it", windows(k1) is None)
        check("another model's runtime is untouched", k2 in keys(api))
        check("so is a runtime that was never linked to a design", korphan in keys(api))

        # ── removing a model from the organisation
        api.post("/api/company/import", json=body(ORG))
        made = api.get("/api/company").json()["live"]["models"]["MD-1"]
        km = make(api, "zz-test-runtime-org", made["design_key"])
        check("a model of the organisation has a runtime", km in keys(api))
        r = api.delete("/api/company/nodes/MD-1")
        check("removing the model from the organisation removes its runtime", r.status_code == 200 and km not in keys(api) and r.json()["removed"].get("runtime_monitors") == 1, r.text)
        check("the audit trail says how many runtimes went", r.json()["removed"]["runtime_monitors"] == 1)
        check("the others are still there", {k2, korphan} <= keys(api))

        # ── starting from scratch
        d3 = mk("zz-test model three")
        k3 = make(api, "zz-test-runtime-three", d3)
        org = api.get("/api/organisation").json()["name"]
        r = api.request("DELETE", "/api/company", json={"confirm": org, "remove_everywhere": True})
        check("starting from scratch removes the runtimes of the models that are gone", r.status_code == 200 and not ({k2, k3, korphan} & keys(api)), r.text)
finally:
    try:
        tidy()
    except Exception as exc:
        print("cleanup failed", exc)
sys.exit(1 if fails else 0)
