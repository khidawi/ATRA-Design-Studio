"""
Tests for the version tracking and decision records of model_monitor.py: a third-party model that changes behind its name, and how people use the outputs.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_model_people
"""
import json
import random
import sys
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from db.models import ApiKey, ModelDecisionWindow, ModelIncident, ModelMonitor
from db.session import SessionLocal
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


rng = random.Random(17)
NAME = "zz-test-llm-api"


def keyed(token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def tidy():
    with SessionLocal() as s:
        for m in s.query(ModelMonitor).filter(ModelMonitor.key.like("zz-test%")).all():
            s.delete(m)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()
    cleanup()


def rec(version, answer_p=0.7, lat=120, err=0.01, at=None):
    r = {"inputs": {"topic": rng.choice(["a", "b", "c"])}, "output": "ok" if rng.random() < answer_p else "refuse", "confidence": min(1, max(0, rng.gauss(0.8, 0.05))),
         "latency_ms": abs(rng.gauss(lat, lat / 6)), "error": rng.random() < err, "model_version": version}
    if at:
        r["at"] = at.isoformat()
    return r


def dec(role="loan officer", action="accepted", secs=20, correct=True, person=None, at=None, reason=False):
    d = {"role": role, "action": action, "review_seconds": secs, "model_correct": correct, "reason": reason, "confidence_shown": True}
    if person:
        d["person"] = person
    if at:
        d["at"] = at.isoformat()
    return d


def post(c, key, path, field, items):
    return c.post(f"/api/model-monitor/{key}/{path}", content=json.dumps({field: items}), headers={"content-type": "application/json"})


BODY = {"name": NAME, "task": "generative", "baseline_target": 100, "features": [{"name": "topic", "kind": "categorical"}], "output": {"name": "reply", "kind": "categorical"}}

try:
    with authed_client("admin", "Compliance lead") as api, authed_client("engineer", "Model owner") as eng, authed_client("auditor") as aud:
        tidy()
        col = keyed(api.post("/api/keys", json={"name": "zz-test-serving", "role": "collector"}).json()["key"])
        key = api.post("/api/model-monitor", json=BODY).json()["key"]
        now = datetime.now(timezone.utc)

        # ── versions
        check("before any version is sent, tracking is off", api.get(f"/api/model-monitor/{key}/versions").json()["tracking"] is False)
        post(col, key, "records", "records", [rec("gpt-x-2026-01", at=now - timedelta(hours=30, seconds=i)) for i in range(300)])
        v = api.get(f"/api/model-monitor/{key}/versions").json()
        check("the first version is recorded and is not a change", v["tracking"] and v["current"] == "gpt-x-2026-01" and v["events"] == [] and v["reasons"] == [] and v["versions"][0]["n"] == 300, v)
        d = api.get(f"/api/model-monitor/{key}").json()
        check("the summary names the current version", d["current_version"] == "gpt-x-2026-01" and d["version_changes"] == 0)

        post(col, key, "records", "records", [rec("gpt-x-2026-01", at=now - timedelta(hours=3, seconds=i)) for i in range(150)])
        post(col, key, "records", "records", [rec("gpt-x-2026-04", answer_p=0.7, at=now - timedelta(hours=1, seconds=i)) for i in range(200)])
        v = api.get(f"/api/model-monitor/{key}/versions").json()
        check("a new version is a change event, with a watch and no incident when behaviour is alike", len(v["events"]) == 1 and v["events"][0]["to"] == "gpt-x-2026-04" and v["reasons"][0]["level"] == "watch", v["reasons"])
        with SessionLocal() as s:
            check("a quiet change opens no incident", s.query(ModelIncident).count() == 0)
        d = api.get(f"/api/model-monitor/{key}").json()
        check("the change shows in the monitor's reasons and moves it to WATCH", d["status"] in ("WATCH", "LEARNING", "OK") and any(r["kind"] == "MODEL_VERSION" for r in d["evaluation"]["reasons"]), d["evaluation"])

        post(col, key, "records", "records", [rec("gpt-x-2026-07", answer_p=0.2, lat=420, err=0.09, at=now - timedelta(minutes=30, seconds=i)) for i in range(220)])
        v = api.get(f"/api/model-monitor/{key}/versions").json()
        r = v["reasons"][0]
        check("a version that behaves differently is a drift naming what moved", len(v["events"]) == 2 and r["level"] == "drift" and {x["what"] for x in r["shifts"]} >= {"answers", "latency", "errors"}, v["reasons"])
        d = api.get(f"/api/model-monitor/{key}").json()
        inc = api.get(f"/api/model-monitor/{key}/incidents").json()
        check("a shift opens a supply-chain incident, which waits for a person", any(i["type"] == "SUPPLY_CHAIN" and i["status"] == "OPEN" for i in inc), inc)
        check("the incident reaches the score through the design signals only as an incident, never as stopped traffic", d["status"] == "DRIFT")
        check("a version longer than the field limit is cut, never fails", post(col, key, "records", "records", [rec("v" * 300)]).status_code == 422)

        # ── decisions: roles, not people
        check("a collector key can send decisions and read nothing", post(col, key, "decisions", "decisions", [dec()]).status_code == 200 and col.get(f"/api/model-monitor/{key}/decisions").status_code == 403)
        check("an auditor cannot send decisions", post(aud, key, "decisions", "decisions", [dec()]).status_code == 403)
        check("a bad action is refused", post(col, key, "decisions", "decisions", [dec(action="shrugged")]).status_code == 422 and post(col, key, "decisions", "decisions", []).status_code == 422)
        check("an unknown monitor is a 404", post(col, "zz-test-none", "decisions", "decisions", [dec()]).status_code == 404)
        old = post(col, key, "decisions", "decisions", [dec(at=now - timedelta(days=90)), dec(at=now + timedelta(hours=3)), dec()]).json()
        check("a timestamp outside the window is rejected", old["rejected"] == 2 and old["accepted"] == 1, old)

        sent = post(col, key, "decisions", "decisions", [dec(person="Alice Smith") for _ in range(5)]).json()
        check("by default a person's name is dropped, not stored", sent["people_ignored"] == 5 and sent["individuals"] is False)
        with SessionLocal() as s:
            blob = json.dumps([w.acc for w in s.query(ModelDecisionWindow).all()])
            check("nothing identifying is in what is kept", "Alice" not in blob and '"people": {}' in blob.replace("'", '"'))

        careful = [dec(action="accepted" if rng.random() < 0.75 else "overridden", secs=abs(rng.gauss(30, 8)), correct=rng.random() > 0.1) for _ in range(250)]
        for x in careful:
            if x["model_correct"] is False and x["action"] == "accepted" and rng.random() < 0.85:
                x["action"] = "overridden"
        post(col, key, "decisions", "decisions", careful)
        g = api.get(f"/api/model-monitor/{key}/decisions").json()
        check("careful review raises no finding and reports the metrics", g["n"] > 250 and g["reasons"] == [] and 0.6 < g["accepted"] < 0.85 and g["advice_only"] is True and g["roles"][0]["role"] == "loan officer", g["reasons"])

        stamp = [dec(role="clerk", action="accepted", secs=abs(rng.gauss(2, 0.5)), correct=rng.random() > 0.2) for _ in range(300)]
        post(col, key, "decisions", "decisions", stamp)
        g = api.get(f"/api/model-monitor/{key}/decisions").json()
        check("a role that accepts nearly everything in seconds, wrong outputs included, is named", any(x["subject"] == "clerk" and x["level"] == "drift" for x in g["reasons"]), g["reasons"])
        d = api.get(f"/api/model-monitor/{key}").json()
        check("it contradicts substantive review and raises the bias risk in the monitor's signals", d["signals"].get("hitl_verified_substantive") is False and d["signals"].get("automation_bias_risk") in ("HIGH", "CRITICAL"), d["signals"])
        inc = api.get(f"/api/model-monitor/{key}/incidents").json()
        check("and opens a human-override incident for a person to look at", any(i["type"] == "HUMAN_OVERRIDE_FAILED" for i in inc), [i["type"] for i in inc])
        design = api.get("/api/designs?subject=MODEL").json()
        sig_ok = api.get("/api/model-monitor/signals?design_key=d-none")
        check("the design signals endpoint carries the oversight facts (shape)", sig_ok.status_code == 200 and "signals" in sig_ok.json())

        # ── individuals: only with compliance sign-off, and forgotten when withdrawn
        check("an engineer cannot turn on counting individuals", eng.put(f"/api/model-monitor/{key}/decision-settings", json={"individuals": True}).status_code == 403)
        check("an unknown threshold is refused", api.put(f"/api/model-monitor/{key}/decision-settings", json={"thresholds": {"nope": 1}}).status_code == 422)
        t = eng.put(f"/api/model-monitor/{key}/decision-settings", json={"thresholds": {"min_decisions": 50}})
        check("the model owner may tune thresholds", t.status_code == 200 and t.json()["custom_thresholds"] == {"min_decisions": 50.0}, t.text)
        on = api.put(f"/api/model-monitor/{key}/decision-settings", json={"individuals": True})
        check("compliance can sign off counting individuals, and it is recorded", on.status_code == 200 and on.json()["individuals"] is True and on.json()["signed_off_by"] == "Compliance lead", on.text)
        post(col, key, "decisions", "decisions", [dec(role="nurse", person=p) for p in ["Alice Smith"] * 20 + ["Bo Chen"] * 5])
        with SessionLocal() as s:
            blob = json.dumps([w.acc for w in s.query(ModelDecisionWindow).all()])
            check("people are pseudonyms, never names", "Alice" not in blob and "Bo Chen" not in blob and '"people": {"' in blob.replace("'", '"'))
        g = api.get(f"/api/model-monitor/{key}/decisions").json()
        check("with people counted, distinct people are reported", g.get("distinct_people") == 2)
        off = api.put(f"/api/model-monitor/{key}/decision-settings", json={"individuals": False})
        with SessionLocal() as s:
            blob = json.dumps([w.acc for w in s.query(ModelDecisionWindow).all()])
            check("withdrawing it forgets who was counted", off.json()["individuals"] is False and not any(w.acc.get("people") for w in s.query(ModelDecisionWindow).all()), blob[:200])

        # ── safety flags: what leaves, what comes back
        sf = api.get(f"/api/model-monitor/{key}/safety").json()
        check("a generative monitor is checked for safety by default", sf["enabled"] is True and {r["flag"] for r in sf["rows"]} >= {"secret_in_prompt", "pii_in_output"} and sf["reasons"] == [], sf)
        recs = [rec("gpt-x-2026-07", answer_p=0.2, lat=420, err=0.09, at=now - timedelta(minutes=5, seconds=i)) for i in range(120)]
        for i in range(12):
            recs[i]["flags"] = {"pii_in_prompt": True}
        recs[50]["flags"] = {"secret_in_output": True}
        recs[51]["flags"] = {"secret_in_prompt": True}
        post(col, key, "records", "records", recs)
        sf = api.get(f"/api/model-monitor/{key}/safety").json()
        kinds = {(r["subject"], r["level"]) for r in sf["reasons"]}
        check("a credential in a reply is flagged however rare, and personal data in prompts by rate", ("secret_in_output", "drift") in kinds and any(k == "pii_in_prompt" for k, _ in kinds), kinds)
        api.get(f"/api/model-monitor/{key}")
        inc = api.get(f"/api/model-monitor/{key}/incidents").json()
        check("they open data-breach and security incidents for a person", {"DATA_BREACH", "SECURITY_EVENT"} <= {i["type"] for i in inc}, [i["type"] for i in inc])
        d = api.get(f"/api/model-monitor/{key}").json()
        check("the safety flags are not also reported as drift against the baseline", not any(r["kind"] == "PREDICTION_DRIFT" and r["subject"] in ("pii_in_prompt", "secret_in_output") for r in d["evaluation"]["reasons"]))
        check("an existing monitor can be given the checks", api.patch(f"/api/model-monitor/{key}", json={"safety_checks": True}).status_code == 200)

        # ── canaries
        check("a collector key may send canary results and read nothing", post(col, key, "canaries", "results", [{"canary": "refund", "passed": True}]).status_code == 200 and col.get(f"/api/model-monitor/{key}/canaries").status_code == 403)
        check("an auditor cannot send them", post(aud, key, "canaries", "results", [{"canary": "refund", "passed": True}]).status_code == 403)
        check("a malformed result is refused", post(col, key, "canaries", "results", [{"canary": "", "passed": True}]).status_code == 422 and post(col, key, "canaries", "results", []).status_code == 422)
        res = [{"canary": "refund", "passed": True, "model_version": "gpt-x-2026-04", "at": (now - timedelta(minutes=50 - i)).isoformat()} for i in range(6)]
        res += [{"canary": "refund", "passed": i == 0, "model_version": "gpt-x-2026-07", "at": (now - timedelta(minutes=20 - i)).isoformat()} for i in range(4)]
        out = post(col, key, "canaries", "results", res + [{"canary": "refund", "passed": True, "at": (now - timedelta(days=90)).isoformat()}]).json()
        check("a stale timestamp is rejected", out["rejected"] == 1 and out["accepted"] == 10, out)
        cn = api.get(f"/api/model-monitor/{key}/canaries").json()
        check("a check that passed on the old version and fails on the new is called out", cn["current_version"] == "gpt-x-2026-07" and cn["reasons"] and cn["reasons"][0]["level"] == "drift" and "earlier versions" in cn["reasons"][0]["text"], cn)
        d = api.get(f"/api/model-monitor/{key}").json()
        check("and it appears in the monitor's findings", any(r["kind"] == "CANARY" for r in d["evaluation"]["reasons"]))

        check("deleting the monitor removes its decisions and versions", api.delete(f"/api/model-monitor/{key}").status_code == 204)
finally:
    try:
        tidy()
    except Exception as exc:
        print("cleanup failed", exc)
sys.exit(1 if fails else 0)
