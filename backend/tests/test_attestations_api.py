"""
Tests for attestations.py and the stamping in design_store.py: who confirmed a declared claim and when, and when it lapses.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_attestations_api
"""
import sys
from datetime import datetime, timedelta, timezone

from db.models import Design, ThresholdFloors
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


def tidy():
    with SessionLocal() as s:
        for d in s.query(Design).filter(Design.name.like("zz-test%")).all():
            s.delete(d)
        s.query(ThresholdFloors).delete(synchronize_session=False)
        s.commit()
    cleanup()


def doc_of(key):
    with SessionLocal() as s:
        return dict(s.query(Design).filter(Design.design_key == key).one().document)


def set_doc(key, doc):
    with SessionLocal() as s:
        d = s.query(Design).filter(Design.design_key == key).one()
        d.document = doc
        s.commit()


try:
    with authed_client("admin", "Compliance lead") as api, authed_client("engineer", "Model owner") as eng, authed_client("auditor") as aud:
        tidy()
        forged = {"dpia_approved": {"by": "Someone Else", "at": "2020-01-01T00:00:00+00:00", "value": True}}
        r = eng.post("/api/designs", json={"name": "zz-test-attested", "domain": "GENERAL", "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1, "life": {"dpia_approved": True, "drift_detected": False}, "attest": forged}})
        d = r.json()
        key = d["design_key"]
        att = doc_of(key).get("attest") or {}
        check("creating a design stamps the claims with the signed-in person, and ignores what the client sent", r.status_code == 201 and att.get("dpia_approved", {}).get("by") == "Model owner" and att["dpia_approved"]["at"] > "2025" and "drift_detected" not in att, att)

        # ── saving
        r = api.put(f"/api/designs/{key}", json={"name": "zz-test-attested", "domain": "GENERAL", "subject": "MODEL", "version": d["version"],
                                                 "document": {"nodes": [], "edges": [], "n": 1, "life": {"dpia_approved": True, "fallback_tested": True}, "attest": forged}})
        att = doc_of(key)["attest"]
        check("a later save stamps only what it changed", r.status_code == 200 and att["fallback_tested"]["by"] == "Compliance lead" and att["dpia_approved"]["by"] == "Model owner", att)

        # a claim that was there before attestation existed
        legacy = doc_of(key)
        legacy.pop("attest")
        legacy["life"] = {"dpia_approved": True, "operator_training_complete": True}
        set_doc(key, legacy)
        rows = {c["fact"]: c for c in api.get(f"/api/attestations/{key}").json()["claims"]}
        check("an old claim with no attestation shows as never confirmed", rows["dpia_approved"]["state"] == "never" and rows["dpia_approved"]["by"] is None and rows["operator_training_complete"]["state"] == "never", rows)
        ver = api.get(f"/api/designs/{key}").json()["version"]
        eng.put(f"/api/designs/{key}", json={"name": "zz-test-attested", "domain": "GENERAL", "subject": "MODEL", "version": ver, "document": {"nodes": [], "edges": [], "n": 1, "life": {"dpia_approved": True, "operator_training_complete": True}}})
        check("saving the design does not credit the person who saved with claims they did not make", "dpia_approved" not in (doc_of(key).get("attest") or {}))

        # ── confirming
        before = api.get(f"/api/designs/{key}").json()["version"]
        r = eng.post(f"/api/attestations/{key}/confirm", json={"facts": ["dpia_approved"]})
        rows = {c["fact"]: c for c in r.json()["claims"]}
        check("a person confirms a claim and it is current, under their name", r.status_code == 200 and rows["dpia_approved"]["state"] == "current" and rows["dpia_approved"]["by"] == "Model owner" and rows["operator_training_complete"]["state"] == "never", r.text)
        check("confirming does not make anyone's open copy of the design stale", api.get(f"/api/designs/{key}").json()["version"] == before)
        check("what they save next keeps it", eng.put(f"/api/designs/{key}", json={"name": "zz-test-attested", "domain": "GENERAL", "subject": "MODEL", "version": before, "document": {"nodes": [], "edges": [], "n": 1, "life": {"dpia_approved": True, "operator_training_complete": True}}}).status_code == 200 and doc_of(key)["attest"]["dpia_approved"]["by"] == "Model owner")
        check("a claim that is not stated, or cannot lapse, cannot be confirmed", eng.post(f"/api/attestations/{key}/confirm", json={"facts": ["fallback_tested"]}).status_code == 422 and eng.post(f"/api/attestations/{key}/confirm", json={"facts": ["drift_detected"]}).status_code == 422 and eng.post(f"/api/attestations/{key}/confirm", json={"facts": []}).status_code == 422)
        check("an auditor cannot confirm", aud.post(f"/api/attestations/{key}/confirm", json={"facts": ["dpia_approved"]}).status_code == 403 and aud.get(f"/api/attestations/{key}").status_code == 200)
        check("an unknown design is a 404", api.get("/api/attestations/d-none").status_code == 404 and api.post("/api/attestations/d-none/confirm", json={"facts": ["dpia_approved"]}).status_code == 404)

        # ── lapsing, and the policy
        doc = doc_of(key)
        doc["attest"]["dpia_approved"]["at"] = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        set_doc(key, doc)
        rows = {c["fact"]: c for c in api.get(f"/api/attestations/{key}").json()["claims"]}
        check("a claim is current inside its period", rows["dpia_approved"]["state"] == "current" and rows["dpia_approved"]["days"] == 365)
        pol = api.get("/api/attestations/policy").json()
        check("the policy lists what can lapse, with the default periods", pol["governed"]["dpia_approved"]["days"] == 365 and "drift_detected" not in pol["governed"] and pol["max_days"] == 730)
        check("a model owner cannot change the periods", eng.put("/api/attestations/policy", json={"days": {"dpia_approved": 30}}).status_code == 403)
        check("a bad period is refused", api.put("/api/attestations/policy", json={"days": {"dpia_approved": 3}}).status_code == 422 and api.put("/api/attestations/policy", json={"days": {"nope": 30}}).status_code == 422)
        r = api.put("/api/attestations/policy", json={"days": {"dpia_approved": 30}})
        check("compliance shortens the period, recorded under their name", r.status_code == 200 and r.json()["governed"]["dpia_approved"]["days"] == 30 and r.json()["updated_by"] == "Compliance lead", r.text)
        rows = {c["fact"]: c for c in api.get(f"/api/attestations/{key}").json()["claims"]}
        check("the claim has now lapsed, and says by how long", rows["dpia_approved"]["state"] == "lapsed" and rows["dpia_approved"]["days_left"] <= -10, rows["dpia_approved"])
        check("the floors set before are not disturbed by a policy change", api.get("/api/model-monitor/floors").status_code == 200)

        due = api.get("/api/attestations?within=14").json()
        mine = [x for x in due if x["design_key"] == key]
        check("the digest lists the model with its lapsed and never-confirmed claims", mine and {c["fact"]: c["state"] for c in mine[0]["claims"]}.get("dpia_approved") == "lapsed" and mine[0]["summary"]["lapsed"] == 1 and mine[0]["summary"]["never"] >= 1, due)
        r = eng.post(f"/api/attestations/{key}/confirm", json={"facts": ["dpia_approved", "operator_training_complete", "hitl_verified_substantive"]})
        check("confirming again renews it", r.status_code == 200 and r.json()["summary"]["lapsed"] == 0 and r.json()["summary"]["never"] == 0, r.text)
        check("and it leaves the digest", not [x for x in api.get("/api/attestations?within=14").json() if x["design_key"] == key])
finally:
    try:
        tidy()
    except Exception as exc:
        print("cleanup failed", exc)
sys.exit(1 if fails else 0)
