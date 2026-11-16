"""
Tests for the design loop of ASTRA phase 4 through the real API (astra_assessment_api.py), on a scratch database:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_gate_loop        # see tests/_guard.py

An agent is assessed (blocked), the controls it is missing are added to its design the way the studio's fixes do, it is assessed again (review), and attested evidence
for the controls it declares brings it to approval. Each assessment can be recorded; a recorded assessment is never edited, and is refused when nothing has changed.
"""
import sys

from sqlalchemy import select

from db.models import AstraAssessment, AuditEvent
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_astra_assessment_api import KEY, MODEL_KEY, attest, base_doc, guarded_doc, ratify, reset, seed, set_doc, STORE, DEPT   # noqa: F401

URL = f"/api/agents/designs/{KEY}/assessment"


def rows_for_key():
    with SessionLocal() as s:
        return list(s.scalars(select(AstraAssessment).where(AstraAssessment.design_key == KEY).order_by(AstraAssessment.created_at)))


def clear():
    with SessionLocal() as s:
        s.query(AstraAssessment).filter(AstraAssessment.design_key == KEY).delete(synchronize_session=False)
        s.commit()
    reset()


def test_the_loop_blocked_then_review_then_approved():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            first = c.get(URL).json()
            assert first["verdict"] == "BLOCKED"
            sug = {x["kind"]: x for x in first["suggestions"]}
            assert sug["iso"]["action"] == "fix" and sug["iso"]["asi"] == "ASI01" and sug["hitl"]["action"] == "fix" and sug["hitl"]["asi"] == "ASI02", first["suggestions"]
            assert first["suggestions"][0]["state"] == "VIO", "the missing controls come first"
            set_doc(guarded_doc())                                                       # what the two fixes do to the design
            second = c.get(URL).json()
            assert second["verdict"] == "REQUIRES_REVIEW", second["verdict"]
            assert second["suggestions"] and all(x["action"] == "manual" and x["state"] == "UNV" for x in second["suggestions"]), second["suggestions"]
            for kind in ("iso", "least", "ident", "life", "hitl"):
                attest(f"astra:{kind}")
            third = c.get(URL).json()
            assert third["verdict"] == "APPROVED" and third["suggestions"] == [], third["suggestions"]
        finally:
            clear()


def test_assessments_are_recorded_in_order_and_never_when_nothing_changed():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            a = c.post(f"{URL}s")
            assert a.status_code == 201, a.text
            ra = a.json()
            assert ra["verdict"] == "BLOCKED" and ra["created_by"] == "Rhea One" and ra["design_version"] == 1 and len(ra["design_hash"]) == 64 and ra["paths"] == 1, ra
            same = c.post(f"{URL}s")
            assert same.status_code == 409 and "Nothing has changed" in same.json()["detail"], same.text
            set_doc(guarded_doc())
            b = c.post(f"{URL}s")
            assert b.status_code == 201 and b.json()["verdict"] == "REQUIRES_REVIEW" and b.json()["design_version"] == 2 and b.json()["design_hash"] != ra["design_hash"], b.text
            hist = c.get(f"{URL}s").json()
            assert [h["verdict"] for h in hist] == ["REQUIRES_REVIEW", "BLOCKED"], hist
            full = c.get(f"{URL}s/{ra['id']}").json()
            assert full["verdict"] == "BLOCKED" and full["result"]["paths"][0]["controls"] and full["result"]["suggestions"], full
            attest("astra:iso")                                                          # the evidence changed, so a new assessment is allowed even for the same design
            assert c.post(f"{URL}s").status_code == 201
            assert len(rows_for_key()) == 3
        finally:
            clear()


def test_a_recorded_assessment_is_never_edited_or_deleted():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            rec = c.post(f"{URL}s").json()
            before = c.get(f"{URL}s/{rec['id']}").json()
            for verb in ("put", "patch", "delete"):
                r = getattr(c, verb)(f"{URL}s/{rec['id']}")
                assert r.status_code in (404, 405), (verb, r.status_code)
            set_doc(guarded_doc())
            c.post(f"{URL}s")
            assert c.get(f"{URL}s/{rec['id']}").json() == before, "a later assessment is a new row; the first one is exactly as it was"
        finally:
            clear()


def test_who_may_record_and_read():
    with authed_client("compliance", "Rhea One") as comp, authed_client("engineer", "Sam Engineer") as eng, authed_client("auditor", "Alex Auditor") as aud:
        try:
            seed()
            assert aud.post(f"{URL}s").status_code == 403, "an auditor reads, never records"
            assert eng.post(f"{URL}s").status_code == 201, "an engineer who is designing the agent can record an assessment"
            assert aud.get(f"{URL}s").status_code == 200 and len(aud.get(f"{URL}s").json()) == 1
            assert comp.get("/api/agents/designs/zz-nope/assessments").status_code == 404
            assert comp.get(f"/api/agents/designs/{MODEL_KEY}/assessments").status_code == 404 and comp.post(f"/api/agents/designs/{MODEL_KEY}/assessments").status_code == 404
            assert comp.get(f"{URL}s/6f0c0e0e-0000-0000-0000-000000000000").status_code == 404
        finally:
            clear()


def test_recording_is_in_the_audit_log_with_the_verdict():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            rec = c.post(f"{URL}s").json()
            with SessionLocal() as s:
                ev = s.scalars(select(AuditEvent).where(AuditEvent.action == "astra.assess").order_by(AuditEvent.seq.desc())).first()
            assert ev is not None and ev.payload["detail"]["verdict"] == "BLOCKED" and ev.payload["detail"]["id"] == rec["id"] and ev.actor_name == "Rhea One", ev and ev.payload
        finally:
            clear()


def test_the_stored_assessment_tracks_the_risk_layer_at_the_time():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        try:
            seed(guarded_doc())
            first = one.post(f"{URL}s").json()
            ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 4, "rationale": "Finance accepts everything for this test."})
            second = one.post(f"{URL}s")
            assert second.status_code == 201 and second.json()["verdict"] == "APPROVED" and first["verdict"] == "REQUIRES_REVIEW", (first["verdict"], second.text)
            assert second.json()["departments"][0]["tolerance"] == 4 and first["departments"][0]["tolerance"] == 0
        finally:
            clear()


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
