"""
Tests for the ST-AI v2.5 policy API and the independence guards over the organisation's reporting structure (st_ai_policy_api.py, st_ai_guards.py, design_review.py),
through the real API and a scratch database:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_st_ai_policy_api      # see tests/_guard.py

The organisation (a scratch one): Engineering (head Eli Head) > Machine learning (head Priya Raman); Operations (head Rhea Patel) is a separate line.
The model's trainer is Diego Alvarez (machine learning), its validator Mina Okafor (engineering), its deployer Priya Raman (head of machine learning), its operator the
dispatchers (engineering). Everyone who holds a role has to be placed in the structure: at a level above PERSON, a person the organisation does not place cannot be shown independent.
"""
import copy
import json
import sys

import method
from db.models import CompanyEdge, CompanyNode, StAiPolicyVersion
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_design_review import DOC, compile_body, forget, payload

COMPANY = {
    "departments": [{"id": "D-ENG", "name": "Engineering", "head": "P-ELI"}, {"id": "D-ML", "name": "Machine learning", "reports_to": "D-ENG", "head": "P-PRIYA"},
                    {"id": "D-OPS", "name": "Operations", "head": "P-RHEA"}],
    "people": [{"id": "P-ELI", "name": "Eli Head", "department": "D-ENG"}, {"id": "P-MINA", "name": "Mina Okafor", "department": "D-ENG"},
               {"id": "P-PRIYA", "name": "Priya Raman", "department": "D-ML"}, {"id": "P-DIEGO", "name": "Diego Alvarez", "department": "D-ML"},
               {"id": "P-RHEA", "name": "Rhea Patel", "department": "D-OPS"}, {"id": "R-DISP", "name": "Dispatchers", "kind": "role", "department": "D-ENG"}],
}


def reset():
    with SessionLocal() as s:
        s.query(StAiPolicyVersion).delete()
        s.query(CompanyEdge).delete()
        s.query(CompanyNode).delete()
        s.commit()


def policy(review_level="PERSON", review_mode="AT_ACT", approval_level="PERSON"):
    return {"independence": {"review": {"level": review_level, "mode": review_mode}, "approval": {"level": approval_level, "mode": "AT_ACT"}}}


def test_policy_api_publishes_versions_validates_and_needs_sign_off():
    with authed_client("compliance", "Rhea Patel") as comp, authed_client("engineer", "Sam Engineer") as eng:
        try:
            reset()
            st = comp.get("/api/st-ai/policy").json()
            assert st["policy"]["number"] == 0 and st["policy"]["independence"]["review"]["level"] == "PERSON" and st["problems"] == [] and st["history"] == [], st
            assert "policy" not in method.parts_now(SessionLocal()), "no policy part in the method until one is published"
            assert eng.get("/api/st-ai/policy").status_code == 200                                              # anyone who can read can read it
            assert eng.post("/api/st-ai/policy", json={"params": policy("UNIT"), "note": "engineers cannot set policy"}).status_code == 403
            bad = comp.post("/api/st-ai/policy", json={"params": {"independence": {"review": {"level": "COUSIN"}}}, "note": "this should be refused"})
            assert bad.status_code == 422 and "level must be" in bad.json()["detail"], bad.text
            assert comp.post("/api/st-ai/policy", json={"params": policy("UNIT"), "note": "x"}).status_code == 422              # a note is required
            ok = comp.post("/api/st-ai/policy", json={"params": policy("REPORTING_LINE"), "note": "Reviews need a different reporting line."})
            assert ok.status_code == 201 and ok.json()["policy"]["number"] == 1 and ok.json()["history"][0]["published_by"] == "Rhea Patel", ok.text
            assert ok.json()["policy"]["independence"]["review"]["level"] == "REPORTING_LINE"
            same = comp.post("/api/st-ai/policy", json={"params": policy("REPORTING_LINE"), "note": "Publishing the same thing again."})
            assert same.status_code == 409, same.text
            assert "policy" in method.parts_now(SessionLocal())                                                   # the method fingerprint now covers it
            two = comp.post("/api/st-ai/policy", json={"params": policy("UNIT"), "note": "Reviews need a different unit."}).json()
            assert two["policy"]["number"] == 2 and len(two["history"]) == 2
        finally:
            reset()


def test_reporting_line_independence_gates_who_can_review():
    with authed_client("compliance", "Rhea Patel") as rhea, authed_client("compliance", "Eli Head") as eli, authed_client("compliance", "Zed Unplaced") as zed:
        d = rhea.post("/api/designs", json={"name": "Independence test", "domain": "GENERAL", "document": DOC}).json()
        key = d["design_key"]
        p = payload()
        body = {**p, "decision": "APPROVED", "note": "Looked at the evidence for each constraint."}
        try:
            reset()
            assert rhea.post("/api/company/import", json={"content": json.dumps(COMPANY), "filename": "company.json"}).status_code == 200
            # at the default level (PERSON) Eli Head, who heads the validator's unit, may review
            assert eli.post(f"/api/designs/{key}/review", json=body).status_code == 201
            assert rhea.post("/api/st-ai/policy", json={"params": policy("REPORTING_LINE"), "note": "Reviews need a different reporting line."}).status_code == 201
            r = eli.post(f"/api/designs/{key}/review", json=body)
            assert r.status_code == 403 and "REPORTING_LINE" in r.json()["detail"] and "not independent" in r.json()["detail"], r.text          # Eli heads a unit above the trainer
            r = zed.post(f"/api/designs/{key}/review", json=body)
            assert r.status_code == 403 and "cannot be established" in r.json()["detail"], r.text                                              # not placed in the structure
            r = rhea.post(f"/api/designs/{key}/review", json=body)
            assert r.status_code == 201 and r.json()["approved"], r.text                                                                       # Rhea is in another line
            a = rhea.post(f"/api/designs/{key}/assess", json=p).json()["review"]
            assert a["approved"] and a["reviews"][0]["current"], a
            # a new policy version lapses the review: it is bound to the policy it was made under
            assert rhea.post("/api/st-ai/policy", json={"params": policy("REPORTING_LINE", approval_level="UNIT"), "note": "Approvals need a different unit."}).status_code == 201
            assert not rhea.post(f"/api/designs/{key}/assess", json=p).json()["review"]["approved"]
        finally:
            assert rhea.delete(f"/api/designs/{key}").status_code == 204
            forget(key)
            reset()


def test_mode_continuing_lapses_a_review_when_a_reorganisation_removes_the_independence():
    with authed_client("compliance", "Rhea Patel") as rhea:
        d = rhea.post("/api/designs", json={"name": "Continuing test", "domain": "GENERAL", "document": DOC}).json()
        key = d["design_key"]
        p = payload()
        body = {**p, "decision": "APPROVED", "note": "Looked at the evidence for each constraint."}
        try:
            reset()
            assert rhea.post("/api/company/import", json={"content": json.dumps(COMPANY), "filename": "company.json"}).status_code == 200
            assert rhea.post("/api/st-ai/policy", json={"params": policy("REPORTING_LINE", "CONTINUING"), "note": "Reviews need a different line, judged continuously."}).status_code == 201
            assert rhea.post(f"/api/designs/{key}/review", json=body).status_code == 201
            assert rhea.post(f"/api/designs/{key}/assess", json=p).json()["review"]["approved"]
            # the reorganisation: Operations now reports to Machine learning, so the deployer (head of Machine learning) supervises the reviewer
            assert rhea.patch("/api/company/nodes/D-OPS", json={"props": {"parent": "D-ML"}}).status_code == 200
            after = rhea.post(f"/api/designs/{key}/assess", json=p).json()["review"]
            assert not after["approved"], after                                                                     # the review no longer counts
            c = rhea.post(f"/api/designs/{key}/compile", json=compile_body(p))
            assert c.status_code == 422, c.text
        finally:
            assert rhea.delete(f"/api/designs/{key}").status_code == 204
            forget(key)
            reset()


def test_an_issuer_who_is_not_independent_needs_a_review_by_someone_who_is():
    with authed_client("compliance", "Eli Head") as eli:
        d = eli.post("/api/designs", json={"name": "Issuer independence", "domain": "GENERAL", "document": DOC}).json()
        key = d["design_key"]
        p = payload()
        try:
            reset()
            assert eli.post("/api/company/import", json={"content": json.dumps(COMPANY), "filename": "company.json"}).status_code == 200
            assert eli.post("/api/st-ai/policy", json={"params": policy("PERSON", approval_level="REPORTING_LINE"), "note": "Approvals need a different line."}).status_code == 201
            rv = eli.post(f"/api/designs/{key}/assess", json=p).json()["review"]
            assert rv["required"] and rv["issuer_problems"] and "REPORTING_LINE" in rv["issuer_problems"][0], rv
            c = eli.post(f"/api/designs/{key}/compile", json=compile_body(p))
            assert c.status_code == 422 and "not independent" in c.json()["detail"], c.text
        finally:
            assert eli.delete(f"/api/designs/{key}").status_code == 204
            forget(key)
            reset()


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
