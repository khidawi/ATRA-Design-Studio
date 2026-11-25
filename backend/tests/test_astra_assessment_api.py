"""
Tests for the ASTRA assessment of an agent design through the real API (astra_assessment_api.py), on a scratch database:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_assessment_api        # see tests/_guard.py

The organisation (scratch nodes, ids starting ZZ-): a department, one data store in it, and the agent. The design is saved the way the studio saves it. The endpoint reads the
design, the organisation, the risk layer, the OWASP checks and attested evidence, and changes nothing.
"""
import copy
import json
import sys
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select

from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import CompanyNode, Design, EvidenceRecord, Organisation, RiskAssetTier, RiskDepartmentTolerance, RiskPosture
from db.session import SessionLocal
from tests._auth import authed_client

DEPT, STORE, AGENT_NODE, KEY, MODEL_KEY = "ZZ-D-FIN", "ZZ-DS-LEDGER", "ZZ-AG-PAY", "zz-asses-1", "zz-asses-model"
NAME = "zz-pay-agent"


def base_doc():
    return {"nodes": [{"id": "a1", "type": "agent", "name": NAME, "p": {"owner": "Rhea", "auto": "approval"}, "primary": True},
                      {"id": "i1", "type": "input", "name": "customer email", "p": {"untrusted": True}},
                      {"id": "t1", "type": "tool", "name": "refund", "p": {"write": True}},
                      {"id": "d1", "type": "data", "name": "ZZ Ledger", "p": {"purpose": "settle customer refunds"}}],
            "edges": [{"from": "i1", "to": "a1", "label": "feeds"}, {"from": "a1", "to": "t1", "label": "uses"}, {"from": "a1", "to": "d1", "label": "reads"}]}


def guarded_doc():
    d = base_doc()
    d["nodes"] += [{"id": "ap1", "type": "approval", "name": "manager approval", "p": {}}, {"id": "g1", "type": "guardrail", "name": "injection filter", "p": {"kind": "injection"}}]
    d["edges"] += [{"from": "ap1", "to": "t1", "label": "gates"}, {"from": "g1", "to": "a1", "label": "limits"}]
    return d


def reset():
    with SessionLocal() as s:
        s.query(EvidenceRecord).filter(EvidenceRecord.design_key.in_((KEY, MODEL_KEY))).delete(synchronize_session=False)
        s.query(Design).filter(Design.design_key.in_((KEY, MODEL_KEY))).delete(synchronize_session=False)
        for M in (RiskAssetTier, RiskDepartmentTolerance, RiskPosture):
            s.query(M).delete()
        s.query(CompanyNode).filter(CompanyNode.ext_id.like("ZZ-%")).delete(synchronize_session=False)
        s.commit()


def seed(doc=None):
    reset()
    with SessionLocal() as s:
        org = s.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
        s.add(CompanyNode(organisation_id=org.id, ext_id=DEPT, type="department", name="ZZ Finance", props={}))
        s.add(CompanyNode(organisation_id=org.id, ext_id=STORE, type="data_store", name="ZZ Ledger", props={"department": DEPT}))
        s.add(CompanyNode(organisation_id=org.id, ext_id=AGENT_NODE, type="agent", name=NAME, props={"department": DEPT, "agent_key": NAME}))
        s.add(Design(design_key=KEY, organisation_id=org.id, subject="AGENT", name=NAME, domain_key="payments", document=doc or base_doc()))
        s.add(Design(design_key=MODEL_KEY, organisation_id=org.id, subject="MODEL", name="a model design", domain_key="GENERAL", document={"nodes": [], "edges": []}))
        s.commit()


def set_doc(doc):
    with SessionLocal() as s:
        d = s.scalar(select(Design).where(Design.design_key == KEY))
        d.document = doc
        d.version += 1
        s.commit()


def attest(control, expires=None):
    with SessionLocal() as s:
        org = s.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
        s.add(EvidenceRecord(organisation_id=org.id, design_key=KEY, subject="AGENT", control_key=control, kind="URL", summary="Reviewed page for the test", url="https://example.test/x",
                             url_status=200, fetched_at=datetime.now(timezone.utc), sha256="0" * 64, uploaded_by="Zz Uploader", status="ATTESTED", attested_by="Zz Attester",
                             attested_role="compliance", attested_at=datetime.now(timezone.utc), expires_at=expires))
        s.commit()


def ratify(one, two, kind, body):
    made = one.post({"tolerance": "/api/risk/tolerances", "asset": "/api/risk/assets"}[kind], json=body)
    assert made.status_code == 201, made.text
    done = two.post(f"/api/risk/proposals/{kind}/{made.json()['id']}/ratify", json={})
    assert done.status_code == 200, done.text


def doc_hash():
    with SessionLocal() as s:
        return json.dumps(s.scalar(select(Design).where(Design.design_key == KEY)).document, sort_keys=True)


def test_an_unguarded_agent_is_blocked_and_the_result_is_read_only():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            before = doc_hash()
            r = c.get(f"/api/agents/designs/{KEY}/assessment")
            assert r.status_code == 200, r.text
            out = r.json()
            assert out["verdict"] == "BLOCKED" and out["agent"] == NAME and out["design_key"] == KEY, out["verdict"]
            p = out["paths"][0]
            assert p["input"] == "customer email" and p["resource_name"] == "ZZ Ledger" and p["department_ext"] == DEPT and p["tier"] == 4 and not p["tier_declared"], p
            by = {c_["kind"]: c_ for c_ in p["controls"]}
            assert by["iso"]["status"] == "VIO" and "ASI01" in by["iso"]["why"] and by["hitl"]["status"] == "VIO", by
            assert out["departments"][0]["tolerance"] == 0 and not out["departments"][0]["tolerance_declared"]
            assert out["limits"] and doc_hash() == before, "reading an assessment changes nothing"
        finally:
            reset()


def test_adding_the_controls_moves_it_to_review_and_the_risk_layer_decides_the_rest():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        try:
            seed(guarded_doc())
            out = one.get(f"/api/agents/designs/{KEY}/assessment").json()
            assert out["verdict"] == "REQUIRES_REVIEW", [(c["kind"], c["status"]) for c in out["paths"][0]["controls"]]
            assert {c["status"] for c in out["paths"][0]["controls"]} <= {"UNV", "NA"}
            ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 4, "rationale": "Finance accepts everything for this test."})
            ratify(one, two, "asset", {"asset_ext": STORE, "tier": 2, "rationale": "A low-impact store for this test."})
            out = one.get(f"/api/agents/designs/{KEY}/assessment").json()
            assert out["verdict"] == "APPROVED", out["verdict"]
            p = out["paths"][0]
            assert p["tier"] == 2 and p["tier_declared"] and out["departments"][0]["tolerance"] == 4 and out["departments"][0]["tolerance_declared"]
        finally:
            reset()


def test_attested_evidence_makes_controls_satisfied_and_lapses():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed(guarded_doc())
            for kind in ("iso", "least", "ident", "life", "hitl"):
                attest(f"astra:{kind}")
            out = c.get(f"/api/agents/designs/{KEY}/assessment").json()
            assert out["verdict"] == "APPROVED" and {x["status"] for x in out["paths"][0]["controls"]} == {"SAT", "NA"}, out["verdict"]
            with SessionLocal() as s:                                                     # one attestation lapses yesterday
                row = s.scalar(select(EvidenceRecord).where(EvidenceRecord.design_key == KEY, EvidenceRecord.control_key == "astra:hitl"))
                row.expires_at = date.today() - timedelta(days=1)
                s.commit()
            out = c.get(f"/api/agents/designs/{KEY}/assessment").json()
            assert out["verdict"] == "REQUIRES_REVIEW" and any(x["kind"] == "hitl" and x["status"] == "UNV" for x in out["paths"][0]["controls"])
        finally:
            reset()


def test_a_design_with_a_gap_is_not_rescued_by_attested_evidence():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            for kind in ("iso", "least", "ident", "life", "hitl"):
                attest(f"astra:{kind}")
            out = c.get(f"/api/agents/designs/{KEY}/assessment").json()
            assert out["verdict"] == "BLOCKED", out["verdict"]
        finally:
            reset()


def test_unknown_designs_and_model_designs_are_not_found_and_an_auditor_can_read():
    with authed_client("compliance", "Rhea One") as c, authed_client("auditor", "Alex Auditor") as aud:
        try:
            seed()
            assert c.get("/api/agents/designs/zz-nope/assessment").status_code == 404
            assert c.get(f"/api/agents/designs/{MODEL_KEY}/assessment").status_code == 404, "a model design is not an agent design"
            assert aud.get(f"/api/agents/designs/{KEY}/assessment").status_code == 200
            assert aud.post(f"/api/agents/designs/{KEY}/assessment", json={}).status_code in (403, 404, 405)
        finally:
            reset()


def test_a_design_without_a_primary_agent_is_refused_with_a_reason():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed(copy.deepcopy({"nodes": [], "edges": []}))
            r = c.get(f"/api/agents/designs/{KEY}/assessment")
            assert r.status_code == 422 and "primary agent" in r.json()["detail"], r.text
        finally:
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
