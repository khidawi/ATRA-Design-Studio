"""
Tests for the runtime verdict (astra_verdicts.py) through the real API, on a scratch database:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_verdicts        # see tests/_guard.py

The design is the guarded agent of the assessment tests with the risk layer ratified, so the gate approves it at design time. A signed contract for it is put straight into the database,
events are sent through the real runtime endpoint, and the verdict is read back. The properties checked: live evidence can only lower a verdict (monotone), what cannot be judged is
never read as fine (fail closed), a lapsed attestation reads the clock, a High divergence below the department's tolerance gives review and not a block, and an invalid contract
outranks everything.
"""
import copy
import os
import sys
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select

import astra_signing as SG
from db.models import AstraAssessment, AstraBaseline, AstraSignedContract, Finding, RuntimeEvent
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_astra_assessment_api import DEPT, KEY, NAME, STORE, attest, guarded_doc, ratify, reset as reset_org, seed

PRIV, PUB = SG.generate("zz-verdict-key")
FMT = "%Y-%m-%dT%H:%M:%SZ"
RANK = {"INVALID_CONTRACT": 0, "BLOCKED": 1, "REQUIRES_REVIEW": 2, "APPROVED": 3}

DOC = {
    "schema_version": "0.1",
    "agent": {"id": NAME, "owner": "owner.zz@example.test", "lifecycle": {"status": "production", "expires": "2099-12-31"}, "model_version": "1.0.0"},
    "permitted_goals": [{"id": "G1", "statement": "Handle payments"}],
    "permitted_tasks": [{"id": "T1", "tool": "lookup", "scope": {}}, {"id": "T2", "tool": "refund", "scope": {"access": "write"}}],
    "resource_scopes": {"memory": {"writes": "validated", "default_context": "ephemeral"}, "data": [{"resource": "ZZ Ledger", "access": "read"}]},
    "delegation": {"may_delegate_to": [], "accepts_delegation_from": [], "mode": "execution_only"},
    "autonomy": {"unattended_actions": ["T1"], "human_in_the_loop": [{"action": "refund", "require": "forced_confirmation"}]},
    "constraints": [], "regulatory_mappings": [],
}


def reset():
    with SessionLocal() as s:
        s.query(RuntimeEvent).filter(RuntimeEvent.agent_key == NAME).delete(synchronize_session=False)
        s.query(Finding).filter(Finding.agent_key == NAME).delete(synchronize_session=False)
        s.query(AstraSignedContract).filter(AstraSignedContract.design_key == KEY).delete(synchronize_session=False)
        s.query(AstraBaseline).filter(AstraBaseline.design_key == KEY).delete(synchronize_session=False)
        s.query(AstraAssessment).filter(AstraAssessment.design_key == KEY).delete(synchronize_session=False)
        s.commit()
    reset_org()


def sign_row(status="ACTIVE", not_before=None, expires=None, doc=None):
    from db.bootstrap import DEFAULT_ORG_SLUG
    from db.models import Organisation
    now = datetime.now(timezone.utc).replace(microsecond=0)
    nb, exp = (not_before or now - timedelta(hours=1)).strftime(FMT), (expires or now + timedelta(days=1)).strftime(FMT)
    kid, key = SG.load_signer({"ASTRA_SIGNING_KEY": PRIV})
    signed = SG.sign(doc or DOC, kid, key, nb, exp)
    with SessionLocal() as s:
        org = s.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
        if status == "ACTIVE":
            for old in s.scalars(select(AstraSignedContract).where(AstraSignedContract.agent_key == NAME, AstraSignedContract.status == "ACTIVE")):
                old.status = "SUPERSEDED"
            s.flush()
        a = AstraAssessment(organisation_id=org.id, design_key=KEY, design_version=1, design_hash="0" * 64, verdict="APPROVED", departments=[], result={}, created_by="Zz Recorder")
        s.add(a)
        s.flush()
        b = AstraBaseline(organisation_id=org.id, design_key=KEY, design_hash="0" * 64, assessment_id=a.id, accepted_by="Zz Acceptor", accepted_by_id=a.id)
        s.add(b)
        s.flush()
        s.add(AstraSignedContract(organisation_id=org.id, agent_key=NAME, design_key=KEY, design_hash="0" * 64, baseline_id=b.id, version="1.0.0", document=signed["document"],
                                  contract_hash=signed["contract_hash"], key_id=kid, signature=signed["signature"], not_before=nb, expires_at=exp, status=status, signed_by="Zz Acceptor"))
        s.commit()


_ready = []


def with_world(fn):
    """A signed contract for the guarded design, the risk layer ratified at tolerance 4 and tier 2, and the signing key in the environment."""
    def run():
        if not _ready:
            from fastapi.testclient import TestClient
            from main import app
            with TestClient(app):
                pass
            _ready.append(1)
        old = os.environ.get("ASTRA_SIGNING_KEY")
        os.environ["ASTRA_SIGNING_KEY"] = PRIV
        try:
            with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two, authed_client("engineer", "Eli Engineer") as eng:
                reset()
                seed(guarded_doc())
                ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 4, "rationale": "Finance accepts everything for this test."})
                ratify(one, two, "asset", {"asset_ext": STORE, "tier": 2, "rationale": "A low-impact store for this test."})
                sign_row()
                fn(one, two, eng)
        finally:
            if old is None:
                os.environ.pop("ASTRA_SIGNING_KEY", None)
            else:
                os.environ["ASTRA_SIGNING_KEY"] = old
            reset()
    run.__name__ = fn.__name__
    return run


def verdict(c):
    r = c.get(f"/api/runtime/verdicts?agent={NAME}")
    assert r.status_code == 200, r.text
    return r.json()["agents"][0]


def send(c, wire, **data):
    r = c.post("/api/runtime/events", json={"agent": NAME, "events": [{"type": wire, **data}]})
    assert r.status_code == 202, r.text
    return r.json()["results"][0]


def lower_tolerance(one, two, t):
    ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": t, "rationale": f"Finance now accepts up to tier {t} for this test."})


def attest_all():
    for kind in ("iso", "least", "ident", "life", "hitl"):
        attest(f"astra:{kind}")


@with_world
def test_a_live_agent_with_no_divergence_has_the_design_verdict(one, two, eng):
    v = verdict(eng)
    assert v["verdict"] == "APPROVED" and v["runtime_name"] == "CONFORMING" and v["design_verdict"] == "APPROVED" and v["controls_moved"] == [], v
    assert v["contract"]["valid"] and v["contract"]["version"] == "1.0.0" and v["findings"] == {"open": 0, "pending": 0, "total": 0}
    assert v["posture"]["recommended"] == "observe" and v["departments"][0]["tolerance"] == 4
    assert one.get("/api/runtime/verdicts").json()["counts"]["APPROVED"] >= 1
    assert one.get("/api/runtime/verdicts?agent=zz-nobody").status_code == 404


@with_world
def test_a_high_divergence_below_the_tolerance_gives_review_not_a_block(one, two, eng):
    r = send(eng, "tool_call", name="shell")
    assert r["verdict"] == "DIVERGENT"
    v = verdict(eng)
    assert v["verdict"] == "REQUIRES_REVIEW" and v["runtime_name"] == "REQUIRES_REVIEW", "tier 2 is within the tolerance of 4: a person looks, nothing is blocked"
    assert [(m["kind"], m["from"], m["to"]) for m in v["controls_moved"]] == [("least", "UNV", "VIO")], v["controls_moved"]
    assert v["findings"]["open"] == 1 and v["posture"]["recommended"] == "flag" and v["posture"]["basis"][0]["tier"] == 2, v["posture"]
    lower_tolerance(one, two, 1)
    v = verdict(eng)
    assert v["verdict"] == "BLOCKED" and v["runtime_name"] == "DIVERGENT", "the same divergence on a department that accepts only tier 1 is a block"


@with_world
def test_unjudgeable_events_lower_a_satisfied_control_to_unverified_never_to_violated(one, two, eng):
    attest_all()
    lower_tolerance(one, two, 1)
    v0 = verdict(eng)
    assert v0["verdict"] == "APPROVED" and v0["design_verdict"] == "APPROVED", v0["controls_moved"]
    r = send(eng, "tool_call", name="refund")                                 # a write tool that needs a person, and no word on whether one confirmed
    assert r["verdict"] == "UNVERIFIED"
    v = verdict(eng)
    assert v["verdict"] == "REQUIRES_REVIEW" and v["unverified_events"] == ["tool_call"], v
    assert [(m["kind"], m["from"], m["to"]) for m in v["controls_moved"]] == [("least", "SAT", "UNV")], v["controls_moved"]
    assert v["findings"]["total"] == 0


@with_world
def test_live_evidence_only_ever_lowers_the_verdict(one, two, eng):
    attest_all()
    lower_tolerance(one, two, 1)
    seen = [verdict(eng)["verdict"]]
    send(eng, "tool_call", name="refund")                                       # unjudgeable
    seen.append(verdict(eng)["verdict"])
    r = send(eng, "tool_call", name="shell")                                    # a High divergence
    seen.append(verdict(eng)["verdict"])
    two.post(f"/api/findings/{r['finding_key']}/acknowledge", json={"acknowledged": True})          # someone has seen it: that proves nothing was fixed
    seen.append(verdict(eng)["verdict"])
    send(eng, "tool_call", name="lookup")                                       # a conforming event does not heal anything
    seen.append(verdict(eng)["verdict"])
    ranks = [RANK[s] for s in seen]
    assert ranks == sorted(ranks, reverse=True), seen
    assert seen == ["APPROVED", "REQUIRES_REVIEW", "BLOCKED", "BLOCKED", "BLOCKED"], seen


@with_world
def test_an_attestation_that_has_lapsed_reads_the_clock(one, two, eng):
    lower_tolerance(one, two, 1)
    for kind in ("iso", "least", "ident", "life", "hitl"):
        attest(f"astra:{kind}", expires=date.today() + timedelta(days=30))
    assert verdict(eng)["verdict"] == "APPROVED"
    with SessionLocal() as s:
        from db.models import EvidenceRecord
        row = s.scalar(select(EvidenceRecord).where(EvidenceRecord.design_key == KEY, EvidenceRecord.control_key == "astra:least"))
        row.expires_at = date.today() - timedelta(days=1)
        s.commit()
    v = verdict(eng)
    assert v["verdict"] == "REQUIRES_REVIEW" and v["design_verdict"] == "REQUIRES_REVIEW", v


@with_world
def test_an_invalid_contract_outranks_every_verdict(one, two, eng):
    assert verdict(eng)["verdict"] == "APPROVED"
    with SessionLocal() as s:
        s.scalar(select(AstraSignedContract).where(AstraSignedContract.agent_key == NAME)).status = "REVOKED"
        s.commit()
    v = verdict(eng)
    assert v["verdict"] == "INVALID_CONTRACT" and not v["contract"]["valid"] and "revoked" in v["reason"], v
    with SessionLocal() as s:
        s.query(AstraSignedContract).delete()
        s.commit()
    sign_row(expires=datetime.now(timezone.utc) - timedelta(hours=1), not_before=datetime.now(timezone.utc) - timedelta(days=2))
    v = verdict(eng)
    assert v["verdict"] == "INVALID_CONTRACT" and "expired" in v["reason"], v


@with_world
def test_a_new_signed_contract_starts_clean(one, two, eng):
    send(eng, "tool_call", name="shell")
    assert verdict(eng)["verdict"] == "REQUIRES_REVIEW"
    sign_row()                                                                  # a new contract version supersedes the first
    v = verdict(eng)
    assert v["verdict"] == "APPROVED" and v["findings"]["total"] == 0 and v["controls_moved"] == [], v
    send(eng, "tool_call", name="shell")
    assert verdict(eng)["verdict"] == "REQUIRES_REVIEW", "a divergence from the new contract counts again"


@with_world
def test_a_semantic_finding_is_unverified_until_a_person_judges_it(one, two, eng):
    attest_all()
    lower_tolerance(one, two, 1)
    r = send(eng, "goal_set", name="Sell the data", source="retrieved document", semantic="out_of_scope")
    assert r["verdict"] == "PENDING"
    v = verdict(eng)
    assert v["verdict"] == "REQUIRES_REVIEW" and v["findings"]["pending"] == 1 and [(m["kind"], m["to"]) for m in v["controls_moved"]] == [("iso", "UNV")], v
    two.post(f"/api/astra/findings/{r['finding_key']}/adjudicate", json={"decision": "confirm", "note": "It really did."})
    v = verdict(eng)
    assert v["verdict"] == "BLOCKED" and [(m["kind"], m["to"]) for m in v["controls_moved"]] == [("iso", "VIO")], v
    r2 = send(eng, "goal_set", name="Handle a different refund", source="user", semantic="integrity")
    two.post(f"/api/astra/findings/{r2['finding_key']}/adjudicate", json={"decision": "dismiss", "note": "A normal request."})
    assert verdict(eng)["findings"]["pending"] == 0


@with_world
def test_the_response_posture_follows_the_ratified_matrix_and_a_halt_request_stays_a_record(one, two, eng):
    r = send(eng, "tool_call", name="refund", confirmed=False)                 # a Critical class (confirmation bypass)
    v = verdict(eng)
    assert v["posture"]["recommended"] == "block" and v["posture"]["basis"][0]["severity"] == "Critical" and v["posture"]["basis"][0]["tier"] == 2, v["posture"]
    before = v["verdict"]
    h = two.post(f"/api/findings/{r['finding_key']}/halt", json={})
    assert h.status_code == 200
    v = verdict(eng)
    assert v["verdict"] == before and v["halt_requests"][0]["finding"] == r["finding_key"] and v["halt_requests"][0]["by"] == "Rhea Two"
    f = one.get("/api/runtime/verdicts").json()["feed"][0]
    assert f["class_code"] == "DVG-AUT-02" and f["class_name"] and f["detection_basis"] == "policy" and f["asi_signal"] == ["ASI09"], f


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
