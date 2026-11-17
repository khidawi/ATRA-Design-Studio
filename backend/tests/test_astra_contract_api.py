"""
Tests for the accepted baseline and the signed contract through the real API (astra_contract_api.py), on a scratch database:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_contract_api        # see tests/_guard.py

The design is the guarded agent of the assessment tests, with the risk layer ratified so the gate says APPROVED. The signing key is generated here and never leaves the process.
"""
import os
import sys

from sqlalchemy import select

import astra_signing as SG
from db.models import AstraAssessment, AstraBaseline, AstraSignedContract, Design, ProbeResult, ProbeRun
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_astra_assessment_api import DEPT, KEY, STORE, guarded_doc, ratify, reset as reset_org, seed

OWNER = "owner.zz@example.test"
PRIV, PUB = SG.generate("zz-test-key")


def doc():
    d = guarded_doc()
    d["nodes"][0]["p"]["owner"] = OWNER
    d["nodes"] += [{"id": "g2", "type": "goal", "name": "Refund small claims", "p": {}}]
    d["edges"] += [{"from": "a1", "to": "g2", "label": "pursues"}]
    return d


def reset():
    with SessionLocal() as s:
        s.query(AstraSignedContract).filter(AstraSignedContract.design_key == KEY).delete(synchronize_session=False)
        s.query(AstraBaseline).filter(AstraBaseline.design_key == KEY).delete(synchronize_session=False)
        s.query(AstraAssessment).filter(AstraAssessment.design_key == KEY).delete(synchronize_session=False)
        ids = list(s.scalars(select(ProbeRun.id).where(ProbeRun.design_key == KEY)))
        s.query(ProbeResult).filter(ProbeResult.run_id.in_(ids)).delete(synchronize_session=False)
        s.query(ProbeRun).filter(ProbeRun.design_key == KEY).delete(synchronize_session=False)
        s.commit()
    reset_org()


def probe(client):
    r = client.post("/api/astra/probe/run", json={"design_key": KEY})
    assert r.status_code == 201, r.text
    return r.json()


def approved(one, two, probed=True):
    """The assessment is APPROVED and recorded. The Probe is run first, as a contract is signed only after the Probe has passed on this version: its evidence changes the assessment."""
    seed(doc())
    ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 4, "rationale": "Finance accepts everything for this test."})
    ratify(one, two, "asset", {"asset_ext": STORE, "tier": 2, "rationale": "A low-impact store for this test."})
    if probed:
        probe(one)
    r = one.post(f"/api/agents/designs/{KEY}/assessments")
    assert r.status_code == 201 and r.json()["verdict"] == "APPROVED", r.text


def with_key(fn):
    def run():
        old = os.environ.get("ASTRA_SIGNING_KEY")
        os.environ["ASTRA_SIGNING_KEY"] = PRIV
        try:
            fn()
        finally:
            if old is None:
                os.environ.pop("ASTRA_SIGNING_KEY", None)
            else:
                os.environ["ASTRA_SIGNING_KEY"] = old
            reset()
    run.__name__ = fn.__name__
    return run


@with_key
def test_the_whole_path_from_assessment_to_a_verified_signed_contract():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        approved(one, two)
        d = one.get(f"/api/agents/designs/{KEY}/contract").json()
        assert d["problems"] == [] and d["document"]["agent"]["owner"] == OWNER and d["baseline"] is None and d["signing_configured"], d["problems"]
        assert one.post(f"/api/agents/designs/{KEY}/sign", json={}).status_code == 409, "nothing is signed without a baseline"
        b = two.post(f"/api/agents/designs/{KEY}/baseline", json={"note": "Looks right."})
        assert b.status_code == 201 and b.json()["accepted_by"] == "Rhea Two", b.text
        s = two.post(f"/api/agents/designs/{KEY}/sign", json={})
        assert s.status_code == 201, s.text
        out = s.json()
        assert out["status"] == "ACTIVE" and out["key_id"] == "zz-test-key" and out["version"] == "1.0.0" and out["document"]["agent"]["signature"].startswith("ed25519:zz-test-key:")
        v = two.get(f"/api/astra/contracts/{out['id']}/verify").json()
        assert v["valid"] and v["reasons"] == [], v
        d = two.get(f"/api/agents/designs/{KEY}/contract").json()
        assert d["signed"]["id"] == out["id"] and d["signed"]["current"]


@with_key
def test_the_person_who_recorded_the_assessment_cannot_accept_it():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        approved(one, two)
        r = one.post(f"/api/agents/designs/{KEY}/baseline", json={})
        assert r.status_code == 403 and "different person" in r.json()["detail"], r.text


@with_key
def test_only_compliance_or_admin_can_accept_sign_or_revoke():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two, authed_client("engineer", "Eli Engineer") as eng, \
            authed_client("auditor", "Alex Auditor") as aud:
        approved(one, two)
        for who in (eng, aud):
            assert who.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 403
            assert who.post(f"/api/agents/designs/{KEY}/sign", json={}).status_code == 403
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 201
        sid = two.post(f"/api/agents/designs/{KEY}/sign", json={}).json()["id"]
        assert eng.post(f"/api/astra/contracts/{sid}/revoke", json={"reason": "no right"}).status_code == 403
        assert aud.get(f"/api/astra/contracts/{sid}/verify").status_code == 200, "anyone signed in can verify"


@with_key
def test_a_baseline_needs_a_current_approved_assessment():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        seed(doc())
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 409, "no assessment recorded yet"
        assert one.post(f"/api/agents/designs/{KEY}/assessments").status_code == 201          # still BLOCKED/REVIEW: no ratified tolerance
        r = two.post(f"/api/agents/designs/{KEY}/baseline", json={})
        assert r.status_code == 409 and "only an APPROVED" in r.json()["detail"], r.text
        ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 4, "rationale": "Finance accepts everything for this test."})
        ratify(one, two, "asset", {"asset_ext": STORE, "tier": 2, "rationale": "A low-impact store for this test."})
        r = two.post(f"/api/agents/designs/{KEY}/baseline", json={})
        assert r.status_code == 409 and "has changed since" in r.json()["detail"], "the risk layer changed after the recording: " + r.text


@with_key
def test_changing_the_design_needs_a_new_assessment_baseline_and_signature():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        approved(one, two)
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 201
        first = two.post(f"/api/agents/designs/{KEY}/sign", json={}).json()
        with SessionLocal() as s:
            d = s.scalar(select(Design).where(Design.design_key == KEY))
            nd = doc()
            nd["nodes"].append({"id": "t2", "type": "tool", "name": "lookup", "p": {}})
            nd["edges"].append({"from": "a1", "to": "t2", "label": "uses"})
            d.document, d.version = nd, d.version + 1
            s.commit()
        c = two.get(f"/api/agents/designs/{KEY}/contract").json()
        assert c["baseline"] is None and c["signed"]["current"] is False and not c["assessment_recorded"]
        assert two.post(f"/api/agents/designs/{KEY}/sign", json={}).status_code == 409
        probe(one)                                                                # the Probe on this new version, before the record and the signature
        assert one.post(f"/api/agents/designs/{KEY}/assessments").status_code == 201
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 201
        second = two.post(f"/api/agents/designs/{KEY}/sign", json={}).json()
        assert second["version"] == "2.0.0" and second["status"] == "ACTIVE"
        assert two.get(f"/api/astra/contracts/{first['id']}/verify").json()["reasons"] == ["it is superseded"]
        assert two.get(f"/api/astra/contracts/{second['id']}/verify").json()["valid"]


@with_key
def test_revoking_makes_it_invalid_and_the_signed_bytes_are_untouched():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        approved(one, two)
        two.post(f"/api/agents/designs/{KEY}/baseline", json={})
        s = two.post(f"/api/agents/designs/{KEY}/sign", json={}).json()
        assert two.post(f"/api/astra/contracts/{s['id']}/revoke", json={"reason": "x"}).status_code == 422
        r = two.post(f"/api/astra/contracts/{s['id']}/revoke", json={"reason": "The agent was retired."})
        assert r.status_code == 200 and r.json()["status"] == "REVOKED" and r.json()["revoked_by"] == "Rhea Two"
        assert two.post(f"/api/astra/contracts/{s['id']}/revoke", json={"reason": "again"}).status_code == 409
        v = two.get(f"/api/astra/contracts/{s['id']}/verify").json()
        assert not v["valid"] and v["reasons"] == ["it is revoked"], v
        assert two.get(f"/api/astra/contracts/{s['id']}").json()["document"] == s["document"]


def test_signing_without_a_key_is_refused_and_the_status_never_shows_the_key():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        old = os.environ.pop("ASTRA_SIGNING_KEY", None)
        try:
            approved(one, two)
            two.post(f"/api/agents/designs/{KEY}/baseline", json={})
            r = two.post(f"/api/agents/designs/{KEY}/sign", json={})
            assert r.status_code == 503 and "ASTRA_SIGNING_KEY" in r.json()["detail"], r.text
            assert two.get("/api/astra/signing").json() == {"configured": False, "key_id": None, "retired": []}
            os.environ["ASTRA_SIGNING_KEY"] = PRIV
            st = two.get("/api/astra/signing").json()
            assert st["configured"] and st["key_id"] == "zz-test-key" and PRIV.split(":", 1)[1] not in str(st)
        finally:
            os.environ.pop("ASTRA_SIGNING_KEY", None)
            if old is not None:
                os.environ["ASTRA_SIGNING_KEY"] = old
            reset()


@with_key
def test_a_design_that_cannot_make_a_valid_contract_is_not_signed():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        seed(guarded_doc())                                                       # no goal, and the owner is a name, not an email
        ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 4, "rationale": "Finance accepts everything for this test."})
        ratify(one, two, "asset", {"asset_ext": STORE, "tier": 2, "rationale": "A low-impact store for this test."})
        assert one.post(f"/api/agents/designs/{KEY}/assessments").status_code == 201
        c = one.get(f"/api/agents/designs/{KEY}/contract").json()
        assert any("goal" in p for p in c["problems"]) and any("owner" in p for p in c["problems"]), c["problems"]
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 201
        r = two.post(f"/api/agents/designs/{KEY}/sign", json={})
        assert r.status_code == 422 and "cannot be signed yet" in r.json()["detail"], r.text


@with_key
def test_a_contract_is_signed_only_after_the_probe_has_passed_on_this_version():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        approved(one, two, probed=False)
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 201
        c = two.get(f"/api/agents/designs/{KEY}/contract").json()
        assert c["probe_admitted"] is False and any("No Probe run" in x for x in c["probe_reasons"]), c
        r = two.post(f"/api/agents/designs/{KEY}/sign", json={})
        assert r.status_code == 409 and "Probe has passed" in r.json()["detail"] and "No Probe run" in r.json()["detail"], r.text
        probe(one)
        c = two.get(f"/api/agents/designs/{KEY}/contract").json()
        assert c["probe_admitted"] is True and c["probe_reasons"] == [], c
        assert two.post(f"/api/agents/designs/{KEY}/sign", json={}).status_code == 201


@with_key
def test_a_probe_run_of_an_earlier_version_does_not_admit_the_next_signature():
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        approved(one, two)
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 201
        assert two.post(f"/api/agents/designs/{KEY}/sign", json={}).status_code == 201
        with SessionLocal() as s:
            d = s.scalar(select(Design).where(Design.design_key == KEY))
            nd = doc()
            nd["nodes"].append({"id": "t2", "type": "tool", "name": "lookup", "p": {}})
            nd["edges"].append({"from": "a1", "to": "t2", "label": "uses"})
            d.document, d.version = nd, d.version + 1
            s.commit()
        assert one.post(f"/api/agents/designs/{KEY}/assessments").status_code == 201
        assert two.post(f"/api/agents/designs/{KEY}/baseline", json={}).status_code == 201
        r = two.post(f"/api/agents/designs/{KEY}/sign", json={})
        assert r.status_code == 409 and "earlier version" in r.json()["detail"], r.text
        probe(one)
        assert two.post(f"/api/agents/designs/{KEY}/sign", json={}).status_code == 201


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
