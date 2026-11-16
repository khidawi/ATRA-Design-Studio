"""
Tests for the organisation risk layer (ASTRA phase 2): impact tiers, department tolerance and response posture, each proposed by one person and ratified by another
(risk_layer.py, risk_api.py), through the real API and a scratch database:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_risk_layer        # see tests/_guard.py

The organisation graph is only read by the layer. The tests add two nodes of their own (ids starting ZZ-) and remove them afterwards.
"""
import sys

import risk_api
import risk_layer as RL
from auth import required_permission
from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import AuditEvent, CompanyNode, Organisation, RiskAssetTier, RiskDepartmentTolerance, RiskPosture
from db.session import SessionLocal
from sqlalchemy import select
from tests._auth import authed_client

FIN, LEDGER = "ZZ-D-FIN", "ZZ-DS-LEDGER"


def reset():
    with SessionLocal() as s:
        for M in (RiskAssetTier, RiskDepartmentTolerance, RiskPosture):
            s.query(M).delete()
        s.query(CompanyNode).filter(CompanyNode.ext_id.like("ZZ-%")).delete(synchronize_session=False)
        s.commit()


def seed():
    reset()
    with SessionLocal() as s:
        org = s.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
        s.add(CompanyNode(organisation_id=org.id, ext_id=FIN, type="department", name="ZZ Finance", props={}))
        s.add(CompanyNode(organisation_id=org.id, ext_id=LEDGER, type="data_store", name="ZZ Ledger", props={"department": FIN}))
        s.commit()


def asset(tier=4, **kw):
    return dict({"asset_ext": LEDGER, "tier": tier, "confidentiality": "HIGH", "integrity": "CRITICAL", "availability": "MEDIUM", "rationale": "Payments are written here."}, **kw)


def audit_actions():
    with SessionLocal() as s:
        return [e.action for e in s.scalars(select(AuditEvent).where(AuditEvent.action.like("risk.%")).order_by(AuditEvent.seq))]


# ── the pure part ───────────────────────────────────────────────────────────

def test_scales_and_fail_closed_defaults():
    assert RL.TIERS == (1, 2, 3, 4) and RL.TOLERANCES == (0, 1, 2, 3, 4)
    assert RL.DEFAULT_TIER == 4, "an asset nobody has rated counts as the most severe"
    assert RL.DEFAULT_TOLERANCE == 0, "a department that has not said what it accepts accepts nothing"
    assert RL.posture_problems(RL.DEFAULT_POSTURE) == [], "the default posture must itself be monotone"
    assert RL.posture_matrix({})[4]["Critical"] == "halt" and RL.posture_matrix({})[1]["Medium"] == "observe"


def test_posture_must_be_monotone():
    m = RL.posture_matrix({(1, "Critical"): "halt"})                       # tier 1 halts but tier 2 only blocks
    assert any("tier 2 / Critical" in p for p in RL.posture_problems(m)), RL.posture_problems(m)
    m = RL.posture_matrix({(4, "Medium"): "halt"})                         # medium halts but high only blocks
    assert any("tier 4 / High" in p for p in RL.posture_problems(m)), RL.posture_problems(m)
    ok = RL.posture_matrix({(4, "Medium"): "block", (4, "High"): "block"})
    assert RL.posture_problems(ok) == [], RL.posture_problems(ok)


def test_validation_of_declarations():
    good = {"tier": 3, "confidentiality": "LOW", "integrity": "LOW", "availability": "LOW", "asset_kind": "data", "asset_ext": "a", "department_ext": "d", "rationale": "because"}
    assert RL.validate_asset(good) == []
    assert RL.validate_asset(dict(good, tier=5)) and RL.validate_asset(dict(good, tier=0)) and RL.validate_asset(dict(good, integrity="HUGE")) and RL.validate_asset(dict(good, rationale="x"))
    assert RL.validate_tolerance({"tolerance": 0, "department_ext": "d", "rationale": "nothing accepted"}) == []
    assert RL.validate_tolerance({"tolerance": 5, "department_ext": "d", "rationale": "nothing accepted"}) and RL.validate_tolerance({"tolerance": -1, "department_ext": "d", "rationale": "nothing accepted"})
    assert RL.validate_posture({"tier": 1, "severity": "High", "posture": "halt", "rationale": "reason"}) == []
    assert RL.validate_posture({"tier": 1, "severity": "Low", "posture": "halt", "rationale": "reason"}) and RL.validate_posture({"tier": 1, "severity": "High", "posture": "panic", "rationale": "reason"})


def test_sign_off_routes_need_sign_off_and_proposals_need_write():
    assert required_permission("GET", "/api/risk") == "read"
    for path in ("/api/risk/assets", "/api/risk/tolerances", "/api/risk/posture"):
        assert required_permission("POST", path) == "write", path
    assert required_permission("POST", "/api/risk/proposals/asset/6f0c0e0e-0000-0000-0000-000000000000/ratify") == "signoff"
    assert required_permission("POST", "/api/risk/proposals/posture/6f0c0e0e-0000-0000-0000-000000000000/reject") == "signoff"


# ── through the API ─────────────────────────────────────────────────────────

def test_nothing_declared_means_the_strictest_values():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            st = c.get("/api/risk").json()
            a = next(x for x in st["assets"] if x["asset_ext"] == LEDGER)
            d = next(x for x in st["departments"] if x["department_ext"] == FIN)
            assert a["effective_tier"] == 4 and not a["declared"] and a["ratified"] is None, a
            assert d["effective_tolerance"] == 0 and not d["declared"], d
            assert all(x["source"] == "default" for x in st["posture"]) and len(st["posture"]) == 12
            with SessionLocal() as s:
                eff = risk_api.effective(s)
            assert risk_api.tier_of(eff, LEDGER) == 4 and risk_api.tolerance_of(eff, FIN) == 0 and eff["posture"][4]["Critical"] == "halt"
        finally:
            reset()


def test_roles_propose_and_ratify():
    with authed_client("compliance", "Rhea One") as c1, authed_client("compliance", "Rhea Two") as c2, authed_client("engineer", "Sam Engineer") as eng, authed_client("auditor", "Alex Auditor") as aud:
        try:
            seed()
            assert aud.post("/api/risk/assets", json=asset(3)).status_code == 403, "an auditor reads, never proposes"
            p = eng.post("/api/risk/assets", json=asset(3))
            assert p.status_code == 201 and p.json()["status"] == "PROPOSED" and p.json()["tier"] == 3 and p.json()["department_ext"] == FIN, p.text
            pid = p.json()["id"]
            with SessionLocal() as s:
                assert risk_api.tier_of(risk_api.effective(s), LEDGER) == 4, "a proposal changes nothing until it is ratified"
            assert eng.post(f"/api/risk/proposals/asset/{pid}/ratify", json={}).status_code == 403, "an engineer cannot ratify"
            assert aud.post(f"/api/risk/proposals/asset/{pid}/ratify", json={}).status_code == 403
            ok = c1.post(f"/api/risk/proposals/asset/{pid}/ratify", json={"note": "Agreed with the finance director."})
            assert ok.status_code == 200, ok.text
            a = next(x for x in ok.json()["assets"] if x["asset_ext"] == LEDGER)
            assert a["effective_tier"] == 3 and a["declared"] and a["ratified"]["decided_by"] == "Rhea One" and a["pending"] is None, a
            assert c2.post(f"/api/risk/proposals/asset/{pid}/ratify", json={}).status_code == 409, "a decided proposal cannot be decided again"
            acts = audit_actions()
            assert acts[-2:] == ["risk.propose", "risk.ratify"], acts
        finally:
            reset()


def test_nobody_ratifies_their_own_proposal():
    with authed_client("compliance", "Rhea One") as c1, authed_client("compliance", "Rhea Two") as c2:
        try:
            seed()
            pid = c1.post("/api/risk/tolerances", json={"department_ext": FIN, "tolerance": 1, "rationale": "Finance accepts minor exposure only."}).json()["id"]
            own = c1.post(f"/api/risk/proposals/tolerance/{pid}/ratify", json={})
            assert own.status_code == 409 and "own proposal" in own.json()["detail"], own.text
            assert c2.post(f"/api/risk/proposals/tolerance/{pid}/ratify", json={}).status_code == 200
            with SessionLocal() as s:
                eff = risk_api.effective(s)
            assert risk_api.tolerance_of(eff, FIN) == 1
        finally:
            reset()


def test_one_waiting_proposal_per_value_and_nothing_to_change():
    with authed_client("compliance", "Rhea One") as c1, authed_client("compliance", "Rhea Two") as c2:
        try:
            seed()
            first = c1.post("/api/risk/assets", json=asset(2))
            assert first.status_code == 201
            second = c1.post("/api/risk/assets", json=asset(3))
            assert second.status_code == 409 and "already waiting" in second.json()["detail"], second.text
            assert c2.post(f"/api/risk/proposals/asset/{first.json()['id']}/ratify", json={}).status_code == 200
            same = c1.post("/api/risk/assets", json=asset(2))
            assert same.status_code == 409 and "Nothing changes" in same.json()["detail"], same.text
        finally:
            reset()


def test_a_newer_value_supersedes_and_one_stays_in_force():
    with authed_client("compliance", "Rhea One") as c1, authed_client("compliance", "Rhea Two") as c2:
        try:
            seed()
            first = c1.post("/api/risk/assets", json=asset(2))
            assert first.status_code == 201, first.text
            r1 = c2.post(f"/api/risk/proposals/asset/{first.json()['id']}/ratify", json={})
            assert r1.status_code == 200, r1.text
            second = c1.post("/api/risk/assets", json=asset(4, rationale="The ledger now holds settlement data."))
            assert second.status_code == 201, second.text
            r2 = c2.post(f"/api/risk/proposals/asset/{second.json()['id']}/ratify", json={})
            assert r2.status_code == 200, r2.text
            st = r2.json()
            assert next(x for x in st["assets"] if x["asset_ext"] == LEDGER)["effective_tier"] == 4, st["assets"]
            with SessionLocal() as s:
                rows = list(s.scalars(select(RiskAssetTier).where(RiskAssetTier.asset_ext == LEDGER)))
            assert sorted(r.status for r in rows) == ["RATIFIED", "SUPERSEDED"], [r.status for r in rows]
            assert [h["status"] for h in st["history"] if h["kind"] == "asset"].count("SUPERSEDED") == 1, st["history"]
        finally:
            reset()


def test_reject_needs_a_reason_and_leaves_the_value_unchanged():
    with authed_client("compliance", "Rhea One") as c1, authed_client("compliance", "Rhea Two") as c2:
        try:
            seed()
            pid = c1.post("/api/risk/tolerances", json={"department_ext": FIN, "tolerance": 4, "rationale": "Accept everything."}).json()["id"]
            assert c2.post(f"/api/risk/proposals/tolerance/{pid}/reject", json={"note": ""}).status_code == 422
            st = c2.post(f"/api/risk/proposals/tolerance/{pid}/reject", json={"note": "Far too permissive for a payments department."})
            assert st.status_code == 200, st.text
            d = next(x for x in st.json()["departments"] if x["department_ext"] == FIN)
            assert d["effective_tolerance"] == 0 and d["pending"] is None and d["ratified"] is None, d
            assert any(h["status"] == "REJECTED" and h["decision_note"] for h in st.json()["history"])
            assert audit_actions()[-1] == "risk.reject"
        finally:
            reset()


def test_unknown_things_and_bad_values_are_refused():
    with authed_client("compliance", "Rhea One") as c:
        try:
            seed()
            assert c.post("/api/risk/assets", json=asset(3, asset_ext="ZZ-DS-NOPE")).status_code == 422, "not a data store of the organisation"
            assert c.post("/api/risk/assets", json=asset(3, department_ext="ZZ-D-NOPE")).status_code == 422, "not a department of the organisation"
            assert c.post("/api/risk/assets", json=asset(5)).status_code == 422 and c.post("/api/risk/assets", json=asset(0)).status_code == 422
            assert c.post("/api/risk/assets", json=asset(3, rationale="x")).status_code == 422
            assert c.post("/api/risk/tolerances", json={"department_ext": "ZZ-D-NOPE", "tolerance": 1, "rationale": "does not exist"}).status_code == 422
            assert c.post("/api/risk/tolerances", json={"department_ext": FIN, "tolerance": 9, "rationale": "too high a value"}).status_code == 422
            assert c.post("/api/risk/posture", json={"tier": 1, "severity": "High", "posture": "panic", "rationale": "not a posture"}).status_code == 422
            assert c.post("/api/risk/proposals/asset/not-a-uuid/ratify", json={}).status_code == 422
            assert c.post("/api/risk/proposals/nothing/6f0c0e0e-0000-0000-0000-000000000000/ratify", json={}).status_code == 404
        finally:
            reset()


def test_posture_is_kept_monotone_when_proposed_and_when_ratified():
    with authed_client("compliance", "Rhea One") as c1, authed_client("compliance", "Rhea Two") as c2:
        try:
            seed()
            bad = c1.post("/api/risk/posture", json={"tier": 1, "severity": "Critical", "posture": "halt", "rationale": "Halt even for a minor asset."})
            assert bad.status_code == 422 and "milder response" in bad.json()["detail"], bad.text
            ok = c1.post("/api/risk/posture", json={"tier": 4, "severity": "High", "posture": "halt", "rationale": "Severe assets halt on a high divergence."})
            assert ok.status_code == 201, ok.text
            st = c2.post(f"/api/risk/proposals/posture/{ok.json()['id']}/ratify", json={}).json()
            cell = next(x for x in st["posture"] if x["tier"] == 4 and x["severity"] == "High")
            assert cell["posture"] == "halt" and cell["source"] == "ratified", cell
            # two proposals that are each fine alone but inconsistent together: the second is caught when it is ratified
            a = c1.post("/api/risk/posture", json={"tier": 4, "severity": "Critical", "posture": "halt", "rationale": "Keep halt at the top."})
            b = c1.post("/api/risk/posture", json={"tier": 3, "severity": "Critical", "posture": "halt", "rationale": "Halt at tier three too."})
            assert a.status_code == 201 and b.status_code == 201
            assert c2.post(f"/api/risk/proposals/posture/{b.json()['id']}/ratify", json={}).status_code == 200
            with SessionLocal() as s:
                eff = risk_api.effective(s)
            assert eff["posture"][3]["Critical"] == "halt" and RL.posture_problems(eff["posture"]) == [], eff["posture"]
        finally:
            reset()


def test_the_organisation_graph_is_not_touched():
    with authed_client("compliance", "Rhea One") as c1, authed_client("compliance", "Rhea Two") as c2:
        try:
            seed()
            with SessionLocal() as s:
                before = sorted((n.ext_id, n.type, n.name, str(n.props)) for n in s.scalars(select(CompanyNode)))
            pid = c1.post("/api/risk/assets", json=asset(3)).json()["id"]
            c2.post(f"/api/risk/proposals/asset/{pid}/ratify", json={})
            with SessionLocal() as s:
                after = sorted((n.ext_id, n.type, n.name, str(n.props)) for n in s.scalars(select(CompanyNode)))
            assert before == after, "the risk layer only reads the organisation graph"
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
