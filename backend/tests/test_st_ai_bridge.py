"""
Tests for the bridge from the registry to the ST-AI v2.5 gate (st_ai_bridge.py, scoring_bridge.py). No database:

    docker compose exec backend python -m tests.test_st_ai_bridge
"""
import os
import sys
from datetime import date, timedelta

from schema import ConstraintDeclaration, ConstraintStatus, MODULATING_CLASS_CONSTRAINTS, NotApplicableRationale, RegistryBlock, VETO_CLASS_CONSTRAINTS
from scoring_bridge import score_registry

HARD = sorted(VETO_CLASS_CONSTRAINTS)
REVIEW = sorted(MODULATING_CLASS_CONSTRAINTS)
EVIDENCE = "record: audit report AR-17, 2026-10-01"


def satisfied(**overrides):
    decls = {cid: ConstraintDeclaration(status=ConstraintStatus.SATISFIED, evidence=EVIDENCE) for cid in HARD + REVIEW}
    decls.update(overrides)
    rb = RegistryBlock()
    rb.governance_state.constraints_declared = decls
    return rb


def st(rb, wf=()):
    res, _ = score_registry(rb, wf)
    return res.gate, res.raw_breakdown["st_ai"]


def test_nothing_declared_is_blocked_by_unknown_hard_constraints():
    gate, d = st(RegistryBlock())
    assert gate == "BLOCKED" and any("is unknown" in b for b in d["blockers"]), d["blockers"]


def test_everything_satisfied_with_evidence_is_approved():
    gate, d = st(satisfied())
    assert gate == "APPROVED" and d["releasable_with_review"] and d["triggers"] == [], d


def test_expired_evidence_makes_a_hard_constraint_unknown():
    old = ConstraintDeclaration(status=ConstraintStatus.SATISFIED, evidence=EVIDENCE, valid_until=date.today() - timedelta(days=1))
    gate, d = st(satisfied(**{HARD[0]: old}))
    assert gate == "BLOCKED" and any(HARD[0] in b for b in d["blockers"])


def test_placeholder_evidence_is_not_evidence():
    ph = ConstraintDeclaration(status=ConstraintStatus.SATISFIED, evidence="n/a")
    gate, _ = st(satisfied(**{REVIEW[0]: ph}))
    assert gate == "REQUIRES_REVIEW"


def test_review_class_shortfall_needs_review_and_a_review_can_clear_it():
    gate, d = st(satisfied(**{REVIEW[0]: ConstraintDeclaration()}))
    assert gate == "REQUIRES_REVIEW" and d["releasable_with_review"] and d["unresolvable"] == [], d


def test_not_applicable_without_a_valid_rationale_is_unknown_and_a_review_cannot_clear_it():
    gate, d = st(satisfied(**{HARD[0]: ConstraintDeclaration(applicable=False)}))
    assert gate == "REQUIRES_REVIEW" and not d["releasable_with_review"] and d["unresolvable"] == ["applicability_unknown"], d
    same_person = NotApplicableRationale(reason="no personal data", author="Ann", reviewer="ann", expires_on=date.today() + timedelta(days=30))
    gate, d = st(satisfied(**{HARD[0]: ConstraintDeclaration(applicable=False, not_applicable=same_person)}))
    assert gate == "REQUIRES_REVIEW" and not d["releasable_with_review"]


def test_not_applicable_with_a_valid_rationale_counts_and_is_not_satisfied():
    ok = NotApplicableRationale(reason="the model processes no personal data", author="Ann", reviewer="Bo", expires_on=date.today() + timedelta(days=30))
    gate, d = st(satisfied(**{HARD[0]: ConstraintDeclaration(applicable=False, not_applicable=ok)}))
    assert gate == "APPROVED", d
    row = next(c for c in d["constraints"] if c["id"] == HARD[0])
    assert row["status"] == "NOT_APPLICABLE" and row["status"] != "SATISFIED"
    lapsed = NotApplicableRationale(reason="no personal data", author="Ann", reviewer="Bo", expires_on=date.today() - timedelta(days=1))
    gate, _ = st(satisfied(**{HARD[0]: ConstraintDeclaration(applicable=False, not_applicable=lapsed)}))
    assert gate == "REQUIRES_REVIEW"


def test_role_separation_is_derived_from_who_holds_the_roles():
    rb = satisfied()
    rb.actors.validator.identity = "Priya Raman"
    rb.actors.deployer.identity = "  priya   raman "
    rb.actors.trainer.identity = "Diego Alvarez"
    gate, d = st(rb)
    row = next(c for c in d["constraints"] if c["id"] == "SC-RCF-2")
    assert row["status"] == "VIOLATED" and gate == "REQUIRES_REVIEW" and d["releasable_with_review"], (row, gate)
    rb.actors.deployer.identity = "Someone Else"
    gate, d = st(rb)
    assert next(c for c in d["constraints"] if c["id"] == "SC-RCF-2")["status"] == "SATISFIED" and gate == "APPROVED"


def test_unmet_constraint_is_violated():
    gate, d = st(satisfied(**{HARD[0]: ConstraintDeclaration(status=ConstraintStatus.UNMET)}))
    assert gate == "BLOCKED" and any("violated" in b for b in d["blockers"])


def test_a_design_that_is_not_well_formed_is_invalid_and_nothing_else_is_computed():
    gate, d = st(satisfied(), wf=["the link x refers to an element that is not in the design (zz)"])
    assert gate == "INVALID_MODEL" and d["triggers"] == [] and d["wf_problems"], d


def test_new_gate_is_never_more_lenient_than_the_legacy_gate():
    from st_ai_gate import GATE_RANK
    for rb in (RegistryBlock(), satisfied(), satisfied(**{REVIEW[0]: ConstraintDeclaration()})):
        gate, d = st(rb)
        assert GATE_RANK[gate] >= GATE_RANK[d["legacy_gate"]], (gate, d["legacy_gate"])


def test_rollback_switch_restores_the_legacy_gate():
    os.environ["ST_AI_GATE"] = "legacy"
    try:
        res, _ = score_registry(satisfied(**{REVIEW[0]: ConstraintDeclaration()}))
        assert res.raw_breakdown["st_ai"] is None
        assert res.gate == "APPROVED"            # the legacy gate does not ask for a review of an unknown review-class constraint
    finally:
        del os.environ["ST_AI_GATE"]


# ── the interval rule as the risk criterion ─────────────────────────────────────────────────────────────────────────────
def with_policy(rb, basis="intervals", tolerances=None, key="d-x"):
    import st_ai_policy as P
    pol = P.normalise({"risk": {"basis": basis}, "tolerances": tolerances if tolerances is not None else [
        {"scope": "organisation", "name": "organisation", "dimension": "Financial", "metric": "R", "value": 1000},
        {"scope": "unit", "name": "Logistics", "dimension": "Financial", "metric": "R", "value": 600, "parent": "organisation"},
        {"scope": "deployment", "name": key, "dimension": "Financial", "metric": "R", "value": 100, "parent": "Logistics"}]})
    pol["number"] = 3
    rb.st_ai = {"design_key": key, "policy": pol}
    return rb


def criterion(**kw):
    from schema import RiskCriterionIn, RiskInterval
    iv = lambda t: None if t is None else RiskInterval(lower=t[0], upper=t[1])           # noqa: E731
    return RiskCriterionIn(id=kw.get("id", "c1"), dimension=kw.get("dimension", "Financial"), metric=kw.get("metric", "R"), evidenced=iv(kw.get("ev")),
                           evidenced_valid_until=kw.get("until"), bounded=iv(kw.get("bd")))


def test_intervals_basis_without_criteria_is_unresolved_and_a_review_cannot_clear_it():
    gate, d = st(with_policy(satisfied()))
    assert gate == "REQUIRES_REVIEW" and d["risk_basis"] == "intervals" and not d["releasable_with_review"] and d["unresolvable"] == ["risk_unresolved"], d


def test_intervals_decide_the_risk_criterion():
    future = date.today() + timedelta(days=60)
    rb = with_policy(satisfied())
    rb.risk.criteria = [criterion(ev=(55, 85), until=future)]
    gate, d = st(rb)
    assert gate == "APPROVED" and d["risk_basis"] == "intervals" and d["policy_number"] == 3 and d["risks"][0]["state"] == "pass", d
    rb.risk.criteria = [criterion(ev=(55, 140), until=future)]
    gate, d = st(rb)
    assert gate == "REQUIRES_REVIEW" and d["releasable_with_review"] and d["unresolvable"] == [], d              # an overlap: a review can clear it
    rb.risk.criteria = [criterion(ev=(110, 160), until=future)]
    gate, d = st(rb)
    assert gate == "BLOCKED" and any("blocked" in b for b in d["blockers"]), d


def test_ratchet_in_the_registry_path():
    past = date.today() - timedelta(days=5)
    rb = with_policy(satisfied())
    rb.risk.criteria = [criterion(ev=(110, 160), until=past, bd=(70, 160))]
    gate, d = st(rb)
    assert gate == "BLOCKED" and "ratchet" in d["risks"][0]["detail"], d


def test_no_tolerance_allocated_to_the_deployment_is_unresolved():
    rb = with_policy(satisfied(), key="d-other", tolerances=[])
    rb.risk.criteria = [criterion(ev=(55, 85), until=date.today() + timedelta(days=60))]
    gate, d = st(rb)
    assert gate == "REQUIRES_REVIEW" and d["unresolvable"] == ["risk_unresolved"] and "no tolerance" in d["risks"][0]["detail"], d


def test_legacy_basis_still_judges_a_design_without_intervals_and_intervals_replace_it_once_stated():
    gate, d = st(with_policy(satisfied(), basis="legacy_until_intervals"))
    assert d["risk_basis"] == "legacy_pcs" and gate == "APPROVED", d
    rb = with_policy(satisfied(), basis="legacy_until_intervals")
    rb.risk.criteria = [criterion(ev=(55, 85), until=date.today() + timedelta(days=60))]
    assert st(rb)[1]["risk_basis"] == "intervals"


def test_unquantified_dimensions():
    from schema import UnquantifiedIn
    rb = with_policy(satisfied())
    rb.risk.criteria = [criterion(ev=(55, 85), until=date.today() + timedelta(days=60))]
    rb.risk.unquantified = [UnquantifiedIn(dimension="Reputation", assessment="noQA")]
    gate, d = st(rb)
    assert gate == "REQUIRES_REVIEW" and d["unresolvable"] == ["no_qualitative_assessment"], d
    rb.risk.unquantified = [UnquantifiedIn(dimension="Reputation", assessment="UNACC", hard=True)]
    assert st(rb)[0] == "BLOCKED"
    rb.risk.unquantified = [UnquantifiedIn(dimension="Reputation", assessment="ACC")]
    assert st(rb)[0] == "APPROVED"


def test_prohibited_conditions_keep_the_legacy_blockers_that_are_conditions_in_their_own_right():
    import st_ai_bridge as B
    blockers = ["\u274c PCS = 97.0 / 100 \u2014 CRITICAL tier (>=60). Deployment is blocked.", "\u274c SC-DPIA-1 \u2014 DPIA not approved.",
                "\u274c AUTOMATED feedback loop from RL agent. This is an unconditional pre-deployment blocker."]
    kept = B.prohibited_conditions(blockers)
    assert len(kept) == 1 and kept[0].startswith("AUTOMATED feedback loop"), kept


def test_a_valid_not_applicable_declaration_turns_the_assessed_verdict_green_and_an_invalid_one_amber():
    from compliance_engine import _constraint_verdict
    from compliance_schema import RiskStatus, RuleSeverity
    ok = NotApplicableRationale(reason="no personal data is processed", author="Ann", reviewer="Bo", expires_on=date.today() + timedelta(days=30))
    rb = satisfied(**{HARD[0]: ConstraintDeclaration(applicable=False, not_applicable=ok)})
    status, why = _constraint_verdict(rb.governance_state, HARD[0], RuleSeverity.REQUIRED)
    assert status == RiskStatus.GREEN and "does not apply" in why, (status, why)
    rb = satisfied(**{HARD[0]: ConstraintDeclaration(applicable=False)})
    status, why = _constraint_verdict(rb.governance_state, HARD[0], RuleSeverity.REQUIRED)
    assert status == RiskStatus.AMBER and "rationale" in why, (status, why)


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
