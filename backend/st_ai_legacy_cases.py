"""
Run the sixteen public-record cases of the first ST-AI paper (fourteen failures, two controls) through the platform's PCS engine and the ST-AI v2.5 gate.

    docker compose run --rm --no-deps -v <cases dir>:/cases backend python st_ai_legacy_cases.py /cases [--out DIR]

Each case file is a fixture of the first paper: a `registry` (the old RegistryState as JSON) and a `_validation` block. This script
  1. converts the registry into the platform's RegistryBlock, keeping every field the PCS engine reads, and states every constraint the way the v2.5 model needs it:
     SATISFIED (with a record), UNMET (the public record shows the gap; where the record is silent the first paper coded the gap, and so does this), or not applicable
     (a rationale with author, independent reviewer and expiry) where the condition of the original rule was not active;
  2. writes the converted case to <out>/registries/NN_name.registry.json, which is the body the platform's /score endpoint takes;
  3. scores it with the platform (scoring_bridge.score_registry): the PCS (score, tier and gate of the legacy engine) and the v2.5 gate;
  4. compares with the ground truth of the first paper (a documented failure must not be released; a governance-compliant control must be approved).
Nothing is written to a database.

How the original rules map (framework/rule_engine.py of the first paper):
  SC-HITL-1, SC-CHALL-1, SC-LIAB-1  apply from OPERATIONAL criticality up; at ADVISORY the original model only warned.
  SC-DPIA-1                         applies to special-category data (and, as a warning, at ADVISORY).
  SC-HALLU-1                        applies to generative (LLM) models.
  SC-MAP-1                          applies to special-category data or CRITICAL / SAFETY_CRITICAL criticality; needs a bias metric and an output-validation gate.
  SC-MC-1, SC-TRAIN-1               documentation duties, review-class.
  SC-RCF-1 / SC-RCF-2               trainer = validator / validator = deployer, derived from who holds the roles.
"""
import argparse
import glob
import json
import os
import sys
from datetime import date
from typing import Any, Dict, List

from schema import (ConstraintDeclaration, ConstraintStatus, DeploymentContext, Department, Lifecycle, NotApplicableRationale, RegistryBlock)
import st_ai_policy as P
from scoring_bridge import score_registry

VALID_UNTIL = date(2027, 12, 31)
CODERS = ("coder A", "coder B")                     # the first paper had two researchers encode each case independently
ACTIVE = ("OPERATIONAL", "CRITICAL", "SAFETY_CRITICAL")
FAILURES_GROUND_TRUTH = "BLOCKED"
LIFECYCLE_FIELDS = set(Lifecycle.model_fields)


def sat(slug: str, fact: str) -> ConstraintDeclaration:
    return ConstraintDeclaration(status=ConstraintStatus.SATISFIED, evidence=f"Case record {slug}: {fact} documented in the public record (citations in the case file)",
                                 valid_until=VALID_UNTIL)


def unmet() -> ConstraintDeclaration:
    return ConstraintDeclaration(status=ConstraintStatus.UNMET)


def not_applicable(reason: str) -> ConstraintDeclaration:
    return ConstraintDeclaration(applicable=False, not_applicable=NotApplicableRationale(reason=reason, author=CODERS[0], reviewer=CODERS[1], expires_on=VALID_UNTIL))


def declarations(slug: str, r: Dict[str, Any]) -> Dict[str, ConstraintDeclaration]:
    crit, sens, mtype = r["ai_criticality"], r["data_sensitivity"], r["model_type"]
    active = crit in ACTIVE
    out: Dict[str, ConstraintDeclaration] = {}

    def duty(cid: str, holds: bool, applies: bool, why_not: str) -> None:
        if holds:
            out[cid] = sat(slug, {"SC-DPIA-1": "an approved DPIA", "SC-HITL-1": "a formal oversight protocol", "SC-CHALL-1": "a documented right to explanation and challenge",
                                  "SC-LIAB-1": "a declared liability boundary", "SC-HALLU-1": "a confabulation-handling policy",
                                  "SC-MAP-1": "a fairness metric and an output-validation gate"}[cid])
        elif applies:
            out[cid] = unmet()
        else:
            out[cid] = not_applicable(why_not)

    duty("SC-HITL-1", bool(r["hitl_formally_specified"]), active, "advisory tier: the first model warned instead of blocking")
    duty("SC-CHALL-1", bool(r["right_to_challenge_documented"]), active, "advisory tier: the first model warned instead of blocking")
    duty("SC-LIAB-1", bool(r["liability_boundary_declared"]), active, "advisory tier: the first model warned instead of blocking")
    duty("SC-DPIA-1", bool(r["dpia_approved"]), sens == "SPECIAL_CATEGORY" and active,
         "the duty binds special-category data at operational tier or above" + ("" if sens == "SPECIAL_CATEGORY" else f"; this data is {sens}"))
    duty("SC-HALLU-1", bool(r["hallucination_constraint_declared"]), mtype == "LLM", f"the model is not generative ({mtype})")
    map_applies = (sens == "SPECIAL_CATEGORY" or crit in ("CRITICAL", "SAFETY_CRITICAL")) and active
    duty("SC-MAP-1", r.get("bias_metric") is not None and bool(r["output_validation_gate_configured"]), map_applies,
         "the duty binds special-category data or critical tiers at operational tier or above")
    out["SC-MC-1"] = sat(slug, "an approved model card") if r["model_card_approved"] else unmet()
    out["SC-TRAIN-1"] = sat(slug, "completed operator training") if r["operator_training_complete"] else unmet()
    out["SC-RCF-1"] = unmet() if r["trainer_is_validator"] else sat(slug, "trainer and validator held by different parties")
    out["SC-RCF-2"] = unmet() if r["validator_is_deployer"] else sat(slug, "validator and deployer held by different parties")
    out["SC-DOMAIN-1"] = sat(slug, "a declared domain rule") if r["domain_rule_declared"] else unmet()
    out["SC-CONSENT-1"] = sat(slug, f"a {r['data_consent'].lower()} consent basis") if r["data_consent"] in ("EXPLICIT", "CONTRACTUAL", "LEGITIMATE_INTEREST") else unmet()
    return out


def to_registry(case: Dict[str, Any], slug: str) -> RegistryBlock:
    r = case["registry"]
    rb = RegistryBlock()
    rb.deployment_context = DeploymentContext(model_type=r["model_type"], ai_criticality=r["ai_criticality"], data_sensitivity=r["data_sensitivity"], domain=r["deployment_name"])
    rb.org_size, rb.governance_maturity, rb.model_type, rb.system_type, rb.risk_tier = r["org_size"], r["governance_maturity"], r["model_type"], r["system_type"], r["risk_tier"]
    rb.feedback_loop, rb.data_consent, rb.data_sensitivity_enum, rb.ai_criticality_enum = r["feedback_loop"], r["data_consent"], r["data_sensitivity"], r["ai_criticality"]
    rb.experience_level, rb.confidence_signal, rb.risk_profile = r["experience_level"], r["confidence_signal"], r["risk_profile"]
    rb.silent_failure = (r.get("silent_failures") or [None])[0]
    rb.gap_scores, rb.compensating_controls = list(r.get("gap_scores") or []), r.get("compensating_controls", 0)
    rb.domain_rule_declared, rb.opaque_components, rb.total_components = r["domain_rule_declared"], r["opaque_components"], r["total_components"]
    rb.hallucination_constraint_declared = bool(r["hallucination_constraint_declared"])
    rb.active_constraints = [str(c) for c in (r.get("active_constraints") or [])]
    # The role-concentration flags are derived from who holds the roles (the old ids are organisations); the old flags say the same thing and are kept as stated.
    rb.trainer_is_validator, rb.validator_is_deployer, rb.trainer_is_deployer = r["trainer_is_validator"], r["validator_is_deployer"], r["trainer_is_deployer"]
    holders = {"trainer": r["trainer_id"], "validator": r["validator_id"], "deployer": r["deployer_id"], "operator": r["operator_id"], "consumer": r["consumer_id"]}
    depts: Dict[str, str] = {}
    for role, who in holders.items():
        dep = f"dep-{who}"
        depts.setdefault(dep, who)
        getattr(rb.actors, role).identity = who
        getattr(rb.actors, role).department_id = dep
    rb.departments = [Department(id=i, name=n) for i, n in depts.items()]
    rb.lifecycle = Lifecycle(**{k: v for k, v in r.items() if k in LIFECYCLE_FIELDS and v is not None})
    rb.governance_state.constraints_declared = declarations(slug, r)
    rb.governance_state.model_card_complete = bool(r["model_card_approved"])
    rb.governance_state.audit_trail_enabled = r.get("audit_frequency") not in (None, "NEVER")
    return rb


def remediated(case: Dict[str, Any]) -> Dict[str, Any]:
    """The same case with every control in place (what a remediated deployment would declare), the deployment facts unchanged: it shows what the score says on its own."""
    c = json.loads(json.dumps(case))
    r = c["registry"]
    for k in ("dpia_approved", "hitl_formally_specified", "right_to_challenge_documented", "liability_boundary_declared", "hallucination_constraint_declared", "model_card_approved",
              "operator_training_complete", "output_validation_gate_configured", "policy_hallucination_acknowledged", "hitl_verified_substantive"):
        r[k] = True
    r["bias_metric"] = "DEMOGRAPHIC_PARITY"
    r["trainer_is_validator"] = r["validator_is_deployer"] = r["trainer_is_deployer"] = False
    r["data_consent"] = "EXPLICIT"
    return c


_profile = {"name": None}


def _with_profile(inner):
    """The platform's registry_block_to_state leaves the registry's risk profile at BALANCED (found with this test); the first paper scored each case under its own profile, so
    the runner applies it for the comparison. The platform's code is not changed."""
    from framework.risk_profile import RiskProfileEnum

    def f(rb):
        rs = inner(rb)
        try:
            rs.risk_profile = RiskProfileEnum(rb.risk_profile)
        except ValueError:
            pass
        return rs
    return f


def run(cases_dir: str, out_dir: str, fix: bool = False, profile: bool = True, basis: str = "") -> List[Dict[str, Any]]:
    os.makedirs(os.path.join(out_dir, "registries"), exist_ok=True)
    if profile:
        import scoring_bridge
        scoring_bridge.registry_block_to_state = _with_profile(scoring_bridge.registry_block_to_state)
    rows: List[Dict[str, Any]] = []
    for path in sorted(glob.glob(os.path.join(cases_dir, "*.json"))):
        case = json.load(open(path, encoding="utf-8"))
        if fix:
            case = remediated(case)
        slug = os.path.basename(path)[:-5]
        rb = to_registry(case, slug)
        if basis:                                    # the policy of the paper's gate: the interval rule alone decides the risk criterion
            pol = P.normalise({"risk": {"basis": basis}})
            rb.st_ai = {"design_key": slug, "policy": pol}
        if not fix:
          with open(os.path.join(out_dir, "registries", f"{slug}.registry.json"), "w", encoding="utf-8") as f:
            json.dump(json.loads(rb.model_dump_json()), f, indent=2)
        res, _ = score_registry(rb)
        st = res.raw_breakdown["st_ai"]
        val, old = case["_validation"], case.get("derived", {})
        control = val["category"] == "control"
        truth = "APPROVED" if control else FAILURES_GROUND_TRUTH
        violated = [c["id"] if "id" in c else c.get("cid") for c in st["constraints"] if c["status"] == "VIOLATED"]
        rows.append({"case": slug, "category": val["category"], "ground_truth": truth, "pre_registered": val["predicted_gate"], "pcs": res.pcs_final, "tier": res.tier,
                     "legacy_gate": st["legacy_gate"], "gate": res.gate, "hard_violated": [v for v in violated if v in ("SC-DPIA-1", "SC-HITL-1", "SC-HALLU-1", "SC-MAP-1", "SC-CHALL-1", "SC-LIAB-1")],
                     "review_violated": [v for v in violated if v in ("SC-MC-1", "SC-TRAIN-1", "SC-RCF-1", "SC-RCF-2", "SC-DOMAIN-1", "SC-CONSENT-1")],
                     "blockers": st["blockers"], "fixture_pcs": old.get("pcs_score"), "fixture_gate": old.get("gate"),
                     "pillars": res.pillar_vector.model_dump() if getattr(res, "pillar_vector", None) is not None else None,
                     "match": (res.gate == "APPROVED") if control else (res.gate != "APPROVED"), "blocked_match": res.gate == truth})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cases_dir")
    ap.add_argument("--out", default="legacy-cases-out")
    ap.add_argument("--remediated", action="store_true", help="score the same cases with every control in place (counterfactual)")
    ap.add_argument("--basis", default="", choices=["", "legacy_until_intervals", "intervals"], help="risk basis of the policy; 'intervals' is the gate of the paper")
    ap.add_argument("--no-profile", action="store_true", help="leave the risk profile at the platform's BALANCED (what the platform does today)")
    a = ap.parse_args()
    rows = run(a.cases_dir, a.out, a.remediated, not a.no_profile, a.basis)
    json.dump({"date": date.today().isoformat(), "remediated": a.remediated, "rows": rows}, open(os.path.join(a.out, ("results_remediated" if a.remediated else "results") + ("_" + a.basis if a.basis else "") + ".json"), "w", encoding="utf-8"), indent=2, default=str)
    print(f"{'case':<28}{'truth':<10}{'PCS':>6} {'tier':<9}{'old gate':<17}{'v2.5 gate':<17}hard violated")
    for r in rows:
        print(f"{r['case']:<28}{r['ground_truth']:<10}{r['pcs']:>6} {r['tier']:<9}{r['legacy_gate']:<17}{r['gate']:<17}{','.join(r['hard_violated']) or '-'}")
    print(f"\nnot released when it should not be / approved when a control: {sum(r['match'] for r in rows)}/{len(rows)}; exactly the ground-truth gate: {sum(r['blocked_match'] for r in rows)}/{len(rows)}")
    return 0 if all(r["match"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
