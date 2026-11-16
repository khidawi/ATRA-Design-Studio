"""
Bridge from the platform's registry to the ST-AI v2.5 gate (st_ai_gate.py).

scoring_bridge.py calls gate_for_registry() with the legacy PCS outcome and takes the gate from here. Until the interval rule is wired to real tolerances and
intervals, the legacy PCS outcome stands in for the quantitative criterion ("legacy_pcs"): its BLOCKED is a blocked criterion, its REQUIRES_REVIEW an overlap that a
review can resolve. So the new gate is never more lenient than the old one on risk, and adds what the old one did not have: UNKNOWN applicability, review-class
shortfalls, non-applicability rationales, well-formedness (INVALID_MODEL) and the rule that a review resolves only what a review can resolve.

Set ST_AI_GATE=legacy to get the old gate back unchanged (rollback switch).
"""
import os
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Tuple

import st_ai_gate as G
import st_ai_policy as P
from schema import MODULATING_CLASS_CONSTRAINTS, VETO_CLASS_CONSTRAINTS, evidence_expired, is_placeholder_evidence


def enabled() -> bool:
    return os.environ.get("ST_AI_GATE", "v25").strip().lower() != "legacy"


# Role separation is a fact about who holds the roles, not something to take on trust: these constraints cannot be SATISFIED while the same person holds both roles.
SEPARATION = {"SC-RCF-1": ("trainer", "validator"), "SC-RCF-2": ("validator", "deployer")}


def role_separation_violated(rb, cid: str) -> bool:
    pair = SEPARATION.get(cid)
    if pair is None:
        return False
    a, b = (getattr(rb.actors, r).identity for r in pair)
    return G.independent(a, b, G.LEVEL_PERSON) == G.F


def constraint_inputs(rb, today: Optional[date] = None) -> List[G.ConstraintInput]:
    """Every declared constraint as a gate input. Satisfied needs evidence that is not a placeholder and has not expired; an unmet constraint is violated; anything
    else is unknown. A constraint declared not applicable counts as such only with a valid rationale."""
    out: List[G.ConstraintInput] = []
    for cid, decl in sorted(rb.governance_state.constraints_declared.items()):
        klass = G.HARD if cid in VETO_CLASS_CONSTRAINTS else G.REVIEW
        app_raw = G.APP_TRUE if decl.applicable is None or decl.applicable else G.APP_FALSE
        na = decl.not_applicable
        valid = bool(na) and G.rationale_valid(na.reason, na.author, na.reviewer, na.expires_on, today)
        status = decl.status.value
        if status == "UNMET":
            sat = G.VIOLATED
        elif status == "SATISFIED" and not is_placeholder_evidence(decl.evidence) and not evidence_expired(decl, today):
            sat = G.SATISFIED
        else:
            sat = G.UNKNOWN
        if sat == G.SATISFIED and role_separation_violated(rb, cid):
            sat = G.VIOLATED                       # derived from who holds the roles, whatever the declaration says
        out.append(G.ConstraintInput(cid, klass, app_raw, valid, sat))
    return out


def legacy_view(rb, today: Optional[date] = None):
    """The registry as the legacy score engine should see it. The legacy engine knows nothing of applicability: a constraint it sees as unmet raises the score and blocks.
    A constraint whose applicability is not TRUE (validly not applicable, or applicability unknown) is judged by the v2.5 gate, so for the legacy score it is neutralised
    rather than counted as a failure; the v2.5 gate turns an unknown applicability into a review trigger that a review cannot clear."""
    from schema import ConstraintDeclaration, ConstraintStatus
    inputs = {c.cid: c for c in constraint_inputs(rb, today)}
    decls = dict(rb.governance_state.constraints_declared)
    changed = False
    for cid, c in inputs.items():
        if c.app != G.APP_TRUE:
            decls[cid] = ConstraintDeclaration(status=ConstraintStatus.SATISFIED, evidence="Applicability is judged by the ST-AI v2.5 gate; see the gate details of this assessment.")
            changed = True
    if not changed:
        return rb
    gs = rb.governance_state.model_copy(update={"constraints_declared": decls})
    return rb.model_copy(update={"governance_state": gs})


def wf_problems_from_design_graph(design_graph: Any) -> List[str]:
    """Well-formedness problems of the rule graph the request carries (a DesignGraphIn, or None when the caller sent none)."""
    if design_graph is None:
        return []
    nodes = [{"id": n.id} for n in design_graph.nodes]
    edges = [{"id": f"{e.from_id}>{e.to_id}", "from_id": e.from_id, "to_id": e.to_id, "label": e.label} for e in design_graph.edges]
    return G.well_formed_graph({"nodes": nodes, "edges": edges})


def policy_of(rb) -> Tuple[Dict[str, Any], Optional[str]]:
    """The policy in force and the saved design's key, as the server set them on the registry (defaults when it did not)."""
    ctx = rb.st_ai or {}
    raw = ctx.get("policy") or {}
    pol = P.normalise(raw)
    pol["number"] = raw.get("number")
    return pol, ctx.get("design_key")


def applicability_state(decl, today: Optional[date] = None) -> Tuple[str, str]:
    """('TRUE' | 'NA' | 'UNKNOWN', reason) for one declared constraint, by the rule of the model: a declared not-applicable needs a valid rationale."""
    if decl.applicable is None or decl.applicable:
        return "TRUE", ""
    na = decl.not_applicable
    if na is not None and G.rationale_valid(na.reason, na.author, na.reviewer, na.expires_on, today):
        return "NA", f"{na.reason.strip()} (reviewed by {na.reviewer.strip()}, until {na.expires_on.isoformat()})"
    return "UNKNOWN", "declared not applicable without a valid rationale (a reason, an author, a different reviewer and an expiry that has not passed)"


def risk_inputs(rb, policy: Dict[str, Any], design_key: Optional[str], today: Optional[date] = None) -> Tuple[List[G.RiskInput], List[G.UnquantifiedInput]]:
    """The design's risk criteria against the tolerances allocated to it by the policy, by the interval rule."""
    risks: List[G.RiskInput] = []
    for i, c in enumerate(rb.risk.criteria, 1):
        pair = lambda iv: None if iv is None else (iv.lower, iv.upper)             # noqa: E731
        metric = c.metric if c.metric in P.METRICS else "R"
        rid = f"{c.id or i} ({c.dimension}, {'expected harm' if metric == 'R' else 'severe-event probability'})"
        risks.append(G.criterion_state(G.CriterionIn(rid, P.tolerance_for(policy, design_key, c.dimension, metric), pair(c.evidenced), c.evidenced_valid_until, pair(c.bounded)), today))
    unq = [G.UnquantifiedInput(u.dimension, u.assessment if u.assessment in ("none", "noQA", "ACC", "UNACC") else "noQA", bool(u.hard)) for u in rb.risk.unquantified]
    return risks, unq


def prohibited_conditions(legacy_blockers: Sequence[str]) -> List[str]:
    """The legacy engine's blockers that are conditions in their own right (an automated feedback loop on an RL agent, an unknown legal basis for personal data, an unresolved
    critical incident). Left out: the score-tier blockers and the SC- constraint messages, which the interval rule and the constraint statuses now decide."""
    out = []
    for b in legacy_blockers:
        t = str(b).lstrip("❌⚠️ ").strip()
        if str(b).startswith("❌ PCS =") or str(b).startswith("❌ SC-") or t.startswith("PCS ="):
            continue
        out.append(t)
    return out


def gate_for_registry(rb, legacy_gate: str, legacy_tier: str = "", wf_problems: Sequence[str] = (), today: Optional[date] = None,
                      legacy_blockers: Sequence[str] = ()) -> Tuple[str, Optional[Dict[str, Any]]]:
    """(the gate to use, the details for the response). With ST_AI_GATE=legacy the legacy gate comes back and the details are None.

    The quantitative criterion is the interval rule over the design's risk criteria and the tolerances the policy allocates to it. Under the basis "legacy_until_intervals" a
    design that states no criteria is still judged by the legacy score (its outcome stands in for the criterion); under "intervals" the legacy score is not consulted at all and a
    design without criteria or tolerances is unresolved, which a review cannot clear."""
    if not enabled():
        return legacy_gate, None
    policy, design_key = policy_of(rb)
    cons = constraint_inputs(rb, today)
    risks, unq = risk_inputs(rb, policy, design_key, today)
    basis = policy["risk"]["basis"]
    prohibited: List[str] = []
    if risks or basis == "intervals":
        used = "intervals"
        prohibited = prohibited_conditions(legacy_blockers)
        if not risks:
            risks = [G.RiskInput("risk_assessment", "unresolved", "no risk criteria are recorded for this design, so nothing can be compared with a tolerance")]
    else:
        used = "legacy_pcs"
        state = {"BLOCKED": "block", "REQUIRES_REVIEW": "overlap"}.get(legacy_gate, "pass")
        risks = [G.RiskInput("legacy_pcs", state, f"the legacy score gate is {legacy_gate} (tier {legacy_tier or 'n/a'}); this design states no risk intervals")]
    res = G.evaluate_gate(cons, risks, prohibited, unq, wf_problems)
    detail = res.as_dict()
    detail.update({
        "risk_basis": used, "policy_basis": basis, "policy_number": policy.get("number"), "legacy_gate": legacy_gate, "releasable_with_review": res.releasable(),
        "risks": [{"id": r.rid, "state": r.state, "detail": r.detail} for r in risks],
        "constraints": [{"id": c.cid, "class": c.klass, "applicability": c.app, "status": c.status} for c in cons],
    })
    return res.result, detail
