"""
ST-AI Design Studio — design-time compliance/risk engine (Tasks 1.3, 1.5 and 3).

Given a RegistryBlock (the exact shape POST /score already consumes) and a
ComplianceDomain (its approved rules, read from PostgreSQL by regulations.py),
grades every rule. How a rule is graded depends on its check_type:

  CONSTRAINT   graded purely from the Security Constraint it names — the one
               evidence-gate system scoring_bridge.py already enforces for the
               PCS engine. NOT_YET_DETERMINED is RED for a REQUIRED rule (the
               same "not explicitly satisfied with evidence = blocking" rule the
               PCS gate applies to veto constraints) and AMBER for a RECOMMENDED
               one. A constraint rule with no constraint named is AMBER.
  ATTESTATION  satisfied by a Regulatory requirement node for the rule's
               regulation and clause, marked Satisfied WITH evidence. Marked
               Satisfied without evidence does not count.
  GRAPH        a data-driven condition on the design itself (rule_checks.py).
               A rule that does not apply to this design is left out entirely
               rather than shown as a pass.

The engine is a pure function: it never reads the database and never calls a
model. compile_design() (Task 1.5) never trusts a client-supplied assessment —
it always re-runs assess_design() itself and gates on that, so the "refuses
unless all-green" rule holds even against a direct API call that skips
/assess entirely or lies about the result.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from compliance_schema import (
    ComplianceDomain,
    CompiledContract,
    ContractStatus,
    DesignGraphIn,
    DesignRiskAssessment,
    ElementVerdict,
    RegulationRule,
    RiskStatus,
    RuleSeverity,
    ScoreBreakdownEntry,
    assert_compilable,
    compute_contract_hash,
)
from rule_checks import CheckConfigError, DesignGraph, GEdge, GNode, evaluate_graph_rule
from schema import ConstraintStatus, GovernanceState, RegistryBlock


class AssessRequest(BaseModel):
    domain: str
    registry: RegistryBlock
    # Optional constraint_id -> canvas node_id map, so a verdict can point
    # at the actual Constraint node on the canvas when one exists. Falls
    # back to the bare constraint_id (no real node to highlight) otherwise.
    constraint_node_ids: Dict[str, str] = Field(default_factory=dict)
    # The design itself, for GRAPH rules. Without it those rules come back AMBER.
    design_graph: Optional[DesignGraphIn] = None


class CompileRequest(BaseModel):
    domain: str
    registry: RegistryBlock
    # Raw nodes/edges, recorded as-is into the contract's design_snapshot —
    # intentionally untyped (not GraphBlock) since this is an audit record,
    # not something re-parsed.
    graph: Dict[str, Any] = Field(default_factory=dict)
    constraint_node_ids: Dict[str, str] = Field(default_factory=dict)
    design_graph: Optional[DesignGraphIn] = None
    issued_by: Optional[str] = None


def to_design_graph(graph: Optional[DesignGraphIn]) -> Optional[DesignGraph]:
    if graph is None:
        return None
    return DesignGraph(
        nodes=[GNode(n.id, n.type, dict(n.props), n.primary) for n in graph.nodes],
        edges=[GEdge(e.from_id, e.to_id, e.label) for e in graph.edges],
    )


def _citation(rule: RegulationRule) -> str:
    return rule.citation_label or f"{rule.instrument} {rule.citation}".strip()


def _severity_status(severity: RuleSeverity) -> RiskStatus:
    return RiskStatus.RED if severity == RuleSeverity.REQUIRED else RiskStatus.AMBER


# ── CONSTRAINT ──────────────────────────────────────────────────────────────

def _constraint_verdict(
    governance: GovernanceState, constraint_id: str, severity: RuleSeverity
) -> Tuple[RiskStatus, str]:
    decl = governance.constraints_declared.get(constraint_id)

    if decl is None:
        return _severity_status(severity), f"Constraint {constraint_id} is not declared on the canvas."

    if decl.status == ConstraintStatus.SATISFIED:
        reason = f"Constraint {constraint_id} is satisfied"
        if decl.evidence:
            reason += f" — {decl.evidence}"
        return RiskStatus.GREEN, reason

    if decl.status == ConstraintStatus.UNMET:
        return RiskStatus.RED, f"Constraint {constraint_id} is explicitly marked Unmet."

    return _severity_status(severity), f"Constraint {constraint_id} is Not Yet Determined."


# ── ATTESTATION ─────────────────────────────────────────────────────────────

def _norm(text: Optional[str]) -> str:
    return " ".join((text or "").lower().split())


def _attestation_verdict(rule: RegulationRule, registry: RegistryBlock) -> Tuple[RiskStatus, str, str]:
    """(status, reason, node_id) — node_id is the matching requirement node when there is one."""
    label = f"{rule.instrument} {rule.citation}".strip()
    match = next(
        (r for r in registry.regulatory_requirements
         if _norm(r.instrument) == _norm(rule.instrument) and _norm(r.clause) == _norm(rule.citation)),
        None,
    )
    pending = _severity_status(rule.severity)
    if match is None:
        return (
            pending,
            f"No Regulatory requirement for {label} in the design yet. Add one and attach evidence to attest it.",
            rule.rule_id,
        )
    if match.status == ConstraintStatus.SATISFIED:
        if (match.evidence or "").strip():
            return RiskStatus.GREEN, f"{label} is attested — {match.evidence.strip()}", match.id
        return pending, f"{label} is marked Satisfied but has no evidence recorded.", match.id
    if match.status == ConstraintStatus.UNMET:
        return RiskStatus.RED, f"{label} is explicitly marked Unmet.", match.id
    return pending, f"{label} is Not Yet Determined.", match.id


# ── GRAPH ───────────────────────────────────────────────────────────────────

def _graph_verdict(rule: RegulationRule, graph: Optional[DesignGraph]) -> Optional[ElementVerdict]:
    citation = _citation(rule)
    if graph is None:
        return ElementVerdict(
            node_id=rule.rule_id, status=RiskStatus.AMBER, citation=citation, rule_id=rule.rule_id,
            reason=f"'{rule.title}' checks the design's structure and needs the design graph, which wasn't sent.",
        )
    try:
        outcome = evaluate_graph_rule(graph, rule.check_config, _severity_status(rule.severity).value)
    except CheckConfigError as exc:
        return ElementVerdict(
            node_id=rule.rule_id, status=RiskStatus.AMBER, citation=citation, rule_id=rule.rule_id,
            reason=f"'{rule.title}' has an invalid check and could not be evaluated: {exc}",
        )
    if outcome.status == "NOT_APPLICABLE":
        return None
    return ElementVerdict(
        node_id=outcome.flagged[0] if outcome.flagged else rule.rule_id,
        status=RiskStatus(outcome.status), reason=outcome.message, citation=citation,
        rule_id=rule.rule_id, flagged_node_ids=outcome.flagged,
    )


# ── one rule -> one verdict ─────────────────────────────────────────────────

def _verdict_for_rule(
    rule: RegulationRule,
    registry: RegistryBlock,
    constraint_node_ids: Dict[str, str],
    graph: Optional[DesignGraph],
) -> Optional[ElementVerdict]:
    citation = _citation(rule)

    if rule.check_type == "GRAPH":
        return _graph_verdict(rule, graph)

    if rule.check_type == "ATTESTATION":
        status, reason, node_id = _attestation_verdict(rule, registry)
        return ElementVerdict(node_id=node_id, status=status, reason=reason, citation=citation, rule_id=rule.rule_id)

    if rule.maps_to_constraint_id is None:
        return ElementVerdict(
            node_id=rule.rule_id,
            status=RiskStatus.AMBER,
            reason=f"'{rule.title}' has no linked Security Constraint yet and cannot be auto-evaluated.",
            citation=citation,
            rule_id=rule.rule_id,
        )

    status, reason = _constraint_verdict(registry.governance_state, rule.maps_to_constraint_id, rule.severity)
    node_id = constraint_node_ids.get(rule.maps_to_constraint_id, rule.maps_to_constraint_id)
    return ElementVerdict(
        node_id=node_id, status=status, reason=reason, citation=citation, rule_id=rule.rule_id,
    )


def assess_design(
    registry: RegistryBlock,
    domain: ComplianceDomain,
    constraint_node_ids: Optional[Dict[str, str]] = None,
    graph: Optional[DesignGraph] = None,
) -> DesignRiskAssessment:
    """Pure function of the registry, the design graph and the domain's approved rules
    (read from the database by regulations.py) — the engine never knows where the rules
    came from."""
    constraint_node_ids = constraint_node_ids or {}

    graded: List[Tuple[RegulationRule, ElementVerdict]] = []
    for rule in domain.rule_set:
        verdict = _verdict_for_rule(rule, registry, constraint_node_ids, graph)
        if verdict is not None:  # a GRAPH rule that doesn't apply to this design is left out
            graded.append((rule, verdict))
    verdicts: List[ElementVerdict] = [v for _, v in graded]

    breakdown: Dict[str, ScoreBreakdownEntry] = {}
    for rule, verdict in graded:
        entry = breakdown.setdefault(
            rule.instrument, ScoreBreakdownEntry(category=rule.instrument, status=RiskStatus.GREEN)
        )
        if verdict.status == RiskStatus.RED:
            entry.failed += 1
        elif verdict.status == RiskStatus.AMBER:
            entry.unknown += 1
        else:
            entry.passed += 1

    for entry in breakdown.values():
        if entry.failed:
            entry.status = RiskStatus.RED
        elif entry.unknown:
            entry.status = RiskStatus.AMBER
        else:
            entry.status = RiskStatus.GREEN

    if any(v.status == RiskStatus.RED for v in verdicts):
        overall = RiskStatus.RED
    elif any(v.status == RiskStatus.AMBER for v in verdicts):
        overall = RiskStatus.AMBER
    else:
        overall = RiskStatus.GREEN

    return DesignRiskAssessment(
        domain=domain.domain_id,
        overall_status=overall,
        score_breakdown=list(breakdown.values()),
        element_verdicts=verdicts,
        assessed_at=datetime.now(tz=timezone.utc),
    )


def compile_design(
    registry: RegistryBlock,
    domain: ComplianceDomain,
    graph: Dict[str, Any],
    constraint_node_ids: Optional[Dict[str, str]],
    deployment_id: str,
    issued_by: Optional[str] = None,
    design_graph: Optional[DesignGraph] = None,
) -> CompiledContract:
    """
    Re-runs assess_design() (never trusts a caller-supplied assessment) and
    refuses — via assert_compilable(), raising ValueError — unless
    overall_status is GREEN, full stop. Only once that holds is the
    contract built and hashed.
    """
    assessment = assess_design(registry, domain, constraint_node_ids, design_graph)
    assert_compilable(assessment)

    contract = CompiledContract(
        contract_id=str(uuid.uuid4()),
        object_type="MODEL",
        deployment_id=deployment_id,
        domain=domain.domain_id,
        design_snapshot={
            "registry": registry.model_dump(mode="json"),
            "graph": graph,
        },
        risk_assessment=assessment,
        issued_at=datetime.now(tz=timezone.utc),
        issued_by=issued_by,
        status=ContractStatus.ACTIVE,
        contract_hash="",
    )
    contract.contract_hash = compute_contract_hash(contract)
    return contract
