"""
ST-AI Design Studio — design-time compliance/risk engine (Task 1.3).

Given a RegistryBlock (the exact shape POST /score already consumes) and a
selected ComplianceDomain (Phase 0's compliance_schema.py), runs the
domain's regulation rules against the registry's existing
GovernanceState.constraints_declared — the one evidence-gate system
scoring_bridge.py already enforces for the PCS engine. New OWASP/EU AI
Act/GDPR-sourced checks are additional citations layered onto that same
gate, not a second, parallel pass/fail mechanism: every rule that maps to
a constraint_id is graded purely from that constraint's existing status.
A rule with no constraint mapping yet (nothing on the canvas evidences it)
comes back AMBER/unknown rather than being silently skipped or guessed at.

NOT_YET_DETERMINED is graded RED for a REQUIRED-severity rule — the same
"not explicitly satisfied with evidence = blocking" rule scoring_bridge.py
already applies to veto-class constraints — and AMBER for a RECOMMENDED
one, mirroring how modulating constraints don't block the PCS gate.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from compliance_schema import (
    ComplianceDomain,
    DesignRiskAssessment,
    ElementVerdict,
    RiskStatus,
    RuleSeverity,
    ScoreBreakdownEntry,
    get_domain,
)
from schema import ConstraintStatus, GovernanceState, RegistryBlock


class AssessRequest(BaseModel):
    domain: str
    registry: RegistryBlock
    # Optional constraint_id -> canvas node_id map, so a verdict can point
    # at the actual Constraint node on the canvas when one exists. Falls
    # back to the bare constraint_id (no real node to highlight) otherwise.
    constraint_node_ids: Dict[str, str] = Field(default_factory=dict)


def _constraint_verdict(
    governance: GovernanceState, constraint_id: str, severity: RuleSeverity
) -> Tuple[RiskStatus, str]:
    decl = governance.constraints_declared.get(constraint_id)

    if decl is None:
        status = RiskStatus.RED if severity == RuleSeverity.REQUIRED else RiskStatus.AMBER
        return status, f"Constraint {constraint_id} is not declared on the canvas."

    if decl.status == ConstraintStatus.SATISFIED:
        reason = f"Constraint {constraint_id} is satisfied"
        if decl.evidence:
            reason += f" — {decl.evidence}"
        return RiskStatus.GREEN, reason

    if decl.status == ConstraintStatus.UNMET:
        return RiskStatus.RED, f"Constraint {constraint_id} is explicitly marked Unmet."

    status = RiskStatus.RED if severity == RuleSeverity.REQUIRED else RiskStatus.AMBER
    return status, f"Constraint {constraint_id} is Not Yet Determined."


def _verdict_for_rule(
    rule, governance: GovernanceState, constraint_node_ids: Dict[str, str]
) -> ElementVerdict:
    citation = f"{rule.instrument} {rule.citation}".strip()

    if rule.maps_to_constraint_id is None:
        return ElementVerdict(
            node_id=rule.rule_id,
            status=RiskStatus.AMBER,
            reason=f"'{rule.title}' has no linked Security Constraint yet and cannot be auto-evaluated.",
            citation=citation,
            rule_id=rule.rule_id,
        )

    status, reason = _constraint_verdict(governance, rule.maps_to_constraint_id, rule.severity)
    node_id = constraint_node_ids.get(rule.maps_to_constraint_id, rule.maps_to_constraint_id)
    return ElementVerdict(
        node_id=node_id, status=status, reason=reason, citation=citation, rule_id=rule.rule_id,
    )


def assess_design(
    registry: RegistryBlock,
    domain_id: str,
    constraint_node_ids: Optional[Dict[str, str]] = None,
) -> DesignRiskAssessment:
    domain: Optional[ComplianceDomain] = get_domain(domain_id)
    if domain is None:
        raise ValueError(f"Unknown assessment domain: {domain_id!r}")
    constraint_node_ids = constraint_node_ids or {}

    verdicts: List[ElementVerdict] = [
        _verdict_for_rule(rule, registry.governance_state, constraint_node_ids)
        for rule in domain.rule_set
    ]

    breakdown: Dict[str, ScoreBreakdownEntry] = {}
    for rule, verdict in zip(domain.rule_set, verdicts):
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
        domain=domain_id,
        overall_status=overall,
        score_breakdown=list(breakdown.values()),
        element_verdicts=verdicts,
        assessed_at=datetime.now(tz=timezone.utc),
    )
