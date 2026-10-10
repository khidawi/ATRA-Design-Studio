


"""
Translates a DesignStudio RegistryBlock → RegistryState,
calls the existing rule engine unchanged, returns PCSResultBlock.
"""
from datetime import datetime, timezone
from typing import List

from schema import RegistryBlock, PCSResultBlock, PillarVector

# -- framework imports (copied into backend/framework/) ----------------------
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from framework.registry import RegistryState
from framework.rule_engine import derive_terms
from framework.enums import (
    OrgSizeEnum, GovernanceMaturityEnum, ModelTypeEnum, AISystemTypeEnum,
    RiskTierEnum, FeedbackLoopEnum, DataConsentEnum, SensitivityEnum,
    ConstraintTypeEnum, SilentFailureEnum, ConfidenceSignalEnum,
    AICriticalityEnum, ExperienceLevelEnum, BudgetBandEnum,
    ConsumptionRoleEnum, AuditFrequencyEnum, GateDecisionEnum,
    ActionTierEnum, RollbackModeEnum, AIDependencyLevelEnum, DeploymentModeEnum,
    DriftTypeEnum, RootCauseEnum, BiasRiskLevelEnum, DecommissioningStatusEnum,
    DisposalMethodEnum,
)
from framework.incidents import (
    Incident, IncidentRegister, IncidentTypeEnum, IncidentStatusEnum, IncidentSeverityEnum,
)

# Mapping from string keys in the Design Studio schema → enum values.
# Only the fields that the front-end will realistically set are mapped here.
# Unknown strings fall back to the RegistryState defaults.

_ORG_SIZE = {e.value: e for e in OrgSizeEnum}
_GOV_MATURITY = {e.value: e for e in GovernanceMaturityEnum}
_MODEL_TYPE = {e.value: e for e in ModelTypeEnum}
_SYSTEM_TYPE = {e.value: e for e in AISystemTypeEnum}
_RISK_TIER = {e.value: e for e in RiskTierEnum}
_FEEDBACK = {e.value: e for e in FeedbackLoopEnum}
_CONSENT = {e.value: e for e in DataConsentEnum}
_SENSITIVITY = {e.value: e for e in SensitivityEnum}
_SILENT_FAILURE = {e.value: e for e in SilentFailureEnum}
_CONFIDENCE = {e.value: e for e in ConfidenceSignalEnum}
_AI_CRITICALITY = {e.value: e for e in AICriticalityEnum}
_EXPERIENCE = {e.value: e for e in ExperienceLevelEnum}
_CONSUMPTION = {e.value: e for e in ConsumptionRoleEnum}
_CONSTRAINT_TYPE = {e.value: e for e in ConstraintTypeEnum}


def _e(mapping: dict, value, default):
    if value is None:
        return default
    return mapping.get(str(value), default)


def _enum_map(enum_cls):
    return {e.value: e for e in enum_cls}


_LIFE_ENUMS = {
    "rollback_mode": _enum_map(RollbackModeEnum),
    "ai_dependency_level": _enum_map(AIDependencyLevelEnum),
    "deployment_mode": _enum_map(DeploymentModeEnum),
    "audit_frequency": _enum_map(AuditFrequencyEnum),
    "drift_type": _enum_map(DriftTypeEnum),
    "consumption_role": _enum_map(ConsumptionRoleEnum),
    "automation_bias_risk": _enum_map(BiasRiskLevelEnum),
    "decommissioning_status": _enum_map(DecommissioningStatusEnum),
    "disposal_method": _enum_map(DisposalMethodEnum),
}
_LIFE_FLAGS = (
    "model_card_approved", "fallback_procedure_exists", "fallback_tested",
    "drift_detected", "domain_violation_occurred", "bias_breach_detected", "quarantine_activated",
    "dpia_approved", "provider_sla_gdpr_dpa", "hitl_formally_specified",
    "policy_hallucination_acknowledged", "liability_boundary_declared", "right_to_challenge_documented",
    "output_validation_gate_configured", "hitl_verified_substantive", "operator_training_complete",
    "legal_hold_active", "post_retirement_verified",
)
_LIFE_COUNTS = ("hallucination_incident_count", "misuse_incident_count")
_INC_TYPES = _enum_map(IncidentTypeEnum)
_INC_STATUS = _enum_map(IncidentStatusEnum)


def _naive(dt):
    return dt.astimezone().replace(tzinfo=None) if dt is not None and dt.tzinfo else dt   # the framework compares against datetime.now()


def _apply_lifecycle(rs: RegistryState, rb: RegistryBlock) -> None:
    """Copy the stated lifecycle facts (layers 6-11) and the incident log into the state; unstated ones keep their defaults."""
    life = rb.lifecycle
    for name, table in _LIFE_ENUMS.items():
        v = getattr(life, name)
        if v is not None and str(v) in table:
            setattr(rs, name, table[str(v)])
    for name in _LIFE_FLAGS:
        v = getattr(life, name)
        if v is not None:
            setattr(rs, name, bool(v))
    for name in _LIFE_COUNTS:
        v = getattr(life, name)
        if v is not None:
            setattr(rs, name, max(0, int(v)))
    if life.conflict_resolution:
        rs.conflict_resolution = life.conflict_resolution
    if life.root_causes:
        rc = _enum_map(RootCauseEnum)
        rs.root_causes = [rc[r] for r in life.root_causes if r in rc]
    reg = IncidentRegister()
    for i in rb.incident_register:
        reg.incidents.append(Incident(
            incident_id=i.id,
            incident_type=_INC_TYPES.get(i.type, IncidentTypeEnum.MODEL_FAILURE),
            severity=IncidentSeverityEnum(i.severity),
            status=_INC_STATUS.get(i.status, IncidentStatusEnum.OPEN),
            occurred_at=_naive(i.occurred_at), detected_at=_naive(i.detected_at),
            mitigated_at=_naive(i.mitigated_at), resolved_at=_naive(i.resolved_at),
            title=i.title, description=i.description, root_cause=i.root_cause,
            lessons_learned=i.lessons_learned, owner=i.owner,
        ))
    rs.incident_register = reg


def registry_block_to_state(rb: RegistryBlock) -> RegistryState:
    """
    Map a DesignStudio RegistryBlock → the existing RegistryState dataclass.
    Only fields reachable from the canvas are mapped; everything else keeps
    its RegistryState default so scoring never crashes on a partial document.
    """
    dc = rb.deployment_context

    # Active constraint types
    active = [
        _e(_CONSTRAINT_TYPE, c, None)
        for c in (rb.active_constraints or [])
        if _e(_CONSTRAINT_TYPE, c, None) is not None
    ]

    # Role concentration flags
    trainer_is_validator  = rb.trainer_is_validator
    validator_is_deployer = rb.validator_is_deployer
    trainer_is_deployer   = rb.trainer_is_deployer

    # Gap scores
    gap_scores = list(rb.gap_scores or [])

    rs = RegistryState(
        org_size=_e(_ORG_SIZE, rb.org_size, OrgSizeEnum.SMALL),
        governance_maturity=_e(_GOV_MATURITY, rb.governance_maturity, GovernanceMaturityEnum.AD_HOC),
        budget_band=BudgetBandEnum.UNDER_10K,
        model_type=_e(_MODEL_TYPE, rb.model_type or dc.model_type, ModelTypeEnum.LLM),
        system_type=_e(_SYSTEM_TYPE, rb.system_type, AISystemTypeEnum.TYPE_1_INHOUSE),
        risk_tier=_e(_RISK_TIER, rb.risk_tier, RiskTierEnum.MEDIUM),
        ai_criticality=_e(_AI_CRITICALITY, rb.ai_criticality_enum or dc.ai_criticality, AICriticalityEnum.OPERATIONAL),
        experience_level=_e(_EXPERIENCE, rb.experience_level, ExperienceLevelEnum.SENIOR),
        feedback_loop=_e(_FEEDBACK, rb.feedback_loop, FeedbackLoopEnum.NONE),
        data_consent=_e(_CONSENT, rb.data_consent, DataConsentEnum.EXPLICIT),
        data_sensitivity=_e(_SENSITIVITY, rb.data_sensitivity_enum or dc.data_sensitivity, SensitivityEnum.INTERNAL),
        trainer_id=rb.actors.trainer.identity or "",
        validator_id=rb.actors.validator.identity or "",
        deployer_id=rb.actors.deployer.identity or "",
        operator_id=rb.actors.operator.identity or "",
        consumer_id=rb.actors.consumer.identity or "",
        trainer_is_validator=trainer_is_validator,
        validator_is_deployer=validator_is_deployer,
        trainer_is_deployer=trainer_is_deployer,
        gap_scores=gap_scores,
        compensating_controls=rb.compensating_controls,
        domain_rule_declared=rb.domain_rule_declared,
        opaque_components=rb.opaque_components,
        total_components=max(1, rb.total_components),
        hallucination_constraint_declared=rb.hallucination_constraint_declared,
        active_constraints=active,
        confidence_signal=_e(_CONFIDENCE, rb.confidence_signal, ConfidenceSignalEnum.QUALITATIVE),
        deployment_name=rb.deployment_context.domain or "",
    )

    _apply_lifecycle(rs, rb)

    # Post-init fields that RegistryState sets in __post_init__ —
    # we only override if the caller explicitly passed something.
    # (risk_profile, assessment_mode, incident_register set by __post_init__)

    return rs


def score_registry(rb: RegistryBlock) -> tuple[PCSResultBlock, list[str]]:
    """
    Run the full ST-AI engine against the given registry block.
    Returns (PCSResultBlock, warnings).
    """
    rs = registry_block_to_state(rb)
    dt = derive_terms(rs)

    warnings: List[str] = list(dt.warnings)

    # Unmet veto constraints from governance_state
    gs = rb.governance_state
    unmet_veto = [
        cid
        for cid, decl in gs.constraints_declared.items()
        if cid in {
            "SC-DPIA-1", "SC-HITL-1", "SC-HALLU-1",
            "SC-MAP-1", "SC-CHALL-1", "SC-LIAB-1",
        }
        and decl.status.value != "SATISFIED"
    ]

    # Gate override — if any veto constraint unmet, gate is always BLOCKED
    gate = dt.gate_decision.value if dt.gate_decision else "APPROVED"
    if unmet_veto:
        gate = "BLOCKED"

    # Pillar vector
    rv = dt.risk_vector
    pv = PillarVector()
    if rv:
        pv = PillarVector(
            likelihood=round(rv.likelihood, 2),
            severity=round(rv.severity, 2),
            vulnerability=round(rv.vulnerability, 2),
            uncertainty=round(rv.uncertainty, 2),
            autonomy=round(rv.autonomy, 2),
            evolution=round(rv.evolution, 2),
        )

    result = PCSResultBlock(
        pcs_mult=round(dt.pcs_score, 3),
        pcs_floor=None,
        pcs_final=round(dt.pcs_score, 3),
        tier=dt.tier.value if dt.tier else "LOW",
        gate=gate,
        pillar_vector=pv,
        unmet_veto_constraints=unmet_veto,
        last_scored_at=datetime.now(tz=timezone.utc),
        raw_breakdown={
            "L": dt.L, "I": dt.I, "delta": dt.delta, "tau": dt.tau,
            "Dm": dt.Dm, "Wr": dt.Wr, "Ws": dt.Ws, "Wf": dt.Wf, "Wh": dt.Wh,
            "rcf_adj": dt.rcf_adj, "eps_b": dt.eps_b, "eps_ia": dt.eps_ia,
            "blockers": dt.blockers,
            "warnings": list(dt.warnings),
            "recommendations": dt.recommendations,
            "derivation_log": dt.derivation_log,
            "risk_vector": {
                "composite": rv.composite if rv else None,
                "gate_blocked": bool(rv.gate_blocked) if rv else False,
                "blocking_dimension": rv.blocking_dimension if rv else "",
                "tiers": ({
                    "likelihood": rv.tier_likelihood.value, "severity": rv.tier_severity.value,
                    "vulnerability": rv.tier_vulnerability.value, "uncertainty": rv.tier_uncertainty.value,
                    "autonomy": rv.tier_autonomy.value, "evolution": rv.tier_evolution.value,
                    "composite": rv.tier_composite.value,
                } if rv else {}),
            },
        },
    )

    if dt.blockers:
        warnings.extend(dt.blockers)

    return result, warnings
