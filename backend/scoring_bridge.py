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
    ActionTierEnum,
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
            "recommendations": dt.recommendations,
            "derivation_log": dt.derivation_log,
        },
    )

    if dt.blockers:
        warnings.extend(dt.blockers)

    return result, warnings
