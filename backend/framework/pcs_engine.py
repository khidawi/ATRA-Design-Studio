"""
ST-AI PCS Engine v2
Full formula: PCS = (L×I×Δ/τ) × D_m × (Wr×Ws×Wf×Wh) × RCF_adj × (1 + ε_b + ε_ia)
Includes model type floor conditioning and organisational proportionality terms.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from framework.enums import (
    ActionTierEnum, ModelTypeEnum, AISystemTypeEnum, OrgSizeEnum,
    GovernanceMaturityEnum, GapSeverityEnum, CompliancePathEnum,
    ResidualRiskBandEnum, PCSBlockReasonEnum, SilentFailureEnum,
    PCS_TIER_THRESHOLDS, MODEL_TYPE_PCS_FLOOR, SYSTEM_TYPE_PCS_FLOOR, GAP_SCORE_MAP
)


@dataclass
class OrgProfile:
    size: OrgSizeEnum
    governance_maturity: GovernanceMaturityEnum
    rcf: float                    # Role Concentration Factor 1.0-3.0
    gap_scores: List[int]         # List of gap_score(c) values across all controls
    compensating_controls: int = 0  # number of active compensating control records


@dataclass
class ModelProfile:
    model_type: ModelTypeEnum
    system_type: AISystemTypeEnum
    silent_failure: Optional[SilentFailureEnum] = None
    feedback_loop_automated: bool = False
    domain_rule_declared: bool = True
    opaque_components: int = 0
    total_components: int = 1


@dataclass
class ThreatInputs:
    L: float   # Likelihood       [0.0, 1.0]
    I: float   # Impact           [1.0, 10.0]
    delta: float  # Exposure days
    tau: float    # Detection latency days (min floor 0.1)
    Dm: float     # Domain multiplier [1.0, 3.0]
    Wr: float = 1.0   # Retraining authority weight
    Ws: float = 1.0   # Deployment scale weight
    Wf: float = 1.0   # Feedback loop weight
    Wh: float = 1.0   # Human-autonomy coupling weight


@dataclass
class PCSResult:
    pcs_score: float
    tier: ActionTierEnum
    rcf_adj: float
    eps_ia: float
    eps_b: float
    pcs_floor_terms: dict
    breakdown: dict
    block_reasons: List[PCSBlockReasonEnum]
    compliance_path: CompliancePathEnum
    residual_risk_band: ResidualRiskBandEnum
    recommendations: List[str]


def compute_rcf_adj(rcf: float) -> float:
    """
    RCF_adj = 1 + (RCF - 1.0) × 0.15
    Range: ×1.00 (fully separated) to ×1.30 (fully consolidated)
    """
    rcf_clamped = max(1.0, min(3.0, rcf))
    return 1.0 + (rcf_clamped - 1.0) * 0.15


def compute_eps_ia(gap_scores: List[int]) -> float:
    """
    ε_ia = mean(gap_score(c)) / 6.0  ∈ [0.0, 0.5]
    gap_score ∈ {0=NONE, 1=ADVISORY, 2=SIGNIFICANT, 3=CRITICAL}
    Divisor 6.0 normalises max average of 3.0 to upper bound 0.5
    """
    if not gap_scores:
        return 0.0
    mean_gap = sum(gap_scores) / len(gap_scores)
    return min(0.5, mean_gap / 6.0)


def apply_model_type_floor(threat: ThreatInputs, model: ModelProfile) -> tuple:
    """
    Returns (eps_b, adjusted_threat, floor_notes) after applying
    model type and system type conditioning to the base threat inputs.
    """
    eps_b = 0.0
    notes = {}
    t = ThreatInputs(**threat.__dict__)  # copy

    eps_b_elevated, Wh_elevated, Wr_elevated, delta_extended = MODEL_TYPE_PCS_FLOOR.get(
        model.model_type, (False, False, False, False)
    )

    if eps_b_elevated:
        eps_b = 0.25
        notes["eps_b"] = f"Elevated by {model.model_type.value} architecture (hallucination normal failure mode)"

    if Wh_elevated:
        t.Wh = max(t.Wh, 1.5)
        notes["Wh"] = f"Elevated to ≥1.5 — human-autonomy coupling risk for {model.model_type.value}"

    if Wr_elevated:
        t.Wr = max(t.Wr, 1.4)
        notes["Wr"] = f"Elevated to ≥1.4 — retraining authority risk for {model.model_type.value}"

    if delta_extended and model.silent_failure in (SilentFailureEnum.BIAS_DRIFT, SilentFailureEnum.PERFORMANCE_DRIFT):
        multiplier = 30 if model.silent_failure == SilentFailureEnum.PERFORMANCE_DRIFT else 14
        t.delta = max(t.delta, multiplier)
        notes["delta"] = f"Extended to {t.delta} days — {model.silent_failure.value} silent accumulation"

    if model.model_type == ModelTypeEnum.PINN and not model.domain_rule_declared:
        notes["PINN_block"] = "BLOCKED: DomainRule not declared — D_m cannot be computed"

    # System type conditioning
    sys_floor = SYSTEM_TYPE_PCS_FLOOR[model.system_type]
    if sys_floor["I_elevated"]:
        t.I = max(t.I, t.I * 1.3)
        notes["I"] = f"Impact elevated 30% — {model.system_type.value} opacity"
    if sys_floor["Ws_elevated"]:
        t.Ws = max(t.Ws, 1.6)
        notes["Ws"] = "W_s elevated to ≥1.6 — Type 3 provider compromise propagates to all consumers"

    # Ensemble: W_s elevated by opaque component ratio
    if model.model_type in (ModelTypeEnum.ENSEMBLE, ModelTypeEnum.HYBRID) and model.total_components > 0:
        ratio = model.opaque_components / model.total_components
        t.Ws = max(t.Ws, 1.0 + ratio)
        notes["Ws_ensemble"] = f"W_s raised by opaque ratio {ratio:.2f} across {model.total_components} components"

    # AUTOMATED feedback loop for RL is a hard blocker
    if model.model_type == ModelTypeEnum.RL and model.feedback_loop_automated:
        notes["RL_blocker"] = "BLOCKER: AUTOMATED feedback loop from RL agent is a pre-deployment blocker"

    return eps_b, t, notes


def classify_tier(score: float) -> ActionTierEnum:
    """v8.1 four-tier classification on the PCS_100 scale.

    LOW       < 10
    MODERATE  10 -- 29
    HIGH      30 -- 59
    CRITICAL  >= 60   (auto-blocks)
    """
    if score >= 60: return ActionTierEnum.CRITICAL
    if score >= 30: return ActionTierEnum.HIGH
    if score >= 10: return ActionTierEnum.MODERATE
    return ActionTierEnum.LOW


def classify_residual_risk(delta: float) -> ResidualRiskBandEnum:
    if delta < 0.5:  return ResidualRiskBandEnum.NEGLIGIBLE
    if delta < 2.0:  return ResidualRiskBandEnum.LOW
    if delta < 5.0:  return ResidualRiskBandEnum.MEDIUM
    if delta < 10.0: return ResidualRiskBandEnum.HIGH
    return ResidualRiskBandEnum.UNACCEPTABLE


def compute_pcs(
    threat: ThreatInputs,
    org: OrgProfile,
    model: ModelProfile,
) -> PCSResult:
    """
    Full ST-AI PCS formula:
    PCS = (L × I × Δ / τ) × D_m × (Wr × Ws × Wf × Wh) × RCF_adj × (1 + ε_b + ε_ia)
    """
    # 1. Apply model type floor conditioning
    eps_b, t, floor_notes = apply_model_type_floor(threat, model)

    # 2. Organisational terms
    rcf_adj = compute_rcf_adj(org.rcf)
    eps_ia  = compute_eps_ia(org.gap_scores)

    # 3. Enforce tau floor
    tau = max(0.1, t.tau)

    # 4. Base formula
    silent_core    = (t.L * t.I * t.delta) / tau
    contextual     = t.Wr * t.Ws * t.Wf * t.Wh
    epistemic_term = 1.0 + eps_b + eps_ia

    pcs = silent_core * t.Dm * contextual * rcf_adj * epistemic_term

    # 5. Tier and block reasons
    tier = classify_tier(pcs)
    block_reasons = []

    if tier == ActionTierEnum.CRITICAL:
        block_reasons.append(PCSBlockReasonEnum.CRITICAL_THREAT)
    if org.rcf >= 2.5 and org.compensating_controls == 0:
        block_reasons.append(PCSBlockReasonEnum.UNCOMPENSATED_ROLE_CONCENTRATION)
    if any(g == 3 for g in org.gap_scores):
        block_reasons.append(PCSBlockReasonEnum.IMPORTANCE_GAP_CRITICAL)
    if model.model_type == ModelTypeEnum.PINN and not model.domain_rule_declared:
        block_reasons.append(PCSBlockReasonEnum.DOMAIN_VIOLATION)
    if model.model_type == ModelTypeEnum.RL and model.feedback_loop_automated:
        block_reasons.append(PCSBlockReasonEnum.CRITICAL_THREAT)

    # 6. Compliance path
    if block_reasons:
        if tier == ActionTierEnum.CRITICAL:
            compliance_path = CompliancePathEnum.NON_COMPLIANT_BLOCKED
        else:
            compliance_path = CompliancePathEnum.CONDITIONAL_DEPLOYMENT
    elif org.compensating_controls > 0:
        compliance_path = CompliancePathEnum.COMPENSATED_COMPLIANCE
    else:
        compliance_path = CompliancePathEnum.FULL_COMPLIANCE

    # 7. Residual risk band (from compensating controls delta proxy)
    residual = org.compensating_controls * 0.8
    residual_band = classify_residual_risk(residual)

    # 8. Recommendations
    recs = []
    if org.rcf > 2.0:
        recs.append(f"RCF={org.rcf:.1f} — implement role separation or add EXTERNAL_VALIDATOR compensating control")
    if eps_ia > 0.2:
        recs.append("High importance alignment gap — review under-prioritised controls before deployment")
    if tier in (ActionTierEnum.CRITICAL, ActionTierEnum.HIGH):
        recs.append("Remediate all block reasons before re-entering deployment gate")
    if model.system_type == AISystemTypeEnum.TYPE_3_THIRDPARTY_API:
        recs.append("Type 3 deployment: validate provider SLA with GDPR Art.28 DPA before SIGN stage")
    if model.model_type == ModelTypeEnum.LLM:
        recs.append("LLM: configure OutputValidationGate for all non-advisory consumption roles")
    if model.model_type == ModelTypeEnum.PINN and not model.domain_rule_declared:
        recs.append("PINN: declare DomainRule before Layer 5 scoring — D_m cannot be computed without it")

    breakdown = {
        "silent_core":    round(silent_core, 4),
        "Dm":             round(t.Dm, 4),
        "contextual":     round(contextual, 4),
        "rcf_adj":        round(rcf_adj, 4),
        "epistemic_term": round(epistemic_term, 4),
        "pcs_raw":        round(pcs, 4),
        "L": t.L, "I": round(t.I, 4),
        "delta": t.delta, "tau": tau,
        "Wr": t.Wr, "Ws": t.Ws, "Wf": t.Wf, "Wh": t.Wh,
        "eps_b": round(eps_b, 4),
        "eps_ia": round(eps_ia, 4),
    }

    return PCSResult(
        pcs_score=round(pcs, 3),
        tier=tier,
        rcf_adj=round(rcf_adj, 4),
        eps_ia=round(eps_ia, 4),
        eps_b=round(eps_b, 4),
        pcs_floor_terms=floor_notes,
        breakdown=breakdown,
        block_reasons=block_reasons,
        compliance_path=compliance_path,
        residual_risk_band=residual_band,
        recommendations=recs,
    )
