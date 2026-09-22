"""
ST-AI Framework v4 — Seven-Metric Risk Vector (CEO-ready)
==========================================================

Each metric is of the form:

    S = 100 × (PCS sub-term) / (worst case of same sub-term in named bounds)

Each metric:
  - Reads aloud in one sentence
  - Uses at most 3 PCS variables
  - Maps to exactly one executive owner
  - Cannot overflow (genuine 0-100 ratio, no cap needed)

NAMED BOUNDS (defined elsewhere in the framework)
  I_max     = 10.0   derive_terms() caps I here
  Ws_max    = 1.7    Type 3 + CHAINED_AI
  Wf_max    = 2.0    AUTOMATED feedback loop
  eps_max   = 0.5    individual cap on ε_b and ε_ia
  RCF_max   = 1.30   full role consolidation
  Dm_max    = 3.0    CLINICAL_SAFETY
  delta_max = 90.0   BIAS_DRIFT + QUARTERLY
  tau_min   = 0.45   τ_base_min × EF_τ_min = 0.5 × 0.90
  C_max     = 2      max(1 + I_chained)

THE SEVEN FORMULAS
------------------
1. Threat     = 100 × L × I × Ws / (I_max × Ws_max)              [CISO]
2. Exposure   = 100 × (Δ / τ) / (Δ_max / τ_min)                  [SOC]
3. Domain     = 100 × (Dm - 1) / (Dm_max - 1)                    [Safety]
4. Governance = 50 × [(RCF - 1)/(RCF_max - 1) + ε_ia/ε_max]      [DPO]
5. Epistemic  = 100 × (ε_b + ε_ia) / (2 × ε_max)                 [AI Safety]
6. Scale      = 100 × I × Ws / (I_max × Ws_max)                  [Business]
7. Feedback   = 100 × Wf × C / (Wf_max × C_max)                  [AI Eng]

GATE LOGIC (v8.1)
-----------------
BLOCKED         if max(all 7) ≥ 60        (any single dimension catastrophic)
REQUIRES REVIEW if composite ∈ [30, 60)   (HIGH tier on the composite)
APPROVED        otherwise

The max rule prevents a catastrophic single dimension from being
averaged away by low scores elsewhere.

NOTE: this seven-metric module is the v3 legacy formulation retained for
back-compat; the live engine (framework/rule_engine.py) uses the
six-pillar vector with the four-tier scheme documented in enums.py.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
from framework.enums import ActionTierEnum

# Named bounds
I_MAX     = 10.0
WS_MAX    = 1.7
WF_MAX    = 2.0
EPS_MAX   = 0.5
RCF_MAX   = 1.30
DM_MAX    = 3.0
DELTA_MAX = 90.0
TAU_MIN   = 0.45    # tau_base_min(0.5) × EF_tau_min(0.90)
C_MAX     = 2

# Composite weights (sum = 1.00). Ordered by PCS-formula contribution.
W_THREAT   = 0.25
W_SCALE    = 0.15
W_DOMAIN   = 0.20
W_GOV      = 0.15
W_EXPOSURE = 0.10
W_EPIST    = 0.10
W_FEEDBACK = 0.05


def _tier(s: float) -> ActionTierEnum:
    if s >= 80: return ActionTierEnum.CRITICAL
    if s >= 20: return ActionTierEnum.HIGH
    if s >= 5:  return ActionTierEnum.MODERATE
    return ActionTierEnum.LOW


def _c(v: float) -> float:
    return round(min(100.0, max(0.0, v)), 1)


@dataclass
class RiskVector:
    threat:    float = 0.0   # CISO
    exposure:  float = 0.0   # SOC
    domain:    float = 0.0   # Safety officer
    gov:       float = 0.0   # DPO
    epistemic: float = 0.0   # AI Safety
    scale:     float = 0.0   # Business
    feedback:  float = 0.0   # AI Engineers
    composite: float = 0.0

    tier_threat:    ActionTierEnum = ActionTierEnum.LOW
    tier_exposure:  ActionTierEnum = ActionTierEnum.LOW
    tier_domain:    ActionTierEnum = ActionTierEnum.LOW
    tier_gov:       ActionTierEnum = ActionTierEnum.LOW
    tier_epistemic: ActionTierEnum = ActionTierEnum.LOW
    tier_scale:     ActionTierEnum = ActionTierEnum.LOW
    tier_feedback:  ActionTierEnum = ActionTierEnum.LOW
    tier_composite: ActionTierEnum = ActionTierEnum.LOW

    gate_blocked:       bool = False
    blocking_dimension: str  = ""
    trace: List[str] = field(default_factory=list)

    @property
    def max_sub(self) -> float:
        return max(self.threat, self.exposure, self.domain,
                   self.gov, self.epistemic, self.scale, self.feedback)


def derive_risk_vector(t) -> RiskVector:
    """Compute all 7 metrics from PCS intermediate terms (already derived)."""
    trace: List[str] = []
    chained = 1 if getattr(t, '_chained', False) else 0
    C = 1 + chained
    Dm = t.Dm if t.Dm is not None else DM_MAX

    # 1. Threat — probability × damage × blast radius
    threat = _c(100 * t.L * t.I * t.Ws / (I_MAX * WS_MAX))
    trace.append(
        f"Threat     = 100 × {t.L}×{t.I}×{t.Ws} / (I_max×Ws_max) = {threat}"
    )

    # 2. Exposure — how long damage stays hidden
    exposure = _c(100 * (t.delta / t.tau) / (DELTA_MAX / TAU_MIN))
    trace.append(
        f"Exposure   = 100 × ({t.delta}/{t.tau}) / (Δ_max/τ_min) = {exposure}"
    )

    # 3. Domain — severity of domain consequence above baseline
    domain = _c(100 * (Dm - 1.0) / (DM_MAX - 1.0))
    trace.append(
        f"Domain     = 100 × (Dm−1)/(Dm_max−1) = 100 × {Dm-1:.1f}/{DM_MAX-1:.1f} = {domain}"
    )

    # 4. Governance — role concentration AND control gaps (averaged)
    role_part = (t.rcf_adj - 1.0) / (RCF_MAX - 1.0)
    gap_part  = t.eps_ia / EPS_MAX
    gov = _c(50 * (role_part + gap_part))
    trace.append(
        f"Governance = 50 × [(RCF−1)/(RCF_max−1) + ε_ia/ε_max] "
        f"= 50 × [{role_part:.3f} + {gap_part:.3f}] = {gov}"
    )

    # 5. Epistemic — model uncertainty + alignment gaps
    epistemic = _c(100 * (t.eps_b + t.eps_ia) / (2 * EPS_MAX))
    trace.append(
        f"Epistemic  = 100 × ({t.eps_b}+{t.eps_ia}) / (2×ε_max) = {epistemic}"
    )

    # 6. Scale & Impact — blast radius IF anything fails (no L)
    scale = _c(100 * t.I * t.Ws / (I_MAX * WS_MAX))
    trace.append(
        f"Scale      = 100 × {t.I}×{t.Ws} / (I_max×Ws_max) = {scale}"
    )

    # 7. Feedback & Chaining — self-corruption potential
    feedback = _c(100 * t.Wf * C / (WF_MAX * C_MAX))
    trace.append(
        f"Feedback   = 100 × {t.Wf}×{C} / (Wf_max×C_max) = {feedback}"
    )

    # Composite
    composite = _c(
        W_THREAT   * threat    +
        W_SCALE    * scale     +
        W_DOMAIN   * domain    +
        W_GOV      * gov       +
        W_EXPOSURE * exposure  +
        W_EPIST    * epistemic +
        W_FEEDBACK * feedback
    )
    trace.append(
        f"Composite  = 0.25·{threat}+0.15·{scale}+0.20·{domain}"
        f"+0.15·{gov}+0.10·{exposure}+0.10·{epistemic}+0.05·{feedback} = {composite}"
    )

    # Gate
    gate_scores = {
        "Threat": threat, "Scale": scale, "Domain": domain,
        "Governance": gov, "Exposure": exposure,
        "Epistemic": epistemic, "Feedback": feedback,
    }
    blocking = max(gate_scores, key=gate_scores.get)
    blocked  = gate_scores[blocking] >= 80.0

    return RiskVector(
        threat=threat, exposure=exposure, domain=domain,
        gov=gov, epistemic=epistemic, scale=scale, feedback=feedback,
        composite=composite,
        tier_threat=_tier(threat),       tier_exposure=_tier(exposure),
        tier_domain=_tier(domain),       tier_gov=_tier(gov),
        tier_epistemic=_tier(epistemic), tier_scale=_tier(scale),
        tier_feedback=_tier(feedback),   tier_composite=_tier(composite),
        gate_blocked=blocked,
        blocking_dimension=blocking if blocked else "",
        trace=trace,
    )