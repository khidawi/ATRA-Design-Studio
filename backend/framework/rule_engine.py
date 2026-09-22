"""
ST-AI Framework v3 — Rule Engine
Derives ALL PCS formula terms deterministically from RegistryState.
No numeric input from user. PCS is emergent from declared enum state.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from framework.enums import (
    ModelTypeEnum, AISystemTypeEnum, FeedbackLoopEnum,
    DataConsentEnum, VectorTypeEnum, InsiderRoleEnum, SilentFailureEnum,
    AuditFrequencyEnum, ConsumptionRoleEnum, ConfidenceSignalEnum,
    LawTypeEnum, PCSBlockReasonEnum, ActionTierEnum,
    CompliancePathEnum, ResidualRiskBandEnum, GateDecisionEnum,
    AIDependencyLevelEnum, RollbackModeEnum, BiasRiskLevelEnum,
    AICriticalityEnum, ExperienceLevelEnum, SensitivityEnum,
    ACM_TABLE, EF_TABLE, ACM_MAX,
)
from framework.registry import RegistryState


@dataclass
class RiskVector:
    """Six-pillar risk vector — each pillar is 100 × (PCS sub-terms) / (max of same terms).

    Four textbook pillars (ISO 31000 / NIST SP 800-30):
       Likelihood, Severity, Vulnerability, Uncertainty
    Two AI-specific pillars (EU AI Act / NIST AI RMF):
       Autonomy, Evolution
    """
    likelihood:    float = 0.0
    severity:      float = 0.0
    vulnerability: float = 0.0
    uncertainty:   float = 0.0
    autonomy:      float = 0.0
    evolution:     float = 0.0
    composite:     float = 0.0
    # tier per pillar (for colouring breakdown)
    tier_likelihood:    ActionTierEnum = ActionTierEnum.LOW
    tier_severity:      ActionTierEnum = ActionTierEnum.LOW
    tier_vulnerability: ActionTierEnum = ActionTierEnum.LOW
    tier_uncertainty:   ActionTierEnum = ActionTierEnum.LOW
    tier_autonomy:      ActionTierEnum = ActionTierEnum.LOW
    tier_evolution:     ActionTierEnum = ActionTierEnum.LOW
    tier_composite:     ActionTierEnum = ActionTierEnum.LOW
    gate_blocked:       bool = False
    blocking_dimension: str  = ""
    trace: List[str] = field(default_factory=list)

    @property
    def max_sub(self) -> float:
        return max(self.likelihood, self.severity, self.vulnerability,
                   self.uncertainty, self.autonomy, self.evolution)


@dataclass
class DerivedTerms:
    """All PCS formula terms — never user-entered, always derived."""
    L: float = 0.3
    I: float = 4.0
    delta: float = 1.0
    tau: float = 7.0
    Dm: Optional[float] = 1.0     # None = PINN without DomainRule → hard block
    Wr: float = 1.0
    Ws: float = 1.0
    Wf: float = 1.0
    Wh: float = 1.0
    rcf_adj: float = 1.0
    eps_b: float = 0.0
    eps_ia: float = 0.0
    # v4 — upstream factors retained for downstream pillar formulas
    acm: float = 1.0
    pcs_score: float = 0.0
    tier: ActionTierEnum = ActionTierEnum.LOW
    block_reasons: List[PCSBlockReasonEnum] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    derivation_log: List[str] = field(default_factory=list)
    compliance_path: CompliancePathEnum = CompliancePathEnum.FULL_COMPLIANCE
    residual_risk_band: ResidualRiskBandEnum = ResidualRiskBandEnum.NEGLIGIBLE
    gate_decision: GateDecisionEnum = GateDecisionEnum.APPROVED
    recommendations: List[str] = field(default_factory=list)
    # v4 — six-pillar risk vector
    risk_vector: Optional[RiskVector] = None
    # v5 — version stamp for reproducibility
    framework_version: str = ""


def derive_terms(reg: RegistryState) -> DerivedTerms:
    """
    Master rule engine. Converts RegistryState → DerivedTerms.
    Called automatically whenever registry state changes.
    """
    t = DerivedTerms()
    log = t.derivation_log
    blocks = t.blockers
    warns = t.warnings
    recs = t.recommendations

    # ══════════════════════════════════════════════════════════════════
    # v4 UPSTREAM FACTORS — ACM and EF look-ups
    # These reshape I, Wh, τ before pillar formulas run.
    # ══════════════════════════════════════════════════════════════════
    acm, s_base = ACM_TABLE.get(reg.ai_criticality, (1.3, 20))
    ef_I_mult, ef_Wh_add, ef_tau_mult = EF_TABLE.get(
        reg.experience_level, (1.00, 0.00, 1.00)
    )
    t.acm = acm
    log.append(
        f"ACM = {acm} ({reg.ai_criticality.value}) · S_base = {s_base}"
    )
    log.append(
        f"EF triple = (I×{ef_I_mult}, Wh+{ef_Wh_add}, τ×{ef_tau_mult}) "
        f"for {reg.experience_level.value}"
    )

    # ══════════════════════════════════════════════════════════════════
    # L — Likelihood
    # Base from attack surface, raised by structural risk conditions
    # ══════════════════════════════════════════════════════════════════
    L = 0.3
    log.append(f"L base = {L} (baseline)")

    if VectorTypeEnum.CHAINED_AI in reg.attack_vectors:
        L = max(L, 0.70)
        log.append("L → 0.70: CHAINED_AI vector declared")

    if VectorTypeEnum.SUPPLY_CHAIN in reg.attack_vectors:
        L = max(L, 0.55)
        log.append("L → 0.55: SUPPLY_CHAIN vector declared")

    if InsiderRoleEnum.DATA_ENGINEER in reg.insider_roles:
        L = max(L, 0.55)
        log.append("L → 0.55: DATA_ENGINEER insider role declared")

    if reg.feedback_loop == FeedbackLoopEnum.AUTOMATED:
        L = max(L, 0.65)
        log.append("L → 0.65: AUTOMATED feedback loop")

    if reg.data_consent in (DataConsentEnum.NONE, DataConsentEnum.UNKNOWN):
        L = max(L, 0.60)
        log.append(f"L → 0.60: data consent = {reg.data_consent.value}")

    if reg.misuse_incident_count > 0:
        delta_L = min(0.30, reg.misuse_incident_count * 0.05)
        L = min(1.0, L + delta_L)
        log.append(f"L +{delta_L:.2f}: {reg.misuse_incident_count} misuse incidents (Layer 10)")

    if reg.drift_detected:
        L = min(1.0, L + 0.10)
        log.append("L +0.10: runtime drift detected (Layer 7)")

    if reg.domain_violation_occurred:
        L = min(1.0, L + 0.15)
        log.append("L +0.15: domain violation at runtime (Layer 7)")

    if not reg.dpia_approved:
        L = min(1.0, L + 0.05)
        log.append("L +0.05: DPIA not approved (Layer 8 gap)")

    t.L = round(L, 3)

    # ══════════════════════════════════════════════════════════════════
    # I — Impact
    # Base from deployment architecture type, raised by consumption role
    # ══════════════════════════════════════════════════════════════════
    I = {
        AISystemTypeEnum.TYPE_1_INHOUSE:        3.5,
        AISystemTypeEnum.TYPE_2_FINETUNED:      5.0,
        AISystemTypeEnum.TYPE_3_THIRDPARTY_API: 7.0,
    }[reg.system_type]
    log.append(f"I base = {I}: system_type = {reg.system_type.value}")

    if reg.consumption_role == ConsumptionRoleEnum.AUTOMATED_EXECUTOR:
        I *= 1.30
        log.append(f"I ×1.30: AUTOMATED_EXECUTOR consumption role")
    elif reg.consumption_role == ConsumptionRoleEnum.REGULATOR_SUBMITTER:
        I *= 1.25
        log.append(f"I ×1.25: REGULATOR_SUBMITTER consumption role")
    elif reg.consumption_role == ConsumptionRoleEnum.DECISION_MAKER:
        I *= 1.10
        log.append(f"I ×1.10: DECISION_MAKER consumption role")

    if not reg.dpia_approved:
        I *= 1.10
        log.append("I ×1.10: DPIA not approved (Layer 8)")

    if not reg.liability_boundary_declared:
        I += 0.15
        log.append("I +0.15: liability boundary undeclared — unmanaged consequence scope (Layer 8)")

    if not reg.right_to_challenge_documented and \
            reg.consumption_role.value in ("DECISION_MAKER","AUTOMATED_EXECUTOR","REGULATOR_SUBMITTER"):
        I = min(10.0, I + 0.10)
        log.append("I +0.10: right to challenge not documented for decision-making role (Layer 8)")

    if not reg.hitl_formally_specified:
        I *= 1.08
        log.append("I ×1.08: HumanInLoop not formally specified (Layer 8)")

    if reg.governance_maturity.value == "AD_HOC":
        I *= 1.10
        log.append("I ×1.10: governance maturity = AD_HOC")

    if reg.bias_breach_detected:
        I *= 1.15
        log.append("I ×1.15: bias breach detected at runtime (Layer 7)")

    # v4: experience factor on impact
    if ef_I_mult != 1.0:
        I *= ef_I_mult
        log.append(f"I ×{ef_I_mult}: experience level = {reg.experience_level.value}")

    t.I = round(min(10.0, I), 3)

    # ══════════════════════════════════════════════════════════════════
    # Δ — Exposure duration (days)
    # Derived from silent failure type + audit frequency
    # ══════════════════════════════════════════════════════════════════
    DELTA_MAP = {
        SilentFailureEnum.PERFORMANCE_DRIFT: {
            AuditFrequencyEnum.CONTINUOUS: 1,
            AuditFrequencyEnum.DAILY:      1,
            AuditFrequencyEnum.WEEKLY:     7,
            AuditFrequencyEnum.QUARTERLY:  90,
        },
        SilentFailureEnum.BIAS_DRIFT: {
            AuditFrequencyEnum.CONTINUOUS: 1,
            AuditFrequencyEnum.DAILY:      1,
            AuditFrequencyEnum.WEEKLY:     14,
            AuditFrequencyEnum.QUARTERLY:  90,
        },
        SilentFailureEnum.DATA_LEAK: {
            AuditFrequencyEnum.CONTINUOUS: 1,
            AuditFrequencyEnum.DAILY:      1,
            AuditFrequencyEnum.WEEKLY:     1,
            AuditFrequencyEnum.QUARTERLY:  1,
        },
    }

    if reg.silent_failures:
        delta = max(
            DELTA_MAP.get(sf, {}).get(reg.audit_frequency, 7)
            for sf in reg.silent_failures
        )
        log.append(
            f"Δ = {delta} days: silent failures "
            f"{[sf.value for sf in reg.silent_failures]} + {reg.audit_frequency.value} audit"
        )
    else:
        delta = 1
        log.append("Δ = 1 day: no silent failure declared")

    if reg.drift_detected:
        delta = max(delta, 14)
        log.append(f"Δ → max({delta}, 14): runtime drift detected")

    if reg.misuse_incident_count > 2:
        delta = int(delta * 1.5)
        log.append(f"Δ ×1.5: recurrent misuse incidents (Layer 10)")

    t.delta = float(delta)

    # ══════════════════════════════════════════════════════════════════
    # τ — Detection latency (days), floor = 0.1
    # Derived from audit frequency
    # ══════════════════════════════════════════════════════════════════
    TAU_MAP = {
        AuditFrequencyEnum.CONTINUOUS: 0.5,
        AuditFrequencyEnum.DAILY:      1.0,
        AuditFrequencyEnum.WEEKLY:     7.0,
        AuditFrequencyEnum.QUARTERLY:  90.0,
    }
    tau_base = TAU_MAP[reg.audit_frequency]
    t.tau = max(0.1, round(tau_base * ef_tau_mult, 2))
    log.append(
        f"τ = {tau_base} × EF({ef_tau_mult}) = {t.tau} days "
        f"({reg.audit_frequency.value} · {reg.experience_level.value})"
    )

    # ══════════════════════════════════════════════════════════════════
    # D_m — Domain law multiplier
    # None = PINN without DomainRule → gate blocked
    # ══════════════════════════════════════════════════════════════════
    if reg.domain_law is None:
        if reg.model_type == ModelTypeEnum.PINN:
            t.Dm = None
            blocks.append(
                "❌ PINN without a declared DomainRule — D_m cannot be computed. "
                "Register a DomainRule at Layer 1 before PCS can be calculated."
            )
            t.block_reasons.append(PCSBlockReasonEnum.PINN_NO_DOMAIN_RULE)
            log.append("D_m = UNDEFINED: PINN without DomainRule → BLOCKER")
        else:
            t.Dm = 1.0
            log.append("D_m = 1.0: no domain law constraint")
    else:
        DM_MAP = {
            LawTypeEnum.PHYSICAL_LAW:         2.5,
            LawTypeEnum.CLINICAL_SAFETY:       3.0,
            LawTypeEnum.FINANCIAL_REGULATION:  2.0,
            LawTypeEnum.MEASUREMENT_STANDARD:  2.2,
            LawTypeEnum.DATA_PROTECTION:       1.8,
            LawTypeEnum.SECTOR_SPECIFIC:       1.5,
        }
        t.Dm = DM_MAP.get(reg.domain_law, 1.5)
        log.append(f"D_m = {t.Dm}: domain law = {reg.domain_law.value}")

        if reg.domain_violation_occurred:
            t.Dm = round(t.Dm * 1.5, 2)
            log.append(f"D_m ×1.5 → {t.Dm}: domain violation at runtime")

    # ══════════════════════════════════════════════════════════════════
    # W_r — Retraining authority weight
    # ══════════════════════════════════════════════════════════════════
    Wr = 1.0
    if reg.rcf >= 1.15:
        Wr = max(Wr, 1.3)
        log.append(f"W_r -> 1.3: RCF = x{reg.rcf:.2f} (role consolidation)")
    if reg.model_type == ModelTypeEnum.RL:
        Wr = max(Wr, 1.4)
        log.append("W_r → 1.4: RL model — reward signal attack surface")
    if VectorTypeEnum.CHAINED_AI in reg.attack_vectors:
        Wr = max(Wr, 1.5)
        log.append("W_r → 1.5: CHAINED_AI vector declared")
    t.Wr = round(Wr, 3)

    # ══════════════════════════════════════════════════════════════════
    # W_s — Deployment scale weight
    # ══════════════════════════════════════════════════════════════════
    Ws = {
        AISystemTypeEnum.TYPE_1_INHOUSE:        1.0,
        AISystemTypeEnum.TYPE_2_FINETUNED:      1.2,
        AISystemTypeEnum.TYPE_3_THIRDPARTY_API: 1.6,
    }[reg.system_type]
    log.append(f"W_s base = {Ws}: {reg.system_type.value}")

    if VectorTypeEnum.CHAINED_AI in reg.attack_vectors:
        Ws = max(Ws, 1.7)
        log.append("W_s → 1.7: CHAINED_AI vector")

    if reg.model_type in (ModelTypeEnum.ENSEMBLE, ModelTypeEnum.HYBRID) \
            and reg.total_components > 0:
        ratio = reg.opaque_components / reg.total_components
        Ws = max(Ws, 1.0 + ratio)
        log.append(f"W_s adjusted for {ratio:.2f} opacity ratio (ensemble)")

    t.Ws = round(Ws, 3)

    # ══════════════════════════════════════════════════════════════════
    # W_f — Feedback loop amplification
    # ══════════════════════════════════════════════════════════════════
    WF_MAP = {
        FeedbackLoopEnum.NONE:           1.0,
        FeedbackLoopEnum.HUMAN_REVIEWED: 1.3,
        FeedbackLoopEnum.AUTOMATED:      2.0,
    }
    t.Wf = WF_MAP[reg.feedback_loop]
    log.append(f"W_f = {t.Wf}: feedback loop = {reg.feedback_loop.value}")

    # ══════════════════════════════════════════════════════════════════
    # W_h — Human-autonomy coupling
    # ══════════════════════════════════════════════════════════════════
    Wh = 1.0
    if reg.model_type == ModelTypeEnum.LLM:
        Wh = max(Wh, 1.5)
        log.append("W_h → 1.5: LLM architecture")
    if reg.model_type == ModelTypeEnum.RL:
        Wh = max(Wh, 1.4)

    if reg.consumption_role in (
        ConsumptionRoleEnum.AUTOMATED_EXECUTOR,
        ConsumptionRoleEnum.REGULATOR_SUBMITTER,
    ):
        Wh = max(Wh, 1.6)
        log.append(f"W_h → 1.6: {reg.consumption_role.value}")

    if not reg.hitl_formally_specified:
        Wh = max(Wh, 1.4)
        log.append("W_h → 1.4: HumanInLoop not specified")

    if not reg.policy_hallucination_acknowledged:
        Wh = max(Wh, 1.3)
        log.append("W_h → 1.3: hallucination not acknowledged in policy")

    if reg.misuse_incident_count > 0:
        Wh = min(2.5, Wh + reg.misuse_incident_count * 0.10)
        log.append(f"W_h +{reg.misuse_incident_count * 0.10:.2f}: misuse accumulation (Layer 10)")

    if reg.automation_bias_risk == BiasRiskLevelEnum.CRITICAL:
        Wh = min(2.5, Wh + 0.3)
        log.append("W_h +0.30: CRITICAL automation bias risk (Layer 10)")
    elif reg.automation_bias_risk and reg.automation_bias_risk.value == "HIGH":
        Wh = min(2.5, Wh + 0.2)
        log.append("W_h +0.20: HIGH automation bias risk (Layer 10)")
    elif reg.automation_bias_risk and reg.automation_bias_risk.value == "MEDIUM":
        Wh = min(2.5, Wh + 0.1)
        log.append("W_h +0.10: MEDIUM automation bias risk (Layer 10)")

    # ── Layer 10: operator training gap ──────────────────────────────
    # SC-TRAIN-1 (modulating-class) — feeds W_h, which lives in both
    # Vulnerability and Autonomy pillar formulas. Re-weighted from +0.10
    # to +0.20 so an unmet SC-TRAIN-1 visibly elevates its bound pillars.
    if not reg.operator_training_complete:
        Wh = min(2.5, Wh + 0.2)
        log.append("W_h +0.20: operator training not complete (SC-TRAIN-1, Layer 10)")

    # ── Layer 10: symbolic HITL ───────────────────────────────────────
    if not reg.hitl_verified_substantive:
        Wh = min(2.5, Wh + 0.2)
        log.append("W_h +0.20: HITL not verified as substantive — symbolic oversight (Layer 10)")

    # ── Layer 8: liability and hallucination policy gaps ─────────────
    if not reg.liability_boundary_declared:
        Wh = min(2.5, Wh + 0.1)
        log.append("W_h +0.10: liability boundary not declared (Layer 8)")

    if not reg.right_to_challenge_documented:
        Wh = min(2.5, Wh + 0.05)
        log.append("W_h +0.05: right to challenge not documented (Layer 8)")

    # ── Layer 9: hallucination constraint ────────────────────────────
    if not reg.hallucination_constraint_declared:
        Wh = min(2.5, Wh + 0.15)
        log.append("W_h +0.15: HallucinationConstraint not declared (Layer 9)")

    # v4: experience factor additive contribution to Wh
    if ef_Wh_add > 0:
        Wh = min(2.5, Wh + ef_Wh_add)
        log.append(
            f"W_h +{ef_Wh_add}: experience level = {reg.experience_level.value}"
        )

    t.Wh = round(min(2.5, Wh), 3)

    # ══════════════════════════════════════════════════════════════════
    # RCF — Role Concentration Factor (direct multiplier, no formula)
    # x1.00 = all roles separated   (no amplification)
    # x1.15 = two roles one person  (15% amplification)
    # x1.30 = all roles one person  (30% amplification)
    # ══════════════════════════════════════════════════════════════════
    t.rcf_adj = reg.rcf   # stored in rcf_adj field for formula compatibility
    RCF_LABELS = {1.00: "fully separated — no amplification",
                  1.15: "partial consolidation — 15% amplification",
                  1.30: "full consolidation — 30% amplification"}
    log.append(f"RCF = x{reg.rcf:.2f} ({RCF_LABELS.get(reg.rcf, '')})")

    if reg.rcf >= 1.30 and reg.compensating_controls == 0:
        blocks.append(
            "❌ All three lifecycle roles held by one person (RCF = x1.30). "
            "No compensating control record found. "
            "Add EXTERNAL_VALIDATOR or PEER_REVIEW compensating control."
        )
        t.block_reasons.append(PCSBlockReasonEnum.UNCOMPENSATED_ROLE_CONCENTRATION)

    # ══════════════════════════════════════════════════════════════════
    # ε_b — Epistemic uncertainty (from model type + runtime incidents)
    # ══════════════════════════════════════════════════════════════════
    EPS_B_BASE = {
        ModelTypeEnum.LLM:      0.25,
        ModelTypeEnum.RL:       0.15,
        ModelTypeEnum.ENSEMBLE: 0.20,
        ModelTypeEnum.HYBRID:   0.25,
        ModelTypeEnum.CNN:      0.05,
        ModelTypeEnum.PINN:     0.03,
        ModelTypeEnum.NN:       0.08,
    }
    eps_b = EPS_B_BASE[reg.model_type]
    log.append(f"ε_b base = {eps_b}: {reg.model_type.value} architecture")

    eps_b += reg.hallucination_incident_count * 0.03
    if reg.hallucination_incident_count > 0:
        log.append(f"ε_b +{reg.hallucination_incident_count * 0.03:.3f}: hallucination incidents (Layer 9)")

    if reg.confidence_signal == ConfidenceSignalEnum.NONE:
        eps_b += 0.05
        log.append("ε_b +0.05: no confidence signalling (Layer 3)")

    if not reg.output_validation_gate_configured:
        eps_b += 0.04
        log.append("ε_b +0.04: OutputValidationGate not configured (Layer 9)")

    # SC-MC-1 (model card) — MODULATING-class. Honours the pcs_term="eps_b"
    # binding declared in tropos_catalogue.py. An unapproved model card is
    # an epistemic / documentation gap, raising ε_b proportionately rather
    # than acting as a hard external blocker. Re-weighted to +0.15 so that
    # an unmet SC-MC-1 visibly elevates the Uncertainty pillar (per the
    # design decision: modulating-class constraints must be quantitatively
    # visible in their bound pillar, not just emit a warning).
    if not reg.model_card_approved:
        eps_b += 0.15
        log.append("ε_b +0.15: ModelCard not approved (SC-MC-1, Layer 8)")

    t.eps_b = round(min(_EPS_MAX, eps_b), 4)

    # ══════════════════════════════════════════════════════════════════
    # ε_ia — Importance alignment (from gap scores)
    # ══════════════════════════════════════════════════════════════════
    if reg.gap_scores:
        mean_gap = sum(reg.gap_scores) / len(reg.gap_scores)
        t.eps_ia = round(min(_EPS_MAX, mean_gap / 6.0), 4)
        log.append(f"ε_ia = {t.eps_ia:.4f}: mean gap score {mean_gap:.2f} / 6.0")
        if any(g == 3 for g in reg.gap_scores):
            blocks.append(
                "❌ CRITICAL importance gap detected — a control rated as NOT_RELEVANT "
                "when framework minimum is HIGH or CRITICAL. "
                "Resolve before deployment gate."
            )
            t.block_reasons.append(PCSBlockReasonEnum.IMPORTANCE_GAP_CRITICAL)
    else:
        t.eps_ia = 0.0
        log.append("ε_ia = 0.0: no control importance ratings provided")

    # ══════════════════════════════════════════════════════════════════
    # ADDITIONAL UNCONDITIONAL BLOCKERS
    # ══════════════════════════════════════════════════════════════════
    if reg.feedback_loop == FeedbackLoopEnum.AUTOMATED \
            and reg.model_type == ModelTypeEnum.RL:
        blocks.append(
            "❌ AUTOMATED feedback loop from RL agent. "
            "This is an unconditional pre-deployment blocker. "
            "Set FeedbackLoopEnum = HUMAN_REVIEWED."
        )
        t.block_reasons.append(PCSBlockReasonEnum.AUTOMATED_RL_FEEDBACK)

    if reg.data_consent in (DataConsentEnum.NONE, DataConsentEnum.UNKNOWN):
        blocks.append(
            f"❌ Data consent basis = {reg.data_consent.value}. "
            "UNKNOWN or NONE blocks deployment for any AI processing personal data. "
            "Establish legal basis before TRAIN stage."
        )
        t.block_reasons.append(PCSBlockReasonEnum.CONSENT_MISSING)

    if reg.system_type == AISystemTypeEnum.TYPE_3_THIRDPARTY_API \
            and not reg.provider_sla_gdpr_dpa:
        blocks.append(
            "❌ Type 3 deployment without a GDPR Article 28 Data Processing Agreement "
            "in the provider SLA. This blocks the SIGN stage unconditionally."
        )
        t.block_reasons.append(PCSBlockReasonEnum.TYPE3_NO_SLA)

    if not reg.signed_at_collection:
        blocks.append(
            "❌ Data not signed at collection (DataLineage.signed_at_collection = FALSE). "
            "This blocks the TRAIN stage."
        )

    # ══════════════════════════════════════════════════════════════════
    # COMPOSITE-GATE MANDATORY CONSTRAINTS (Option B — security
    # constraint enforcement with criticality gating)
    #
    # VETO-CLASS constraints (non-compensable). Six constraints from the
    # SC-catalogue (tropos_catalogue.py) map to mandatory pre-deployment
    # obligations in EU AI Act / GDPR. These encode legal *preconditions*,
    # not quantities of risk, so they are deliberately NOT folded into the
    # PCS score — a low score on other dimensions must never be allowed to
    # buy them off. Violating any of them at OPERATIONAL-or-higher
    # criticality is a hard blocker — the deployment cannot ship. At
    # ADVISORY criticality they remain warnings, since the regulatory bar
    # is lower for advisory-only systems.
    #
    # Note on legal precision: EU AI Act Art 14 (HITL) is strictly
    # mandatory only for High-Risk AI systems listed in Annex III.
    # This framework extends Art 14's spirit to any deployment at
    # OPERATIONAL criticality or higher as a proportionate
    # risk-stratification measure — not as a claim that Art 14 itself
    # mandates HITL at that threshold.
    #
    # Mandatory obligations (close the gate):
    #   SC-HITL-1   — EU AI Act Art 14 (mandatory human oversight for
    #                  High-Risk AI; framework extends to OPERATIONAL+)
    #   SC-DPIA-1   — GDPR Art 35 + EU AI Act Art 27 (pre-deployment
    #                  DPIA for special-category data)
    #   SC-CHALL-1  — GDPR Art 22 (right to contest automated decisions)
    #                  + EU AI Act Art 86 (right to explanation)
    #   SC-LIAB-1   — EU AI Act Art 25 (value-chain provider
    #                  re-classification thresholds documented)
    #   SC-HALLU-1  — EU AI Act Art 50 (transparency for generative AI)
    #                  + NIST AI 600-1 Confabulation (GAI risk category)
    #   SC-MAP-1    — NIST AI RMF MAP 3.x (sociotechnical context +
    #                  bias-proxy assessment for deployments affecting
    #                  protected groups or making safety/criticality-tier
    #                  decisions; v8.1)
    #
    # MODULATING-class constraints (compensable). These do NOT veto the
    # gate; instead each raises the PCS score through an existing PCS term,
    # so a sufficiently risky deployment still blocks via the PCS path:
    #   SC-MC-1    (model card)        → ε_b      (Uncertainty pillar)
    #   SC-TRAIN-1 (operator training) → W_h      (Vulnerability/Autonomy)
    #   SC-RCF-1/2 (role separation)   → RCF_adj  (Vulnerability pillar)
    # Their absence increases risk proportionately rather than imposing a
    # non-compensable legal veto. Their advisory warnings are still emitted
    # at their respective layers for transparency.
    # ══════════════════════════════════════════════════════════════════
    _crit_blocks_apply = reg.ai_criticality in (
        AICriticalityEnum.OPERATIONAL,
        AICriticalityEnum.CRITICAL,
        AICriticalityEnum.SAFETY_CRITICAL,
    )

    # ══════════════════════════════════════════════════════════════════
    # VETO-CLASS QUANTITATIVE PENALTIES
    #
    # Per the framework design decision: when a veto-class constraint is
    # unmet, the PCS and the affected pillar must reflect the violation
    # quantitatively — not only via the gate veto. Each unmet veto-class
    # constraint at OPERATIONAL+ criticality adds a penalty to its
    # NATURALLY BOUND pillar term, so the affected pillar visibly
    # elevates (typically into the red band) and the composite PCS rises
    # accordingly. The existing hard-block veto below still fires; the
    # quantitative penalty makes the violation visible in the score.
    #
    # Bindings (natural pillar mapping):
    #   SC-HITL-1   → ACM term      → Autonomy        (oversight gap)
    #   SC-CHALL-1  → ACM term      → Autonomy        (no contestability)
    #   SC-DPIA-1   → I  term       → Severity        (impact on subjects)
    #   SC-CONSENT-1→ I  term       → Severity        (unauthorised scope)
    #   SC-LIAB-1   → rcf_adj       → Vulnerability   (governance gap)
    #   SC-HALLU-1  → ε_b           → Uncertainty     (confabulation)
    #   SC-MAP-1    → ε_b           → Uncertainty     (bias-proxy gap)
    # ══════════════════════════════════════════════════════════════════
    if _crit_blocks_apply:
        # SC-HITL-1 → Autonomy (via ACM)
        if not reg.hitl_formally_specified:
            t.acm = min(ACM_MAX, t.acm + 2.0)
            log.append("ACM +2.0: SC-HITL-1 unmet — Autonomy elevated")

        # SC-CHALL-1 → Autonomy (via ACM)
        if not reg.right_to_challenge_documented:
            t.acm = min(ACM_MAX, t.acm + 1.5)
            log.append("ACM +1.5: SC-CHALL-1 unmet — Autonomy elevated")

        # SC-DPIA-1 → Severity (via I multiplier)
        if reg.data_sensitivity == SensitivityEnum.SPECIAL_CATEGORY \
                and not reg.dpia_approved:
            t.I = round(min(10.0, t.I * 1.5), 3)
            log.append("I ×1.5: SC-DPIA-1 unmet — Severity elevated")

        # SC-LIAB-1 → Vulnerability (via rcf_adj)
        if not reg.liability_boundary_declared:
            t.rcf_adj = min(_RCF_MAX, t.rcf_adj + 0.15)
            log.append("rcf_adj +0.15: SC-LIAB-1 unmet — Vulnerability elevated")

        # SC-HALLU-1 → Uncertainty (via ε_b)
        if reg.model_type in (ModelTypeEnum.LLM,) \
                and not reg.hallucination_constraint_declared:
            t.eps_b = round(min(_EPS_MAX, t.eps_b + 0.25), 4)
            log.append("ε_b +0.25: SC-HALLU-1 unmet — Uncertainty elevated")

        # SC-MAP-1 → Uncertainty (via ε_b)
        _map1_pen_applies = (
            reg.data_sensitivity == SensitivityEnum.SPECIAL_CATEGORY
            or reg.ai_criticality in (
                AICriticalityEnum.CRITICAL,
                AICriticalityEnum.SAFETY_CRITICAL,
            )
        )
        if _map1_pen_applies and (
            reg.bias_metric is None
            or not reg.output_validation_gate_configured
        ):
            t.eps_b = round(min(_EPS_MAX, t.eps_b + 0.20), 4)
            log.append("ε_b +0.20: SC-MAP-1 unmet — Uncertainty elevated")

    # SC-CONSENT-1 → Severity (via I multiplier) — applies at all
    # criticality tiers because the existing SC-CONSENT-1 hard block
    # itself fires unconditionally above (line 540), so its quantitative
    # contribution must match that scope.
    if not reg.signed_at_collection:
        t.I = round(min(10.0, t.I * 1.3), 3)
        log.append("I ×1.3: SC-CONSENT-1 unmet — Severity elevated")

    if _crit_blocks_apply:
        # SC-HITL-1 — EU AI Act Art 14 (High-Risk, Annex III) /
        #             NIST AI RMF GOVERN-3.2 / ISO/IEC 42001 §5.3
        if not reg.hitl_formally_specified:
            blocks.append(
                "❌ SC-HITL-1 — Human oversight protocol not formally specified. "
                f"At AI criticality = {reg.ai_criticality.value}, this framework "
                "requires a documented oversight protocol (EU AI Act Art 14 "
                "spirit, extended from High-Risk AI / Annex III to operational "
                "tier as a risk-stratification measure; NIST AI RMF GOVERN-3.2; "
                "ISO/IEC 42001 §5.3). "
                "Document which decisions require a human checkpoint, who acts "
                "as the checkpoint, and the override authority."
            )

        # SC-DPIA-1 — GDPR Art 35 / EU AI Act Art 27
        if reg.data_sensitivity == SensitivityEnum.SPECIAL_CATEGORY \
                and not reg.dpia_approved:
            blocks.append(
                "❌ SC-DPIA-1 — DPIA not approved for special-category data "
                "processing. Mandatory pre-deployment obligation under "
                "GDPR Art 35, EU AI Act Art 27, and ISO/IEC 29134. "
                "File the DPIA before the deployment gate can open."
            )

        # SC-CHALL-1 — GDPR Art 22 (right to contest) + EU AI Act Art 86
        #              (right to explanation)
        if not reg.right_to_challenge_documented:
            blocks.append(
                "❌ SC-CHALL-1 — Right to explanation and challenge not "
                f"documented. At AI criticality = {reg.ai_criticality.value}, "
                "the deployment must document both the explanation path "
                "(EU AI Act Art 86, for High-Risk AI under Annex III) and "
                "the contestability path (GDPR Art 22(3), for automated "
                "individual decision-making) with a named human reviewer "
                "and SLA."
            )

        # SC-LIAB-1 — EU AI Act Art 25 (value-chain accountability)
        if not reg.liability_boundary_declared:
            blocks.append(
                "❌ SC-LIAB-1 — Value-chain accountability boundary not "
                "declared. EU AI Act Art 25 governs when a distributor, "
                "importer, deployer or other third-party becomes a "
                "\"provider\" by re-branding, substantial modification, or "
                "change of intended purpose. Document the deployment's "
                "value-chain position and the thresholds that would trigger "
                "provider re-classification (Art 25, NIST AI RMF GOVERN-1.1). "
                "Civil tort liability is addressed separately by the "
                "(proposed) EU AI Liability Directive."
            )

        # SC-HALLU-1 — EU AI Act Art 50 (transparency for generative AI)
        #              + NIST AI 600-1 Confabulation
        if reg.model_type in (ModelTypeEnum.LLM,) \
                and not reg.hallucination_constraint_declared:
            blocks.append(
                "❌ SC-HALLU-1 — Confabulation-handling policy not declared "
                f"for generative model type = {reg.model_type.value}. "
                "EU AI Act Art 50 mandates transparency obligations for "
                "generative AI (including user disclosure that they are "
                "interacting with an AI). NIST AI 600-1 identifies "
                "\"confabulation\" (hallucination) as a primary GAI risk "
                "category. "
                "Declare a policy covering hallucination monitoring, "
                "end-user disclosure, and downstream safety guardrails."
            )

        # SC-MAP-1 — NIST AI RMF MAP function (sociotechnical context +
        #             bias-proxy assessment for deployments affecting
        #             protected groups or making safety-critical decisions).
        # Operationalises the failure mode catalogued by NIST as MAP 3.x:
        # a deployment that processes special-category data OR makes
        # safety-/criticality-tier decisions affecting people must have
        # (a) a declared fairness/bias metric AND
        # (b) an output-validation gate configured before deployment.
        # This is the constraint that the Optum / Obermeyer 2019 case
        # would have triggered — bias proxy unexamined, no output gate,
        # SPECIAL_CATEGORY data, SAFETY_CRITICAL criticality.
        _map1_applies = (
            reg.data_sensitivity == SensitivityEnum.SPECIAL_CATEGORY
            or reg.ai_criticality in (
                AICriticalityEnum.CRITICAL,
                AICriticalityEnum.SAFETY_CRITICAL,
            )
        )
        if _map1_applies and (
            reg.bias_metric is None
            or not reg.output_validation_gate_configured
        ):
            _gaps = []
            if reg.bias_metric is None:
                _gaps.append("no fairness/bias metric declared")
            if not reg.output_validation_gate_configured:
                _gaps.append("no OutputValidationGate configured")
            blocks.append(
                "❌ SC-MAP-1 — Pre-deployment fairness/bias-proxy "
                "assessment incomplete. "
                f"Triggers: data_sensitivity={reg.data_sensitivity.value}, "
                f"ai_criticality={reg.ai_criticality.value}; "
                f"gaps: {', '.join(_gaps)}. "
                "NIST AI RMF MAP 3.x requires that AI systems making "
                "consequential decisions about people, or processing "
                "special-category data, be evaluated for sociotechnical "
                "context and proxy-variable bias before deployment, with "
                "the assessment artefact (metric + validation gate) "
                "captured in the registry. This constraint complements "
                "SC-DPIA-1 (which covers data-protection impact under "
                "GDPR Art 35) by adding the fairness/proxy-bias dimension "
                "that NIST MAP catches but GDPR DPIA does not necessarily."
            )
            t.block_reasons.append(PCSBlockReasonEnum.MAP_VALIDATION_MISSING)
    else:
        # ADVISORY criticality — these constraints become warnings, not
        # blockers. The deployment can ship with documentation gaps but
        # the team is notified.
        if not reg.hitl_formally_specified:
            warns.append(
                "⚠️ SC-HITL-1 — HITL not formally specified (ADVISORY criticality; "
                "would block at OPERATIONAL+)."
            )
        if reg.data_sensitivity == SensitivityEnum.SPECIAL_CATEGORY \
                and not reg.dpia_approved:
            warns.append(
                "⚠️ SC-DPIA-1 — DPIA missing for special-category data "
                "(ADVISORY criticality; would block at OPERATIONAL+)."
            )

    # ── Layer 11: decommissioning governance ─────────────────────────
    if reg.decommissioning_status is not None:
        if reg.legal_hold_active and reg.disposal_method is None:
            blocks.append(
                "❌ Legal hold is active but no disposal method has been declared. "
                "Data cannot be deleted — document the legal hold basis and retention schedule."
            )
        if reg.decommissioning_status.value in ("WEIGHTS_DISPOSED", "DATA_DELETED", "AUDIT_COMPLETE") \
                and not reg.post_retirement_verified:
            warns.append(
                "⚠️ Decommissioning status claims completion but post-retirement verification "
                "has not been confirmed. Verify no live endpoints, no residual weights, "
                "and that audit trail is archived."
            )
        if reg.decommissioning_status.value == "IN_PROGRESS":
            warns.append(
                "⚠️ Decommissioning in progress — PCS remains active until AUDIT_COMPLETE. "
                "Ensure inference endpoints are shut down before weights are disposed."
            )

    # ── Layer 8: right-to-challenge gap warning ───────────────────────
    if not reg.right_to_challenge_documented and \
            reg.consumption_role.value in ("DECISION_MAKER", "AUTOMATED_EXECUTOR", "REGULATOR_SUBMITTER"):
        warns.append(
            "⚠️ Right to challenge AI decisions not documented (GDPR Art.22 / EU AI Act). "
            "Mandatory for decision-making consumption roles. Document the challenge path before deployment."
        )

    # ── Layer 8: ModelCard gate ───────────────────────────────────────
    if not reg.model_card_approved:
        warns.append(
            "⚠️ ModelCard not approved. Required before SIGN stage. "
            "Document training data, evaluation results, and known limitations."
        )

    # ══════════════════════════════════════════════════════════════════
    # PCS FORMULA
    # PCS = (L × I × Δ / τ) × D_m × (Wr × Ws × Wf × Wh) × RCF_adj × (1 + ε_b + ε_ia)
    # ══════════════════════════════════════════════════════════════════
    if t.Dm is None:
        t.pcs_score = 999.0  # undefined — gate blocks
        t.tier = ActionTierEnum.CRITICAL
    else:
        silent_core   = (t.L * t.I * t.delta) / t.tau
        contextual    = t.Wr * t.Ws * t.Wf * t.Wh
        epistemic     = 1.0 + t.eps_b + t.eps_ia
        raw           = silent_core * t.Dm * contextual * t.rcf_adj * epistemic
        # ── Normalise to 0-100 scale (k=4) ────────────────────────────
        t.pcs_score   = round(min(100.0, raw * 4.0), 1)

        # ══════════════════════════════════════════════════════════════
        # VETO-CLASS SEVERITY-WEIGHTED FLOOR
        #
        # The multiplicative composite can suppress to near-zero on
        # cases where a single input (notably Δ/τ on mature deployments,
        # or L on never-incidented systems) zeroes the product, even
        # when several mandatory legal preconditions are unmet. That
        # makes the composite an unreliable headline for cases where
        # veto-class constraints have failed.
        #
        # Per the framework design: when veto-class constraints are
        # unmet at OPERATIONAL+ criticality, the PCS composite must
        # reflect the regulatory failure quantitatively, not only via
        # the gate veto. The floor is severity-weighted so that the
        # heaviest legal obligations (DPIA, HITL, HALLU) dominate the
        # lighter ones (LIAB, CHALL). The base ensures any single
        # unmet veto immediately lands at HIGH minimum.
        #
        # Per-constraint weights reflect the underlying legal severity:
        #   SC-DPIA-1  (+25) — GDPR Art 35 (special-category processing)
        #   SC-HITL-1  (+20) — EU AI Act Art 14 (human oversight)
        #   SC-HALLU-1 (+20) — EU AI Act Art 50 + NIST GAI confabulation
        #   SC-MAP-1   (+18) — NIST AI RMF MAP 3.x (fairness/bias)
        #   SC-CHALL-1 (+15) — GDPR Art 22 (right to contest)
        #   SC-LIAB-1  (+12) — Governance/value-chain liability gap
        #
        # The floor only raises; never lowers. Cases where the
        # multiplicative composite already exceeds the floor (Optum 75,
        # Klarna 100, COMPAS 99.8) are untouched. Cases where the
        # composite suppresses but constraints fail (Air Canada, Apple
        # Card, Replika, Chevrolet) inherit the floor and land in the
        # CRITICAL band as the regulatory state demands.
        # ══════════════════════════════════════════════════════════════
        if _crit_blocks_apply:
            _veto_weights = 0
            if not reg.hitl_formally_specified:
                _veto_weights += 20
            if reg.data_sensitivity == SensitivityEnum.SPECIAL_CATEGORY \
                    and not reg.dpia_approved:
                _veto_weights += 25
            if not reg.right_to_challenge_documented:
                _veto_weights += 15
            if not reg.liability_boundary_declared:
                _veto_weights += 12
            if reg.model_type == ModelTypeEnum.LLM \
                    and not reg.hallucination_constraint_declared:
                _veto_weights += 20
            _map1_applies_floor = (
                reg.data_sensitivity == SensitivityEnum.SPECIAL_CATEGORY
                or reg.ai_criticality in (
                    AICriticalityEnum.CRITICAL,
                    AICriticalityEnum.SAFETY_CRITICAL,
                )
            )
            if _map1_applies_floor and (
                reg.bias_metric is None
                or not reg.output_validation_gate_configured
            ):
                _veto_weights += 18

            if _veto_weights > 0:
                _floor = min(100.0, 30.0 + _veto_weights)
                if _floor > t.pcs_score:
                    log.append(
                        f"PCS floored {t.pcs_score} → {_floor}: veto-class "
                        f"severity-weighted floor (base 30 + Σweights {_veto_weights})"
                    )
                    t.pcs_score = _floor

        # ── v8.1 four-tier scheme ─────────────────────────────────────
        # Tier boundaries: LOW<10 · MODERATE 10-29 · HIGH 30-59 · CRITICAL≥60
        # CRITICAL threshold lowered from 80 to 60 so that multi-factor
        # accumulation cases (Optum-class) auto-block via PCS path even
        # when no single mandatory constraint is the obvious driver.
        if   t.pcs_score >= 60: t.tier = ActionTierEnum.CRITICAL
        elif t.pcs_score >= 30: t.tier = ActionTierEnum.HIGH
        elif t.pcs_score >= 10: t.tier = ActionTierEnum.MODERATE
        else:                    t.tier = ActionTierEnum.LOW

        log.append(
            f"PCS_raw = ({t.L} × {t.I} × {t.delta} / {t.tau}) "
            f"× {t.Dm} × ({t.Wr}×{t.Ws}×{t.Wf}×{t.Wh}) "
            f"× RCF x{t.rcf_adj:.2f} × (1+{t.eps_b}+{t.eps_ia}) = {round(raw, 3)}"
        )
        log.append(
            f"PCS_100 = min(100, {round(raw, 3)} × 4) = {t.pcs_score} / 100"
        )

    if t.tier == ActionTierEnum.CRITICAL:
        blocks.append(
            f"❌ PCS = {t.pcs_score:.1f} / 100 — CRITICAL tier (≥60). "
            "Deployment is blocked unconditionally regardless of organisation size. "
            "Remediate the conditions below and recompute."
        )
        t.block_reasons.append(PCSBlockReasonEnum.CRITICAL_THREAT)
    elif t.tier == ActionTierEnum.HIGH:
        warns.append(
            f"⚠️ PCS = {t.pcs_score:.1f} / 100 — HIGH tier (≥30). "
            "Constrained deployment with structural constraint and "
            "executive sign-off required; enhanced monitoring mandatory."
        )

    # ══════════════════════════════════════════════════════════════════
    # COMPLIANCE PATH
    # ══════════════════════════════════════════════════════════════════
    if t.blockers:
        if t.tier == ActionTierEnum.CRITICAL:
            t.compliance_path = CompliancePathEnum.NON_COMPLIANT_BLOCKED
        else:
            t.compliance_path = CompliancePathEnum.CONDITIONAL_DEPLOYMENT
    elif reg.compensating_controls > 0:
        t.compliance_path = CompliancePathEnum.COMPENSATED_COMPLIANCE
    else:
        t.compliance_path = CompliancePathEnum.FULL_COMPLIANCE

    t.gate_decision = (
        GateDecisionEnum.BLOCKED if t.blockers else
        GateDecisionEnum.REQUIRES_REVIEW if t.warnings else
        GateDecisionEnum.APPROVED
    )

    # ══════════════════════════════════════════════════════════════════
    # RESIDUAL RISK BAND
    # ══════════════════════════════════════════════════════════════════
    residual = reg.compensating_controls * 0.8
    if   residual < 0.5:  t.residual_risk_band = ResidualRiskBandEnum.NEGLIGIBLE
    elif residual < 2.0:  t.residual_risk_band = ResidualRiskBandEnum.LOW
    elif residual < 5.0:  t.residual_risk_band = ResidualRiskBandEnum.MEDIUM
    elif residual < 10.0: t.residual_risk_band = ResidualRiskBandEnum.HIGH
    else:                  t.residual_risk_band = ResidualRiskBandEnum.UNACCEPTABLE

    # ══════════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════════
    _generate_recommendations(reg, t)

    # ══════════════════════════════════════════════════════════════════
    # v5 — INCIDENT FEEDBACK (NIST AI RMF MANAGE loop)
    # Open incidents and recurring patterns elevate L and ε_b.
    # ══════════════════════════════════════════════════════════════════
    try:
        from framework.incidents import (
            IncidentRegister, IncidentSeverityEnum, IncidentTypeEnum,
        )
        ir = getattr(reg, "incident_register", None)
        if ir is not None and isinstance(ir, IncidentRegister):
            # Severe-or-worse open incidents elevate Likelihood
            severe_open = ir.open_severe_or_worse()
            if severe_open:
                t.L = min(1.0, t.L + 0.10 * len(severe_open))
                log.append(
                    f"L +0.10×{len(severe_open)}: open severe/critical incidents"
                )
            # Recurring drift or bias-breach incidents in last 90d → ε_b
            for inc_type in (IncidentTypeEnum.DRIFT_DETECTION,
                             IncidentTypeEnum.BIAS_BREACH,
                             IncidentTypeEnum.HALLUCINATION_HARM):
                count = ir.recurring_in_window(inc_type, window_days=90)
                if count >= 3:
                    t.eps_b = min(_EPS_MAX, t.eps_b + 0.05)
                    log.append(
                        f"ε_b +0.05: ≥3 {inc_type.value} incidents in last 90 days"
                    )
            # Unresolved critical incidents over 72h → hard blocker
            stuck = ir.unresolved_critical_over_72h()
            if stuck:
                blocks.append(
                    f"❌ {len(stuck)} CRITICAL-severity incident(s) unresolved "
                    f"for over 72 hours — gate cannot open until they are "
                    f"resolved or formally accepted."
                )
    except (ImportError, AttributeError):
        pass

    # ══════════════════════════════════════════════════════════════════
    # v4 — SIX-PILLAR RISK VECTOR
    # Each pillar = 100 × (current PCS sub-product) / (max of same sub-product).
    # Anchored to ISO 31000, NIST SP 800-30, EU AI Act, NIST AI RMF.
    # ══════════════════════════════════════════════════════════════════
    t.risk_vector = _compute_risk_vector(reg, t)

    # ══════════════════════════════════════════════════════════════════
    # v5 — STAMP FRAMEWORK VERSION (reproducibility audit trail)
    # ══════════════════════════════════════════════════════════════════
    try:
        from framework import __version__
        t.framework_version = __version__
    except ImportError:
        t.framework_version = "unknown"

    return t


# ── Named bounds (PCS framework enum maxima and explicit caps) ────────
_I_MAX     = 10.0
_WS_MAX    = 1.7
_WR_MAX    = 1.5
_WF_MAX    = 2.0
_WH_MAX    = 2.5
_EPS_MAX   = 1.0
_RCF_MAX   = 1.30
_DM_MAX    = 3.0
_DELTA_MAX = 90.0
_TAU_MIN   = 0.45        # τ_base_min(0.5) × EF_τ_min(0.90)
_C_MAX     = 2           # max chaining (standalone=1, chained=2)


def _tier_for(score: float) -> ActionTierEnum:
    if score >= 60: return ActionTierEnum.CRITICAL
    if score >= 30: return ActionTierEnum.HIGH
    if score >= 10: return ActionTierEnum.MODERATE
    return ActionTierEnum.LOW


def _clip(v: float) -> float:
    return round(min(100.0, max(0.0, v)), 1)


def _compute_risk_vector(reg: RegistryState, t: DerivedTerms) -> RiskVector:
    """
    Six pillars, each pure ratio of PCS sub-terms to their named maxima:

      1. Likelihood    = 100 × L × Δ/τ     / (L_max × Δ_max/τ_min)
      2. Severity      = 100 × I × Ws × Dm / (I_max × Ws_max × Dm_max)
      3. Vulnerability = 100 × RCF × Wh × Wf × Wr / (max product)
      4. Uncertainty   = 100 × (ε_b + ε_ia) / (2 × ε_max)
      5. Autonomy      = 100 × ACM × Wh    / (ACM_max × Wh_max)
      6. Evolution     = 100 × Wf × C      / (Wf_max × C_max)
    """
    rv = RiskVector()

    # If Dm is undefined (PINN blocker) keep zero vector
    if t.Dm is None:
        rv.composite = 0.0
        return rv

    chained = 1 if VectorTypeEnum.CHAINED_AI in reg.attack_vectors else 0
    C = 1 + chained

    # 1. Likelihood
    like_raw = t.L * (t.delta / max(t.tau, 0.1))
    like_max = 1.0 * (_DELTA_MAX / _TAU_MIN)
    rv.likelihood = _clip(100 * like_raw / like_max)
    rv.trace.append(
        f"Likelihood    = 100 × L({t.L}) × Δ({t.delta})/τ({t.tau}) "
        f"/ (1×{_DELTA_MAX}/{_TAU_MIN}) = {rv.likelihood}"
    )

    # 2. Severity
    sev_raw = t.I * t.Ws * t.Dm
    sev_max = _I_MAX * _WS_MAX * _DM_MAX
    rv.severity = _clip(100 * sev_raw / sev_max)
    rv.trace.append(
        f"Severity      = 100 × I({t.I}) × Ws({t.Ws}) × Dm({t.Dm}) "
        f"/ ({_I_MAX}×{_WS_MAX}×{_DM_MAX}) = {rv.severity}"
    )

    # 3. Vulnerability
    vuln_raw = t.rcf_adj * t.Wh * t.Wf * t.Wr
    vuln_max = _RCF_MAX * _WH_MAX * _WF_MAX * _WR_MAX
    rv.vulnerability = _clip(100 * vuln_raw / vuln_max)
    rv.trace.append(
        f"Vulnerability = 100 × RCF({t.rcf_adj})·Wh({t.Wh})·Wf({t.Wf})·Wr({t.Wr}) "
        f"/ ({_RCF_MAX}×{_WH_MAX}×{_WF_MAX}×{_WR_MAX}) = {rv.vulnerability}"
    )

    # 4. Uncertainty
    uncert_raw = t.eps_b + t.eps_ia
    uncert_max = 2 * _EPS_MAX
    rv.uncertainty = _clip(100 * uncert_raw / uncert_max)
    rv.trace.append(
        f"Uncertainty   = 100 × (ε_b({t.eps_b}) + ε_ia({t.eps_ia})) "
        f"/ (2×{_EPS_MAX}) = {rv.uncertainty}"
    )

    # 5. Autonomy
    auto_raw = t.acm * t.Wh
    auto_max = ACM_MAX * _WH_MAX
    rv.autonomy = _clip(100 * auto_raw / auto_max)
    rv.trace.append(
        f"Autonomy      = 100 × ACM({t.acm}) × Wh({t.Wh}) "
        f"/ ({ACM_MAX}×{_WH_MAX}) = {rv.autonomy}"
    )

    # 6. Evolution
    evol_raw = t.Wf * C
    evol_max = _WF_MAX * _C_MAX
    rv.evolution = _clip(100 * evol_raw / evol_max)
    rv.trace.append(
        f"Evolution     = 100 × Wf({t.Wf}) × C({C}) "
        f"/ ({_WF_MAX}×{_C_MAX}) = {rv.evolution}"
    )

    # Composite — weights from the declared risk profile (or BALANCED default).
    # The profile is read from reg.risk_profile if present; otherwise BALANCED.
    try:
        from framework.risk_profile import RiskProfileEnum, get_weights
        _profile = getattr(reg, "risk_profile", RiskProfileEnum.BALANCED)
        w = get_weights(_profile)
        _profile_name = _profile.value
    except (ImportError, AttributeError):
        # Fallback to original spec weights
        w = {
            "Likelihood": 0.20, "Severity": 0.25, "Vulnerability": 0.20,
            "Uncertainty": 0.10, "Autonomy": 0.15, "Evolution": 0.10,
        }
        _profile_name = "BALANCED"

    composite = (
        w["Likelihood"]    * rv.likelihood    +
        w["Severity"]      * rv.severity      +
        w["Vulnerability"] * rv.vulnerability +
        w["Uncertainty"]   * rv.uncertainty   +
        w["Autonomy"]      * rv.autonomy      +
        w["Evolution"]     * rv.evolution
    )
    rv.composite = _clip(composite)
    rv.trace.append(
        f"Composite ({_profile_name}) = "
        f"{w['Likelihood']:.2f}·L + {w['Severity']:.2f}·S + "
        f"{w['Vulnerability']:.2f}·V + {w['Uncertainty']:.2f}·U + "
        f"{w['Autonomy']:.2f}·A + {w['Evolution']:.2f}·E "
        f"= {rv.composite}"
    )

    # Tiers
    rv.tier_likelihood    = _tier_for(rv.likelihood)
    rv.tier_severity      = _tier_for(rv.severity)
    rv.tier_vulnerability = _tier_for(rv.vulnerability)
    rv.tier_uncertainty   = _tier_for(rv.uncertainty)
    rv.tier_autonomy      = _tier_for(rv.autonomy)
    rv.tier_evolution     = _tier_for(rv.evolution)
    rv.tier_composite     = _tier_for(rv.composite)

    # Gate: any pillar ≥ 80 blocks
    pillars = {
        "Likelihood":    rv.likelihood,
        "Severity":      rv.severity,
        "Vulnerability": rv.vulnerability,
        "Uncertainty":   rv.uncertainty,
        "Autonomy":      rv.autonomy,
        "Evolution":     rv.evolution,
    }
    top = max(pillars, key=pillars.get)
    if pillars[top] >= 80.0:
        rv.gate_blocked = True
        rv.blocking_dimension = top

    return rv


def _generate_recommendations(reg: RegistryState, t: DerivedTerms):
    recs = t.recommendations

    if reg.audit_frequency == AuditFrequencyEnum.QUARTERLY and reg.silent_failures:
        recs.append(
            "📋 Move from QUARTERLY to WEEKLY audit frequency — "
            f"current Δ = {t.delta} days due to silent failure modes. "
            "This alone could cut the silent failure core by up to 6×."
        )
    if reg.rcf >= 1.15 and reg.compensating_controls == 0:
        recs.append(
            "📋 Add a CompensatingControlRecord with EXTERNAL_VALIDATOR or PEER_REVIEW "
            f"to address RCF = {reg.rcf:.1f} role consolidation."
        )
    if reg.model_type == ModelTypeEnum.LLM \
            and not reg.output_validation_gate_configured:
        recs.append(
            "📋 Configure OutputValidationGate for all non-advisory consumption roles. "
            "LLM hallucination is a normal failure mode — gate is mandatory."
        )
    if reg.system_type == AISystemTypeEnum.TYPE_3_THIRDPARTY_API \
            and not reg.provider_sla_gdpr_dpa:
        recs.append(
            "📋 Obtain GDPR Article 28 Data Processing Agreement from provider. "
            "This is a hard pre-deployment blocker for all Type 3 systems."
        )
    if not reg.policy_hallucination_acknowledged:
        recs.append(
            "📋 Update OrganisationalAIPolicy to formally acknowledge hallucination "
            "as a normal failure mode. Absence maps to NO_POLICY accountability failure."
        )
    if reg.model_type == ModelTypeEnum.PINN and reg.domain_law is None:
        recs.append(
            "📋 Register a DomainRule at Layer 1 before PCS can be computed for a PINN. "
            "Without it, D_m is undefined and the deployment gate is blocked."
        )
    if reg.misuse_incident_count > 0:
        recs.append(
            f"📋 {reg.misuse_incident_count} misuse incidents recorded. "
            "Classify root causes using RootCauseEnum and remediate the identified "
            "design gap at the prior layer. PCS inflation persists until remediated."
        )
    if not reg.dpia_approved and reg.risk_tier.value in ("CRITICAL", "HIGH"):
        recs.append(
            "📋 Complete and approve DPIA (GDPR Article 35). "
            "Required for high-risk AI processing. Absence raises both L and I."
        )