"""
ST-AI Framework v3 — Registry State
All inputs are enum-based or boolean. No numeric inputs from user.
PCS terms are derived, never entered.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from framework.enums import (
    OrgSizeEnum, GovernanceMaturityEnum, BudgetBandEnum,
    ModelTypeEnum, AISystemTypeEnum, RiskTierEnum, LawTypeEnum,
    FeedbackLoopEnum, DataConsentEnum, SensitivityEnum,
    SupplyChainTypeEnum, VettingStatusEnum,
    ConfidenceSignalEnum, ConsumptionRoleEnum, BiasMetricEnum,
    VectorTypeEnum, InsiderRoleEnum, SilentFailureEnum,
    RollbackModeEnum, AIDependencyLevelEnum, DeploymentModeEnum,
    AuditFrequencyEnum, DriftTypeEnum,
    RootCauseEnum, BiasRiskLevelEnum,
    DecommissioningStatusEnum, DecommissionReasonEnum, DisposalMethodEnum,
    ActorLifecycleRoleEnum, ConstraintTypeEnum,
    AICriticalityEnum, ExperienceLevelEnum,
    RetrainingTriggerEnum,
)


@dataclass
class RegistryState:
    """
    Complete declared state of one AI deployment across all 11 layers.
    Every field is an enum, boolean, or count. No raw numeric inputs.
    PCS formula terms are derived from this state by the rule engine.
    """

    # ── LAYER 1: Org Profile + AI Identity ────────────────────────────
    org_size: OrgSizeEnum                     = OrgSizeEnum.SMALL
    governance_maturity: GovernanceMaturityEnum = GovernanceMaturityEnum.AD_HOC
    budget_band: BudgetBandEnum               = BudgetBandEnum.UNDER_10K
    model_type: ModelTypeEnum                 = ModelTypeEnum.LLM
    system_type: AISystemTypeEnum             = AISystemTypeEnum.TYPE_1_INHOUSE
    risk_tier: RiskTierEnum                   = RiskTierEnum.MEDIUM
    domain_law: Optional[LawTypeEnum]         = None

    # v4 additions — drive ACM (Autonomy pillar) and EF (Severity/Vuln/Autonomy)
    ai_criticality: AICriticalityEnum         = AICriticalityEnum.OPERATIONAL
    experience_level: ExperienceLevelEnum     = ExperienceLevelEnum.SENIOR

    # v5 additions — risk profile + assessment mode + incident register
    risk_profile: "RiskProfileEnum"           = None    # set in __post_init__
    assessment_mode: "AssessmentModeEnum"     = None    # set in __post_init__
    incident_register: "IncidentRegister"     = None    # set in __post_init__
    deployment_name: str                      = ""
    deployment_id: str                        = ""

    # v5 — actor identifiers (Secure Tropos: every dependency edge needs a
    # named depender + dependee). Strings so they accept email, staff ID,
    # vendor name, or any free-form identifier. Empty by default for
    # forwards-compatibility with v4 registries.
    trainer_id:    str = ""
    validator_id:  str = ""
    deployer_id:   str = ""
    operator_id:   str = ""
    consumer_id:   str = ""

    # Role concentration: who holds each lifecycle role?
    # True = same person as previous role (increases RCF)
    trainer_is_validator: bool    = False
    validator_is_deployer: bool   = False
    trainer_is_deployer: bool     = False

    # Importance ratings for key controls (0=NONE 1=ADVISORY 2=SIGNIFICANT 3=CRITICAL gap)
    # Computed from ImportanceRatingEnum vs framework minimum
    gap_scores: List[int]         = field(default_factory=list)

    # Compensating control records in place
    compensating_controls: int    = 0

    # Domain rule formally declared?
    domain_rule_declared: bool    = True

    # Ensemble / Hybrid component counts
    opaque_components: int        = 0
    total_components: int         = 1

    # ── LAYER 2: Data Provenance ───────────────────────────────────────
    feedback_loop: FeedbackLoopEnum       = FeedbackLoopEnum.NONE
    data_consent: DataConsentEnum         = DataConsentEnum.EXPLICIT
    data_sensitivity: SensitivityEnum     = SensitivityEnum.INTERNAL
    retraining_trigger: RetrainingTriggerEnum = None
    supply_chain_types: List[SupplyChainTypeEnum] = field(default_factory=list)
    provider_sla_gdpr_dpa: bool           = True
    signed_at_collection: bool            = True

    # ── LAYER 3: Constraints ───────────────────────────────────────────
    active_constraints: List[ConstraintTypeEnum] = field(default_factory=list)
    confidence_signal: ConfidenceSignalEnum = ConfidenceSignalEnum.QUALITATIVE
    bias_metric: Optional[BiasMetricEnum]  = None
    hallucination_constraint_declared: bool = False
    conflict_resolution: Optional[str]     = None

    # ── LAYER 4: Adversarial Threats ──────────────────────────────────
    attack_vectors: List[VectorTypeEnum]   = field(default_factory=list)
    insider_roles: List[InsiderRoleEnum]   = field(default_factory=list)
    silent_failures: List[SilentFailureEnum] = field(default_factory=list)

    # ── LAYER 6: Deployment ────────────────────────────────────────────
    rollback_mode: RollbackModeEnum        = RollbackModeEnum.MANUAL
    ai_dependency_level: AIDependencyLevelEnum = AIDependencyLevelEnum.IMPORTANT
    deployment_mode: DeploymentModeEnum    = DeploymentModeEnum.STANDARD
    model_card_approved: bool              = False
    fallback_procedure_exists: bool        = False
    fallback_tested: bool                  = False

    # ── LAYER 7: Runtime Monitoring ───────────────────────────────────
    audit_frequency: AuditFrequencyEnum    = AuditFrequencyEnum.WEEKLY
    drift_detected: bool                   = False
    drift_type: Optional[DriftTypeEnum]    = None
    domain_violation_occurred: bool        = False
    bias_breach_detected: bool             = False
    quarantine_activated: bool             = False

    # ── LAYER 8: Governance ────────────────────────────────────────────
    dpia_approved: bool                    = False
    hitl_formally_specified: bool          = False
    policy_hallucination_acknowledged: bool = False
    liability_boundary_declared: bool      = False
    right_to_challenge_documented: bool    = False

    # ── LAYER 9: Epistemic ─────────────────────────────────────────────
    consumption_role: ConsumptionRoleEnum  = ConsumptionRoleEnum.ADVISORY_READER
    hallucination_incident_count: int      = 0
    output_validation_gate_configured: bool = False

    # ── LAYER 10: Culture & Misuse ─────────────────────────────────────
    misuse_incident_count: int             = 0
    root_causes: List[RootCauseEnum]       = field(default_factory=list)
    automation_bias_risk: Optional[BiasRiskLevelEnum] = None
    hitl_verified_substantive: bool        = True
    operator_training_complete: bool       = False

    # ── LAYER 11: Decommissioning ──────────────────────────────────────
    decommissioning_status: Optional[DecommissioningStatusEnum] = None
    legal_hold_active: bool                = False
    disposal_method: Optional[DisposalMethodEnum] = None
    post_retirement_verified: bool         = False

    @property
    def rcf(self) -> float:
        """
        Role Concentration Factor — direct PCS multiplier.
        Assigned by the framework from declared role structure:
          x1.00  all three roles held by different people (no amplification)
          x1.15  two roles held by one person (15% amplification)
          x1.30  all three roles held by one person (30% amplification)
        """
        consolidations = sum([
            self.trainer_is_validator,
            self.validator_is_deployer,
            self.trainer_is_deployer,
        ])
        if consolidations == 0:
            return 1.00
        elif consolidations == 1:
            return 1.15
        else:
            return 1.30

    @property
    def rcf_adj(self) -> float:
        """Alias kept for backward compatibility — returns rcf directly."""
        return self.rcf

    def __post_init__(self):
        # v5 — late-bound defaults that need imports to avoid circularity
        if self.risk_profile is None:
            from framework.risk_profile import RiskProfileEnum
            self.risk_profile = RiskProfileEnum.BALANCED
        if self.assessment_mode is None:
            from framework.assessment_mode import AssessmentModeEnum
            self.assessment_mode = AssessmentModeEnum.SELF
        if self.incident_register is None:
            from framework.incidents import IncidentRegister
            self.incident_register = IncidentRegister()


# ── Import fix: RetrainingTriggerEnum referenced above ───────────────────────
from framework.enums import RetrainingTriggerEnum