"""ST-AI Framework v3 — Complete Enumeration Registry (all 11 layers).

v8.1 changes:
  * Tier scheme collapsed from 5 to 4 levels: LOW / MODERATE / HIGH / CRITICAL.
    The URGENT tier has been removed — its operational consequences are
    absorbed into HIGH (REQUIRES_REVIEW with structural constraint) and
    CRITICAL (BLOCKED) depending on score.
  * Tier thresholds on the 0-100 PCS scale rebased so that:
        LOW       < 10
        MODERATE  10 -- 29
        HIGH      30 -- 59
        CRITICAL  >= 60
    The CRITICAL threshold is lowered from 80 to 60 so that the
    auto-block fires earlier, capturing documented failures that
    accumulate three-plus structural risk factors. Calibration
    scenarios re-baselined accordingly.
"""
import enum


class AISystemTypeEnum(str, enum.Enum):
    TYPE_1_INHOUSE        = "TYPE_1_INHOUSE"
    TYPE_2_FINETUNED      = "TYPE_2_FINETUNED"
    TYPE_3_THIRDPARTY_API = "TYPE_3_THIRDPARTY_API"

class ModelTypeEnum(str, enum.Enum):
    NN = "NN"; RL = "RL"; ENSEMBLE = "ENSEMBLE"
    PINN = "PINN"; LLM = "LLM"; CNN = "CNN"; HYBRID = "HYBRID"

class RiskTierEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"; LOW = "LOW"

class LawTypeEnum(str, enum.Enum):
    PHYSICAL_LAW = "PHYSICAL_LAW"; FINANCIAL_REGULATION = "FINANCIAL_REGULATION"
    CLINICAL_SAFETY = "CLINICAL_SAFETY"; MEASUREMENT_STANDARD = "MEASUREMENT_STANDARD"
    DATA_PROTECTION = "DATA_PROTECTION"; SECTOR_SPECIFIC = "SECTOR_SPECIFIC"

class OrgSizeEnum(str, enum.Enum):
    MICRO = "MICRO"; SMALL = "SMALL"; MEDIUM = "MEDIUM"
    LARGE = "LARGE"; ENTERPRISE = "ENTERPRISE"

class GovernanceMaturityEnum(str, enum.Enum):
    AD_HOC = "AD_HOC"; DOCUMENTED = "DOCUMENTED"; MANAGED = "MANAGED"
    MEASURED = "MEASURED"; OPTIMISING = "OPTIMISING"

class BudgetBandEnum(str, enum.Enum):
    UNDER_10K = "UNDER_10K"; BAND_10K_50K = "BAND_10K_50K"
    BAND_50K_250K = "BAND_50K_250K"; BAND_250K_1M = "BAND_250K_1M"; OVER_1M = "OVER_1M"

class ImportanceRatingEnum(str, enum.Enum):
    NOT_RELEVANT = "NOT_RELEVANT"; LOW = "LOW"; MEDIUM = "MEDIUM"
    HIGH = "HIGH"; CRITICAL = "CRITICAL"

class GapSeverityEnum(str, enum.Enum):
    NONE = "NONE"; ADVISORY = "ADVISORY"; SIGNIFICANT = "SIGNIFICANT"; CRITICAL = "CRITICAL"

class EnforcementLevelEnum(str, enum.Enum):
    MANDATORY = "MANDATORY"; COMPENSATABLE = "COMPENSATABLE"
    RECOMMENDED = "RECOMMENDED"; OPTIONAL = "OPTIONAL"

class CompensatingMechanismEnum(str, enum.Enum):
    EXTERNAL_AUDIT = "EXTERNAL_AUDIT"; PEER_REVIEW = "PEER_REVIEW"
    CERTIFIED_TOOLING = "CERTIFIED_TOOLING"
    PERIODIC_MANUAL_REVIEW = "PERIODIC_MANUAL_REVIEW"
    DOCUMENTED_RISK_ACCEPT = "DOCUMENTED_RISK_ACCEPT"
    EXTERNAL_VALIDATOR = "EXTERNAL_VALIDATOR"; SIMPLIFIED_DPIA = "SIMPLIFIED_DPIA"

class ActorLifecycleRoleEnum(str, enum.Enum):
    TRAINER = "TRAINER"; VALIDATOR = "VALIDATOR"; DEPLOYER = "DEPLOYER"
    MONITOR = "MONITOR"; RETIRER = "RETIRER"

class FeedbackLoopEnum(str, enum.Enum):
    NONE = "NONE"; HUMAN_REVIEWED = "HUMAN_REVIEWED"; AUTOMATED = "AUTOMATED"

class DataConsentEnum(str, enum.Enum):
    EXPLICIT = "EXPLICIT"; IMPLIED = "IMPLIED"; NONE = "NONE"; UNKNOWN = "UNKNOWN"

class SensitivityEnum(str, enum.Enum):
    PUBLIC = "PUBLIC"; INTERNAL = "INTERNAL"; CONFIDENTIAL = "CONFIDENTIAL"
    SENSITIVE_PERSONAL = "SENSITIVE_PERSONAL"; SPECIAL_CATEGORY = "SPECIAL_CATEGORY"

class RetrainingTriggerEnum(str, enum.Enum):
    SCHEDULED = "SCHEDULED"; DRIFT_DETECTED = "DRIFT_DETECTED"
    MANUAL = "MANUAL"; FEEDBACK_LOOP = "FEEDBACK_LOOP"

class SupplyChainTypeEnum(str, enum.Enum):
    DATASET = "DATASET"; PRETRAINED_MODEL = "PRETRAINED_MODEL"
    LIBRARY = "LIBRARY"; API_SERVICE = "API_SERVICE"; LABELING_SERVICE = "LABELING_SERVICE"

class VettingStatusEnum(str, enum.Enum):
    UNVETTED = "UNVETTED"; IN_REVIEW = "IN_REVIEW"; APPROVED = "APPROVED"
    REJECTED = "REJECTED"; CONDITIONALLY_APPROVED = "CONDITIONALLY_APPROVED"

class ConstraintTypeEnum(str, enum.Enum):
    SECURITY = "SECURITY"; PRIVACY = "PRIVACY"; DOMAIN = "DOMAIN"; BIAS = "BIAS"
    HALLUCINATION = "HALLUCINATION"; CONFIDENCE_SIGNAL = "CONFIDENCE_SIGNAL"
    OUTPUT_PROVENANCE = "OUTPUT_PROVENANCE"

class ConfidenceSignalEnum(str, enum.Enum):
    NONE = "NONE"; QUALITATIVE = "QUALITATIVE"
    NUMERIC = "NUMERIC"; INTERVAL = "INTERVAL"

class VectorTypeEnum(str, enum.Enum):
    DATA = "DATA"; MODEL = "MODEL"; INFERENCE = "INFERENCE"
    ACCESS = "ACCESS"; SUPPLY_CHAIN = "SUPPLY_CHAIN"; CHAINED_AI = "CHAINED_AI"

class InsiderRoleEnum(str, enum.Enum):
    DATA_ENGINEER = "DATA_ENGINEER"; ML_ENGINEER = "ML_ENGINEER"
    CLOUD_OPERATOR = "CLOUD_OPERATOR"

class BiasMetricEnum(str, enum.Enum):
    DEMOGRAPHIC_PARITY = "DEMOGRAPHIC_PARITY"
    EQUALISED_ODDS = "EQUALISED_ODDS"; CALIBRATION = "CALIBRATION"

class ConflictResolutionEnum(str, enum.Enum):
    PRIORITISE_PRIVACY = "PRIORITISE_PRIVACY"; PRIORITISE_SAFETY = "PRIORITISE_SAFETY"
    HUMAN_DECISION = "HUMAN_DECISION"; BOARD_DECISION = "BOARD_DECISION"

class SilentFailureEnum(str, enum.Enum):
    PERFORMANCE_DRIFT = "PERFORMANCE_DRIFT"
    BIAS_DRIFT = "BIAS_DRIFT"; DATA_LEAK = "DATA_LEAK"

class ExploitWindowEnum(str, enum.Enum):
    IMMEDIATE = "IMMEDIATE"; DAYS = "DAYS"; WEEKS = "WEEKS"; MONTHS = "MONTHS"


# ── Four-tier action classification ────────────────────────────────────────
# Operational semantics:
#   LOW       (<10)   — standard deployment, routine monitoring
#   MODERATE  (10-29) — APPROVED with conditions; monitoring plan required
#   HIGH      (30-59) — REQUIRES_REVIEW; structural constraint; executive sign-off
#   CRITICAL  (>=60)  — BLOCKED; auto-quarantine; remediate before re-gate
class ActionTierEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"
    MODERATE = "MODERATE"; LOW = "LOW"

class CompliancePathEnum(str, enum.Enum):
    FULL_COMPLIANCE = "FULL_COMPLIANCE"
    COMPENSATED_COMPLIANCE = "COMPENSATED_COMPLIANCE"
    CONDITIONAL_DEPLOYMENT = "CONDITIONAL_DEPLOYMENT"
    NON_COMPLIANT_BLOCKED = "NON_COMPLIANT_BLOCKED"

class ResidualRiskBandEnum(str, enum.Enum):
    NEGLIGIBLE = "NEGLIGIBLE"; LOW = "LOW"; MEDIUM = "MEDIUM"
    HIGH = "HIGH"; UNACCEPTABLE = "UNACCEPTABLE"

class PCSBlockReasonEnum(str, enum.Enum):
    DOMAIN_VIOLATION = "DOMAIN_VIOLATION"; HALLUCINATION_RISK = "HALLUCINATION_RISK"
    FAIRNESS_BREACH = "FAIRNESS_BREACH"; CRITICAL_THREAT = "CRITICAL_THREAT"
    MISSING_VALIDATION = "MISSING_VALIDATION"
    IMPORTANCE_GAP_CRITICAL = "IMPORTANCE_GAP_CRITICAL"
    UNCOMPENSATED_ROLE_CONCENTRATION = "UNCOMPENSATED_ROLE_CONCENTRATION"
    PINN_NO_DOMAIN_RULE = "PINN_NO_DOMAIN_RULE"
    AUTOMATED_RL_FEEDBACK = "AUTOMATED_RL_FEEDBACK"
    # ── v8.1 ──
    # SC-MAP-1: pre-deployment fairness / bias-proxy assessment missing.
    # Used when a deployment touches protected groups (special-category
    # data or safety-critical decisions affecting people) but has no
    # declared bias metric and no output-validation gate — the failure
    # mode that NIST AI RMF MAP catches via its sociotechnical context
    # requirement (MAP 3.x).
    MAP_VALIDATION_MISSING = "MAP_VALIDATION_MISSING"

class GateDecisionEnum(str, enum.Enum):
    APPROVED = "APPROVED"; BLOCKED = "BLOCKED"; REQUIRES_REVIEW = "REQUIRES_REVIEW"

class AIDependencyLevelEnum(str, enum.Enum):
    CRITICAL_NO_FALLBACK = "CRITICAL_NO_FALLBACK"
    CRITICAL_WITH_FALLBACK = "CRITICAL_WITH_FALLBACK"
    IMPORTANT = "IMPORTANT"; ADVISORY = "ADVISORY"

class RollbackModeEnum(str, enum.Enum):
    AUTOMATED = "AUTOMATED"; MANUAL = "MANUAL"; NOT_POSSIBLE = "NOT_POSSIBLE"

class StageNameEnum(str, enum.Enum):
    COLLECT = "COLLECT"; TRAIN = "TRAIN"; VALIDATE = "VALIDATE"
    SIGN = "SIGN"; DEPLOY = "DEPLOY"; MONITOR = "MONITOR"

class ContinuityStateEnum(str, enum.Enum):
    NORMAL = "NORMAL"; DEGRADED = "DEGRADED"
    FALLBACK = "FALLBACK"; MANUAL_ONLY = "MANUAL_ONLY"

class DeploymentModeEnum(str, enum.Enum):
    STANDARD = "STANDARD"; CANARY = "CANARY"; SHADOW = "SHADOW"
    BLUE_GREEN = "BLUE_GREEN"; EMERGENCY_ROLLBACK = "EMERGENCY_ROLLBACK"

class AuditFrequencyEnum(str, enum.Enum):
    CONTINUOUS = "CONTINUOUS"; DAILY = "DAILY"; WEEKLY = "WEEKLY"; QUARTERLY = "QUARTERLY"

class ShutdownTriggerEnum(str, enum.Enum):
    DRIFT_THRESHOLD = "DRIFT_THRESHOLD"; BIAS_BREACH = "BIAS_BREACH"
    DOMAIN_VIOLATION = "DOMAIN_VIOLATION"

class DriftTypeEnum(str, enum.Enum):
    DATA_DRIFT = "DATA_DRIFT"; CONCEPT_DRIFT = "CONCEPT_DRIFT"
    PERFORMANCE_DRIFT = "PERFORMANCE_DRIFT"; PREDICTION_DRIFT = "PREDICTION_DRIFT"

class ConsumptionRoleEnum(str, enum.Enum):
    ADVISORY_READER = "ADVISORY_READER"; DECISION_MAKER = "DECISION_MAKER"
    AUTOMATED_EXECUTOR = "AUTOMATED_EXECUTOR"
    REGULATOR_SUBMITTER = "REGULATOR_SUBMITTER"; AUDITOR = "AUDITOR"

# ── v4 additions: AI Criticality & Experience Factor ──────────────────────────
class AICriticalityEnum(str, enum.Enum):
    """How autonomously the AI's output is consumed.
    Drives the ACM (AI Criticality Multiplier) and S_base (severity anchor)."""
    ADVISORY        = "ADVISORY"          # AI suggests; human decides
    OPERATIONAL     = "OPERATIONAL"       # Routine business process with HITL
    CRITICAL        = "CRITICAL"          # Consequential decisions affecting people
    SAFETY_CRITICAL = "SAFETY_CRITICAL"   # Output directly triggers physical/clinical action

class ExperienceLevelEnum(str, enum.Enum):
    """Operator competence tier — drives the EF (Experience Factor) modifiers
    on I (impact), Wh (human-AI coupling), and τ (audit cycle)."""
    SENIOR           = "SENIOR"            # Domain expert; baseline
    JUNIOR           = "JUNIOR"            # Some experience; minor reliability tax
    NOVICE           = "NOVICE"            # Limited experience; noticeable error rate
    OVERCENTRALISED  = "OVERCENTRALISED"   # Single expert; bus-factor risk

class OutputTrustLevelEnum(str, enum.Enum):
    LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"

class EvidenceStatusEnum(str, enum.Enum):
    ADMISSIBLE = "ADMISSIBLE"; BLOCKED = "BLOCKED"; REVIEW_REQUIRED = "REVIEW_REQUIRED"

class RootCauseEnum(str, enum.Enum):
    NO_TRAINING = "NO_TRAINING"; TRAINING_INADEQUATE = "TRAINING_INADEQUATE"
    REVIEW_BYPASSED_DELIBERATELY = "REVIEW_BYPASSED_DELIBERATELY"
    REVIEW_BYPASSED_INADVERTENTLY = "REVIEW_BYPASSED_INADVERTENTLY"
    SYSTEM_DID_NOT_SIGNAL_UNCERTAINTY = "SYSTEM_DID_NOT_SIGNAL_UNCERTAINTY"
    ORGANISATION_DID_NOT_ACCEPT_HALLUCINATION_RISK = "ORGANISATION_DID_NOT_ACCEPT_HALLUCINATION_RISK"

class BiasRiskLevelEnum(str, enum.Enum):
    LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"

class DecommissioningStatusEnum(str, enum.Enum):
    PLANNED = "PLANNED"; IN_PROGRESS = "IN_PROGRESS"
    WEIGHTS_DISPOSED = "WEIGHTS_DISPOSED"; DATA_DELETED = "DATA_DELETED"
    AUDIT_COMPLETE = "AUDIT_COMPLETE"; LEGALLY_HELD = "LEGALLY_HELD"

class DecommissionReasonEnum(str, enum.Enum):
    RISK = "RISK"; OBSOLESCENCE = "OBSOLESCENCE"
    REGULATORY = "REGULATORY"; BUSINESS = "BUSINESS"

class DisposalMethodEnum(str, enum.Enum):
    SECURE_DELETE = "SECURE_DELETE"
    CRYPTOGRAPHIC_DESTRUCTION = "CRYPTOGRAPHIC_DESTRUCTION"
    ARCHIVE_ENCRYPTED = "ARCHIVE_ENCRYPTED"
    TRANSFER_TO_SUCCESSOR = "TRANSFER_TO_SUCCESSOR"

# ── PCS tier thresholds (0-100 scale, k=4 normalisation) ─────────────────────
# PCS_100 = min(100, PCS_raw × 4)
#
# v8.1 four-tier scheme:
#   CRITICAL ≥ 60  → 3+ structural risk factors compounding; deployment
#                     auto-blocks; remediation mandatory before re-gate
#   HIGH     ≥ 30  → 2 factors compounding; REQUIRES_REVIEW; structural
#                     constraint and executive sign-off required
#   MODERATE ≥ 10  → 1 factor elevated; APPROVED with documented monitoring
#   LOW      <  10 → all factors at baseline; standard deployment
#
# The URGENT tier (formerly 50-79) has been removed. Its operational
# consequences are absorbed into HIGH (REQUIRES_REVIEW) for the lower
# half of its range and CRITICAL (BLOCKED) for the upper half, with the
# CRITICAL threshold lowered from 80 to 60 to make the auto-block fire
# earlier on documented multi-factor failure modes (Optum-class cases
# previously sitting at PCS=57 now block via the CRITICAL path when
# combined with the new SC-MAP-1 constraint).
PCS_TIER_THRESHOLDS = {
    ActionTierEnum.CRITICAL: 60.0,
    ActionTierEnum.HIGH:     30.0,
    ActionTierEnum.MODERATE: 10.0,
    ActionTierEnum.LOW:       0.0,
}

# ── PCS tier colour map ────────────────────────────────────────────────────────
PCS_TIER_COLOURS = {
    ActionTierEnum.CRITICAL: "#c62828",
    ActionTierEnum.HIGH:     "#f9a825",
    ActionTierEnum.MODERATE: "#2e7d32",
    ActionTierEnum.LOW:      "#1565c0",
}

PCS_TIER_BG = {
    ActionTierEnum.CRITICAL: "#3a0a0a",
    ActionTierEnum.HIGH:     "#2a2000",
    ActionTierEnum.MODERATE: "#0a2010",
    ActionTierEnum.LOW:      "#0a1530",
}

TIER_EMOJI = {
    ActionTierEnum.CRITICAL: "🔴",
    ActionTierEnum.HIGH:     "🟡",
    ActionTierEnum.MODERATE: "🟢",
    ActionTierEnum.LOW:      "🔵",
}

# ── v4 lookup tables: ACM and EF ──────────────────────────────────────────────
# ACM_TABLE: (acm_multiplier, s_base_anchor)
#   acm_multiplier drives the Autonomy pillar (1.0=advisory → 2.5=safety-critical)
#   s_base is a consequence severity anchor used elsewhere in the framework
ACM_TABLE = {
    AICriticalityEnum.ADVISORY:        (1.0,  5),
    AICriticalityEnum.OPERATIONAL:     (1.3, 20),
    AICriticalityEnum.CRITICAL:        (1.8, 45),
    AICriticalityEnum.SAFETY_CRITICAL: (2.5, 75),
}
ACM_MAX = 2.5

# EF_TABLE: (ef_I_mult, ef_Wh_add, ef_tau_mult)
#   ef_I_mult     — multiplies I (impact)
#   ef_Wh_add     — additive contribution to Wh (human-AI coupling)
#   ef_tau_mult   — multiplies τ (audit cycle)
EF_TABLE = {
    ExperienceLevelEnum.SENIOR:          (1.00, 0.00, 1.00),
    ExperienceLevelEnum.JUNIOR:          (1.08, 0.10, 1.15),
    ExperienceLevelEnum.NOVICE:          (1.20, 0.25, 1.40),
    ExperienceLevelEnum.OVERCENTRALISED: (1.10, 0.15, 0.90),
}
EF_I_MAX   = 1.20
EF_WH_MAX  = 0.25
EF_TAU_MIN = 0.90
EF_TAU_MAX = 1.40

# noqa: E305
# fmt: off
MODEL_TYPE_PCS_FLOOR = {
    ModelTypeEnum.LLM:      (True,  True,  False, True),
    ModelTypeEnum.RL:       (False, True,  True,  False),
    ModelTypeEnum.CNN:      (True,  False, False, True),
    ModelTypeEnum.ENSEMBLE: (False, False, False, False),
    ModelTypeEnum.HYBRID:   (False, False, False, False),
    ModelTypeEnum.PINN:     (False, False, False, True),
    ModelTypeEnum.NN:       (False, False, False, False),
}

SYSTEM_TYPE_PCS_FLOOR = {
    AISystemTypeEnum.TYPE_1_INHOUSE:        {"I_elevated": False, "Ws_elevated": False},
    AISystemTypeEnum.TYPE_2_FINETUNED:      {"I_elevated": True,  "Ws_elevated": False},
    AISystemTypeEnum.TYPE_3_THIRDPARTY_API: {"I_elevated": True,  "Ws_elevated": True},
}

GAP_SCORE_MAP = {
    GapSeverityEnum.NONE:        0,
    GapSeverityEnum.ADVISORY:    1,
    GapSeverityEnum.SIGNIFICANT: 2,
    GapSeverityEnum.CRITICAL:    3,
}
# fmt: on
