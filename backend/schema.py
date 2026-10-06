"""
ST-AI Design Studio — canonical Pydantic schema.

One DesignStudioDocument covers:
  - registry   : maps to the existing RegistryState / rule_engine inputs
  - graph      : canvas layout (nodes + typed edges) — presentational only
  - pcs_result : populated by POST /score, never written by client
  - _validation: optional fixture block for the 16-case suite
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Node / Edge type enumerations ─────────────────────────────────────────────

class NodeType(str, Enum):
    ACTOR               = "ACTOR"
    DEPARTMENT          = "DEPARTMENT"
    AI_MODEL            = "AI_MODEL"
    TRAINING_DATASET    = "TRAINING_DATASET"
    DEPLOYMENT_ENV      = "DEPLOYMENT_ENV"
    CONSTRAINT          = "CONSTRAINT"
    CONSENT_RECORD      = "CONSENT_RECORD"
    LEGAL_BASIS         = "LEGAL_BASIS"
    REGULATORY_REQ      = "REGULATORY_REQ"
    DATA_CATEGORY       = "DATA_CATEGORY"
    MONITORING_SIGNAL   = "MONITORING_SIGNAL"
    INCIDENT            = "INCIDENT"


class ActorSubtype(str, Enum):
    TRAINER   = "TRAINER"
    VALIDATOR = "VALIDATOR"
    DEPLOYER  = "DEPLOYER"
    OPERATOR  = "OPERATOR"
    CONSUMER  = "CONSUMER"


class EdgeType(str, Enum):
    IMPOSED_BY    = "IMPOSED_BY"
    ON_DEPENDENCY = "ON_DEPENDENCY"
    BELONGS_TO    = "BELONGS_TO"
    TRAINS        = "TRAINS"
    VALIDATES     = "VALIDATES"
    DEPLOYS       = "DEPLOYS"
    OPERATES      = "OPERATES"
    CONSUMED_BY   = "CONSUMED_BY"
    RUNS_IN       = "RUNS_IN"
    TRAINED_ON    = "TRAINED_ON"
    COVERED_BY    = "COVERED_BY"
    REQUIRES      = "REQUIRES"
    MONITORED_BY  = "MONITORED_BY"
    REPORTS_TO    = "REPORTS_TO"


class ConstraintStatus(str, Enum):
    SATISFIED          = "SATISFIED"
    UNMET              = "UNMET"
    NOT_YET_DETERMINED = "NOT_YET_DETERMINED"


class StatusIndicator(str, Enum):
    SATISFIED          = "SATISFIED"
    UNMET              = "UNMET"
    NOT_YET_DETERMINED = "NOT_YET_DETERMINED"
    NEUTRAL            = "NEUTRAL"


# ── Veto-class constraint IDs (safety invariant) ───────────────────────────────

VETO_CLASS_CONSTRAINTS = frozenset({
    "SC-DPIA-1", "SC-HITL-1", "SC-HALLU-1",
    "SC-MAP-1",  "SC-CHALL-1", "SC-LIAB-1",
})

MODULATING_CLASS_CONSTRAINTS = frozenset({
    "SC-MC-1", "SC-TRAIN-1", "SC-RCF-1",
    "SC-RCF-2", "SC-DOMAIN-1", "SC-CONSENT-1",
})


# ── Registry sub-models ────────────────────────────────────────────────────────

class ConstraintDeclaration(BaseModel):
    status:              ConstraintStatus = ConstraintStatus.NOT_YET_DETERMINED
    evidence:            Optional[str]    = None
    evidence_attached_at: Optional[datetime] = None

    @model_validator(mode="after")
    def evidence_required_for_satisfied(self) -> "ConstraintDeclaration":
        if self.status == ConstraintStatus.SATISFIED and not (self.evidence or "").strip():
            raise ValueError(
                "evidence must be non-empty when status is SATISFIED. "
                "This is a hard server-side rule — it cannot be bypassed via the API."
            )
        return self


class ConsentRecord(BaseModel):
    id:                 str
    diaprod_consent_id: Optional[str]       = None
    legal_basis:        str                 = ""
    data_category_ids:  List[str]           = Field(default_factory=list)
    validated_at:       Optional[datetime]  = None
    validation_source:  Optional[str]       = None   # "MANUAL" | "DIAPROD_API"


class RegulatoryRequirement(BaseModel):
    id:        str
    instrument: str = ""
    clause:    str  = ""
    risk_tier: Optional[str] = None
    status:    ConstraintStatus = ConstraintStatus.NOT_YET_DETERMINED
    # Needed for the requirement to attest a rule (Task 3). Not enforced here, so /score
    # behaves as before; the compliance engine treats Satisfied-without-evidence as not attested.
    evidence:  Optional[str] = None


class DataCategory(BaseModel):
    id:          str
    name:        str
    sensitivity: str = "NON_PERSONAL"   # NON_PERSONAL | PERSONAL | SPECIAL_CATEGORY


class Department(BaseModel):
    id:                       str
    name:                     str
    reports_to_department_id: Optional[str] = None


class DeploymentContext(BaseModel):
    model_type:       str = "CLASSICAL_ML"
    ai_criticality:   str = "OPERATIONAL"
    data_sensitivity: str = "NON_PERSONAL"
    domain:           str = ""
    delta_days:       Optional[float] = None
    tau_days:         Optional[float] = None


class ActorEntry(BaseModel):
    identity:      str          = ""
    department_id: Optional[str] = None


class ActorSet(BaseModel):
    trainer:   ActorEntry = Field(default_factory=ActorEntry)
    validator: ActorEntry = Field(default_factory=ActorEntry)
    deployer:  ActorEntry = Field(default_factory=ActorEntry)
    operator:  ActorEntry = Field(default_factory=ActorEntry)
    consumer:  ActorEntry = Field(default_factory=ActorEntry)


class GovernanceState(BaseModel):
    constraints_declared: Dict[str, ConstraintDeclaration] = Field(
        default_factory=lambda: {
            cid: ConstraintDeclaration()
            for cid in list(VETO_CLASS_CONSTRAINTS) + list(MODULATING_CLASS_CONSTRAINTS)
        }
    )
    model_card_complete: bool = False
    audit_trail_enabled: bool = False

    @field_validator("constraints_declared", mode="before")
    @classmethod
    def no_auto_satisfy_veto(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extra guard: raise if any veto-class constraint arrives pre-satisfied
        without evidence. The ConstraintDeclaration validator also catches this,
        but this catches bulk writes where evidence might be missing.
        """
        for cid, decl in v.items():
            if cid in VETO_CLASS_CONSTRAINTS:
                status = decl.get("status") if isinstance(decl, dict) else getattr(decl, "status", None)
                evidence = decl.get("evidence") if isinstance(decl, dict) else getattr(decl, "evidence", None)
                if status == "SATISFIED" and not (evidence or "").strip():
                    raise ValueError(
                        f"Veto-class constraint {cid} cannot be set to SATISFIED "
                        f"without non-empty evidence. This is enforced server-side."
                    )
        return v


class IncidentEntry(BaseModel):
    id:          str
    type:        str
    severity:    int = Field(ge=1, le=5)
    status:      str = "OPEN"
    detected_at: datetime
    resolved_at: Optional[datetime] = None


class RegistryBlock(BaseModel):
    deployment_context:      DeploymentContext  = Field(default_factory=DeploymentContext)
    actors:                  ActorSet           = Field(default_factory=ActorSet)
    departments:             List[Department]   = Field(default_factory=list)
    governance_state:        GovernanceState    = Field(default_factory=GovernanceState)
    incident_register:       List[IncidentEntry] = Field(default_factory=list)
    risk_profile:            str                = "BALANCED"
    consent_records:         List[ConsentRecord] = Field(default_factory=list)
    regulatory_requirements: List[RegulatoryRequirement] = Field(default_factory=list)
    data_categories:         List[DataCategory]  = Field(default_factory=list)

    # Fields that map directly to RegistryState flat fields
    org_size:                Optional[str] = None
    governance_maturity:     Optional[str] = None
    model_type:              Optional[str] = None
    system_type:             Optional[str] = None
    risk_tier:               Optional[str] = None
    feedback_loop:           Optional[str] = None
    data_consent:            Optional[str] = None
    data_sensitivity_enum:   Optional[str] = None
    trainer_is_validator:    bool = False
    validator_is_deployer:   bool = False
    trainer_is_deployer:     bool = False
    gap_scores:              List[int] = Field(default_factory=list)
    compensating_controls:   int = 0
    domain_rule_declared:    bool = True
    opaque_components:       int = 0
    total_components:        int = 1
    hallucination_constraint_declared: bool = False
    active_constraints:      List[str] = Field(default_factory=list)
    silent_failure:          Optional[str] = None
    confidence_signal:       Optional[str] = None
    ai_criticality_enum:     Optional[str] = None
    experience_level:        Optional[str] = None


# ── Graph sub-models ───────────────────────────────────────────────────────────

class NodePosition(BaseModel):
    x: float = 0.0
    y: float = 0.0


class CanvasNode(BaseModel):
    id:               str
    type:             NodeType
    subtype:          Optional[str]          = None
    registry_ref:     Optional[str]          = None
    label:            str                    = ""
    position:         NodePosition           = Field(default_factory=NodePosition)
    status_indicator: StatusIndicator        = StatusIndicator.NEUTRAL
    data:             Dict[str, Any]         = Field(default_factory=dict)


class CanvasEdge(BaseModel):
    id:             str
    type:           EdgeType
    source_node_id: str
    target_node_id: str
    label:          Optional[str] = None


class Viewport(BaseModel):
    zoom:  float = 1.0
    pan_x: float = 0.0
    pan_y: float = 0.0


class GraphBlock(BaseModel):
    nodes:    List[CanvasNode] = Field(default_factory=list)
    edges:    List[CanvasEdge] = Field(default_factory=list)
    viewport: Viewport         = Field(default_factory=Viewport)


# ── PCS result block ───────────────────────────────────────────────────────────

class PillarVector(BaseModel):
    likelihood:    Optional[float] = None
    severity:      Optional[float] = None
    vulnerability: Optional[float] = None
    uncertainty:   Optional[float] = None
    autonomy:      Optional[float] = None
    evolution:     Optional[float] = None


class PCSResultBlock(BaseModel):
    pcs_mult:                Optional[float]     = None
    pcs_floor:               Optional[float]     = None
    pcs_final:               Optional[float]     = None
    tier:                    Optional[str]        = None   # LOW|MODERATE|HIGH|CRITICAL
    gate:                    Optional[str]        = None   # APPROVED|REVIEW|BLOCKED
    pillar_vector:           PillarVector         = Field(default_factory=PillarVector)
    unmet_veto_constraints:  List[str]            = Field(default_factory=list)
    last_scored_at:          Optional[datetime]   = None
    raw_breakdown:           Optional[Dict[str, Any]] = None


# ── Validation fixture block ───────────────────────────────────────────────────

class ValidationBlock(BaseModel):
    ground_truth_gate:   Optional[str]  = None
    attested_failures:   List[str]      = Field(default_factory=list)
    sources:             List[str]      = Field(default_factory=list)


# ── Top-level document ─────────────────────────────────────────────────────────

class DesignStudioDocument(BaseModel):
    schema_version:    str              = "1.0.0"
    framework_version: str              = "1.0.0"
    deployment_id:     str              = ""
    deployment_name:   str              = ""
    created_at:        Optional[datetime] = None
    updated_at:        Optional[datetime] = None
    registry:          RegistryBlock    = Field(default_factory=RegistryBlock)
    graph:             GraphBlock       = Field(default_factory=GraphBlock)
    pcs_result:        PCSResultBlock   = Field(default_factory=PCSResultBlock)
    validation:        Optional[ValidationBlock] = None


# ── Score request / response (minimal API surface) ────────────────────────────

class ScoreRequest(BaseModel):
    registry: RegistryBlock


class ScoreResponse(BaseModel):
    pcs_result: PCSResultBlock
    warnings:   List[str] = Field(default_factory=list)
