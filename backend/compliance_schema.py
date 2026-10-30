"""
ST-AI / ASTRA Platform — Phase 0 data contracts.

These are the shared definitions every later phase (Design, Runtime,
Decommissioning, Integration) depends on. No endpoint or engine logic
lives here yet — this module only fixes the shapes so later tasks can't
drift from each other. Four contracts, per the Phase 0 brief:

  1. Two-score data model — DesignRiskAssessment (design-time, one per
     design) vs RuntimeLiveScore (runtime, continuous per deployed
     instance). Kept as separate classes on purpose: they must never
     collapse into one "risk score" field.
  2. DeploymentDescription — the portable JSON a user uploads to
     auto-populate the canvas (Task 1.1). Only structural fields exist
     on this model; it has no field through which a veto-class
     constraint could arrive pre-satisfied, so "never auto-set to
     Satisfied" is a structural guarantee, not a convention someone can
     forget to enforce in the import code.
  3. ComplianceDomain / RegulationRule — the pluggable rule-set
     registry per domain (Task 1.2/1.3), each rule carrying a citation
     so a red flag can show its source. Citations here reuse the same
     standards already catalogued in framework/crosswalk.py rather than
     inventing a second reference list.
  4. CompiledContract — the artefact `Compile` produces once a design
     is all-green (Task 1.5), shaped to match the ASTRA Behavioural
     Contract (object_type distinguishes MODEL vs AGENT) so Phase 2 can
     build one reconciliation engine instead of two.
"""
from __future__ import annotations

import hashlib
import json as _json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schema import ActorSubtype, PillarVector


# ── 1. Two-score data model ────────────────────────────────────────────────

class RiskStatus(str, Enum):
    RED   = "RED"
    AMBER = "AMBER"
    GREEN = "GREEN"


class ElementVerdict(BaseModel):
    node_id:  str
    status:   RiskStatus
    reason:   str           = ""
    citation: Optional[str] = None   # e.g. "GDPR Art. 35"
    rule_id:  Optional[str] = None   # RegulationRule.rule_id, when sourced from a domain rule
    # Where the rule comes from, so a reader can tell a regulation from an organisation policy (instrument "ORG_POLICY").
    instrument: Optional[str] = None
    check_type: Optional[str] = None
    # Explanation for the studio (never signed, see UNSIGNED_VERDICT_FIELDS): what the rule asks for, and the step that would fix it.
    title:       Optional[str] = None
    requirement: Optional[str] = None
    fix:         Optional[Dict[str, Any]] = None
    # Every element a GRAPH rule flagged (node_id is the first); lets a studio ring them all.
    flagged_node_ids: List[str] = Field(default_factory=list)


# Added to a verdict after contracts were first signed, so a stored contract does not carry them. They explain a finding to the reader and are not part of what
# a contract attests, so they are left out of the hashed payload: signing and verifying a contract gives the same hash with or without them.
UNSIGNED_VERDICT_FIELDS = ("instrument", "check_type", "title", "requirement", "fix")


class ReviewOut(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    note:     str
    reviewer: str
    role:     str
    at:       datetime
    pcs:      float
    tier:     str
    gate:     str
    current:  bool                   # made of this very version of the design (a change to the design makes it lapse)


class ReviewState(BaseModel):
    """Where a design stands on the human review the gate may ask for. Computed per request, never signed."""
    required:    bool                # the gate says REQUIRES_REVIEW
    gate:        str
    pcs:         float
    tier:        str
    fingerprint: str
    approved:    bool = False        # the newest review of this version approves it
    rejected:    bool = False
    reviews:     List[ReviewOut] = Field(default_factory=list)


class Finding(BaseModel):
    """One thing wrong with the design itself, found by checking it against the Secure Tropos model (not a regulation or a policy)."""
    finding_id: str
    severity:   Literal["error", "warning"]
    title:      str
    detail:     str                      # what is wrong, in plain words
    why:        str = ""                 # why it matters
    blocks:     List[str] = Field(default_factory=list)   # "gate" (the PCS gate) and/or "compile"
    node_id:    Optional[str] = None     # the element it is about, when there is one
    fix:        Optional[Dict[str, Any]] = None


class ScoreBreakdownEntry(BaseModel):
    category: str                      # regulation/instrument name, e.g. "GDPR"
    status:   RiskStatus
    passed:   int = 0
    failed:   int = 0
    unknown:  int = 0


class DesignRiskAssessment(BaseModel):
    """Computed at design time by POST /api/designs/{id}/assess (Task 1.3)."""
    assessment_id:   str                       = ""
    deployment_id:   str                       = ""
    domain:          str                       = ""   # ComplianceDomain.domain_id assessed against
    overall_status:  RiskStatus                = RiskStatus.AMBER
    score_breakdown: List[ScoreBreakdownEntry] = Field(default_factory=list)
    element_verdicts: List[ElementVerdict]     = Field(default_factory=list)
    assessed_at:     Optional[datetime]        = None
    formal_findings: List[Finding]             = Field(default_factory=list)   # never signed (see canonical_payload)
    review:          Optional[ReviewState]     = None                           # never signed


class RuntimeLiveScore(BaseModel):
    """
    Computed continuously per deployed instance (Phase 2). Mirrors the
    existing PCS/LiveRisk non-compensable shape: live_score is always
    max(composite, floor) — a high floor term can never be averaged away
    by a low composite term, same invariant as PCSResultBlock's
    pcs_mult/pcs_floor/pcs_final today.
    """
    instance_id:      str                  = ""
    contract_id:      str                  = ""
    composite:        Optional[float]      = None
    floor:            Optional[float]      = None
    live_score:       Optional[float]      = None
    tier:             Optional[str]        = None
    gate:             Optional[str]        = None
    pillar_vector:    PillarVector         = Field(default_factory=PillarVector)
    active_incidents: List[str]            = Field(default_factory=list)
    last_updated_at:  Optional[datetime]   = None

    @model_validator(mode="after")
    def _compute_live_score(self) -> "RuntimeLiveScore":
        if self.composite is not None and self.floor is not None:
            self.live_score = max(self.composite, self.floor)
        elif self.composite is not None:
            self.live_score = self.composite
        elif self.floor is not None:
            self.live_score = self.floor
        return self


# ── 2. JSON deployment-description schema (Task 1.1 input) ────────────────

class DeploymentDescriptionDepartment(BaseModel):
    temp_id:            str
    name:                str
    reports_to_temp_id: Optional[str] = None


class DeploymentDescriptionActor(BaseModel):
    temp_id:             str
    subtype:             ActorSubtype
    identity:            str           = ""
    department_temp_id:  Optional[str] = None


class DeploymentDescriptionAIModel(BaseModel):
    temp_id:              str
    name:                 str
    model_type:           str = "LLM"
    ai_criticality:       str = "OPERATIONAL"
    data_sensitivity:     str = "INTERNAL"
    hosting_environment:  str = "TYPE_1_INHOUSE"
    domain:               str = ""


class DeploymentDescriptionEnvironment(BaseModel):
    temp_id:     str
    name:        str
    description: str = ""


class DeploymentDescription(BaseModel):
    """
    The portable JSON a user/colleague uploads to auto-populate the
    canvas (POST /api/designs/import, Task 1.1).

    Only STRUCTURAL fields are accepted here: actors, AI model,
    deployment environment, departments. There is deliberately no field
    on this model for constraint/veto status — a deployment description
    cannot claim DPIA, HITL, the challenge mechanism, etc. are satisfied
    no matter what the uploaded JSON contains. json_to_canvas_graph()
    (Task 1.1) seeds every constraint from schema.GovernanceState's
    default, which is already NOT_YET_DETERMINED for every veto-class
    ID — the same rule the chatbot's SYSTEM_PROMPT already follows in
    chat.py, now enforced structurally for file import too.
    """
    schema_version:          str                                     = "1.0"
    deployment_name:         str                                     = ""
    description:             str                                     = ""
    assessment_domain:       Optional[str]                           = None  # ComplianceDomain.domain_id
    departments:              List[DeploymentDescriptionDepartment]  = Field(default_factory=list)
    actors:                   List[DeploymentDescriptionActor]       = Field(default_factory=list)
    ai_models:                 List[DeploymentDescriptionAIModel]    = Field(default_factory=list)
    deployment_environments:   List[DeploymentDescriptionEnvironment] = Field(default_factory=list)


# ── 3. Regulation / domain registry schema ─────────────────────────────────

class RuleSeverity(str, Enum):
    REQUIRED    = "REQUIRED"     # veto-equivalent — a fail here cannot be averaged away
    RECOMMENDED = "RECOMMENDED"  # modulating-equivalent


class RegulationRule(BaseModel):
    rule_id:               str
    instrument:             str              # e.g. "GDPR", "EU AI Act", "ORG_POLICY"
    citation:                str              # e.g. "Art. 35"
    title:                   str              = ""
    description:             str              = ""
    severity:                RuleSeverity     = RuleSeverity.REQUIRED
    # When this rule is really an existing veto/modulating Security Constraint
    # wearing a regulation's citation, link it instead of duplicating the
    # evidence-gate logic — Task 1.3's "one evidence-gate system" rule.
    maps_to_constraint_id:   Optional[str]    = None
    # CONSTRAINT: graded from maps_to_constraint_id. ATTESTATION: satisfied by a Regulatory
    # requirement node for this instrument + citation, Satisfied with evidence.
    # GRAPH: a data-driven condition on the design (see rule_checks.py).
    check_type:              Literal["CONSTRAINT", "ATTESTATION", "GRAPH"] = "CONSTRAINT"
    check_config:            Dict[str, Any] = Field(default_factory=dict)
    # How the rule is cited on a verdict. Defaults to "<instrument> <citation>"; an organisation
    # policy is cited as "ORG_POLICY: <title>".
    citation_label:          Optional[str] = None


class ComplianceDomain(BaseModel):
    domain_id:   str          # "HEALTHCARE" | "FINANCIAL_SERVICES" | "GENERAL" | ...
    name:        str
    description: str          = ""
    subject:     Literal["MODEL", "AGENT"] = "MODEL"   # what the domain assesses
    rule_set:    List[RegulationRule] = Field(default_factory=list)


# ── The design a GRAPH rule inspects (the same shape for models and agents) ────

class DesignNodeIn(BaseModel):
    id:      str
    type:    str                                  # e.g. "AI_MODEL" (model design) or "tool" (agent design)
    props:   Dict[str, Any] = Field(default_factory=dict)
    primary: bool = False


class DesignEdgeIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_id: str = Field(alias="from")
    to_id:   str = Field(alias="to")
    label:   str = ""


class DesignGraphIn(BaseModel):
    nodes: List[DesignNodeIn] = Field(default_factory=list)
    edges: List[DesignEdgeIn] = Field(default_factory=list)


# The domain/rule data itself is no longer defined here: it lives in PostgreSQL
# (seeded from db/seed.py) and is read by regulations.py, which hands the engine
# a ComplianceDomain built from approved rules.


# ── 4. Contract file format (Task 1.5 artefact) ────────────────────────────

class ContractStatus(str, Enum):
    DRAFT      = "DRAFT"
    ACTIVE     = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED    = "REVOKED"


class CompiledContract(BaseModel):
    """
    What POST /api/designs/{id}/compile produces once a design is
    all-green (Task 1.5). object_type distinguishes MODEL vs AGENT so
    Phase 2's reconciliation engine can stay a single parameterised
    module rather than two parallel ones — same shape the ASTRA
    Behavioural Contract already uses.
    """
    contract_id:          str
    version:               str                 = "1.0.0"
    object_type:           str                 = "MODEL"   # "MODEL" | "AGENT"
    deployment_id:         str
    domain:                str                 = ""
    design_snapshot:       Dict[str, Any]               # the full DesignStudioDocument at compile time
    risk_assessment:       DesignRiskAssessment
    issued_at:              datetime
    issued_by:              Optional[str]       = None
    status:                 ContractStatus      = ContractStatus.ACTIVE
    contract_hash:          str                 = ""      # sha256 over everything above, computed by compute_contract_hash()

    def canonical_payload(self) -> Dict[str, Any]:
        """The exact payload that gets hashed into contract_hash."""
        payload = self.model_dump(mode="json", exclude={"contract_hash"})
        assessment = payload.get("risk_assessment") or {}
        assessment.pop("formal_findings", None)
        assessment.pop("review", None)
        for verdict in assessment.get("element_verdicts") or []:
            for name in UNSIGNED_VERDICT_FIELDS:
                verdict.pop(name, None)
        return payload


def compute_contract_hash(contract: CompiledContract) -> str:
    canonical = _json.dumps(contract.canonical_payload(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assert_compilable(assessment: DesignRiskAssessment) -> None:
    """
    Server-side compile gate (Task 1.5): refuses unless overall_status is
    GREEN, full stop, even via a direct API call — same principle as the
    non-empty-evidence rule schema.py already enforces on every /score call.
    """
    if assessment.overall_status != RiskStatus.GREEN:
        raise ValueError(
            f"Cannot compile: overall_status is {assessment.overall_status.value}, not GREEN. "
            f"Every element must be validated before a contract can be produced."
        )
    # "pcs-gate" restates the score, which compile_design checks on its own with the figure in the message; it is not a flaw in the design.
    open_errors = [f for f in assessment.formal_findings if f.severity == "error" and "compile" in f.blocks and f.finding_id != "pcs-gate"]
    if open_errors:
        raise ValueError(
            f"Cannot compile: the design is not correct against the formal model ({len(open_errors)} open): "
            + "; ".join(f.title for f in open_errors[:5]) + (" …" if len(open_errors) > 5 else "") + "."
        )
