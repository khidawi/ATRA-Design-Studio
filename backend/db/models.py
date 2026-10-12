"""
ORM models. Only what each task needs is added, one migration at a time.

Task 1: the organisation. There is exactly one ("default") until Task 8 adds
users and sign-in; every table added later carries organisation_id so the
move to several organisations needs no data migration.

Task 2: regulations, rules and domains. organisation_id NULL means shared
reference data (GDPR, EU AI Act, ...); a value means the row belongs to that
organisation (its own policies and domains, Task 4).
"""
import uuid
from datetime import date, datetime
from typing import Optional

from typing import Any, Dict, List

from sqlalchemy import BigInteger, Boolean, CheckConstraint, Date, DateTime, Float, ForeignKey, Identity, Integer, String, Text, UniqueConstraint, Uuid, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Regulation(Base):
    """A source of obligations: a law, a standard, or the organisation's own policy."""

    __tablename__ = "regulations"
    __table_args__ = (
        CheckConstraint("kind IN ('REGULATION', 'STANDARD', 'ORG_POLICY')", name="ck_regulations_kind"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # The label shown on a verdict and in the per-regulation breakdown, e.g. "EU AI Act".
    instrument: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    source_url: Mapped[Optional[str]] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Rule(Base):
    """One obligation, with the citation that lets a red flag show its source."""

    __tablename__ = "rules"
    __table_args__ = (
        CheckConstraint("severity IN ('REQUIRED', 'RECOMMENDED')", name="ck_rules_severity"),
        CheckConstraint("status IN ('DRAFT', 'APPROVED', 'RETIRED')", name="ck_rules_status"),
        CheckConstraint("check_type IN ('CONSTRAINT', 'ATTESTATION', 'GRAPH')", name="ck_rules_check_type"),
        CheckConstraint("subject IN ('MODEL', 'AGENT')", name="ck_rules_subject"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Stable human-readable id (e.g. GDPR-ART35-DPIA); what verdicts and contracts refer to.
    rule_key: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    regulation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("regulations.id"), nullable=False)
    organisation_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("organisations.id"))
    citation: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # Links the rule to the existing Security Constraint evidence gate (one gate, more sources).
    maps_to_constraint_id: Mapped[Optional[str]] = mapped_column(String(32))
    # How the rule is checked (Task 3):
    #   CONSTRAINT  - graded from the Security Constraint named in maps_to_constraint_id
    #   ATTESTATION - satisfied by a Regulatory requirement node for this regulation and clause,
    #                 marked Satisfied with evidence
    #   GRAPH       - a data-driven condition on the design itself (see rule_checks.py)
    check_type: Mapped[str] = mapped_column(String(16), nullable=False, server_default="CONSTRAINT")
    check_config: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    # What kind of design the rule checks. A domain only holds rules for its own subject.
    subject: Mapped[str] = mapped_column(String(8), nullable=False, server_default="MODEL")
    # Organisation policies (Task 4) can apply to every domain of their subject instead of
    # being listed in each one, so a domain added later is covered too.
    applies_to_all: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    # The form an organisation policy was authored in, so it can be edited again.
    spec: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    # Where an extracted rule came from (Task 5): the page and the verbatim passage a reviewer approved.
    source_url: Mapped[Optional[str]] = mapped_column(String(500))
    source_quote: Mapped[Optional[str]] = mapped_column(Text)
    # Only APPROVED rules are evaluated. LLM-extracted rules (Task 5) start as DRAFT.
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="APPROVED")
    origin: Mapped[str] = mapped_column(String(16), nullable=False, server_default="SEED")
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Domain(Base):
    """An assessment domain: the rule set a design is checked against."""

    __tablename__ = "domains"
    __table_args__ = (CheckConstraint("subject IN ('MODEL', 'AGENT')", name="ck_domains_subject"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    domain_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    organisation_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("organisations.id"))
    # What the domain assesses: an AI model deployment (the Model studio) or an agent design.
    subject: Mapped[str] = mapped_column(String(8), nullable=False, server_default="MODEL")
    position: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DomainRule(Base):
    """Which rules a domain contains, in the order verdicts and the breakdown list them."""

    __tablename__ = "domain_rules"

    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True)
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False)


class AppSetting(Base):
    """Small key/value store; used to remember which reference-data seed has been applied."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False)


class RcrProfile(Base):
    """A requirement registry for the agent design-time RCR score (rcr_engine.py)."""

    __tablename__ = "rcr_profiles"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    profile_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # c_p: the share of credit a half-handled requirement receives
    partial_credit: Mapped[float] = mapped_column(Float, nullable=False, server_default="0.5")
    organisation_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("organisations.id"))
    position: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")


class RcrRequirement(Base):
    __tablename__ = "rcr_requirements"
    __table_args__ = (
        UniqueConstraint("profile_id", "req_key", name="uq_rcr_requirement"),
        CheckConstraint("cls IN ('veto', 'ordinary')", name="ck_rcr_cls"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("rcr_profiles.id", ondelete="CASCADE"), nullable=False)
    req_key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    instrument: Mapped[str] = mapped_column(String(64), nullable=False)
    cls: Mapped[str] = mapped_column(String(8), nullable=False)
    weight: Mapped[int] = mapped_column(Integer, nullable=False)
    phi: Mapped[Optional[float]] = mapped_column(Float)
    position: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # A condition on the agent design (rule_checks.py). When set, the design itself supplies the status and
    # evidence; when null the status and evidence are declared per design.
    design_check: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    unsatisfied_declared: Mapped[str] = mapped_column(String(10), nullable=False, server_default="Gap")
    # The declaration a new design starts with (demo content for the seeded profiles).
    default_declaration: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)


class IngestionRun(Base):
    """One pass over a source page (or pasted text) that asks the local model for candidate rules (Task 5)."""

    __tablename__ = "ingestion_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    regulation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("regulations.id"), nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(String(500))
    source_kind: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    fetched_chars: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    source_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    passages_total: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    passage_offset: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    passages_planned: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    passages_done: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    proposed: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    kept: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    dropped_unverified: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    dropped_duplicate: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class RuleCandidate(Base):
    """A rule the model proposed. Never evaluated: it becomes a rule only when a person approves it."""

    __tablename__ = "rule_candidates"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ingestion_runs.id", ondelete="CASCADE"), nullable=False)
    regulation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("regulations.id"), nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(String(500))
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    citation: Mapped[str] = mapped_column(String(120), nullable=False)
    # Verified by the program to appear word for word in the source before the candidate is stored.
    quote: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="PENDING")
    rule_key: Mapped[Optional[str]] = mapped_column(String(80))
    decision_note: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class Design(Base):
    """A saved design (Task 6). `document` is what the studio edits: nodes, edges and its id counter."""

    __tablename__ = "designs"
    __table_args__ = (CheckConstraint("subject IN ('MODEL', 'AGENT')", name="ck_designs_subject"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    design_key: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    subject: Mapped[str] = mapped_column(String(8), nullable=False, server_default="MODEL")
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    domain_key: Mapped[str] = mapped_column(String(64), nullable=False)
    document: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # Bumped on every save; a save that names an older version is refused so two tabs cannot overwrite each other.
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Contract(Base):
    """A compiled contract, stored exactly as issued. Never edited; the hash can be re-verified at any time."""

    __tablename__ = "contracts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    contract_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    design_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("designs.id", ondelete="SET NULL"))
    object_type: Mapped[str] = mapped_column(String(8), nullable=False, server_default="MODEL")
    deployment_id: Mapped[str] = mapped_column(String(80), nullable=False)
    origin: Mapped[str] = mapped_column(String(10), nullable=False, server_default="COMPILED")
    document: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    contract_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Current state, kept beside the immutable document so the hash never has to change (Task 7b).
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="ACTIVE")
    status_reason: Mapped[Optional[str]] = mapped_column(Text)
    status_by: Mapped[Optional[str]] = mapped_column(String(120))
    status_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    superseded_by: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Agent(Base):
    """An agent in the inventory (Task 7). Rows come from a ratified design, a manual registration, or the demo set."""

    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("organisation_id", "agent_key", name="uq_agents_org_key"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_key: Mapped[str] = mapped_column(String(80), nullable=False)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    owner: Mapped[Optional[str]] = mapped_column(String(120))
    framework: Mapped[str] = mapped_column(String(80), nullable=False, server_default="Not built yet")
    tools_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    mode: Mapped[str] = mapped_column(String(12), nullable=False, server_default="NOT_RUNNING")
    origin: Mapped[str] = mapped_column(String(10), nullable=False)
    design_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("designs.id", ondelete="SET NULL"))
    note: Mapped[Optional[str]] = mapped_column(String(200))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))   # last time the runtime SDK reported it (Task 12)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Finding(Base):
    """A divergence between what an agent did and what its contract allows (Task 7c)."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    seq: Mapped[int] = mapped_column(Integer, Identity(start=1001), unique=True)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    agent_key: Mapped[str] = mapped_column(String(80), nullable=False)
    contract_id: Mapped[Optional[str]] = mapped_column(String(64))
    contract_version: Mapped[Optional[str]] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(8), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    class_code: Mapped[str] = mapped_column(String(16), nullable=False)
    observed: Mapped[str] = mapped_column(Text, nullable=False)
    permitted: Mapped[str] = mapped_column(Text, nullable=False)
    element: Mapped[str] = mapped_column(String(40), nullable=False)
    threat: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence: Mapped[str] = mapped_column(String(200), nullable=False)
    event: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    source: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(14), nullable=False, server_default="OPEN")
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(120))
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    test_spec: Mapped[Optional[str]] = mapped_column(Text)
    halt_requested_by: Mapped[Optional[str]] = mapped_column(String(120))
    halt_requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DriftItem(Base):
    """A proposed change to an agent compared with its ratified contract, waiting for a decision (Task 7c)."""

    __tablename__ = "drift_items"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    agent_key: Mapped[str] = mapped_column(String(80), nullable=False)
    contract_id: Mapped[Optional[str]] = mapped_column(String(64))
    design_key: Mapped[Optional[str]] = mapped_column(String(40))
    source: Mapped[str] = mapped_column(String(10), nullable=False)
    source_label: Mapped[str] = mapped_column(String(200), nullable=False)
    from_version: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    policy: Mapped[str] = mapped_column(String(8), nullable=False, server_default="block")
    proposed: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    changes: Mapped[List[Dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    impact: Mapped[List[str]] = mapped_column(JSONB, nullable=False)
    rcr_before: Mapped[Optional[float]] = mapped_column(Float)
    rcr_after: Mapped[Optional[float]] = mapped_column(Float)
    gate_after: Mapped[Optional[str]] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="OPEN")
    decided_by: Mapped[Optional[str]] = mapped_column(String(120))
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[Optional[str]] = mapped_column(Text)
    new_contract_id: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CoverageAssignment(Base):
    """Who owns closing a threat check on the coverage scorecard, and by when (Task 7d). Statuses are never stored."""

    __tablename__ = "coverage_assignments"
    __table_args__ = (UniqueConstraint("organisation_id", "code", name="uq_coverage_assignment"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    code: Mapped[str] = mapped_column(String(40), nullable=False)
    owner: Mapped[Optional[str]] = mapped_column(String(120))
    due_date: Mapped[Optional[date]] = mapped_column(Date)
    note: Mapped[Optional[str]] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EvidencePack(Base):
    """A generated Trust report or Assurance Pack, stored exactly as hashed and chained to the one before (Task 7e)."""

    __tablename__ = "evidence_packs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    seq: Mapped[int] = mapped_column(Integer, Identity(start=1001), unique=True)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    template: Mapped[str] = mapped_column(String(10), nullable=False)
    period_label: Mapped[str] = mapped_column(String(40), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(120), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    content: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_pack_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    pack_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    claims: Mapped[int] = mapped_column(Integer, nullable=False)
    evidenced: Mapped[int] = mapped_column(Integer, nullable=False)
    gaps: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False)


class User(Base):
    """A person who can sign in (Task 8). Local account: the password is kept only as a scrypt hash."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin', 'compliance', 'engineer', 'auditor')", name="ck_users_role"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(12), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(300), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class UserSession(Base):
    """A sign-in. Only a hash of the cookie's token is stored."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class AuditEvent(Base):
    """One entry in the hash-chained audit log. Only ever appended (see audit.py)."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    seq: Mapped[int] = mapped_column(Integer, Identity(start=1), unique=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_name: Mapped[str] = mapped_column(String(200), nullable=False)
    actor_role: Mapped[Optional[str]] = mapped_column(String(12))
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    outcome: Mapped[str] = mapped_column(String(12), nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class ApiKey(Base):
    """A credential for a pipeline or collector (Task 11). Only a hash is stored; the key is shown once, at creation."""

    __tablename__ = "api_keys"
    __table_args__ = (CheckConstraint("role IN ('engineer', 'auditor')", name="ck_api_keys_role"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(12), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    revoked_by: Mapped[Optional[str]] = mapped_column(String(200))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class RuntimeEvent(Base):
    """One thing an agent did, as reported by the runtime SDK, with how it compared with its active contract (Task 12)."""

    __tablename__ = "runtime_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    seq: Mapped[int] = mapped_column(BigInteger, Identity(start=1), unique=True)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    agent_key: Mapped[str] = mapped_column(String(80), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")
    attrs: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    verdict: Mapped[str] = mapped_column(String(14), nullable=False)
    contract_version: Mapped[Optional[str]] = mapped_column(String(16))
    finding_key: Mapped[Optional[str]] = mapped_column(String(12))
    reported_by: Mapped[str] = mapped_column(String(200), nullable=False)


class CompanyNode(Base):
    """One thing in the organisation model: a department, person, role, outside party, AI agent or model, data store, or a
    modelling element (goal, operation, policy, threat, protection, rule, environment, breach-plan step). The views are drawn from these."""

    __tablename__ = "company_nodes"
    __table_args__ = (UniqueConstraint("organisation_id", "ext_id", name="uq_company_nodes_org_ext"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    ext_id: Mapped[str] = mapped_column(String(64), nullable=False)          # the company's own id (EMP-1042, D-CX): what an import matches on
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    props: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class CompanyEdge(Base):
    """A connection between two nodes (identified by ext_id): works with, hands a task to, reads, performs, targets, mitigates, and so on."""

    __tablename__ = "company_edges"
    __table_args__ = (UniqueConstraint("organisation_id", "from_ext", "to_ext", "kind", "label", name="uq_company_edges"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    from_ext: Mapped[str] = mapped_column(String(64), nullable=False)
    to_ext: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    label: Mapped[str] = mapped_column(String(80), nullable=False, server_default="")
    props: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CompanyDraftCache(Base):
    """A draft the organisation assistant produced, kept against a fingerprint of everything that determines it (the description, the prompt, the
    schema, the generation settings and the model), so the same description always gives the same draft. Not organisation data: safe to delete."""

    __tablename__ = "company_draft_cache"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    raw: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RemovedContract(Base):
    """What is left of a contract that was removed together with its agent or model: enough for an evidence pack that cited it to say so (Task 15)."""

    __tablename__ = "removed_contracts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    contract_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    object_type: Mapped[str] = mapped_column(String(8), nullable=False)
    deployment_id: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False, server_default="")
    contract_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    removed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")
    removed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RepoConnection(Base):
    """A source repository the organisation has connected so its agent definitions can be found and kept in step. The access token and the
    webhook secret are kept encrypted (repo_connect.py); neither is ever returned by the API after it was created."""

    __tablename__ = "repo_connections"
    __table_args__ = (UniqueConstraint("organisation_id", "url", "branch", "subpath", name="uq_repo_connection"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(12), nullable=False)               # github | gitlab | bitbucket | azure | git
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    branch: Mapped[str] = mapped_column(String(120), nullable=False, server_default="")      # empty: the repository's default branch
    subpath: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")     # scan only this folder
    token_enc: Mapped[Optional[str]] = mapped_column(Text)
    webhook_secret_enc: Mapped[Optional[str]] = mapped_column(Text)
    auto_sync: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    include_tests: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="NEVER")  # NEVER | OK | ERROR
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_commit: Mapped[Optional[str]] = mapped_column(String(40))
    last_error: Mapped[Optional[str]] = mapped_column(String(400))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RepoScan(Base):
    """One scan of a connected repository: the commit that was read and what was found in it."""

    __tablename__ = "repo_scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repo_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    trigger: Mapped[str] = mapped_column(String(12), nullable=False)                 # manual | webhook
    result: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RepoImport(Base):
    """Which repository definition an agent was last imported from, and the fingerprint of it, so a later scan can tell what changed."""

    __tablename__ = "repo_imports"
    __table_args__ = (UniqueConstraint("connection_id", "agent_key", name="uq_repo_import"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repo_connections.id", ondelete="CASCADE"), nullable=False)
    agent_key: Mapped[str] = mapped_column(String(80), nullable=False)
    path: Mapped[str] = mapped_column(String(300), nullable=False)
    line: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(10), nullable=False)               # created | updated | drift
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IdpConnection(Base):
    """An identity provider (Entra ID, Okta, Auth0, Keycloak) the organisation has connected to find the service accounts and OAuth clients tagged as AI agents.
    Only read access. The credential used to read it is kept encrypted (idp_connect.py) and is never returned by the API."""

    __tablename__ = "idp_connections"
    __table_args__ = (UniqueConstraint("organisation_id", "name", name="uq_idp_connection_name"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(12), nullable=False)               # entra | okta | auth0 | keycloak
    account: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")   # the tenant or organisation name the provider reported
    config: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)           # tenant, client id, address: nothing secret
    secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    rule: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)             # how an identity is marked as an agent
    status: Mapped[str] = mapped_column(String(10), nullable=False, server_default="NEVER")
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[Optional[str]] = mapped_column(String(400))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IdpScan(Base):
    """One reading of an identity provider: the identities tagged as agents, and what they hold."""

    __tablename__ = "idp_scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("idp_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    result: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IdpImport(Base):
    """Which identity an agent was last imported from, and the fingerprint of its permissions, so a later scan can tell a permission was added."""

    __tablename__ = "idp_imports"
    __table_args__ = (UniqueConstraint("connection_id", "agent_key", name="uq_idp_import"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    connection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("idp_connections.id", ondelete="CASCADE"), nullable=False)
    agent_key: Mapped[str] = mapped_column(String(80), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(10), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TelemetrySettings(Base):
    """How the organisation wants OpenTelemetry spans read: how an agent is recognised, and whether an agent the platform has not seen is registered."""

    __tablename__ = "telemetry_settings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False, unique=True)
    agent_from_service: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))   # a span with no agent name belongs to the agent named like its service
    discover: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))


class TelemetryIngest(Base):
    """One request to the OTLP endpoint and what became of its spans: kept for two weeks so the person setting telemetry up can see what is understood."""

    __tablename__ = "telemetry_ingest"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False, index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    key_name: Mapped[str] = mapped_column(String(200), nullable=False)
    spans: Mapped[int] = mapped_column(Integer, nullable=False)
    mapped: Mapped[int] = mapped_column(Integer, nullable=False)
    ignored: Mapped[int] = mapped_column(Integer, nullable=False)
    unattributed: Mapped[int] = mapped_column(Integer, nullable=False)
    agents: Mapped[int] = mapped_column(Integer, nullable=False)
    events: Mapped[int] = mapped_column(Integer, nullable=False)
    divergent: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    invalid: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    unknown: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    waiting: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    samples: Mapped[List[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")


class ModelMonitor(Base):
    """A production monitor for one AI model: what its inputs and outputs look like when it is really used, compared with what normal looks like.
    Holds statistics only (model_stats.py): never the records themselves."""

    __tablename__ = "model_monitors"
    __table_args__ = (UniqueConstraint("organisation_id", "key", name="uq_model_monitor_key"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    organisation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organisations.id"), nullable=False)
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    design_key: Mapped[Optional[str]] = mapped_column(String(40))                 # the model design in the AI Models module this watches
    task: Mapped[str] = mapped_column(String(16), nullable=False)                 # classification | regression | generative
    spec: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    thresholds: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    baseline: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    buffer: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)               # what the learning phase has accumulated, until the baseline is frozen
    baseline_target: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1000")
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, server_default="30")
    status: Mapped[str] = mapped_column(String(12), nullable=False, server_default="LEARNING")   # LEARNING | OK | WATCH | DRIFT | LOW_VOLUME | NO_DATA
    reasons: Mapped[List[Any]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    signals: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    records_total: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    rejected_total: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    last_record_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_eval_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ModelWindow(Base):
    """One hour of a monitor's aggregates."""

    __tablename__ = "model_windows"
    __table_args__ = (UniqueConstraint("monitor_id", "window_start", name="uq_model_window"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    monitor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("model_monitors.id", ondelete="CASCADE"), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acc: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)


class ModelIncident(Base):
    """An incident raised by production monitoring. A person changes its status; monitoring only opens it and notes when the signal has gone."""

    __tablename__ = "model_incidents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    seq: Mapped[int] = mapped_column(Integer, Identity(start=1), unique=True)
    monitor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("model_monitors.id", ondelete="CASCADE"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)                 # DRIFT_DETECTION | BIAS_BREACH | MODEL_FAILURE
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    detail: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    status: Mapped[str] = mapped_column(String(14), nullable=False, server_default="OPEN")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recovered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[Optional[str]] = mapped_column(String(200))
