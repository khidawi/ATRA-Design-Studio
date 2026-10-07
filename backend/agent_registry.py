"""
Agent inventory and ratification (Task 7a).

An agent enters the inventory in one of three ways:
  * DESIGNED   - a design from the Agent design studio is ratified. The server re-runs the OWASP analysis
                 and the design-time RCR score on the stored design (never on what a page claims), refuses a
                 Blocked design, and stores an agent contract with the score and analysis in its snapshot.
  * REGISTERED - registered by hand (name, owner, framework). Finding agents in a repository, telemetry or an
                 identity provider needs collectors, which do not exist yet.
  * DEMO       - the sample inventory from the prototype, loaded on request and removable, so the other screens
                 can be explored. These rows are labelled as demo data everywhere.

An agent with no owner is UNOWNED. Ratifying records the signed-in person (Task 8).
Contract status changes (superseded, revoked) are not implemented: the status is part of what the contract
hash covers, so that needs a decision of its own (Task 7b).
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import agent_contract
import demo_data
from agent_analysis import AgentAnalyseRequest, analyse_agent
from auth import AuthUser, current_user
from compliance_schema import CompiledContract, DesignGraphIn, DesignRiskAssessment, RiskStatus, compute_contract_hash
from db.models import Agent, Contract, Design, DriftItem, Finding
from db.session import get_session
from design_store import store_contract
from organisation import current_organisation
from rcr import Declaration, RcrRequest, score_agent

router = APIRouter(prefix="/api/agents", tags=["agents"])

Status = Literal["ASSURED", "TO_RATIFY", "DESIGNED", "UNOWNED"]
AGENT_DOMAIN = "OWASP_AGENTIC"


def agent_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:80]


class AgentOut(BaseModel):
    agent_key: str
    name: str
    owner: Optional[str]
    framework: str
    tools_count: int
    status: Status
    mode: str
    origin: str
    design_key: Optional[str]
    note: Optional[str]
    last_seen_at: Optional[datetime] = None
    last_finding: Optional[str]
    contract_count: int
    updated_at: datetime


def _out(session: Session, a: Agent) -> AgentOut:
    design_key = session.scalar(select(Design.design_key).where(Design.id == a.design_id)) if a.design_id else None
    contracts = session.scalar(select(func.count()).select_from(Contract).where(
        Contract.object_type == "AGENT", Contract.deployment_id == a.agent_key)) or 0
    latest = session.scalar(select(Finding).where(Finding.agent_key == a.agent_key).order_by(Finding.created_at.desc(), Finding.seq.desc()))
    last = f"{latest.severity} \u00b7 {latest.created_at.strftime('%d %b %H:%M')}" if latest and a.origin != "DEMO" else None
    return AgentOut(agent_key=a.agent_key, name=a.name, owner=a.owner, framework=a.framework, tools_count=a.tools_count,
                    status=a.status, mode=a.mode, origin=a.origin, design_key=design_key, note=a.note, last_seen_at=a.last_seen_at, last_finding=last,
                    contract_count=contracts, updated_at=a.updated_at)


def _get(session: Session, key: str) -> Agent:
    a = session.scalar(select(Agent).where(Agent.agent_key == key))
    if a is None:
        raise HTTPException(status_code=404, detail="No such agent.")
    return a


@router.get("", response_model=List[AgentOut])
def list_agents(session: Session = Depends(get_session)) -> List[AgentOut]:
    return [_out(session, a) for a in session.scalars(select(Agent).order_by(Agent.created_at, Agent.name))]


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    owner: Optional[str] = Field(None, max_length=120)
    framework: str = Field("Not recorded", max_length=80)
    tools_count: int = Field(0, ge=0, le=500)

    @field_validator("name", "owner", "framework", mode="before")
    @classmethod
    def strip(cls, v):
        return (v.strip() or None) if isinstance(v, str) else v


@router.post("/register", response_model=AgentOut, status_code=201)
def register(body: RegisterRequest, session: Session = Depends(get_session)) -> AgentOut:
    key = agent_key(body.name)
    if len(key) < 2:
        raise HTTPException(status_code=422, detail="The name needs letters or digits.")
    if session.scalar(select(Agent.id).where(Agent.agent_key == key)):
        raise HTTPException(status_code=409, detail=f"An agent called {key!r} is already in the inventory.")
    a = Agent(agent_key=key, organisation_id=current_organisation(session).id, name=body.name, owner=body.owner,
              framework=body.framework or "Not recorded", tools_count=body.tools_count,
              status="TO_RATIFY" if body.owner else "UNOWNED", mode="OBSERVE", origin="REGISTERED")
    session.add(a)
    session.commit()
    return _out(session, a)


class OwnerUpdate(BaseModel):
    owner: str = Field(min_length=1, max_length=120)

    @field_validator("owner", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


@router.patch("/{key}", response_model=AgentOut)
def set_owner(key: str, body: OwnerUpdate, session: Session = Depends(get_session)) -> AgentOut:
    a = _get(session, key)
    a.owner = body.owner
    if a.status == "UNOWNED":
        a.status = "TO_RATIFY"
    a.updated_at = func.now()
    session.commit()
    session.refresh(a)
    return _out(session, a)


# ── Ratification ────────────────────────────────────────────────────────────

class RatifyRequest(BaseModel):
    design_key: str
    reviewer: str = Field("", max_length=120)      # ignored: the signed-in person is recorded


class RatifyOut(BaseModel):
    agent: AgentOut
    contract: CompiledContract


def _graph(doc: Dict[str, Any]) -> DesignGraphIn:
    """The studio's nodes and edges in the form the engines read (the page's agentGraphPayload)."""
    return DesignGraphIn(
        nodes=[{"id": n["id"], "type": n["type"], "props": {"name": n.get("name", ""), **(n.get("p") or {})}, "primary": bool(n.get("primary"))}
               for n in doc.get("nodes", [])],
        edges=[{"from": e["from"], "to": e["to"], "label": e.get("label", "")} for e in doc.get("edges", [])])


@router.post("/ratify", response_model=RatifyOut)
def ratify(body: RatifyRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> RatifyOut:
    design = session.scalar(select(Design).where(Design.design_key == body.design_key))
    if design is None or design.subject != "AGENT":
        raise HTTPException(status_code=404, detail="No such agent design.")
    return ratify_design(session, design, user.name)


def ratify_design(session: Session, design: Design, reviewer: str) -> RatifyOut:
    doc = design.document
    primary = next((n for n in doc.get("nodes", []) if n.get("primary") and n.get("type") == "agent"), None)
    if primary is None or not str(primary.get("name", "")).strip():
        raise HTTPException(status_code=422, detail="The design needs a primary agent with a name.")
    name = str(primary["name"]).strip()
    key = agent_key(name)
    if len(key) < 2:
        raise HTTPException(status_code=422, detail="The primary agent's name needs letters or digits.")

    graph = _graph(doc)
    profile = doc.get("profile") or "payments"
    declarations = {k: Declaration(**v) for k, v in (doc.get("req") or {}).items()}
    rcr = score_agent(RcrRequest(profile=profile, graph=graph, declarations=declarations), session)
    if rcr.gate == "BLOCK":
        raise HTTPException(status_code=422, detail=(
            f"The design is Blocked (risk score {rcr.score:g}). Close the critical gaps first"
            + (f", starting with {rcr.floor_name}." if rcr.floor_name else ".")))
    analysis = analyse_agent(AgentAnalyseRequest(graph=graph, domain=AGENT_DOMAIN), session)

    existing = session.scalar(select(Agent).where(Agent.agent_key == key))
    if existing is not None and existing.design_id not in (None, design.id) and existing.origin == "DESIGNED":
        raise HTTPException(status_code=409, detail=f"An agent called {key!r} already comes from another design.")
    if existing is not None and existing.origin == "DEMO":
        raise HTTPException(status_code=409, detail=f"{key!r} is a demo agent. Remove the demo agents or rename this one.")

    overall = RiskStatus.RED if any(r.status == "Gap" for r in analysis.rows) else (
        RiskStatus.AMBER if any(r.status == "Partial" for r in analysis.rows) else RiskStatus.GREEN)
    version = (session.scalar(select(func.count()).select_from(Contract).where(
        Contract.object_type == "AGENT", Contract.deployment_id == key)) or 0) + 1
    previous = session.scalar(select(Contract).where(
        Contract.object_type == "AGENT", Contract.deployment_id == key, Contract.status == "ACTIVE").order_by(Contract.issued_at.desc()))
    snapshot = {"name": name, "nodes": doc.get("nodes", []), "edges": doc.get("edges", [])}
    change = (agent_contract.change_between(previous.document["design_snapshot"], snapshot, previous.document["version"])
              if previous is not None else agent_contract.first_version())
    contract = CompiledContract(
        contract_id=str(uuid.uuid4()), version=f"{version}.0.0", object_type="AGENT", deployment_id=key, domain=AGENT_DOMAIN,
        design_snapshot={"name": name, "nodes": doc.get("nodes", []), "edges": doc.get("edges", []), "profile": profile,
                         "declarations": doc.get("req") or {}, "drift_policy": doc.get("policy"),
                         "rcr": rcr.model_dump(mode="json"), "analysis": analysis.model_dump(mode="json"), "change": change},
        risk_assessment=DesignRiskAssessment(assessment_id=str(uuid.uuid4()), deployment_id=key, domain=AGENT_DOMAIN,
                                             overall_status=overall, assessed_at=datetime.now(timezone.utc)),
        issued_at=datetime.now(timezone.utc), issued_by=reviewer.strip())
    contract.contract_hash = compute_contract_hash(contract)
    store_contract(session, contract, design.design_key)

    tools = sum(1 for n in doc.get("nodes", []) if n.get("type") in ("tool", "mcp"))
    owner = (primary.get("p") or {}).get("owner") or None
    if existing is None:
        existing = Agent(agent_key=key, organisation_id=current_organisation(session).id, name=name, origin="DESIGNED")
        session.add(existing)
    existing.design_id, existing.tools_count = design.id, tools
    existing.owner = owner or existing.owner
    existing.status = "ASSURED" if existing.status == "ASSURED" else "DESIGNED"
    if existing.status == "DESIGNED":
        existing.framework, existing.mode = "Not built yet", "NOT_RUNNING"
    existing.updated_at = func.now()
    # Anything still waiting for review was compared with a contract that is no longer the newest.
    for item in session.scalars(select(DriftItem).where(DriftItem.agent_key == key, DriftItem.status == "OPEN")):
        item.status, item.decision_note = "SUPERSEDED", f"Contract version {version}.0.0 was issued."
    session.commit()
    session.refresh(existing)
    return RatifyOut(agent=_out(session, existing), contract=contract)


# ── Demo set ────────────────────────────────────────────────────────────────

DEMO = [
    ("billing-agent", "Payments eng", "LangGraph", 6, "TO_RATIFY", "OBSERVE", "Draft v3, none yet"),
    ("invoice-agent", "Finance ops eng", "OpenAI Agents SDK", 4, "ASSURED", "FLAG", "1 high · today"),
    ("support-agent", "CX eng", "LangGraph", 7, "ASSURED", "BLOCK", "1 medium · today"),
    ("research-agent", "Data team", "CrewAI", 5, "ASSURED", "OBSERVE", "1 medium · today"),
    ("refund-agent", "Payments eng", "LangGraph", 3, "ASSURED", "BLOCK", "None in 30 days"),
    ("notify-agent", "Platform", "OpenAI Agents SDK", 2, "ASSURED", "BLOCK", "None in 30 days"),
    ("kyc-agent", "Risk eng", "LangGraph", 5, "ASSURED", "FLAG", "None in 30 days"),
    ("onboarding-agent", "Growth", "OpenAI Agents SDK", 4, "ASSURED", "OBSERVE", "None in 30 days"),
    ("reconcile-agent", "Finance ops eng", "LangGraph", 3, "ASSURED", "FLAG", "None in 30 days"),
    ("docs-agent", "Platform", "CrewAI", 2, "ASSURED", "OBSERVE", "None in 30 days"),
    ("refund-assist-agent", "CX eng", "Not built yet", 3, "DESIGNED", "NOT_RUNNING", "Drift on PR #517"),
    ("sandbox-agent", None, "MCP only", 3, "UNOWNED", "OBSERVE", "Discovered 2 days ago"),
]


@router.post("/demo", response_model=List[AgentOut], status_code=201)
def load_demo(session: Session = Depends(get_session)) -> List[AgentOut]:
    org = current_organisation(session)
    taken = {k for (k,) in session.execute(select(Agent.agent_key))}
    for name, owner, framework, tools, status, mode, note in DEMO:
        if name not in taken:
            session.add(Agent(agent_key=name, organisation_id=org.id, name=name, owner=owner, framework=framework,
                              tools_count=tools, status=status, mode=mode, origin="DEMO", note=note))
    if not session.scalar(select(func.count()).select_from(Finding).where(Finding.source == "DEMO")):
        session.add_all([Finding(organisation_id=org.id, **f) for f in demo_data.DEMO_FINDINGS])
    if not session.scalar(select(func.count()).select_from(DriftItem).where(DriftItem.source == "DEMO")):
        session.add_all([DriftItem(organisation_id=org.id, **x) for x in demo_data.DEMO_DRIFT])
    session.commit()
    return list_agents(session)


@router.delete("/demo", status_code=204)
def remove_demo(session: Session = Depends(get_session)) -> None:
    for a in session.scalars(select(Agent).where(Agent.origin == "DEMO")):
        session.delete(a)
    for f in session.scalars(select(Finding).where(Finding.source == "DEMO")):
        session.delete(f)
    for x in session.scalars(select(DriftItem).where(DriftItem.source == "DEMO")):
        session.delete(x)
    session.commit()
