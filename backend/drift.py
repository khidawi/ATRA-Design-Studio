"""
Drift review (Task 7c): a proposed change to an agent compared with its ratified contract, waiting for a decision.

Real source (no collectors needed): the studio's "submit change for review" compares the edited design with the agent's
active contract. Simulated source: the simulator edits a copy of the ratified design to stand in for a code or runtime
change that nothing observed; the comparison, scoring and approval then work exactly the same way. Rows labelled DEMO
are the prototype's sample data.

Approving a real or simulated item writes the proposed design into the agent's design and ratifies it, which issues a
new contract version and supersedes the old one. Ratification is refused if the proposed design's risk score is Blocked,
and then the item stays open. Declining only records the decision: the agent stays on its current contract.
"""
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import drift_engine
from auth import AuthUser, current_user
from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_registry import AGENT_DOMAIN, _graph, ratify_design
from db.models import Agent, Contract, Design, DriftItem
from db.session import get_session
from findings import active_contract
from organisation import current_organisation
from rcr import Declaration, RcrRequest, score_agent

router = APIRouter(prefix="/api/drift", tags=["drift"])

TITLE = {"Widening": "scope widened", "Narrowing": "scope narrowed", "Review": "changes need review"}


class DriftOut(BaseModel):
    id: str
    agent_key: str
    source: str
    source_label: str
    from_version: str
    title: str
    kind: str
    policy: str
    changes: List[Dict[str, Any]]
    impact: List[str]
    rcr_before: Optional[float]
    rcr_after: Optional[float]
    gate_after: Optional[str]
    status: str
    decided_by: Optional[str]
    decided_at: Optional[datetime]
    decision_note: Optional[str]
    new_contract_id: Optional[str]
    design_key: Optional[str]
    created_at: datetime


def _out(d: DriftItem) -> DriftOut:
    return DriftOut(id=str(d.id), agent_key=d.agent_key, source=d.source, source_label=d.source_label, from_version=d.from_version,
                    title=d.title, kind=d.kind, policy=d.policy, changes=d.changes, impact=d.impact, rcr_before=d.rcr_before,
                    rcr_after=d.rcr_after, gate_after=d.gate_after, status=d.status, decided_by=d.decided_by,
                    decided_at=d.decided_at, decision_note=d.decision_note, new_contract_id=d.new_contract_id,
                    design_key=d.design_key, created_at=d.created_at)


@router.get("", response_model=List[DriftOut])
def list_drift(session: Session = Depends(get_session)) -> List[DriftOut]:
    rows = session.scalars(select(DriftItem).order_by((DriftItem.status != "OPEN"), DriftItem.created_at.desc()))
    return [_out(d) for d in rows]


def _build(session: Session, agent: Agent, contract: Contract, proposed: Dict[str, Any], source: str, label: str,
           design_key: Optional[str]) -> DriftItem:
    snap = contract.document["design_snapshot"]
    changes = drift_engine.detailed_changes(snap, {"nodes": proposed["nodes"], "edges": proposed["edges"]})
    if not changes:
        raise HTTPException(status_code=409, detail="The proposed design does not differ from the ratified contract.")
    graph = _graph(proposed)
    after = analyse_agent(AgentAnalyseRequest(graph=graph, domain=AGENT_DOMAIN), session)
    profile = proposed.get("profile") or snap.get("profile") or "payments"
    declarations = {k: Declaration(**v) for k, v in (proposed.get("req") or {}).items()}
    rcr = score_agent(RcrRequest(profile=profile, graph=graph, declarations=declarations), session)
    before_rows = {r["id"]: r for r in snap.get("analysis", {}).get("rows", [])}
    impact = [f"{r.id} {r.name}: {before_rows[r.id]['status']} → {r.status}" + (f" ({r.why})" if r.why else "")
              for r in after.rows if r.id in before_rows and before_rows[r.id]["status"] != r.status]
    before_score = (snap.get("rcr") or {}).get("score")
    if before_score is not None:
        impact.append(f"Design-time risk score {before_score:g} → {rcr.score:g} ({rcr.band}, gate {rcr.gate})")
    kind = drift_engine.kind_of(changes)
    return DriftItem(organisation_id=current_organisation(session).id, agent_key=agent.agent_key, contract_id=contract.contract_id,
                     design_key=design_key, source=source, source_label=label, from_version=contract.document["version"],
                     title=TITLE[kind], kind=kind, policy=proposed.get("policy") or snap.get("drift_policy") or "block",
                     proposed=proposed, changes=changes, impact=impact, rcr_before=before_score, rcr_after=rcr.score, gate_after=rcr.gate)


class ProposeRequest(BaseModel):
    design_key: str


@router.post("/propose", response_model=DriftOut, status_code=201)
def propose(body: ProposeRequest, session: Session = Depends(get_session)) -> DriftOut:
    """The design as it is now, compared with the active contract of the agent it belongs to."""
    design = session.scalar(select(Design).where(Design.design_key == body.design_key, Design.subject == "AGENT"))
    agent = session.scalar(select(Agent).where(Agent.design_id == design.id)) if design else None
    if design is None or agent is None:
        raise HTTPException(status_code=404, detail="No ratified agent comes from this design.")
    contract = active_contract(session, agent.agent_key)
    item = _build(session, agent, contract, dict(design.document), "DESIGN", "Design edited in the design studio", design.design_key)
    for old in session.scalars(select(DriftItem).where(DriftItem.agent_key == agent.agent_key, DriftItem.status == "OPEN", DriftItem.source == "DESIGN")):
        old.status, old.decision_note = "SUPERSEDED", "Replaced by a newer submission of the same design."
    session.add(item)
    session.commit()
    session.refresh(item)
    return _out(item)


class Scenario(BaseModel):
    id: str
    label: str


@router.get("/scenarios", response_model=List[Scenario])
def scenarios() -> List[Scenario]:
    return [Scenario(id=i, label=l) for i, l in drift_engine.SCENARIOS]


class SimulateRequest(BaseModel):
    agent: str
    scenario: str


@router.post("/simulate", response_model=DriftOut, status_code=201)
def simulate(body: SimulateRequest, session: Session = Depends(get_session)) -> DriftOut:
    contract = active_contract(session, body.agent)
    agent = session.scalar(select(Agent).where(Agent.agent_key == body.agent))
    snap = contract.document["design_snapshot"]
    base = {"nodes": snap["nodes"], "edges": snap["edges"], "n": 200, "profile": snap.get("profile"), "req": snap.get("declarations") or {},
            "policy": snap.get("drift_policy")}
    try:
        proposed = drift_engine.apply_scenario(body.scenario, base)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    label = "Simulated code change · nothing was scanned; the ratified design was edited to stand in for one"
    design_key = session.scalar(select(Design.design_key).where(Design.id == agent.design_id)) if agent.design_id else None
    item = _build(session, agent, contract, proposed, "SIMULATED", label, design_key)
    session.add(item)
    session.commit()
    session.refresh(item)
    return _out(item)


class DecideRequest(BaseModel):
    decision: Literal["approve", "decline"]
    reviewer: str = Field("", max_length=120)      # ignored: the signed-in person is recorded
    note: str = Field("", max_length=500)

    @field_validator("reviewer", "note", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


@router.post("/{item_id}/decide", response_model=DriftOut)
def decide(item_id: str, body: DecideRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> DriftOut:
    try:
        item = session.get(DriftItem, uuid.UUID(item_id))
    except ValueError:
        item = None
    if item is None:
        raise HTTPException(status_code=404, detail="No such drift item.")
    if item.status != "OPEN":
        raise HTTPException(status_code=409, detail=f"This item was already {item.status.lower()}.")
    if body.decision == "approve" and item.source != "DEMO":
        agent = session.scalar(select(Agent).where(Agent.agent_key == item.agent_key))
        design = session.get(Design, agent.design_id) if agent is not None and agent.design_id else None
        if design is None:
            raise HTTPException(status_code=409, detail="The design this contract came from no longer exists, so a new version cannot be ratified from it.")
        active_contract(session, item.agent_key)
        design.document = {**item.proposed, "ratified": True}
        design.version += 1
        design.updated_at = func.now()
        primary = next((n for n in item.proposed["nodes"] if n.get("primary")), None)
        if primary and primary.get("name"):
            design.name = primary["name"]
        session.flush()
        try:
            out = ratify_design(session, design, user.name)
        except HTTPException:
            session.rollback()
            raise
        item = session.get(DriftItem, uuid.UUID(item_id))
        item.new_contract_id = out.contract.contract_id
    item.status = "APPROVED" if body.decision == "approve" else "DECLINED"
    item.decided_by, item.decided_at, item.decision_note = user.name, func.now(), body.note or None
    session.commit()
    session.refresh(item)
    return _out(item)
