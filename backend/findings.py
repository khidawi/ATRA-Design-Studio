"""
Findings (Task 7c): divergences between what an agent did and what its active contract allows.

Observed events arrive at POST /api/findings/ingest. That endpoint is the seam for real collectors (an OpenTelemetry
adapter, an MCP gateway, a framework hook): nothing in this repository sends real events yet. The simulator
(POST /api/findings/simulate) produces events and sends them through the same check, so what it shows is what a real
event would produce against the same contract. A finding is never invented by the simulator: the deterministic check in
divergence.py decides, and a conforming event produces no finding.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import agent_contract
from auth import AuthUser, current_user
import divergence
from db.models import Agent, Contract, Finding
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/findings", tags=["findings"])


class FindingOut(BaseModel):
    finding_key: str
    agent_key: str
    contract_version: Optional[str]
    severity: str
    title: str
    class_code: str
    observed: str
    permitted: str
    element: str
    threat: str
    evidence: str
    source: str
    status: str
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    test_spec: Optional[str]
    halt_requested_by: Optional[str]
    halt_requested_at: Optional[datetime]
    created_at: datetime


def _out(f: Finding) -> FindingOut:
    return FindingOut(finding_key=f"F-{f.seq}", agent_key=f.agent_key, contract_version=f.contract_version, severity=f.severity,
                      title=f.title, class_code=f.class_code, observed=f.observed, permitted=f.permitted, element=f.element,
                      threat=f.threat, evidence=f.evidence, source=f.source, status=f.status, acknowledged_by=f.acknowledged_by,
                      acknowledged_at=f.acknowledged_at, test_spec=f.test_spec, halt_requested_by=f.halt_requested_by,
                      halt_requested_at=f.halt_requested_at, created_at=f.created_at)


def _get(session: Session, key: str) -> Finding:
    try:
        seq = int(key.removeprefix("F-"))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such finding.")
    f = session.scalar(select(Finding).where(Finding.seq == seq))
    if f is None:
        raise HTTPException(status_code=404, detail="No such finding.")
    return f


@router.get("", response_model=List[FindingOut])
def list_findings(agent: Optional[str] = None, session: Session = Depends(get_session)) -> List[FindingOut]:
    q = select(Finding)
    if agent:
        q = q.where(Finding.agent_key == agent)
    return [_out(f) for f in session.scalars(q.order_by(Finding.created_at.desc(), Finding.seq.desc()))]


@router.get("/series")
def series(days: int = 14, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """Trends for the charts: findings per day by severity, by divergence class (with its OWASP agentic category) and by agent, open against acknowledged."""
    days = min(max(days, 3), 90)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    day = func.date_trunc("day", Finding.created_at)
    per_day = {d.date().isoformat(): {"date": d.date().isoformat(), "High": 0, "Medium": 0, "Low": 0} for d in (start + timedelta(days=i) for i in range(days))}
    for d, sev, c in session.execute(select(day, Finding.severity, func.count()).where(Finding.created_at >= start).group_by(day, Finding.severity)).all():
        k = d.date().isoformat()
        if k in per_day and sev in per_day[k]:
            per_day[k][sev] += c
    threat = {code: (el, thr) for code, el, thr in divergence.CLASSES.values()}
    by_class: Dict[str, Dict[str, Any]] = {}
    by_agent: Dict[str, Dict[str, Any]] = {}
    for code, agent, status, c in session.execute(select(Finding.class_code, Finding.agent_key, Finding.status, func.count()).group_by(Finding.class_code, Finding.agent_key, Finding.status)).all():
        cl = by_class.setdefault(code, {"class_code": code, "category": threat.get(code, ("", ""))[1], "total": 0, "open": 0})
        ag = by_agent.setdefault(agent, {"agent_key": agent, "open": 0, "acknowledged": 0, "total": 0})
        for d in (cl, ag):
            d["total"] += c
        if status == "OPEN":
            cl["open"] += c
            ag["open"] += c
        else:
            ag["acknowledged"] += c
    total = sum(c["total"] for c in by_class.values())
    return {"days": days, "by_day": list(per_day.values()), "by_class": sorted(by_class.values(), key=lambda x: -x["total"]), "by_agent": sorted(by_agent.values(), key=lambda x: -x["total"]),
            "total": total, "open": sum(c["open"] for c in by_class.values())}


class Event(BaseModel):
    type: Literal["tool_call", "delegation", "mcp_connect", "memory_write", "data_access"]
    name: str = Field("", max_length=200)
    write: Optional[bool] = None
    signed: Optional[bool] = None
    scope: Optional[Literal["long_term", "session"]] = None


class IngestRequest(BaseModel):
    agent: str
    event: Event
    source: Literal["COLLECTED", "SIMULATED"] = "COLLECTED"


class IngestOut(BaseModel):
    checked_against: str            # the contract version the event was compared with
    finding: Optional[FindingOut]   # none when the event conforms to the contract


def active_contract(session: Session, agent_key: str) -> Contract:
    agent = session.scalar(select(Agent).where(Agent.agent_key == agent_key))
    if agent is None:
        raise HTTPException(status_code=404, detail=f"No agent called {agent_key!r}.")
    c = session.scalar(select(Contract).where(Contract.object_type == "AGENT", Contract.deployment_id == agent_key,
                                              Contract.status == "ACTIVE").order_by(Contract.issued_at.desc()))
    if c is None:
        raise HTTPException(status_code=409, detail=f"{agent_key} has no active contract to compare against. Ratify its design first.")
    return c


def ingest(session: Session, agent_key: str, event: Dict[str, Any], source: str) -> IngestOut:
    contract = active_contract(session, agent_key)
    view = agent_contract.view(contract.document["design_snapshot"])
    try:
        found = divergence.check_event(view, event)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    version = contract.document["version"]
    if found is None:
        return IngestOut(checked_against=version, finding=None)
    f = Finding(organisation_id=current_organisation(session).id, agent_key=agent_key, contract_id=contract.contract_id,
                contract_version=version, severity=found["severity"], title=found["title"], class_code=found["class_code"],
                observed=found["observed"], permitted=found["permitted"], element=found["element"], threat=found["threat"],
                evidence="sha256:" + divergence.evidence_hash(agent_key, contract.contract_id, event)[:16] + " · event " + uuid.uuid4().hex[:6],
                event=event, source=source)
    session.add(f)
    session.commit()
    session.refresh(f)
    return IngestOut(checked_against=version, finding=_out(f))


@router.post("/ingest", response_model=IngestOut)
def ingest_event(body: IngestRequest, session: Session = Depends(get_session)) -> IngestOut:
    return ingest(session, body.agent, body.event.model_dump(exclude_none=True), body.source)


class Scenario(BaseModel):
    id: str
    label: str


@router.get("/scenarios", response_model=List[Scenario])
def scenarios() -> List[Scenario]:
    return [Scenario(id=i, label=l) for i, l, _ in divergence.SCENARIOS]


class SimulateRequest(BaseModel):
    agent: str
    scenario: str


@router.post("/simulate", response_model=IngestOut)
def simulate(body: SimulateRequest, session: Session = Depends(get_session)) -> IngestOut:
    contract = active_contract(session, body.agent)
    view = agent_contract.view(contract.document["design_snapshot"])
    try:
        event = divergence.scenario_event(body.scenario, view)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ingest(session, body.agent, event, "SIMULATED")


class Actor(BaseModel):
    by: str = Field("", max_length=120)      # ignored: the signed-in person is recorded

    @field_validator("by", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class AckRequest(Actor):
    acknowledged: bool = True


@router.post("/{key}/acknowledge", response_model=FindingOut)
def acknowledge(key: str, body: AckRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> FindingOut:
    f = _get(session, key)
    f.status = "ACKNOWLEDGED" if body.acknowledged else "OPEN"
    f.acknowledged_by, f.acknowledged_at = (user.name, func.now()) if body.acknowledged else (None, None)
    session.commit()
    session.refresh(f)
    return _out(f)


@router.post("/{key}/test", response_model=FindingOut)
def draft_test(key: str, session: Session = Depends(get_session)) -> FindingOut:
    f = _get(session, key)
    if f.test_spec is None:
        if not f.event:
            raise HTTPException(status_code=409, detail="This finding has no recorded event to draft a test from.")
        f.test_spec = divergence.draft_test_spec(f.agent_key, f.contract_version or "?", {"key": f"F-{f.seq}", "class_code": f.class_code, "threat": f.threat}, f.event)
        session.commit()
        session.refresh(f)
    return _out(f)


@router.post("/{key}/halt", response_model=FindingOut)
def request_halt(key: str, body: Actor, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> FindingOut:
    """Records that a person asked for the agent to be halted. Nothing here can stop a running agent: there is no
    runtime enforcement yet, so this is evidence of the request, not a kill switch."""
    f = _get(session, key)
    f.halt_requested_by, f.halt_requested_at = user.name, datetime.now(timezone.utc)
    session.commit()
    session.refresh(f)
    return _out(f)
