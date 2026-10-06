"""
Coverage scorecard (Task 7d): how far the agents that have an active contract meet each threat check.

Nothing here is stored except who owns closing a check and by when. Every status is computed on request:
  * each agent with an ACTIVE contract (demo agents are never counted) has the checks of the OWASP Agentic domain
    re-run against the design held in that contract, with today's rules (so a rule or organisation policy added
    later shows up here);
  * a check's status across agents is the worst one: Gap if any agent has a gap, else Partial if any is partial,
    else Covered if at least one agent it applies to meets it, else No data (no agent it applies to);
  * ASI10 also counts the agents in the inventory that have no owner, as the inventory screen says it does;
  * findings are counted per check from their threat mapping.
"worst case across agents" is deliberately strict: a scorecard that averages away a gap would hide it.
"""
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_registry import AGENT_DOMAIN, _graph
from db.models import Agent, Contract, CoverageAssignment, Finding
from db.session import get_session
from organisation import current_organisation
from regulations import require_domain

router = APIRouter(prefix="/api/coverage", tags=["coverage"])


class Breakdown(BaseModel):
    agent: str
    version: Optional[str]
    status: str
    why: str


class CoverageRow(BaseModel):
    code: str
    name: str
    group: str                       # OWASP | OTHER (organisation policies and other checks in the agent domain)
    status: str                      # Covered | Partial | Gap | No data
    summary: str
    agents_applicable: int
    agents_covered: int
    open_findings: int
    finding_keys: List[str]
    owner: Optional[str]
    due: Optional[date]
    due_label: str
    note: Optional[str]
    breakdown: List[Breakdown]


class CoverageOut(BaseModel):
    generated_at: datetime
    agents_in_scope: int
    agents_without_contract: int
    demo_agents_excluded: int
    covered: int
    partial: int
    gap: int
    no_data: int
    rows: List[CoverageRow]


def worst(statuses: List[str]) -> str:
    applicable = [s for s in statuses if s != "Not applicable"]
    if not applicable:
        return "No data"
    if "Gap" in applicable:
        return "Gap"
    if "Partial" in applicable:
        return "Partial"
    return "Covered"


def due_label(status: str, due: Optional[date], today: date) -> str:
    if status == "Covered":
        return "Met"
    if due is None:
        return "No date set"
    days = (today - due).days
    return f"Overdue by {days} day{'s' if days != 1 else ''}" if days > 0 else ("Due today" if days == 0 else due.strftime("%d %b %Y"))


def summarise(status: str, breakdown: List[Breakdown], applicable: int) -> str:
    if status == "No data":
        return "No agent with an active contract is in scope for this check yet."
    bad = [b.agent for b in breakdown if b.status == "Gap"]
    part = [b.agent for b in breakdown if b.status == "Partial"]
    if status == "Gap":
        return f"{len(bad)} of {applicable} agents have a gap: {', '.join(bad)}."
    if status == "Partial":
        return f"{len(part)} of {applicable} agents meet this only in part: {', '.join(part)}."
    return f"All {applicable} agents this check applies to meet it."


@router.get("", response_model=CoverageOut)
def coverage(session: Session = Depends(get_session)) -> CoverageOut:
    domain = require_domain(session, AGENT_DOMAIN, "AGENT")
    catalogue: Dict[str, str] = {}
    for rule in domain.rule_set:
        catalogue[rule.check_config.get("code") or rule.citation] = rule.title
    agents = list(session.scalars(select(Agent).where(Agent.origin != "DEMO")))
    contracts = {c.deployment_id: c for c in session.scalars(select(Contract).where(
        Contract.object_type == "AGENT", Contract.status == "ACTIVE").order_by(Contract.issued_at))}
    in_scope = [a for a in agents if a.agent_key in contracts]

    per_code: Dict[str, List[Breakdown]] = {code: [] for code in catalogue}
    for a in in_scope:
        c = contracts[a.agent_key]
        snap = c.document["design_snapshot"]
        analysis = analyse_agent(AgentAnalyseRequest(graph=_graph(snap), domain=AGENT_DOMAIN), session)
        for r in analysis.rows:
            per_code.setdefault(r.id, []).append(Breakdown(agent=a.name, version=c.document["version"], status=r.status, why=r.why))
            catalogue.setdefault(r.id, r.name)
    for a in agents:                                       # the inventory's own rule for ASI10
        if a.status == "UNOWNED" and "ASI10" in per_code:
            per_code["ASI10"].append(Breakdown(agent=a.name, version=None, status="Gap", why="No owner is assigned in the inventory"))

    findings: Dict[str, List[str]] = {}
    for f in session.scalars(select(Finding).where(Finding.status == "OPEN", Finding.source != "DEMO")):
        findings.setdefault(f.threat.split(" ")[0], []).append(f"F-{f.seq}")
    org = current_organisation(session)
    assigned = {x.code: x for x in session.scalars(select(CoverageAssignment).where(CoverageAssignment.organisation_id == org.id))}
    today = datetime.now(timezone.utc).date()

    rows: List[CoverageRow] = []
    for code, name in catalogue.items():
        bd = per_code.get(code, [])
        status = worst([b.status for b in bd])
        applicable = sum(1 for b in bd if b.status != "Not applicable")
        asg = assigned.get(code)
        rows.append(CoverageRow(
            code=code, name=name, group="OWASP" if code.startswith("ASI") else "OTHER", status=status,
            summary=summarise(status, bd, applicable), agents_applicable=applicable,
            agents_covered=sum(1 for b in bd if b.status == "Covered"), open_findings=len(findings.get(code, [])),
            finding_keys=findings.get(code, []), owner=asg.owner if asg else None, due=asg.due_date if asg else None,
            due_label=due_label(status, asg.due_date if asg else None, today), note=asg.note if asg else None, breakdown=bd))
    rows.sort(key=lambda r: (r.group != "OWASP", r.code))
    count = lambda s: sum(1 for r in rows if r.group == "OWASP" and r.status == s)
    return CoverageOut(
        generated_at=datetime.now(timezone.utc), agents_in_scope=len(in_scope), agents_without_contract=len(agents) - len(in_scope),
        demo_agents_excluded=session.scalar(select(func.count()).select_from(Agent).where(Agent.origin == "DEMO")) or 0,
        covered=count("Covered"), partial=count("Partial"), gap=count("Gap"), no_data=count("No data"), rows=rows)


class AssignmentIn(BaseModel):
    owner: Optional[str] = Field(None, max_length=120)
    due: Optional[date] = None
    note: Optional[str] = Field(None, max_length=500)

    @field_validator("owner", "note", mode="before")
    @classmethod
    def blank_is_none(cls, v):
        return (v.strip() or None) if isinstance(v, str) else v


@router.put("/{code}", response_model=CoverageRow)
def assign(code: str, body: AssignmentIn, session: Session = Depends(get_session)) -> CoverageRow:
    known = {r.code for r in coverage(session).rows}
    if code not in known:
        raise HTTPException(status_code=404, detail=f"No threat check {code!r}.")
    org = current_organisation(session)
    row = session.scalar(select(CoverageAssignment).where(CoverageAssignment.organisation_id == org.id, CoverageAssignment.code == code))
    if row is None:
        row = CoverageAssignment(organisation_id=org.id, code=code)
        session.add(row)
    row.owner, row.due_date, row.note = body.owner, body.due, body.note
    session.commit()
    return next(r for r in coverage(session).rows if r.code == code)
