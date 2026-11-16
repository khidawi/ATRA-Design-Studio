"""
The ASTRA assessment of an agent design (phase 3), read only:

  GET /api/agents/designs/{design_key}/assessment    the attack paths of the design, the controls each needs and their status, the department risk vector and the
                                                     gate verdict the formal model gives (astra_model), with what could not be mapped and the approximations used

It reads the saved design, the organisation graph (departments, data stores, agents), the values ratified in the risk layer, the OWASP checks on the design and the
attested evidence records. It changes nothing. The gate verdict here is what the model says; acting on it (suggested controls, ratifying, signing) is later phases.
"""
from datetime import date
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import astra_estate as AE
import risk_api
from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_registry import AGENT_DOMAIN, _graph, agent_key
from db.models import Agent, CompanyNode, Design, EvidenceRecord
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/agents/designs", tags=["astra"])


def _rows(session: Session, doc: Dict[str, Any]):
    a = analyse_agent(AgentAnalyseRequest(graph=_graph(doc), domain=AGENT_DOMAIN), session)
    return [{"id": r.id, "status": r.status, "why": r.why} for r in a.rows]


def _evidence(session: Session, design_key: str) -> Dict[str, Any]:
    """Control key -> the day number its attestation lapses (None: it does not), for attested, unexpired, intact records with the key astra:<kind>."""
    today = date.today()
    rows = session.execute(select(EvidenceRecord.control_key, EvidenceRecord.kind, EvidenceRecord.size, func.octet_length(EvidenceRecord.content), EvidenceRecord.expires_at)
                           .where(EvidenceRecord.design_key == design_key, EvidenceRecord.status == "ATTESTED", EvidenceRecord.control_key.like("astra:%"),
                                  (EvidenceRecord.expires_at.is_(None)) | (EvidenceRecord.expires_at >= today))).all()
    out: Dict[str, Any] = {}
    for key, kind, size, stored, expires in rows:
        if kind != "URL" and stored != size:
            continue                                  # a file whose stored size no longer matches is not counted
        day, prev = (expires.toordinal() if expires else None), out.get(key, False)
        out[key] = None if (prev is None or day is None) else (day if prev is False else max(prev, day))
    return out


def context(session: Session, doc: Dict[str, Any]) -> AE.Ctx:
    org = current_organisation(session)
    eff = risk_api.effective(session)
    nodes = list(session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.type.in_(("department", "data_store", "agent")))))
    ctx = AE.Ctx(dept_names={n.ext_id: n.name for n in nodes if n.type == "department"}, tiers={k: v["tier"] for k, v in eff["tiers"].items()}, tolerance=dict(eff["tolerance"]))
    for n in nodes:
        props = n.props or {}
        if n.type == "data_store":
            ctx.stores[AE._norm(n.name)] = {"ext": n.ext_id, "department": props.get("department") or (eff["tiers"].get(n.ext_id) or {}).get("department_ext")}
        elif n.type == "agent" and props.get("department"):
            ctx.dept_of_agent[AE._norm(n.name)] = props["department"]
            if props.get("agent_key"):
                ctx.dept_of_agent[AE._norm(props["agent_key"])] = props["department"]
    prim = AE._primary(doc)
    pn = AE._norm(prim["name"])
    dept = ctx.dept_of_agent.get(pn) or ctx.dept_of_agent.get(AE._norm(agent_key(prim["name"])))
    if dept:
        ctx.dept_of_agent[pn] = dept
    wanted = {AE._norm(n["name"]) for e in doc.get("edges", []) if e.get("label") == "delegates" for n in doc.get("nodes", []) if n["id"] == e["to"]}
    for a in session.scalars(select(Agent).where(Agent.organisation_id == org.id, Agent.design_id.is_not(None))):
        if AE._norm(a.name) in wanted:
            d = session.get(Design, a.design_id)
            if d is not None and d.subject == "AGENT":
                ctx.others[AE._norm(a.name)] = AE.Source(d.document, _rows(session, d.document), _evidence(session, d.design_key))
    return ctx


def assess(session: Session, design: Design) -> Dict[str, Any]:
    doc = design.document
    try:
        ctx = context(session, doc)
        built = AE.build(AE.Source(doc, _rows(session, doc), _evidence(session, design.design_key)), ctx)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    out = AE.describe(built, ctx, date.today().toordinal())
    out.update(design_key=design.design_key, design_version=design.version, design_name=design.name)
    return out


@router.get("/{design_key}/assessment")
def get_assessment(design_key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    design = session.scalar(select(Design).where(Design.design_key == design_key))
    if design is None or design.subject != "AGENT":
        raise HTTPException(status_code=404, detail="No such agent design.")
    return assess(session, design)
