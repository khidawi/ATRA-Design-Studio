"""
The ASTRA assessment of an agent design (phase 3), read only:

  GET  /api/agents/designs/{design_key}/assessment            the attack paths of the design, the controls each needs and their status, the department risk vector, the
                                                              gate verdict the formal model gives (astra_model), what to do about each control that keeps the verdict down,
                                                              what could not be mapped and the approximations used
  POST /api/agents/designs/{design_key}/assessments           record the assessment as it is now (never edited afterwards; refused when nothing has changed since the last one)
  GET  /api/agents/designs/{design_key}/assessments           the recorded assessments of the design, newest first
  GET  /api/agents/designs/{design_key}/assessments/{id}      one recorded assessment in full

It reads the saved design, the organisation graph (departments, data stores, agents), the values ratified in the risk layer, the OWASP checks on the design and the
attested evidence records. It changes nothing. The gate verdict here is what the model says; acting on it (suggested controls, ratifying, signing) is later phases.
"""
import hashlib
import json
import uuid
from datetime import date
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import astra_estate as AE
import audit
import risk_api
from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_registry import AGENT_DOMAIN, _graph, agent_key
from auth import AuthUser, current_user
from db.models import Agent, AstraAssessment, CompanyNode, Design, EvidenceRecord
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


def _hash(doc: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _agent_design(session: Session, design_key: str) -> Design:
    design = session.scalar(select(Design).where(Design.design_key == design_key))
    if design is None or design.subject != "AGENT":
        raise HTTPException(status_code=404, detail="No such agent design.")
    return design


def _summary(r: AstraAssessment) -> Dict[str, Any]:
    return {"id": str(r.id), "design_key": r.design_key, "design_version": r.design_version, "design_hash": r.design_hash, "verdict": r.verdict, "departments": r.departments,
            "paths": len(r.result.get("paths", [])), "created_by": r.created_by, "created_at": r.created_at.isoformat()}


@router.post("/{design_key}/assessments", status_code=201)
def record_assessment(design_key: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    design = _agent_design(session, design_key)
    org = current_organisation(session)
    out = json.loads(json.dumps(assess(session, design), default=str))              # plain JSON, exactly as served and as stored
    last = session.scalar(select(AstraAssessment).where(AstraAssessment.organisation_id == org.id, AstraAssessment.design_key == design_key)
                          .order_by(AstraAssessment.created_at.desc()).limit(1))
    if last is not None and last.design_hash == _hash(design.document) and last.result == out:
        raise HTTPException(status_code=409, detail=f"Nothing has changed since the assessment recorded at {last.created_at.isoformat()}: the design, the organisation, the risk layer and the evidence are the same.")
    row = AstraAssessment(organisation_id=org.id, design_key=design_key, design_version=design.version, design_hash=_hash(design.document), verdict=out["verdict"],
                          departments=out["departments"], result=out, created_by=user.name)
    session.add(row)
    session.commit()
    audit.record(user.name, user.role, "astra.assess", detail={"design_key": design_key, "design_version": design.version, "verdict": out["verdict"], "id": str(row.id)})
    return _summary(row)


@router.get("/{design_key}/assessments")
def list_assessments(design_key: str, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    _agent_design(session, design_key)
    org = current_organisation(session)
    rows = session.scalars(select(AstraAssessment).where(AstraAssessment.organisation_id == org.id, AstraAssessment.design_key == design_key)
                           .order_by(AstraAssessment.created_at.desc()).limit(30))
    return [_summary(r) for r in rows]


@router.get("/{design_key}/assessments/{assessment_id}")
def get_recorded_assessment(design_key: str, assessment_id: uuid.UUID, session: Session = Depends(get_session)) -> Dict[str, Any]:
    _agent_design(session, design_key)
    org = current_organisation(session)
    row = session.get(AstraAssessment, assessment_id)
    if row is None or row.organisation_id != org.id or row.design_key != design_key:
        raise HTTPException(status_code=404, detail="No such recorded assessment.")
    return {**_summary(row), "result": row.result}
