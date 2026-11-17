"""
The temporal graph network through the API (ASTRA phase 10). The network runs in the separate `learned` service; see astra_tgn.py for what the platform does and refuses.

  GET  /api/astra/learned/stream                      names, kinds and times of runtime events, with the department and the impact tier of the agent (collector key allowed)
  POST /api/astra/learned/tgn/evaluations             a candidate model and its evaluation against the baseline; the decision recorded is the platform's own (collector key allowed)
  GET  /api/astra/learned/tgn/models                  candidate and past models, each with its newest evaluation
  GET  /api/astra/learned/tgn/active                  the adopted model: what a service needs to score with it (collector key allowed)
  POST /api/astra/learned/tgn/scores                  window scores from the service, accepted only for the adopted model (collector key allowed)
  POST /api/astra/learned/tgn/models/{id}/adopt       switch a candidate on, advisory-only; refused unless its evaluation passed (signoff)
  POST /api/astra/learned/tgn/rollback                retire the adopted model and bring back the previous one that passed (signoff)
  GET  /api/astra/learned/tgn/health                  is the detector itself still behaving like the one that was evaluated
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import astra_assessment_api as AA
import astra_estate as AE
import astra_learned_api as LA
import astra_tgn as T
import audit
from agent_registry import agent_key as slug
from astra_contract_export import contract_agent_id
from auth import AuthUser, current_user
from db.models import Design, LearnedEvaluation, LearnedModel, RuntimeEvent
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/astra/learned", tags=["astra"])
log = logging.getLogger(__name__)
MAX_STREAM = 5000


def _estate_of(session: Session, org_id: uuid.UUID, agent_key: str, cache: Dict[str, Any]) -> Dict[str, Any]:
    """(department name, highest impact tier it can reach) of an agent, from its saved design and the organisation. Unknown: unassigned and the most severe tier (fail closed)."""
    if agent_key in cache:
        return cache[agent_key]
    out = {"dept": "(unassigned)", "tier": 4}
    try:
        for d in session.scalars(select(Design).where(Design.organisation_id == org_id, Design.subject == "AGENT")):
            try:
                name = AE._primary(d.document)["name"]
            except ValueError:
                continue
            if contract_agent_id(name) != agent_key:
                continue
            ctx = AA.context(session, d.document)
            ext = ctx.dept_of_agent.get(AE._norm(name))
            out = {"dept": ctx.dept_names.get(ext, ext) if ext else "(unassigned)", "tier": LA.reach_tier(session, org_id, agent_key)}
            break
    except Exception:
        log.warning("the estate of %s could not be read for the stream", agent_key, exc_info=True)
    cache[agent_key] = out
    return out


@router.get("/stream")
def stream(since: float = 0.0, until: Optional[float] = None, limit: int = 2000, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """The events a learned detector may read: a time, who, what kind, to what (a name), and where the agent sits in the estate. Never an argument, a prompt or a result."""
    org = current_organisation(session)
    until = until if until is not None else datetime.now(timezone.utc).timestamp()
    limit = min(max(limit, 1), MAX_STREAM)
    lo, hi = datetime.fromtimestamp(max(since, 0), timezone.utc), datetime.fromtimestamp(until, timezone.utc)
    rows = session.execute(select(RuntimeEvent.at, RuntimeEvent.agent_key, RuntimeEvent.type, RuntimeEvent.name).where(RuntimeEvent.organisation_id == org.id, RuntimeEvent.at >= lo,
                                                                                                                       RuntimeEvent.at < hi, RuntimeEvent.type != "heartbeat")
                           .order_by(RuntimeEvent.at, RuntimeEvent.seq).limit(limit + 1)).all()
    cache: Dict[str, Any] = {}
    out = []
    for at, agent, kind, name in rows[:limit]:
        e = _estate_of(session, org.id, agent, cache)
        out.append({"t": (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).timestamp(), "agent": agent, "kind": kind, "target": name or kind, "dept": e["dept"], "tier": e["tier"]})
    return {"events": out, "more": len(rows) > limit}


class EvaluationIn(BaseModel):
    checksum: str = Field(min_length=64, max_length=64)
    metrics: Dict[str, Any]
    vocab: Optional[Dict[str, Any]] = None
    hyper: Dict[str, Any]
    training: Optional[Dict[str, Any]] = None


@router.post("/tgn/evaluations", status_code=201)
def post_evaluation(body: EvaluationIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    try:
        out = T.register(session, org.id, user.name, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    session.commit()
    audit.record(user.name, user.role, "astra.tgn.evaluation", detail={"model": out["model"]["id"], "passed": out["evaluation"]["passed"], "disagrees": out["disagrees"]})
    return out


@router.get("/tgn/models")
def models(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    org = current_organisation(session)
    out = []
    for m in session.scalars(select(LearnedModel).where(LearnedModel.organisation_id == org.id, LearnedModel.detector == "tgn").order_by(LearnedModel.version.desc()).limit(20)):
        ev = T.latest_evaluation(session, m.id)
        out.append({**T.model_row(m), "evaluation": T.evaluation_row(ev) if ev else None})
    return out


@router.get("/tgn/active")
def active(session: Session = Depends(get_session)) -> Optional[Dict[str, Any]]:
    return T.active_info(session, current_organisation(session).id)


class WindowIn(BaseModel):
    agent: str = Field(min_length=1, max_length=80)
    window_start: float
    events: int = Field(ge=0, le=1_000_000)
    score: float


class ScoresIn(BaseModel):
    model_id: uuid.UUID
    windows: List[WindowIn] = Field(max_length=500)


@router.post("/tgn/scores")
def post_scores(body: ScoresIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    try:
        out = T.accept_scores(session, org.id, body.model_id, [w.model_dump() for w in body.windows])
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    session.commit()
    if out["flagged"]:
        audit.record(user.name, user.role, "astra.tgn.flag", detail={"model": str(body.model_id), **out})
    return out


@router.post("/tgn/models/{model_id}/adopt")
def adopt(model_id: uuid.UUID, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    m = session.get(LearnedModel, model_id)
    if m is None or m.organisation_id != org.id or m.detector != "tgn":
        raise HTTPException(status_code=404, detail="No such model.")
    try:
        T.adopt(session, org.id, user.name, m)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    session.commit()
    audit.record(user.name, user.role, "astra.tgn.adopt", detail={"model": str(m.id), "version": m.version, "advisory_only": True})
    return T.model_row(m)


@router.post("/tgn/rollback")
def rollback(session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    try:
        prev = T.rollback(session, org.id, user.name)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    session.commit()
    audit.record(user.name, user.role, "astra.tgn.rollback", detail={"restored": str(prev.id) if prev else None})
    return {"restored": T.model_row(prev) if prev else None, "adopted": prev is not None}


@router.get("/tgn/health")
def tgn_health(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return T.health(session, current_organisation(session).id)
