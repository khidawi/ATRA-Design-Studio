"""
Learned detectors through the API (ASTRA phase 9). What a learned detector may do is fixed in astra_learned.py (it can only move the baseline control to unverified); this is how people
and schedules use it.

  GET  /api/astra/learned/detectors                     each detector and whether it exists yet
  GET  /api/astra/learned/agents                        per agent: calibration state, model, last score, open flags
  POST /api/astra/learned/agents/{key}/calibrate        train the baseline from the agent's conforming events (signoff: it decides what counts as normal)
  POST /api/astra/learned/agents/{key}/score            score the windows since the last score (write)
  POST /api/astra/learned/score-all                     what a schedule calls
  GET  /api/astra/learned/agents/{key}/scores           recent window scores
  GET  /api/astra/learned/flags                         flags, the ones on agents that can reach the highest impact tier first
  POST /api/astra/learned/flags/{id}/adjudicate         benign for a number of days, or real (signoff)
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import astra_assessment_api as AA
import astra_baseline as B
import astra_contract_export as EX
import astra_estate as AE
import astra_learned as L
import audit
from agent_registry import agent_key as slug
from auth import AuthUser, current_user
from db.models import Design, LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/astra/learned", tags=["astra"])
log = logging.getLogger(__name__)


def reach_tier(session: Session, org_id: uuid.UUID, agent_key: str) -> int:
    """The highest impact tier of what the agent can reach, by its saved design. Unknown reach is read as the most severe tier (fail closed)."""
    try:
        for d in session.scalars(select(Design).where(Design.organisation_id == org_id, Design.subject == "AGENT")):
            try:
                if EX.contract_agent_id(AE._primary(d.document)["name"]) != agent_key:
                    continue
            except ValueError:
                continue
            ctx = AA.context(session, d.document)
            built = AE.build(AE.Source(d.document, AA._rows(session, d.document), AA._evidence(session, d.design_key)), ctx)
            tiers = [built.estate.res[r][1] for a in built.estate.agents.values() for r in a.resources if r in built.estate.res]
            return max(tiers) if tiers else 1
    except Exception:
        log.warning("the reach of %s could not be worked out", agent_key, exc_info=True)
    return 4


def _model(m: LearnedModel) -> Dict[str, Any]:
    p = m.parameters
    return {"id": str(m.id), "detector": m.detector, "version": m.version, "status": m.status, "created_by": m.created_by, "created_at": m.created_at.isoformat(), "trained_on": m.trained_on,
            "window_seconds": p["window_seconds"], "threshold": p["threshold"]}


def _flag(f: LearnedFlag, tier: int, now: datetime) -> Dict[str, Any]:
    return {"id": str(f.id), "agent_key": f.agent_key, "detector": f.detector, "score": f.score, "threshold": f.threshold, "control": f.control, "level": f.level, "status": f.status,
            "effective": L.effective(f, now), "tier": tier, "detail": f.detail, "adjudicated_by": f.adjudicated_by, "adjudication_note": f.adjudication_note,
            "expires_at": f.expires_at.isoformat() if f.expires_at else None, "created_at": f.created_at.isoformat(), "window_start": None}


@router.get("/detectors")
def detectors(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    org = current_organisation(session)
    n_models = session.scalar(select(func.count()).select_from(LearnedModel).where(LearnedModel.organisation_id == org.id, LearnedModel.status == "ACTIVE", LearnedModel.detector == "baseline"))
    n_flags = session.scalar(select(func.count()).select_from(LearnedFlag).where(LearnedFlag.organisation_id == org.id, LearnedFlag.status == "OPEN"))
    out = []
    for d in L.DETECTORS:
        flags_of = session.scalar(select(func.count()).select_from(LearnedFlag).where(LearnedFlag.organisation_id == org.id, LearnedFlag.status == "OPEN", LearnedFlag.detector == d["id"]))
        d = {**d, "models": n_models if d["id"] == "baseline" else 0, "open_flags": flags_of if d["id"] != "baseline" else n_flags}
        if d["id"] == "tgn":
            cands = session.scalars(select(LearnedModel).where(LearnedModel.organisation_id == org.id, LearnedModel.detector == "tgn", LearnedModel.status == "CANDIDATE")).all()
            adopted = session.scalar(select(LearnedModel).where(LearnedModel.organisation_id == org.id, LearnedModel.detector == "tgn", LearnedModel.status == "ACTIVE", LearnedModel.adopted.is_(True)))
            d.update(models=1 if adopted else 0, candidates=len(cands), status="adopted" if adopted else ("candidate" if cands else "available"))
        out.append(d)
    return out


@router.get("/agents")
def agents(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    org = current_organisation(session)
    since = datetime.now(timezone.utc) - timedelta(days=L.LOOKBACK_DAYS)
    keys = {k for (k,) in session.execute(select(RuntimeEvent.agent_key).where(RuntimeEvent.organisation_id == org.id, RuntimeEvent.at >= since).distinct()).all()}
    keys |= {k for (k,) in session.execute(select(LearnedModel.agent_key).where(LearnedModel.organisation_id == org.id)).all()}
    now = datetime.now(timezone.utc)
    out = []
    for k in sorted(keys):
        m = L.active_model(session, org.id, k)
        ws = m.parameters["window_seconds"] if m else B.DEFAULT_WINDOW_SECONDS
        n, nw = L.counts(session, org.id, k, ws)
        retired = bool(session.scalar(select(LearnedModel.id).where(LearnedModel.organisation_id == org.id, LearnedModel.agent_key == k, LearnedModel.status == "RETIRED").limit(1)))
        st = B.calibration_state(n, nw, m is not None, retired)
        last = session.scalar(select(LearnedScore).where(LearnedScore.organisation_id == org.id, LearnedScore.agent_key == k).order_by(LearnedScore.window_start.desc()).limit(1))
        flags = [f for f in session.scalars(select(LearnedFlag).where(LearnedFlag.organisation_id == org.id, LearnedFlag.agent_key == k)) if L.effective(f, now)]
        out.append({"agent_key": k, "state": st["state"], "missing": st["missing"], "events": n, "windows": nw, "model": _model(m) if m else None,
                    "last_score": None if last is None else {"score": last.score, "threshold": last.threshold, "window_start": last.window_start.isoformat(), "why": (last.detail or {}).get("why", [])},
                    "open_flags": len(flags), "defaults": {"window_seconds": B.DEFAULT_WINDOW_SECONDS, "min_events": B.MIN_EVENTS, "min_windows": B.MIN_WINDOWS, "threshold": B.DEFAULT_THRESHOLD}})
    return out


class CalibrateIn(BaseModel):
    window_seconds: int = Field(B.DEFAULT_WINDOW_SECONDS, ge=B.FLOORS["window_seconds"], le=86400)
    threshold: float = Field(B.DEFAULT_THRESHOLD, ge=2.0, le=20.0)
    min_events: int = Field(B.MIN_EVENTS, ge=B.FLOORS["events"], le=100000)
    min_windows: int = Field(B.MIN_WINDOWS, ge=B.FLOORS["windows"], le=10000)


@router.post("/agents/{agent_key}/calibrate", status_code=201)
def calibrate(agent_key: str, body: CalibrateIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    try:
        m = L.calibrate(session, org.id, slug(agent_key), user.name, body.window_seconds, body.threshold, body.min_events, body.min_windows)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    session.commit()
    audit.record(user.name, user.role, "astra.learned.calibrate", detail={"agent": m.agent_key, "detector": "baseline", "version": m.version, "events": m.trained_on["events"]})
    return _model(m)


@router.post("/agents/{agent_key}/score")
def score_agent(agent_key: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    try:
        out = L.score(session, org.id, slug(agent_key))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    session.commit()
    if out["flagged"]:
        audit.record(user.name, user.role, "astra.learned.flag", detail={"agent": out["agent_key"], "flags": out["flags"]})
    return out


@router.post("/score-all")
def score_all(session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    out: List[Dict[str, Any]] = []
    for (k,) in session.execute(select(LearnedModel.agent_key).where(LearnedModel.organisation_id == org.id, LearnedModel.status == "ACTIVE", LearnedModel.detector == "baseline")).all():
        try:
            r = L.score(session, org.id, k)
            session.commit()
            out.append(r)
        except Exception:                                                  # one agent that cannot be scored must not stop the rest
            session.rollback()
            log.exception("could not score %s", k)
            out.append({"agent_key": k, "error": "This agent could not be scored; the reason is in the server log."})
    return {"agents": out, "flagged": sum(r.get("flagged", 0) for r in out), "failed": sum(1 for r in out if "error" in r)}


@router.get("/agents/{agent_key}/scores")
def scores(agent_key: str, limit: int = 48, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    org = current_organisation(session)
    rows = session.scalars(select(LearnedScore).where(LearnedScore.organisation_id == org.id, LearnedScore.agent_key == slug(agent_key)).order_by(LearnedScore.window_start.desc()).limit(min(max(limit, 1), 200)))
    return [{"window_start": r.window_start.isoformat(), "window_end": r.window_end.isoformat(), "events": r.events, "score": r.score, "threshold": r.threshold, "why": (r.detail or {}).get("why", [])} for r in rows]


@router.get("/flags")
def flags(status: Literal["open", "all"] = "all", session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    org = current_organisation(session)
    now = datetime.now(timezone.utc)
    rows = list(session.scalars(select(LearnedFlag).where(LearnedFlag.organisation_id == org.id).order_by(LearnedFlag.created_at.desc()).limit(200)))
    tiers: Dict[str, int] = {}
    out = []
    for f in rows:
        if status == "open" and not L.effective(f, now):
            continue
        if f.agent_key not in tiers:
            tiers[f.agent_key] = reach_tier(session, org.id, f.agent_key)
        s = session.get(LearnedScore, f.score_id)
        d = _flag(f, tiers[f.agent_key], now)
        d["window_start"] = s.window_start.isoformat() if s else None
        out.append(d)
    out.sort(key=lambda d: (not d["effective"], -d["tier"], -d["score"]))
    return out


class AdjudicateIn(BaseModel):
    outcome: Literal["benign", "real"]
    note: str = Field(..., min_length=3, max_length=500)
    days: int = Field(30, ge=1, le=365)                                   # how long a benign judgement lasts


@router.post("/flags/{flag_id}/adjudicate")
def adjudicate(flag_id: uuid.UUID, body: AdjudicateIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    f = session.get(LearnedFlag, flag_id)
    if f is None or f.organisation_id != org.id:
        raise HTTPException(status_code=404, detail="No such flag.")
    now = datetime.now(timezone.utc)
    if f.status != "OPEN" and not (f.status == "BENIGN" and L.effective(f, now)):
        raise HTTPException(status_code=409, detail="This flag has already been judged.")
    f.status = "BENIGN" if body.outcome == "benign" else "REAL"
    f.adjudicated_by, f.adjudicated_at, f.adjudication_note = user.name, now, body.note.strip()
    f.expires_at = now + timedelta(days=body.days) if body.outcome == "benign" else None
    session.commit()
    audit.record(user.name, user.role, "astra.learned.adjudicate", detail={"flag": str(f.id), "agent": f.agent_key, "outcome": body.outcome, "days": body.days if body.outcome == "benign" else None})
    return _flag(f, reach_tier(session, org.id, f.agent_key), now)
