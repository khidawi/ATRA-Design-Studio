"""
The organisation risk layer (ASTRA phase 2): who declares how much harm matters to each department, and who accepts it.

  GET  /api/risk                                      departments, data stores, the posture matrix, what is waiting, the history, and the values in force
  POST /api/risk/assets                               propose the impact tier of an asset (a data store of the organisation graph)
  POST /api/risk/tolerances                           propose the tolerance of a department
  POST /api/risk/posture                              propose the response posture for one tier and severity
  POST /api/risk/proposals/{kind}/{id}/ratify         accept a proposal (sign-off permission, and not the person who proposed it)
  POST /api/risk/proposals/{kind}/{id}/reject         refuse a proposal, with a reason

Anyone who may write can propose. Only someone with sign-off permission can ratify, and never their own proposal. A ratified value is in force until another is ratified;
nothing is edited or deleted. Every proposal and decision goes into the audit chain.

effective() is what later phases read: the values in force, with the fail-closed defaults of risk_layer.py for whatever has not been ratified.
The organisation graph (company_nodes) is only read here, never changed.
"""
import uuid
from typing import Any, Dict, List, Literal, Optional, Tuple, Type

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import audit
import risk_layer as RL
from auth import AuthUser, current_user
from db.models import CompanyNode, RiskAssetTier, RiskDepartmentTolerance, RiskPosture
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/risk", tags=["risk"])

MODELS: Dict[str, Type] = {"asset": RiskAssetTier, "tolerance": RiskDepartmentTolerance, "posture": RiskPosture}
Level = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AssetIn(BaseModel):
    asset_ext: str = Field(min_length=1, max_length=64)
    department_ext: Optional[str] = Field(default=None, max_length=64)
    tier: int = Field(ge=1, le=4)
    asset_kind: Literal["data", "memory"] = "data"
    confidentiality: Level = "MEDIUM"
    integrity: Level = "MEDIUM"
    availability: Level = "MEDIUM"
    rationale: str = Field(min_length=RL.MIN_RATIONALE, max_length=2000)


class ToleranceIn(BaseModel):
    department_ext: str = Field(min_length=1, max_length=64)
    tolerance: int = Field(ge=0, le=4)
    rationale: str = Field(min_length=RL.MIN_RATIONALE, max_length=2000)


class PostureIn(BaseModel):
    tier: int = Field(ge=1, le=4)
    severity: Literal["Medium", "High", "Critical"]
    posture: Literal["observe", "flag", "block", "halt"]
    rationale: str = Field(min_length=RL.MIN_RATIONALE, max_length=2000)


class DecisionIn(BaseModel):
    note: str = Field(default="", max_length=2000)


# ── reading ─────────────────────────────────────────────────────────────────

def _key(kind: str, row: Any) -> Tuple:
    if kind == "asset":
        return (row.asset_ext,)
    if kind == "tolerance":
        return (row.department_ext,)
    return (row.tier, row.severity)


def _key_filter(kind: str, row: Any) -> List[Any]:
    M = MODELS[kind]
    if kind == "asset":
        return [M.asset_ext == row.asset_ext]
    if kind == "tolerance":
        return [M.department_ext == row.department_ext]
    return [M.tier == row.tier, M.severity == row.severity]


def _value(kind: str, row: Any) -> Dict[str, Any]:
    if kind == "asset":
        return {"tier": row.tier, "asset_kind": row.kind, "confidentiality": row.confidentiality, "integrity": row.integrity, "availability": row.availability,
                "department_ext": row.department_ext}
    if kind == "tolerance":
        return {"tolerance": row.tolerance}
    return {"posture": row.posture}


def _row(kind: str, r: Any) -> Dict[str, Any]:
    out = {"id": str(r.id), "kind": kind, "status": r.status, "rationale": r.rationale, "proposed_by": r.proposed_by, "proposed_at": r.proposed_at.isoformat(),
           "decided_by": r.decided_by, "decided_at": r.decided_at.isoformat() if r.decided_at else None, "decision_note": r.decision_note}
    if kind == "asset":
        out.update(asset_ext=r.asset_ext, name=r.name)
    elif kind == "tolerance":
        out.update(department_ext=r.department_ext)
    else:
        out.update(tier=r.tier, severity=r.severity)
    out.update(_value(kind, r))
    return out


def _rows(session: Session, org_id: uuid.UUID, kind: str, *statuses: str) -> List[Any]:
    M = MODELS[kind]
    return list(session.scalars(select(M).where(M.organisation_id == org_id, M.status.in_(statuses)).order_by(M.proposed_at)))


def effective(session: Session) -> Dict[str, Any]:
    """The values in force, for later phases: ratified declarations, and the fail-closed default for everything else."""
    org = current_organisation(session)
    tiers = {r.asset_ext: {"tier": r.tier, "department_ext": r.department_ext, "name": r.name, "asset_kind": r.kind, "source": "ratified"} for r in _rows(session, org.id, "asset", "RATIFIED")}
    tol = {r.department_ext: r.tolerance for r in _rows(session, org.id, "tolerance", "RATIFIED")}
    over = {(r.tier, r.severity): r.posture for r in _rows(session, org.id, "posture", "RATIFIED")}
    return {"tiers": tiers, "tolerance": tol, "posture": RL.posture_matrix(over), "default_tier": RL.DEFAULT_TIER, "default_tolerance": RL.DEFAULT_TOLERANCE}


def tier_of(eff: Dict[str, Any], asset_ext: str) -> int:
    t = eff["tiers"].get(asset_ext)
    return t["tier"] if t else eff["default_tier"]


def tolerance_of(eff: Dict[str, Any], department_ext: str) -> int:
    return eff["tolerance"].get(department_ext, eff["default_tolerance"])


def _graph(session: Session, org_id: uuid.UUID) -> Tuple[Dict[str, CompanyNode], Dict[str, CompanyNode]]:
    nodes = list(session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org_id, CompanyNode.type.in_(("department", "data_store")))))
    return ({n.ext_id: n for n in nodes if n.type == "department"}, {n.ext_id: n for n in nodes if n.type == "data_store"})


def _summary(kind: str, r: Any, names: Optional[Dict[str, str]] = None) -> str:
    if kind == "asset":
        return f"{r.name}: impact tier {r.tier}"
    if kind == "tolerance":
        return f"{(names or {}).get(r.department_ext, r.department_ext)}: tolerance {r.tolerance}"
    return f"tier {r.tier}, {r.severity} severity: {r.posture}"


def _state(session: Session) -> Dict[str, Any]:
    org = current_organisation(session)
    depts, stores = _graph(session, org.id)
    eff = effective(session)
    live = {k: {_key(k, r): r for r in _rows(session, org.id, k, "RATIFIED")} for k in MODELS}
    wait = {k: {_key(k, r): r for r in _rows(session, org.id, k, "PROPOSED")} for k in MODELS}
    one = lambda kind, key: _row(kind, live[kind][key]) if key in live[kind] else None            # noqa: E731
    pend = lambda kind, key: _row(kind, wait[kind][key]) if key in wait[kind] else None           # noqa: E731

    asset_keys = {(e,) for e in stores} | set(live["asset"]) | set(wait["asset"])
    assets = []
    for (ext,) in sorted(asset_keys):
        n = stores.get(ext)
        ratified = one("asset", (ext,))
        assets.append({"asset_ext": ext, "name": n.name if n else (ratified or pend("asset", (ext,)))["name"], "in_graph": n is not None,
                       "department_ext": (n.props or {}).get("department") if n else None, "ratified": ratified, "pending": pend("asset", (ext,)),
                       "effective_tier": tier_of(eff, ext), "declared": ext in eff["tiers"]})
    dept_keys = {(e,) for e in depts} | set(live["tolerance"]) | set(wait["tolerance"])
    departments = []
    for (ext,) in sorted(dept_keys):
        n = depts.get(ext)
        departments.append({"department_ext": ext, "name": n.name if n else ext, "in_graph": n is not None, "ratified": one("tolerance", (ext,)), "pending": pend("tolerance", (ext,)),
                            "effective_tolerance": tolerance_of(eff, ext), "declared": ext in eff["tolerance"]})
    cells = []
    for t in RL.TIERS:
        for s in RL.SEVERITIES:
            cells.append({"tier": t, "severity": s, "posture": eff["posture"][t][s], "source": "ratified" if (t, s) in live["posture"] else "default",
                          "ratified": one("posture", (t, s)), "pending": pend("posture", (t, s))})
    names = {e: n.name for e, n in depts.items()}
    pending = sorted(({"summary": _summary(k, r, names), **_row(k, r)} for k in MODELS for r in wait[k].values()), key=lambda x: x["proposed_at"])
    decided = []
    for k in MODELS:
        decided += [{"summary": _summary(k, r, names), **_row(k, r)} for r in _rows(session, org.id, k, "RATIFIED", "SUPERSEDED", "REJECTED")]
    decided.sort(key=lambda x: x["decided_at"] or x["proposed_at"], reverse=True)
    return {"departments": departments, "assets": assets, "posture": cells, "pending": pending, "history": decided[:40],
            "defaults": {"tier": RL.DEFAULT_TIER, "tolerance": RL.DEFAULT_TOLERANCE, "posture": RL.DEFAULT_POSTURE},
            "scales": {"tiers": list(RL.TIERS), "tolerances": list(RL.TOLERANCES), "severities": list(RL.SEVERITIES), "postures": list(RL.POSTURES), "levels": list(RL.CIA_LEVELS)}}


@router.get("")
def get_state(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return _state(session)


# ── proposing ───────────────────────────────────────────────────────────────

def _propose(session: Session, user: AuthUser, kind: str, row: Any) -> Dict[str, Any]:
    org = current_organisation(session)
    M = MODELS[kind]
    waiting = session.scalar(select(M).where(M.organisation_id == org.id, M.status == "PROPOSED", *_key_filter(kind, row)))
    if waiting is not None:
        raise HTTPException(status_code=409, detail=f"A proposal for this is already waiting ({_summary(kind, waiting)}, proposed by {waiting.proposed_by}). Ratify or reject it first.")
    live = session.scalar(select(M).where(M.organisation_id == org.id, M.status == "RATIFIED", *_key_filter(kind, row)))
    if live is not None and _value(kind, live) == _value(kind, row):
        raise HTTPException(status_code=409, detail="Nothing changes: this is already the value in force.")
    row.organisation_id, row.proposed_by, row.proposed_by_id, row.status = org.id, user.name, user.id, "PROPOSED"
    session.add(row)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="A proposal for this was made at the same moment. Reload and look at it.")
    audit.record(user.name, user.role, "risk.propose", detail={"kind": kind, "id": str(row.id), "summary": _summary(kind, row)})
    return _row(kind, row)


@router.post("/assets", status_code=201)
def propose_asset(body: AssetIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    depts, stores = _graph(session, org.id)
    node = stores.get(body.asset_ext)
    if node is None:
        raise HTTPException(status_code=422, detail=f"{body.asset_ext!r} is not a data store of the organisation. Add it to the organisation first.")
    dept = body.department_ext or (node.props or {}).get("department")
    if not dept:
        raise HTTPException(status_code=422, detail="Say which department the harm falls on: the data store does not name one.")
    if dept not in depts:
        raise HTTPException(status_code=422, detail=f"{dept!r} is not a department of the organisation.")
    data = body.model_dump()
    data["department_ext"] = dept
    problems = RL.validate_asset(data)
    if problems:
        raise HTTPException(status_code=422, detail="; ".join(problems))
    row = RiskAssetTier(asset_ext=body.asset_ext, name=node.name, department_ext=dept, kind=body.asset_kind, tier=body.tier, confidentiality=body.confidentiality,
                        integrity=body.integrity, availability=body.availability, rationale=body.rationale.strip())
    return _propose(session, user, "asset", row)


@router.post("/tolerances", status_code=201)
def propose_tolerance(body: ToleranceIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    depts, _stores = _graph(session, org.id)
    if body.department_ext not in depts:
        raise HTTPException(status_code=422, detail=f"{body.department_ext!r} is not a department of the organisation.")
    problems = RL.validate_tolerance(body.model_dump())
    if problems:
        raise HTTPException(status_code=422, detail="; ".join(problems))
    return _propose(session, user, "tolerance", RiskDepartmentTolerance(department_ext=body.department_ext, tolerance=body.tolerance, rationale=body.rationale.strip()))


def _matrix_with(session: Session, org_id: uuid.UUID, row: RiskPosture) -> Dict[int, Dict[str, str]]:
    over = {(r.tier, r.severity): r.posture for r in _rows(session, org_id, "posture", "RATIFIED")}
    over[(row.tier, row.severity)] = row.posture
    return RL.posture_matrix(over)


@router.post("/posture", status_code=201)
def propose_posture(body: PostureIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    problems = RL.validate_posture(body.model_dump())
    if problems:
        raise HTTPException(status_code=422, detail="; ".join(problems))
    row = RiskPosture(tier=body.tier, severity=body.severity, posture=body.posture, rationale=body.rationale.strip())
    bad = RL.posture_problems(_matrix_with(session, org.id, row))
    if bad:
        raise HTTPException(status_code=422, detail="A higher tier or severity must not get a milder response: " + "; ".join(bad[:3]))
    return _propose(session, user, "posture", row)


# ── deciding ────────────────────────────────────────────────────────────────

def _load(session: Session, kind: str, pid: uuid.UUID) -> Any:
    if kind not in MODELS:
        raise HTTPException(status_code=404, detail=f"Unknown kind {kind!r}; expected asset, tolerance or posture.")
    org = current_organisation(session)
    row = session.get(MODELS[kind], pid)
    if row is None or row.organisation_id != org.id:
        raise HTTPException(status_code=404, detail="No such proposal.")
    if row.status != "PROPOSED":
        raise HTTPException(status_code=409, detail=f"This proposal is already {row.status.lower()}.")
    return row


@router.post("/proposals/{kind}/{pid}/ratify")
def ratify(kind: str, pid: uuid.UUID, body: DecisionIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    row = _load(session, kind, pid)
    if row.proposed_by_id == user.id:
        raise HTTPException(status_code=409, detail="You cannot ratify your own proposal: another person with sign-off permission has to.")
    if kind == "posture":
        bad = RL.posture_problems(_matrix_with(session, row.organisation_id, row))
        if bad:
            raise HTTPException(status_code=422, detail="Ratifying this would make the posture inconsistent: " + "; ".join(bad[:3]))
    M = MODELS[kind]
    old = session.scalar(select(M).where(M.organisation_id == row.organisation_id, M.status == "RATIFIED", *_key_filter(kind, row)))
    if old is not None:
        old.status = "SUPERSEDED"
        session.flush()                       # the unique index allows one ratified value per key, so the old one has to leave first
    row.status, row.decided_by, row.decided_by_id, row.decision_note = "RATIFIED", user.name, user.id, body.note.strip() or None
    row.decided_at = _now()
    session.commit()
    audit.record(user.name, user.role, "risk.ratify", detail={"kind": kind, "id": str(row.id), "summary": _summary(kind, row), "replaces": str(old.id) if old else None})
    return _state(session)


@router.post("/proposals/{kind}/{pid}/reject")
def reject(kind: str, pid: uuid.UUID, body: DecisionIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    row = _load(session, kind, pid)
    if len(body.note.strip()) < RL.MIN_RATIONALE:
        raise HTTPException(status_code=422, detail="Say why it is refused.")
    row.status, row.decided_by, row.decided_by_id, row.decision_note = "REJECTED", user.name, user.id, body.note.strip()
    row.decided_at = _now()
    session.commit()
    audit.record(user.name, user.role, "risk.reject", detail={"kind": kind, "id": str(row.id), "summary": _summary(kind, row), "note": body.note.strip()})
    return _state(session)


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)
