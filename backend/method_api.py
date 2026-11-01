"""
Methods over the API: which method is in force, publishing the next one, and re-scoring a signed contract under the method in force now.

A contract is never rewritten. Re-scoring shows what the same design would score today beside what it scored when it was signed, so a reader can see whether a change of method
changes the answer; to act on it, the design is ratified or compiled again under the current method.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import method
from auth import AuthUser, current_user
from db.models import Contract
from db.session import get_session

router = APIRouter(prefix="/api", tags=["method"])


class MethodOut(BaseModel):
    number: int
    fingerprint: str
    engine: str
    note: str
    published_by: str
    published_at: str
    changed: List[str] = []          # which parts differ from the method before it


class MethodState(BaseModel):
    current: Optional[Dict[str, Any]]
    changed_since_published: List[str]
    history: List[MethodOut]


def _history_out(rows) -> List[MethodOut]:
    by_number = {r.number: r for r in rows}
    return [MethodOut(number=r.number, fingerprint=r.fingerprint, engine=r.engine, note=r.note, published_by=r.published_by, published_at=r.published_at.isoformat(),
                      changed=method.changed_parts(by_number[r.number - 1].parts, r.parts) if r.number - 1 in by_number else []) for r in rows]


def _state(session: Session) -> MethodState:
    stamp = method.stamp(session)
    rows = method.history(session)
    changed = method.changed_parts(rows[0].parts, method.parts_now(session)) if rows and stamp and stamp["unpublished"] else []
    return MethodState(current=stamp, changed_since_published=changed, history=_history_out(rows))


@router.get("/method", response_model=MethodState)
def get_method(session: Session = Depends(get_session)) -> MethodState:
    return _state(session)


class PublishBody(BaseModel):
    note: str = Field(min_length=5, max_length=2000)


@router.post("/method/publish", response_model=MethodState, status_code=201)
def publish_method(body: PublishBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> MethodState:
    try:
        method.publish(session, user.name, body.note)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _state(session)


def _signed(doc: Dict[str, Any]) -> Dict[str, Any]:
    snap = doc.get("design_snapshot") or {}
    assurance = snap.get("assurance") or {}
    if doc.get("object_type") == "AGENT":
        rcr = snap.get("rcr") or {}
        return {"score": rcr.get("score"), "band": rcr.get("band"), "gate": rcr.get("gate"), "method": assurance.get("method")}
    pcs = assurance.get("pcs") or {}
    return {"score": pcs.get("final"), "band": pcs.get("tier"), "gate": pcs.get("gate"), "method": assurance.get("method")}


@router.get("/contracts/{contract_id}/rescore")
def rescore(contract_id: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    row = session.scalar(select(Contract).where(Contract.contract_id == contract_id))
    if row is None:
        raise HTTPException(status_code=404, detail="No such contract.")
    doc, snap = row.document, row.document.get("design_snapshot") or {}
    signed = _signed({**doc, "object_type": row.object_type})
    try:
        if row.object_type == "AGENT":
            from agent_review import _score
            res = _score(session, {"profile": snap.get("profile"), "req": snap.get("declarations") or {}, "nodes": snap.get("nodes", []), "edges": snap.get("edges", [])})
            now = {"score": res.score, "band": res.band, "gate": res.gate}
        else:
            from schema import RegistryBlock
            from scoring_bridge import score_registry
            pcs, _ = score_registry(RegistryBlock(**snap["registry"]))
            now = {"score": pcs.pcs_final, "band": pcs.tier, "gate": pcs.gate}
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"This contract could not be scored again: {exc}")
    now["method"] = method.stamp(session)
    sm, nm = signed.get("method"), now["method"]
    method_changed = bool(sm and nm and sm.get("fingerprint") != nm.get("fingerprint"))
    differs = signed.get("gate") is not None and (signed["gate"] != now["gate"] or signed["band"] != now["band"] or abs((signed["score"] or 0) - (now["score"] or 0)) > 1e-6)
    return {"contract_id": contract_id, "signed": signed, "now": now, "method_changed": method_changed, "unrecorded": sm is None, "differs": differs,
            "note": ("Signed before methods were recorded; compared with the method in force now." if sm is None else
                     "Signed under a different method." if method_changed else "Signed under the method in force now.")}
