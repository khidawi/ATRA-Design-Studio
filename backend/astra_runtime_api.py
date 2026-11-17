"""
The divergence classes at runtime (ASTRA phase 6):

  GET    /api/astra/classes                  the 22 classes of the specification: what the platform does about each, and whether any collector sends the events it needs
  GET    /api/astra/bindings?agent=          which contract element an observed name stands for (signoff to change: a binding decides what a name is allowed to be)
  POST   /api/astra/bindings                 {agent, element, selector, contract_name}
  DELETE /api/astra/bindings/{id}
  GET    /api/astra/peer-keys                the public keys agents sign their messages with
  POST   /api/astra/peer-keys                {key_id, agent, public_key} (public half only)
  POST   /api/astra/findings/{key}/adjudicate   a person judges a pending semantic finding: confirm (it stays open) or dismiss (acknowledged, not a divergence)

How a class is shown: "monitored" means the check exists and runs on every event of the kind; "events" counts what collectors have actually sent for it in the last 30 days. A monitored
class with no events is shown as needing a collector event, never as covered.
"""
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import astra_conformity as AR
import astra_signing as SG
import audit
from agent_registry import agent_key
from astra_model.classes import CLASSES
from auth import AuthUser, current_user
from db.models import AstraBinding, AstraPeerKey, Finding, LearnedScore, RuntimeEvent
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/astra", tags=["astra"])
WINDOW_DAYS = 30


@router.get("/classes")
def classes(session: Session = Depends(get_session)) -> Dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    seen = {t: (n, last) for t, n, last in session.execute(select(RuntimeEvent.type, func.count(), func.max(RuntimeEvent.at)).where(RuntimeEvent.at >= since).group_by(RuntimeEvent.type)).all()}
    opened = {c: n for c, n in session.execute(select(Finding.class_code, func.count()).where(Finding.status == "OPEN", Finding.class_code.in_(list(CLASSES))).group_by(Finding.class_code)).all()}
    rows: List[Dict[str, Any]] = []
    for cid, c in CLASSES.items():
        state = AR.class_state(cid)
        wires = AR.WIRE.get(c.event, [])
        n = sum(seen.get(w, (0, None))[0] for w in wires)
        if c.event == "score":                                                       # the baseline is not fed by collector events but by the windows it has scored
            n = session.scalar(select(func.count()).select_from(LearnedScore).where(LearnedScore.created_at >= since)) or 0
        last = max([seen[w][1] for w in wires if w in seen] or [None], key=lambda x: x or datetime.min.replace(tzinfo=timezone.utc))
        rows.append({"id": cid, "name": c.name, "element": c.element, "construct": c.construct, "asi": list(c.asi), "basis": c.basis, "severity": c.severity, "event": c.event, "state": state,
                     "events": n, "last_event": last.isoformat() if last else None, "open_findings": opened.get(cid, 0),
                     "needs": AR.NEEDS.get(c.event) if n == 0 else None,
                     "note": "a learned detector: it can only mark the baseline control unverified, never block on its own" if state == "advisory" else ("a classifier or a person judges; the platform queues it for adjudication" if state == "pending" else None)})
    monitored = [r for r in rows if r["state"] in ("monitored", "pending", "advisory")]
    return {"classes": rows, "window_days": WINDOW_DAYS,
            "counts": {"total": len(rows), "monitored": len(monitored), "deterministic": sum(1 for r in rows if r["state"] == "monitored"), "pending": sum(1 for r in rows if r["state"] == "pending"),
                       "advisory": sum(1 for r in rows if r["state"] == "advisory"), "receiving_events": sum(1 for r in monitored if r["events"] > 0), "needs_collector": sum(1 for r in monitored if r["events"] == 0)}}


class BindingIn(BaseModel):
    agent: str = Field(min_length=2, max_length=80)
    element: Literal["tool", "resource", "delegate", "component"]
    selector: str = Field(min_length=1, max_length=200)
    contract_name: str = Field(min_length=1, max_length=200)


def _binding(b: AstraBinding) -> Dict[str, Any]:
    return {"id": str(b.id), "agent_key": b.agent_key, "element": b.element, "selector": b.selector, "contract_name": b.contract_name, "created_by": b.created_by, "created_at": b.created_at.isoformat()}


@router.get("/bindings")
def list_bindings(agent: Optional[str] = None, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    q = select(AstraBinding).where(AstraBinding.organisation_id == current_organisation(session).id)
    if agent:
        q = q.where(AstraBinding.agent_key == agent_key(agent))
    return [_binding(b) for b in session.scalars(q.order_by(AstraBinding.created_at))]


@router.post("/bindings", status_code=201)
def add_binding(body: BindingIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    key = agent_key(body.agent)
    if session.scalar(select(AstraBinding.id).where(AstraBinding.organisation_id == org.id, AstraBinding.agent_key == key, AstraBinding.element == body.element, AstraBinding.selector == body.selector)):
        raise HTTPException(status_code=409, detail="That selector is already bound for this agent and element.")
    b = AstraBinding(organisation_id=org.id, agent_key=key, element=body.element, selector=body.selector.strip(), contract_name=body.contract_name.strip(), created_by=user.name)
    session.add(b)
    session.commit()
    audit.record(user.name, user.role, "astra.bind", detail={"agent": key, "element": b.element, "selector": b.selector, "contract_name": b.contract_name})
    return _binding(b)


@router.delete("/bindings/{binding_id}")
def delete_binding(binding_id: uuid.UUID, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    b = session.get(AstraBinding, binding_id)
    if b is None or b.organisation_id != current_organisation(session).id:
        raise HTTPException(status_code=404, detail="No such binding.")
    session.delete(b)
    session.commit()
    audit.record(user.name, user.role, "astra.unbind", detail={"agent": b.agent_key, "element": b.element, "selector": b.selector})
    return {"deleted": str(binding_id)}


class PeerKeyIn(BaseModel):
    key_id: str = Field(min_length=2, max_length=64)
    agent: str = Field(min_length=2, max_length=80)
    public_key: str = Field(min_length=20, max_length=64)


@router.get("/peer-keys")
def list_peer_keys(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    return [{"key_id": k.key_id, "agent_key": k.agent_key, "created_by": k.created_by, "created_at": k.created_at.isoformat()}
            for k in session.scalars(select(AstraPeerKey).where(AstraPeerKey.organisation_id == current_organisation(session).id).order_by(AstraPeerKey.created_at))]


@router.post("/peer-keys", status_code=201)
def add_peer_key(body: PeerKeyIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    if not SG.KEY_ID.match(body.key_id):
        raise HTTPException(status_code=422, detail="A key id is 2 to 64 letters, digits, dots, dashes or underscores.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", body.public_key):
        raise HTTPException(status_code=422, detail="The public key is a 32-byte Ed25519 key in unpadded base64url (43 characters).")
    try:
        SG.Ed25519PublicKey.from_public_bytes(SG._b64d(body.public_key))
    except Exception:
        raise HTTPException(status_code=422, detail="That is not a valid Ed25519 public key.")
    if session.scalar(select(AstraPeerKey.id).where(AstraPeerKey.organisation_id == org.id, AstraPeerKey.key_id == body.key_id)):
        raise HTTPException(status_code=409, detail="A key with that id is already registered; keys are not replaced, register a new id.")
    k = AstraPeerKey(organisation_id=org.id, key_id=body.key_id, agent_key=agent_key(body.agent), public_key=body.public_key, created_by=user.name)
    session.add(k)
    session.commit()
    audit.record(user.name, user.role, "astra.peerkey", detail={"key_id": k.key_id, "agent": k.agent_key})
    return {"key_id": k.key_id, "agent_key": k.agent_key}


class AdjudicateIn(BaseModel):
    decision: Literal["confirm", "dismiss"]
    note: str = Field(..., min_length=3, max_length=500)


@router.post("/findings/{key}/adjudicate")
def adjudicate(key: str, body: AdjudicateIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    try:
        seq = int(key.removeprefix("F-"))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such finding.")
    f = session.scalar(select(Finding).where(Finding.seq == seq))
    if f is None:
        raise HTTPException(status_code=404, detail="No such finding.")
    if f.adjudication != "PENDING":
        raise HTTPException(status_code=409, detail="This finding is not waiting for a judgement.")
    f.adjudication = "CONFIRMED" if body.decision == "confirm" else "DISMISSED"
    f.adjudicated_by, f.adjudicated_at, f.adjudication_note = user.name, datetime.now(timezone.utc), body.note.strip()
    if body.decision == "dismiss":
        f.status, f.acknowledged_by, f.acknowledged_at = "ACKNOWLEDGED", user.name, datetime.now(timezone.utc)
    session.commit()
    audit.record(user.name, user.role, "astra.adjudicate", detail={"finding": f"F-{f.seq}", "decision": body.decision, "class": f.class_code})
    return {"finding_key": f"F-{f.seq}", "adjudication": f.adjudication, "status": f.status, "adjudicated_by": user.name}
