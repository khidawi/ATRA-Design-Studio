"""
The audit log (Task 8): every state-changing request, sign-in, failed sign-in and refused action is recorded, each event
chained to the one before by hash, so editing or removing an event is detectable.

Event hash = sha256(previous event's hash + ":" + canonical payload). The payload holds who, what, when and the outcome;
it never holds a request body, so passwords and drafts are not logged. Events are only ever appended.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from db.models import AuditEvent
from db.session import SessionLocal, get_session

router = APIRouter(prefix="/api/audit", tags=["audit"])
GENESIS = "GENESIS"


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def event_hash(previous: str, payload: Dict[str, Any]) -> str:
    return hashlib.sha256(f"{previous}:{canonical(payload)}".encode("utf-8")).hexdigest()


def record(actor_name: str, actor_role: Optional[str], action: str, outcome: str = "ok", detail: Optional[Dict[str, Any]] = None) -> None:
    """Appends one event in its own transaction, one writer at a time so the chain cannot fork."""
    now = datetime.now(timezone.utc)
    payload = {"at": now.isoformat(), "actor": actor_name, "role": actor_role, "action": action, "outcome": outcome, "detail": detail or {}}
    with SessionLocal() as s:
        s.execute(text("SELECT pg_advisory_xact_lock(7002)"))
        prev = s.scalar(select(AuditEvent.event_hash).order_by(AuditEvent.seq.desc()).limit(1)) or GENESIS
        s.add(AuditEvent(at=now, actor_name=actor_name, actor_role=actor_role, action=action, outcome=outcome, payload=payload,
                         prev_hash=prev, event_hash=event_hash(prev, payload)))
        s.commit()


class EventOut(BaseModel):
    seq: int
    at: datetime
    actor: str
    role: Optional[str]
    action: str
    outcome: str
    detail: Dict[str, Any]
    event_hash: str


@router.get("", response_model=List[EventOut])
def list_events(limit: int = 100, before: Optional[int] = None, session: Session = Depends(get_session)) -> List[EventOut]:
    q = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(min(max(limit, 1), 500))
    if before:
        q = q.where(AuditEvent.seq < before)
    return [EventOut(seq=e.seq, at=e.at, actor=e.actor_name, role=e.actor_role, action=e.action, outcome=e.outcome,
                     detail=e.payload.get("detail", {}), event_hash=e.event_hash) for e in session.scalars(q)]


class VerifyOut(BaseModel):
    ok: bool
    events: int
    broken_at: Optional[int]
    problem: Optional[str]
    head_hash: Optional[str]


@router.get("/verify", response_model=VerifyOut)
def verify(session: Session = Depends(get_session)) -> VerifyOut:
    """Re-computes every event's hash from its stored payload and checks each one points at the one before."""
    expected, count, head = GENESIS, 0, None
    for e in session.scalars(select(AuditEvent).order_by(AuditEvent.seq)):
        count += 1
        if e.prev_hash != expected:
            return VerifyOut(ok=False, events=count, broken_at=e.seq, problem="This event does not follow the one before it: an event was removed or inserted.", head_hash=head)
        if event_hash(e.prev_hash, e.payload) != e.event_hash:
            return VerifyOut(ok=False, events=count, broken_at=e.seq, problem="The recorded content of this event no longer matches its hash.", head_hash=head)
        expected = head = e.event_hash
    return VerifyOut(ok=True, events=count, broken_at=None, problem=None, head_hash=head)
