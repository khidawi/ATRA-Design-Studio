"""
The ST-AI v2.5 policy: read it, and publish a new version (st_ai_policy.py has the rules and the validation).

  GET  /api/st-ai/policy   the policy in force (with its version number), its history, the saved model designs a tolerance can be allocated to, and any problem with it
  POST /api/st-ai/policy   publish a new version: the full set of parameters and a note saying what changed and why. Needs sign-off permission. Versions are never edited.

The policy in force is stamped on every registry the server assesses (enrich), so a review is bound to the version it was made under and lapses when a new one is published.
"""
import hashlib
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import audit
import st_ai_policy as P
from auth import AuthUser, current_user
from db.models import Design, StAiPolicyVersion
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/st-ai", tags=["st-ai"])


def _latest(session: Session, org_id) -> Optional[StAiPolicyVersion]:
    return session.scalar(select(StAiPolicyVersion).where(StAiPolicyVersion.organisation_id == org_id).order_by(StAiPolicyVersion.number.desc()).limit(1))


def current(session: Session) -> Dict[str, Any]:
    """The policy in force: every parameter present, with the version number (0: none published yet, the defaults apply)."""
    org = current_organisation(session)
    row = _latest(session, org.id)
    out = P.normalise(row.params if row is not None else None)
    out["number"] = row.number if row is not None else 0
    return out


def fingerprint_part(session: Session) -> Optional[str]:
    """For the method fingerprint (method.py): a hash of the published policy, or None while none has been published."""
    org = current_organisation(session)
    row = _latest(session, org.id)
    if row is None:
        return None
    return hashlib.sha256(json.dumps(P.normalise(row.params), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def enrich(session: Session, design_key: Optional[str], registry) -> None:
    """Sets, from the server's own records, the policy in force and the saved design's key. Whatever the caller sent is replaced."""
    registry.st_ai = {"design_key": design_key, "policy": current(session)}


class PolicyBody(BaseModel):
    params: Dict[str, Any]
    note: str = Field(min_length=5, max_length=2000)


def _state(session: Session) -> Dict[str, Any]:
    org = current_organisation(session)
    rows = list(session.scalars(select(StAiPolicyVersion).where(StAiPolicyVersion.organisation_id == org.id).order_by(StAiPolicyVersion.number.desc()).limit(20)))
    cur = current(session)
    designs = [{"key": d.design_key, "name": d.name} for d in session.scalars(select(Design).where(Design.organisation_id == org.id, Design.subject == "MODEL").order_by(Design.name))]
    return {
        "policy": cur, "problems": P.validate(cur), "designs": designs, "options": {"levels": list(P.LEVELS), "modes": list(P.MODES), "bases": list(P.BASES), "uses": list(P.USES), "metrics": list(P.METRICS)},
        "history": [{"number": r.number, "note": r.note, "published_by": r.published_by, "published_at": r.published_at.isoformat(), "params": P.normalise(r.params)} for r in rows],
    }


@router.get("/policy")
def get_policy(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return _state(session)


@router.post("/policy", status_code=201)
def publish_policy(body: PolicyBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    problems = P.validate(body.params)
    if problems:
        raise HTTPException(status_code=422, detail="The policy cannot be published: " + "; ".join(problems[:6]) + (f" (and {len(problems) - 6} more)" if len(problems) > 6 else ""))
    org = current_organisation(session)
    last = _latest(session, org.id)
    new = P.normalise(body.params)
    if last is not None and P.normalise(last.params) == new:
        raise HTTPException(status_code=409, detail=f"Nothing changed since version {last.number}: there is nothing to publish.")
    row = StAiPolicyVersion(organisation_id=org.id, number=(last.number if last else 0) + 1, params=new, note=body.note.strip(), published_by=user.name)
    session.add(row)
    session.commit()
    audit.record(user.name, user.role, "st_ai.policy", detail={"number": row.number, "note": body.note.strip()})
    return _state(session)
