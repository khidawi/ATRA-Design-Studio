"""
Declared claims that lapse (attestation.py): the endpoints.

  GET  /api/attestations/policy             which claims can lapse, how long each stays valid, and who set it
  PUT  /api/attestations/policy             set the validity of claims for the organisation (a compliance sign-off)
  GET  /api/attestations?within=14          across the models: claims lapsed, never confirmed, or lapsing within N days (for a weekly digest from cron)
  GET  /api/attestations/{design_key}       one model's claims with who confirmed each and when it lapses
  POST /api/attestations/{design_key}/confirm   the signed-in person confirms claims as they stand, so they stay valid for another period

The attestation of a claim is stamped by the server when a design is saved (design_store.py) and when someone confirms it here. It is never taken from what a
browser sends. A lapse is advice: it is shown beside the claim, in the assurance gap and in the assurance pack, and it does not change the score.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

import attestation as at
from auth import AuthUser, current_user
from db.models import Design, ThresholdFloors
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/attestations", tags=["attestations"])


def policy_days(session: Session) -> Dict[str, int]:
    row = session.get(ThresholdFloors, current_organisation(session).id)
    return dict(row.attestation_days or {}) if row else {}


def design_rows(session: Session, d: Design, policy: Optional[Dict[str, int]] = None, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    return at.evaluate(d.document.get("life") or {}, d.document.get("attest") or {}, policy if policy is not None else policy_days(session), now or datetime.now(timezone.utc))


def _design(session: Session, key: str) -> Design:
    d = session.scalar(select(Design).where(Design.design_key == key, Design.organisation_id == current_organisation(session).id, Design.subject == "MODEL"))
    if d is None:
        raise HTTPException(status_code=404, detail="No such model design.")
    return d


def _policy_out(session: Session) -> Dict[str, Any]:
    row = session.get(ThresholdFloors, current_organisation(session).id)
    days = (row.attestation_days or {}) if row else {}
    return {"governed": {k: {"label": g["label"], "default_days": g["days"], "days": at.days_for(k, days), "favourable": g.get("favourable"), "default_true": bool(g.get("default_true"))} for k, g in at.GOVERNED.items()},
            "soon_days": at.SOON_DAYS, "max_days": at.MAX_DAYS, "custom": days, "updated_by": row.updated_by if row else None}


@router.get("/policy")
def get_policy(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return _policy_out(session)


class PolicyBody(BaseModel):
    days: Dict[str, int]


@router.put("/policy")
def set_policy(body: PolicyBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    try:
        clean = at.clean_days(body.days)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    org = current_organisation(session)
    row = session.get(ThresholdFloors, org.id)
    if row is None:
        session.add(ThresholdFloors(organisation_id=org.id, floors={}, attestation_days=clean, updated_by=user.name))
    else:
        row.attestation_days, row.updated_by, row.updated_at = clean, user.name, datetime.now(timezone.utc)
    session.commit()
    return _policy_out(session)


@router.get("")
def due(within: int = 14, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Models with claims that have lapsed, were never confirmed, or lapse within `within` days: what a weekly digest would send."""
    within = min(max(within, 0), at.MAX_DAYS)
    policy = policy_days(session)
    out = []
    for d in session.scalars(select(Design).where(Design.organisation_id == current_organisation(session).id, Design.subject == "MODEL").order_by(Design.name)):
        rows = design_rows(session, d, policy)
        flagged = [r for r in rows if r["state"] in ("lapsed", "never") or (r["state"] == "due_soon" and (r["days_left"] or 0) <= within)]
        if flagged:
            out.append({"design_key": d.design_key, "name": d.name, "summary": at.summary(rows), "claims": flagged})
    return out


@router.get("/{design_key}")
def get_design_attestations(design_key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    rows = design_rows(session, _design(session, design_key))
    return {"claims": rows, "summary": at.summary(rows)}


class ConfirmBody(BaseModel):
    facts: List[str] = Field(min_length=1, max_length=40)


@router.post("/{design_key}/confirm")
def confirm(design_key: str, body: ConfirmBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    d = _design(session, design_key)
    doc = dict(d.document)
    try:
        doc["attest"] = at.confirm(doc.get("life") or {}, doc.get("attest") or {}, body.facts, user.name, datetime.now(timezone.utc).isoformat())
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    # In place, with no new version: a person who has the design open is not told it "changed elsewhere", and what they save next keeps these (the server owns attestations).
    session.execute(update(Design).where(Design.id == d.id).values(document=doc))
    session.commit()
    session.refresh(d)
    rows = design_rows(session, d)
    return {"attest": d.document.get("attest") or {}, "claims": rows, "summary": at.summary(rows)}
