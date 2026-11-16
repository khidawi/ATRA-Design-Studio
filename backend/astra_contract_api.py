"""
The accepted baseline and the signed behavioural contract of an agent design (ASTRA phase 5):

  GET  /api/agents/designs/{key}/contract        the draft contract in the Appendix A format, what in the design stops it being valid, the accepted baseline and the signed contract
  POST /api/agents/designs/{key}/baseline        accept the design as it is now (signoff: compliance or admin; the assessment must be recorded, APPROVED, current, and recorded by someone else)
  POST /api/agents/designs/{key}/sign            sign the contract of the accepted baseline with the signing key (signoff)
  GET  /api/astra/contracts/{id}                 one signed contract with its signature
  GET  /api/astra/contracts/{id}/verify          is it valid right now, and if not, why
  POST /api/astra/contracts/{id}/revoke          revoke it with a reason (signoff)
  GET  /api/astra/signing                        whether a signing key is configured, its id and the retired key ids (never the key)

Nothing here changes the legacy contracts of /api/contracts. Enforcing a signed contract at runtime is phase 6.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import astra_assessment_api as AA
import astra_contract_export as EX
import astra_estate as AE
import astra_signing as SG
import audit
from auth import AuthUser, current_user
from db.models import Agent, AstraAssessment, AstraBaseline, AstraSignedContract, User
from db.session import get_session
from organisation import current_organisation

router = APIRouter(tags=["astra"])
FMT = "%Y-%m-%dT%H:%M:%SZ"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _is_email(s: Optional[str]) -> bool:
    return bool(s) and SG_EMAIL(s)


def SG_EMAIL(s: str) -> bool:
    import astra_schema
    return bool(astra_schema.EMAIL.match(s.strip()))


def _owner_email(session: Session, doc: Dict[str, Any]) -> Optional[str]:
    """The owner as an email: the design's owner if it is one, else the registered agent's owner, else the platform user with that name."""
    prim = AE._primary(doc)
    org = current_organisation(session)
    names = []
    for raw in ((prim.get("p") or {}).get("owner"),
                session.scalar(select(Agent.owner).where(Agent.organisation_id == org.id, Agent.name == prim["name"]))):
        if raw and str(raw).strip():
            names.append(str(raw).strip())
    for n in names:
        if _is_email(n):
            return n
    for n in names:
        u = session.scalar(select(User).where(User.organisation_id == org.id, User.active.is_(True), User.full_name.ilike(n)))
        if u is not None:
            return u.email
    return None


def _latest_assessment(session: Session, design_key: str) -> Optional[AstraAssessment]:
    org = current_organisation(session)
    return session.scalar(select(AstraAssessment).where(AstraAssessment.organisation_id == org.id, AstraAssessment.design_key == design_key)
                          .order_by(AstraAssessment.created_at.desc()).limit(1))


def _baseline(session: Session, design_key: str, dhash: str) -> Optional[AstraBaseline]:
    org = current_organisation(session)
    return session.scalar(select(AstraBaseline).where(AstraBaseline.organisation_id == org.id, AstraBaseline.design_key == design_key, AstraBaseline.design_hash == dhash)
                          .order_by(AstraBaseline.created_at.desc()).limit(1))


def _public(row: AstraSignedContract, full: bool = False) -> Dict[str, Any]:
    out = {"id": str(row.id), "agent_key": row.agent_key, "design_key": row.design_key, "version": row.version, "contract_hash": row.contract_hash, "key_id": row.key_id,
           "signature": row.signature, "not_before": row.not_before, "expires_at": row.expires_at, "status": row.status, "signed_by": row.signed_by,
           "signed_at": row.signed_at.isoformat(), "revoked_by": row.revoked_by, "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
           "revoke_reason": row.revoke_reason}
    if full:
        out["document"] = row.document
    return out


def _draft(session: Session, design, version: str = "1.0.0", status: str = "production", valid_days: int = 365):
    expires = (_now() + timedelta(days=valid_days)).date().isoformat()
    assessment = AA.assess(session, design)
    return EX.build_document(design.document, assessment, owner_email=_owner_email(session, design.document), version=version, lifecycle_status=status, expires=expires), assessment


def _next_version(session: Session, agent_key: str) -> str:
    org = current_organisation(session)
    n = len(session.scalars(select(AstraSignedContract.id).where(AstraSignedContract.organisation_id == org.id, AstraSignedContract.agent_key == agent_key)).all())
    return f"{n + 1}.0.0"


@router.get("/api/agents/designs/{design_key}/contract")
def get_contract(design_key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    design = AA._agent_design(session, design_key)
    org = current_organisation(session)
    (document, problems), assessment = _draft(session, design, version=_next_version(session, EX.contract_agent_id(AE._primary(design.document)["name"])))
    dhash = AA._hash(design.document)
    base = _baseline(session, design_key, dhash)
    last = _latest_assessment(session, design_key)
    signed = session.scalar(select(AstraSignedContract).where(AstraSignedContract.organisation_id == org.id, AstraSignedContract.design_key == design_key)
                            .order_by(AstraSignedContract.signed_at.desc()).limit(1))
    signer = SG.load_signer()
    return {"design_key": design_key, "document": document, "problems": problems, "verdict": assessment["verdict"],
            "assessment_recorded": last is not None and last.design_hash == dhash,
            "baseline": None if base is None else {"id": str(base.id), "accepted_by": base.accepted_by, "note": base.note, "created_at": base.created_at.isoformat(),
                                                   "assessment_id": str(base.assessment_id)},
            "signed": None if signed is None else {**_public(signed), "current": signed.design_hash == dhash},
            "signing_configured": signer is not None}


class BaselineIn(BaseModel):
    note: Optional[str] = Field(None, max_length=500)


@router.post("/api/agents/designs/{design_key}/baseline", status_code=201)
def accept_baseline(design_key: str, body: BaselineIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    design = AA._agent_design(session, design_key)
    org = current_organisation(session)
    dhash = AA._hash(design.document)
    last = _latest_assessment(session, design_key)
    if last is None or last.design_hash != dhash:
        raise HTTPException(status_code=409, detail="Record an assessment of the design as it is now before accepting it as the baseline.")
    fresh = json.loads(json.dumps(AA.assess(session, design), default=str))
    if last.result != fresh:
        raise HTTPException(status_code=409, detail="The organisation, the risk layer or the evidence has changed since the assessment was recorded. Record a new assessment.")
    if last.verdict != "APPROVED":
        raise HTTPException(status_code=409, detail=f"The assessment's verdict is {last.verdict}: only an APPROVED design can become the baseline.")
    if last.created_by == user.name:
        raise HTTPException(status_code=403, detail="A different person from the one who recorded the assessment has to accept the baseline.")
    row = AstraBaseline(organisation_id=org.id, design_key=design_key, design_hash=dhash, assessment_id=last.id, accepted_by=user.name, accepted_by_id=user.id, note=body.note)
    session.add(row)
    session.commit()
    audit.record(user.name, user.role, "astra.baseline", detail={"design_key": design_key, "design_hash": dhash, "assessment_id": str(last.id), "id": str(row.id)})
    return {"id": str(row.id), "design_key": design_key, "design_hash": dhash, "accepted_by": user.name, "assessment_id": str(last.id)}


class SignIn(BaseModel):
    valid_days: int = Field(365, ge=1, le=1830)
    lifecycle_status: str = Field("production", max_length=12)


@router.post("/api/agents/designs/{design_key}/sign", status_code=201)
def sign_contract(design_key: str, body: SignIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    design = AA._agent_design(session, design_key)
    org = current_organisation(session)
    try:
        signer = SG.load_signer()
    except SG.SigningError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if signer is None:
        raise HTTPException(status_code=503, detail="No signing key is configured. Generate one with 'python astra_signing.py generate <key_id>' and set ASTRA_SIGNING_KEY.")
    dhash = AA._hash(design.document)
    base = _baseline(session, design_key, dhash)
    if base is None:
        raise HTTPException(status_code=409, detail="The design as it is now has no accepted baseline. Accept the baseline first.")
    agent_id = EX.contract_agent_id(AE._primary(design.document)["name"])
    (document, problems), _ = _draft(session, design, version=_next_version(session, agent_id), status=body.lifecycle_status, valid_days=body.valid_days)
    if problems:
        raise HTTPException(status_code=422, detail="The contract cannot be signed yet: " + " ".join(problems))
    now = _now()
    not_before, expires = now.strftime(FMT), (now + timedelta(days=body.valid_days)).strftime(FMT)
    s = SG.sign(document, signer[0], signer[1], not_before, expires)
    for old in session.scalars(select(AstraSignedContract).where(AstraSignedContract.organisation_id == org.id, AstraSignedContract.agent_key == agent_id,
                                                                  AstraSignedContract.status == "ACTIVE")):
        old.status = "SUPERSEDED"
    session.flush()
    row = AstraSignedContract(organisation_id=org.id, agent_key=agent_id, design_key=design_key, design_hash=dhash, baseline_id=base.id, version=document["agent"]["model_version"],
                              document=s["document"], contract_hash=s["contract_hash"], key_id=s["key_id"], signature=s["signature"], not_before=not_before, expires_at=expires,
                              status="ACTIVE", signed_by=user.name)
    session.add(row)
    session.commit()
    audit.record(user.name, user.role, "astra.sign", detail={"design_key": design_key, "agent": agent_id, "version": row.version, "key_id": row.key_id, "id": str(row.id)})
    return _public(row, full=True)


def _signed(session: Session, contract_id: uuid.UUID) -> AstraSignedContract:
    row = session.get(AstraSignedContract, contract_id)
    if row is None or row.organisation_id != current_organisation(session).id:
        raise HTTPException(status_code=404, detail="No such signed contract.")
    return row


@router.get("/api/astra/contracts/{contract_id}")
def get_signed(contract_id: uuid.UUID, session: Session = Depends(get_session)) -> Dict[str, Any]:
    return _public(_signed(session, contract_id), full=True)


@router.get("/api/astra/contracts/{contract_id}/verify")
def verify_signed(contract_id: uuid.UUID, session: Session = Depends(get_session)) -> Dict[str, Any]:
    row = _signed(session, contract_id)
    try:
        keys = SG.load_public_keys()
    except SG.SigningError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    why = SG.verify({"document": row.document, "contract_hash": row.contract_hash, "key_id": row.key_id, "signature": row.signature, "not_before": row.not_before,
                     "expires_at": row.expires_at, "status": row.status}, keys, _now().strftime(FMT))
    return {"id": str(row.id), "valid": not why, "reasons": why, "status": row.status}


class RevokeIn(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


@router.post("/api/astra/contracts/{contract_id}/revoke")
def revoke_signed(contract_id: uuid.UUID, body: RevokeIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    row = _signed(session, contract_id)
    if row.status == "REVOKED":
        raise HTTPException(status_code=409, detail="It is already revoked.")
    row.status, row.revoked_by, row.revoked_at, row.revoke_reason = "REVOKED", user.name, _now(), body.reason.strip()
    session.commit()
    audit.record(user.name, user.role, "astra.revoke", detail={"id": str(row.id), "agent": row.agent_key, "reason": body.reason.strip()})
    return _public(row)


@router.get("/api/astra/signing")
def signing_status() -> Dict[str, Any]:
    try:
        signer = SG.load_signer()
        keys = SG.load_public_keys()
    except SG.SigningError as exc:
        return {"configured": False, "error": str(exc), "key_id": None, "retired": []}
    kid = signer[0] if signer else None
    return {"configured": signer is not None, "key_id": kid, "retired": sorted(k for k in keys if k != kid)}
