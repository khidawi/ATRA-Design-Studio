"""
Saved designs and compiled contracts (Task 6).

The studio autosaves the design it is editing; every save carries the version it was based on, and a
save based on an older version is refused (409) so a second tab cannot silently overwrite the first.
Compiling a contract stores it as issued. Contracts are never edited, and a contract outlives the
design it came from. Any stored contract can be re-hashed to show it is unchanged.

There is no sign-in yet (Task 8): everything belongs to the one organisation.
"""
import secrets
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

import agent_contract
from auth import AuthUser, current_user, has
from compliance_schema import CompiledContract, compute_contract_hash
from db.models import Agent, Contract, Design, Domain
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api", tags=["designs"])

MAX_NODES = 2000
MAX_DOCUMENT_BYTES = 4_000_000


class DesignDocument(BaseModel):
    nodes: List[Dict[str, Any]] = Field(default_factory=list, max_length=MAX_NODES)
    edges: List[Dict[str, Any]] = Field(default_factory=list, max_length=MAX_NODES * 4)
    n: int = Field(1, ge=1)
    model_config = {"extra": "allow"}


class DesignIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    domain: str
    document: DesignDocument
    subject: Literal["MODEL", "AGENT"] = "MODEL"

    @field_validator("name", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class DesignUpdate(DesignIn):
    version: int           # the version this edit was based on


class DesignOut(BaseModel):
    design_key: str
    subject: str
    name: str
    domain: str
    version: int
    document: DesignDocument
    created_at: datetime
    updated_at: datetime


class DesignSummary(BaseModel):
    design_key: str
    subject: str
    name: str
    domain: str
    version: int
    node_count: int
    contract_count: int
    updated_at: datetime


def _out(d: Design) -> DesignOut:
    return DesignOut(design_key=d.design_key, subject=d.subject, name=d.name, domain=d.domain_key, version=d.version,
                     document=DesignDocument(**d.document), created_at=d.created_at, updated_at=d.updated_at)


def _check(session: Session, body: DesignIn) -> None:
    if not session.scalar(select(Domain.id).where(Domain.domain_key == body.domain, Domain.subject == body.subject)):
        raise HTTPException(status_code=422, detail=f"Unknown {body.subject.lower()} assessment domain: {body.domain!r}")
    if len(body.document.model_dump_json()) > MAX_DOCUMENT_BYTES:
        raise HTTPException(status_code=413, detail="The design is too large to save.")


def check_signoffs(old_doc: Optional[Dict[str, Any]], new_doc: Dict[str, Any], user: AuthUser) -> None:
    """A sign-off on a requirement is the signed-in person's own, and only someone who may sign off can add or remove one.
    An engineer saving a design therefore cannot create, change or drop a sign-off by editing it."""
    old = {k: ((v or {}).get("signed_off_by") or "") for k, v in ((old_doc or {}).get("req") or {}).items()}
    new = {k: ((v or {}).get("signed_off_by") or "") for k, v in (new_doc.get("req") or {}).items()}
    for key in set(old) | set(new):
        before, after = old.get(key, ""), new.get(key, "")
        if before == after:
            continue
        if not has(user.role, "signoff"):
            raise HTTPException(status_code=403, detail=f"Only compliance can sign off a requirement ({key}); your role is {user.role}.")
        if after and after != user.name:
            raise HTTPException(status_code=403, detail=f"A sign-off records the person signed in; you cannot sign for {after}.")


def _get(session: Session, key: str) -> Design:
    d = session.scalar(select(Design).where(Design.design_key == key))
    if d is None:
        raise HTTPException(status_code=404, detail="No such design.")
    return d


@router.get("/designs", response_model=List[DesignSummary])
def list_designs(subject: Literal["MODEL", "AGENT"] = "MODEL", session: Session = Depends(get_session)) -> List[DesignSummary]:
    counts = dict(session.execute(select(Contract.design_id, func.count()).group_by(Contract.design_id)).all())
    return [DesignSummary(design_key=d.design_key, subject=d.subject, name=d.name, domain=d.domain_key, version=d.version,
                          node_count=len(d.document.get("nodes", [])), contract_count=counts.get(d.id, 0), updated_at=d.updated_at)
            for d in session.scalars(select(Design).where(Design.subject == subject).order_by(Design.updated_at.desc()))]


@router.post("/designs", response_model=DesignOut, status_code=201)
def create_design(body: DesignIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> DesignOut:
    _check(session, body)
    if body.subject == "AGENT":
        check_signoffs(None, body.document.model_dump(mode="json"), user)
    d = Design(design_key="d-" + secrets.token_hex(5), organisation_id=current_organisation(session).id, subject=body.subject,
               name=body.name, domain_key=body.domain, document=body.document.model_dump(mode="json"))
    session.add(d)
    session.commit()
    return _out(d)


@router.get("/designs/{design_key}", response_model=DesignOut)
def get_design(design_key: str, session: Session = Depends(get_session)) -> DesignOut:
    return _out(_get(session, design_key))


@router.put("/designs/{design_key}", response_model=DesignOut)
def save_design(design_key: str, body: DesignUpdate, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> DesignOut:
    _check(session, body)
    d = _get(session, design_key)
    if d.subject == "AGENT":
        check_signoffs(d.document, body.document.model_dump(mode="json"), user)
    if d.subject != body.subject:
        raise HTTPException(status_code=422, detail="A design cannot change its kind.")
    # The version check and the write are one statement, so two saves cannot both win.
    changed = session.execute(
        update(Design).where(Design.id == d.id, Design.version == body.version)
        .values(name=body.name, domain_key=body.domain, document=body.document.model_dump(mode="json"),
                version=Design.version + 1, updated_at=func.now())
    ).rowcount
    session.commit()
    session.refresh(d)
    if not changed:
        raise HTTPException(status_code=409, detail=f"This design was changed elsewhere (it is at version {d.version}, your edit was based on {body.version}). Reload it to continue.")
    return _out(d)


@router.delete("/designs/{design_key}", status_code=204)
def delete_design(design_key: str, session: Session = Depends(get_session)) -> None:
    session.delete(_get(session, design_key))     # contracts stay; their design link is cleared
    session.commit()


# ── Contracts ───────────────────────────────────────────────────────────────

def store_contract(session: Session, contract: CompiledContract, design_key: Optional[str], origin: str = "COMPILED") -> Contract:
    """Stores the contract and, if it was issued by this server, retires the earlier ones for the same deployment."""
    design = session.scalar(select(Design).where(Design.design_key == design_key)) if design_key else None
    row = Contract(contract_id=contract.contract_id, organisation_id=current_organisation(session).id,
                   design_id=design.id if design else None, object_type=contract.object_type,
                   deployment_id=contract.deployment_id, origin=origin, document=contract.model_dump(mode="json"),
                   contract_hash=contract.contract_hash, issued_at=contract.issued_at)
    session.add(row)
    if origin == "COMPILED":
        for old in session.scalars(select(Contract).where(
                Contract.object_type == contract.object_type, Contract.deployment_id == contract.deployment_id,
                Contract.status == "ACTIVE", Contract.contract_id != contract.contract_id)):
            old.status, old.status_by, old.status_at = "SUPERSEDED", contract.issued_by or "system", func.now()
            old.status_reason, old.superseded_by = f"Replaced by version {contract.version}.", contract.contract_id
    session.commit()
    return row


class ContractRecord(BaseModel):
    """A contract as issued plus what is true of it now."""
    contract: CompiledContract
    status: str
    status_reason: Optional[str]
    status_by: Optional[str]
    status_at: Optional[datetime]
    superseded_by: Optional[str]
    origin: str
    design_key: Optional[str]
    view: Optional[Dict[str, Any]] = None       # agent contracts: what the contract allows, derived from the snapshot


def _record(session: Session, row: Contract) -> ContractRecord:
    contract = CompiledContract(**row.document)
    design_key = session.scalar(select(Design.design_key).where(Design.id == row.design_id)) if row.design_id else None
    view = agent_contract.view(contract.design_snapshot) if row.object_type == "AGENT" else None
    return ContractRecord(contract=contract, status=row.status, status_reason=row.status_reason, status_by=row.status_by,
                          status_at=row.status_at, superseded_by=row.superseded_by, origin=row.origin, design_key=design_key, view=view)


@router.get("/contract-records", response_model=List[ContractRecord])
def contract_records(object_type: Literal["MODEL", "AGENT"] = "MODEL", deployment: Optional[str] = None,
                     session: Session = Depends(get_session)) -> List[ContractRecord]:
    q = select(Contract).where(Contract.object_type == object_type)
    if deployment:
        q = q.where(Contract.deployment_id == deployment)
    return [_record(session, r) for r in session.scalars(q.order_by(Contract.issued_at))]


class RevokeRequest(BaseModel):
    reviewer: str = Field("", max_length=120)      # ignored: the signed-in person is recorded
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reviewer", "reason", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


@router.post("/contracts/{contract_id}/revoke", response_model=ContractRecord)
def revoke_contract(contract_id: str, body: RevokeRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ContractRecord:
    """Takes a contract out of force. The contract itself is not touched, so its hash still verifies."""
    row = session.scalar(select(Contract).where(Contract.contract_id == contract_id))
    if row is None:
        raise HTTPException(status_code=404, detail="No such contract.")
    if row.status != "ACTIVE":
        raise HTTPException(status_code=409, detail=f"This contract is already {row.status.lower()}.")
    row.status, row.status_by, row.status_reason, row.status_at = "REVOKED", user.name, body.reason, func.now()
    if row.object_type == "AGENT":
        agent = session.scalar(select(Agent).where(Agent.agent_key == row.deployment_id))
        still_active = session.scalar(select(func.count()).select_from(Contract).where(
            Contract.object_type == "AGENT", Contract.deployment_id == row.deployment_id, Contract.status == "ACTIVE",
            Contract.contract_id != contract_id))
        if agent is not None and not still_active and agent.status in ("DESIGNED", "ASSURED"):
            agent.mode = "OBSERVE" if agent.status == "ASSURED" else "NOT_RUNNING"
            agent.status = "TO_RATIFY"
    session.commit()
    session.refresh(row)
    return _record(session, row)


@router.get("/contracts", response_model=List[CompiledContract])
def list_contracts(object_type: Literal["MODEL", "AGENT"] = "MODEL", design: Optional[str] = None,
                   session: Session = Depends(get_session)) -> List[CompiledContract]:
    q = select(Contract).where(Contract.object_type == object_type)
    if design:
        q = q.join(Design, Design.id == Contract.design_id).where(Design.design_key == design)
    return [CompiledContract(**c.document) for c in session.scalars(q.order_by(Contract.issued_at))]


class VerifyOut(BaseModel):
    contract_id: str
    ok: bool
    stored_hash: str
    computed_hash: str
    origin: str


@router.get("/contracts/{contract_id}/verify", response_model=VerifyOut)
def verify_contract(contract_id: str, session: Session = Depends(get_session)) -> VerifyOut:
    row = session.scalar(select(Contract).where(Contract.contract_id == contract_id))
    if row is None:
        raise HTTPException(status_code=404, detail="No such contract.")
    computed = compute_contract_hash(CompiledContract(**row.document))
    return VerifyOut(contract_id=contract_id, ok=computed == row.contract_hash == row.document.get("contract_hash"),
                     stored_hash=row.contract_hash, computed_hash=computed, origin=row.origin)


@router.post("/contracts/import", response_model=CompiledContract, status_code=201)
def import_contract(contract: CompiledContract, design: Optional[str] = None, session: Session = Depends(get_session)) -> CompiledContract:
    """For contracts compiled before contracts were stored here (they lived in a browser). The hash must
    match the content; the contract is marked IMPORTED because this server did not issue it."""
    if compute_contract_hash(contract) != contract.contract_hash:
        raise HTTPException(status_code=422, detail="The contract's hash does not match its content, so it was not imported.")
    if session.scalar(select(Contract.id).where(Contract.contract_id == contract.contract_id)):
        raise HTTPException(status_code=409, detail="This contract is already stored.")
    store_contract(session, contract, design, origin="IMPORTED")
    return contract
