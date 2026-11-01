"""
Evidence records: the difference between "someone wrote down that it is done" and "someone independent looked at the record".

A control is declared met with some words. Those words become a *record* when a file is kept here (hashed with SHA-256 when it is uploaded) or a page is snapshotted (the address, what
the site answered, when, and the hash of what it returned), and the record becomes *attested* when a person with sign-off permission says they looked at it. Only an attested record
makes a control count in the verified score.

Who may attest: not the person who uploaded the record, not the owner of an agent, and not a person who holds one of the roles of the model (trainer, validator, deployer, operator),
by what the canvas names and, when the caller sends it, by who holds each role now. The same separation of duties as a design review.

A file is checked again whenever it is read: the hash is recomputed and a mismatch is refused, never served. A web page is only a snapshot (the page may have changed since), and says so.

Which score decides the gate is one switch for the organisation, "declared" or "verified". It starts on declared, is flipped by a person with sign-off permission who gives a reason, is
recorded in the audit log, and never changes by itself when the first record appears. Both scores are always shown.
"""
import base64
import binascii
import hashlib
import mimetypes
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Set

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import audit
from auth import AuthUser, current_user
from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import AppSetting, Design, EvidenceRecord, Organisation
from db.session import get_session

router = APIRouter(prefix="/api/evidence", tags=["evidence"])

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_PAGE_BYTES = 2 * 1024 * 1024
BASIS_KEY = "gate_basis"
BASES = ("declared", "verified")
LIFECYCLE_ROLES = ("trainer", "validator", "deployer", "operator")


def _norm(text: Any) -> str:
    return " ".join(str(text or "").split()).lower()


# ── The switch: which score decides the gate ────────────────────────────────

def gate_basis(session: Session) -> str:
    row = session.get(AppSetting, BASIS_KEY)
    return row.value if row is not None and row.value in BASES else "declared"


class BasisBody(BaseModel):
    basis: Literal["declared", "verified"]
    note: str = Field(min_length=5, max_length=2000)


@router.get("/policy")
def get_policy(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return {"gate_basis": gate_basis(session)}


@router.put("/policy")
def set_policy(body: BasisBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    before = gate_basis(session)
    if before == body.basis:
        raise HTTPException(status_code=409, detail=f"The gate is already decided on the {before} score.")
    row = session.get(AppSetting, BASIS_KEY)
    if row is None:
        session.add(AppSetting(key=BASIS_KEY, value=body.basis))
    else:
        row.value = body.basis
    session.commit()
    audit.record(user.name, user.role, "evidence.gate_basis", detail={"from": before, "to": body.basis, "note": body.note.strip()})
    return {"gate_basis": body.basis}


# ── What the scoring reads ──────────────────────────────────────────────────

def attested_keys(session: Session, design_key: Optional[str]) -> Optional[Set[str]]:
    """The controls of a saved design that have an attested record behind them. None when there is no design to look at: the score then falls back to reading the evidence text."""
    if not design_key:
        return None
    rows = session.execute(select(EvidenceRecord.control_key, EvidenceRecord.kind, EvidenceRecord.size, func.octet_length(EvidenceRecord.content))
                           .where(EvidenceRecord.design_key == design_key, EvidenceRecord.status == "ATTESTED",
                                  (EvidenceRecord.expires_at.is_(None)) | (EvidenceRecord.expires_at >= date.today()))).all()
    return {key for key, kind, size, stored in rows if kind == "URL" or stored == size}      # a file whose stored size no longer matches, or whose attestation has lapsed, is not counted


def enrich_registry(session: Session, design_key: Optional[str], registry) -> None:
    """Sets, from the server's own records, which controls are attested and which score decides the gate. Whatever the caller sent for these is replaced."""
    keys = attested_keys(session, design_key)
    registry.attested_controls = sorted(keys) if keys is not None else None
    registry.gate_basis = gate_basis(session)


# ── Records ─────────────────────────────────────────────────────────────────

class EvidenceIn(BaseModel):
    design_key: str = Field(min_length=1, max_length=40)
    control: str = Field(min_length=1, max_length=64)
    kind: Literal["FILE", "URL"]
    summary: str = Field(min_length=5, max_length=1000)
    filename: Optional[str] = Field(default=None, max_length=255)
    content_base64: Optional[str] = None
    url: Optional[str] = Field(default=None, max_length=500)


class EvidenceOut(BaseModel):
    id: str
    design_key: str
    control: str
    kind: str
    summary: str
    filename: Optional[str]
    size: int
    sha256: str
    url: Optional[str]
    url_status: Optional[int]
    fetched_at: Optional[str]
    uploaded_by: str
    uploaded_at: str
    status: str
    attested_by: Optional[str]
    attested_role: Optional[str]
    attested_at: Optional[str]
    expires_at: Optional[str]
    expired: bool
    revoked_by: Optional[str]
    revoke_reason: Optional[str]
    integrity: str                 # intact | changed (a file whose content no longer matches its hash) | snapshot (a page: the site may have changed since)
    counts: bool                   # attested and intact: it makes the control count in the verified score


def _iso(t: Optional[datetime]) -> Optional[str]:
    return t.isoformat() if t else None


def _integrity(r: EvidenceRecord) -> str:
    if r.kind == "URL":
        return "snapshot"
    return "intact" if r.content is not None and hashlib.sha256(r.content).hexdigest() == r.sha256 else "changed"


def _lapsed(r: EvidenceRecord) -> bool:
    return r.status == "ATTESTED" and r.expires_at is not None and r.expires_at < date.today()


def _out(r: EvidenceRecord) -> EvidenceOut:
    integrity = _integrity(r)
    return EvidenceOut(
        id=str(r.id), design_key=r.design_key, control=r.control_key, kind=r.kind, summary=r.summary, filename=r.filename, size=r.size, sha256=r.sha256, url=r.url, url_status=r.url_status,
        fetched_at=_iso(r.fetched_at), uploaded_by=r.uploaded_by, uploaded_at=_iso(r.uploaded_at) or "", status=r.status, attested_by=r.attested_by, attested_role=r.attested_role,
        attested_at=_iso(r.attested_at), expires_at=r.expires_at.isoformat() if r.expires_at else None, expired=_lapsed(r), revoked_by=r.revoked_by, revoke_reason=r.revoke_reason,
        integrity=integrity, counts=r.status == "ATTESTED" and integrity != "changed" and not _lapsed(r))


def _design(session: Session, key: str) -> Design:
    org = session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
    design = session.scalar(select(Design).where(Design.design_key == key, Design.organisation_id == org.id))
    if design is None:
        raise HTTPException(status_code=422, detail="Save the design first: evidence belongs to a saved design.")
    return design


def snapshot_url(url: str):
    """What a public web page said, now: (status, bytes). Only public http(s) addresses, no redirects followed, a size limit."""
    from ingestion import check_fetchable
    try:
        check_fetchable(url)
        with httpx.stream("GET", url, headers={"User-Agent": "ASTRA-evidence/1.0"}, timeout=20.0, follow_redirects=False) as resp:
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > MAX_PAGE_BYTES:
                    raise ValueError("The page is larger than 2 MB. Keep it as a file instead.")
            return resp.status_code, body
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=422, detail=f"The address could not be read: {exc.__class__.__name__}.")


@router.post("", response_model=EvidenceOut, status_code=201)
def add_evidence(body: EvidenceIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> EvidenceOut:
    design = _design(session, body.design_key)
    row = EvidenceRecord(id=uuid.uuid4(), organisation_id=design.organisation_id, design_key=design.design_key, subject=design.subject, control_key=body.control.strip(),
                         kind=body.kind, summary=body.summary.strip(), uploaded_by=user.name, status="UPLOADED")
    if body.kind == "FILE":
        if not body.content_base64 or not (body.filename or "").strip():
            raise HTTPException(status_code=422, detail="A file needs its name and its content.")
        try:
            data = base64.b64decode(body.content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=422, detail="The file content could not be read.")
        if not data:
            raise HTTPException(status_code=422, detail="The file is empty.")
        if len(data) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail="The file is larger than 5 MB.")
        row.filename, row.content, row.size = body.filename.strip(), data, len(data)
        row.content_type = mimetypes.guess_type(row.filename)[0] or "application/octet-stream"
        row.sha256 = hashlib.sha256(data).hexdigest()
    else:
        if not (body.url or "").strip():
            raise HTTPException(status_code=422, detail="A link needs its address.")
        status, page = snapshot_url(body.url.strip())
        if status != 200:
            raise HTTPException(status_code=422, detail=f"The site answered HTTP {status}, so there is nothing to keep as evidence.")
        row.url, row.url_status, row.fetched_at, row.size = body.url.strip(), status, datetime.now(timezone.utc), len(page)
        row.sha256 = hashlib.sha256(page).hexdigest()
    session.add(row)
    session.commit()
    session.refresh(row)
    return _out(row)


@router.get("", response_model=List[EvidenceOut])
def list_evidence(design_key: str, session: Session = Depends(get_session)) -> List[EvidenceOut]:
    rows = session.scalars(select(EvidenceRecord).where(EvidenceRecord.design_key == design_key).order_by(EvidenceRecord.uploaded_at.desc()))
    return [_out(r) for r in rows]


@router.get("/{evidence_id}/download")
def download(evidence_id: str, session: Session = Depends(get_session)) -> Response:
    row = _get(session, evidence_id)
    if row.kind != "FILE":
        raise HTTPException(status_code=422, detail="This record is a snapshot of a web page, not a file.")
    if _integrity(row) != "intact":
        raise HTTPException(status_code=409, detail="This file no longer matches the hash recorded when it was uploaded, so it is not served. The record no longer counts.")
    return Response(content=row.content, media_type=row.content_type or "application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{(row.filename or "evidence").replace(chr(34), "")}"', "X-Evidence-SHA256": row.sha256})


def _get(session: Session, evidence_id: str) -> EvidenceRecord:
    try:
        key = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="No such evidence record.")
    row = session.get(EvidenceRecord, key)
    if row is None:
        raise HTTPException(status_code=404, detail="No such evidence record.")
    return row


class AttestBody(BaseModel):
    # The day the attestation lapses (optional). After it the record stops counting until it is attested again.
    expires_on: Optional[date] = None
    # What the caller (the model studio) knows about who holds each role now: the effective holders, which can differ from what the canvas names.
    holders: Dict[str, str] = Field(default_factory=dict)


def _holds_a_role(session: Session, design: Design, name: str, holders: Dict[str, str]) -> Optional[str]:
    me = _norm(name)
    for role in LIFECYCLE_ROLES:
        if holders.get(role) and _norm(holders[role]) == me:
            return role
    for n in (design.document or {}).get("nodes", []):
        data = n.get("data") or {}
        if n.get("kind") == "ACTOR" and str(data.get("subtype", "")).lower() in LIFECYCLE_ROLES and _norm(data.get("identity")) == me:
            return str(data["subtype"]).lower()
    return None


@router.post("/{evidence_id}/attest", response_model=EvidenceOut)
def attest(evidence_id: str, body: AttestBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> EvidenceOut:
    row = _get(session, evidence_id)
    if row.status != "UPLOADED":
        raise HTTPException(status_code=409, detail="This record has already been decided." if row.status == "ATTESTED" else "This record was revoked.")
    if _integrity(row) == "changed":
        raise HTTPException(status_code=409, detail="This file no longer matches the hash recorded when it was uploaded, so it cannot be attested.")
    if _norm(user.name) == _norm(row.uploaded_by):
        raise HTTPException(status_code=403, detail=f"{user.name} uploaded this record and cannot also attest it. Another person with sign-off permission has to.")
    design = _design(session, row.design_key)
    if design.subject == "AGENT":
        primary = next((n for n in (design.document or {}).get("nodes", []) if n.get("primary") and n.get("type") == "agent"), None)
        if primary is not None and _norm((primary.get("p") or {}).get("owner")) == _norm(user.name):
            raise HTTPException(status_code=403, detail=f"{user.name} is this agent's owner and cannot attest its evidence. Another person with sign-off permission has to.")
    else:
        role = _holds_a_role(session, design, user.name, body.holders)
        if role:
            raise HTTPException(status_code=403, detail=f"{user.name} is named as the {role} of this model and cannot attest its evidence. Another person with sign-off permission has to.")
    if body.expires_on is not None and body.expires_on <= date.today():
        raise HTTPException(status_code=422, detail="The attestation has to run past today.")
    row.status, row.attested_by, row.attested_role, row.attested_at = "ATTESTED", user.name, user.role, datetime.now(timezone.utc)
    row.expires_at = body.expires_on
    session.commit()
    session.refresh(row)
    return _out(row)


class RevokeBody(BaseModel):
    reason: str = Field(min_length=5, max_length=2000)


@router.post("/{evidence_id}/revoke", response_model=EvidenceOut)
def revoke(evidence_id: str, body: RevokeBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> EvidenceOut:
    row = _get(session, evidence_id)
    if row.status == "REVOKED":
        raise HTTPException(status_code=409, detail="This record was already revoked.")
    row.status, row.revoked_by, row.revoked_at, row.revoke_reason = "REVOKED", user.name, datetime.now(timezone.utc), body.reason.strip()
    session.commit()
    session.refresh(row)
    return _out(row)


# ── What is about to lapse ──────────────────────────────────────────────────

@router.get("/expiring")
def expiring(within: int = 30, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Evidence that has lapsed or lapses within `within` days, across models and agents: the valid-until day of a declaration and the expiry of an attested record, soonest first.
    For an agent it also says what the gate would be if the evidence lapsed."""
    within = min(max(within, 0), 366)
    today = date.today()
    horizon = today + timedelta(days=within)
    org = session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
    out: List[Dict[str, Any]] = []

    def add(design: Design, control: str, kind: str, day: date, what: str) -> None:
        if day <= horizon:
            out.append({"design_key": design.design_key, "design": design.name, "subject": design.subject, "control": control, "kind": kind, "date": day.isoformat(),
                        "days_left": (day - today).days, "what": what})

    def day_of(value: Any) -> Optional[date]:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None

    designs = list(session.scalars(select(Design).where(Design.organisation_id == org.id).order_by(Design.name)))
    for d in designs:
        doc = d.document or {}
        if d.subject == "AGENT":
            for key, decl in (doc.get("req") or {}).items():
                day = day_of(decl.get("valid_until")) if decl.get("valid_until") else None
                if day and decl.get("status") in ("Covered", "Partial"):
                    add(d, key, "declaration", day, "The evidence declared for it passes its valid-until day.")
        else:
            for n in doc.get("nodes", []):
                data = n.get("data") or {}
                day = day_of(data.get("validUntil")) if data.get("validUntil") else None
                if n.get("kind") == "CONSTRAINT" and data.get("status") == "SATISFIED" and day:
                    add(d, str(data.get("constraintId") or ""), "declaration", day, "The evidence declared for it passes its valid-until day.")
    names = {d.design_key: d for d in designs}
    for r in session.scalars(select(EvidenceRecord).where(EvidenceRecord.status == "ATTESTED", EvidenceRecord.expires_at.is_not(None))):
        if r.design_key in names:
            add(names[r.design_key], r.control_key, "record", r.expires_at, f"The attestation of \u201c{r.summary}\u201d by {r.attested_by} lapses.")
    out.sort(key=lambda x: (x["date"], x["design"], x["control"]))
    _gate_effects(session, names, out)
    return out


def _gate_effects(session: Session, names: Dict[str, Design], rows: List[Dict[str, Any]]) -> None:
    """For agents: score the design and read what losing that requirement would do to the gate. A model's score is built in the studio from the whole canvas, so for a model the page says to open it."""
    cache: Dict[str, Any] = {}
    for row in rows:
        d = names[row["design_key"]]
        if d.subject != "AGENT":
            continue
        if d.design_key not in cache:
            try:
                from agent_review import _score
                cache[d.design_key] = _score(session, d.document, d.design_key)
            except Exception:
                cache[d.design_key] = None
        res = cache[d.design_key]
        if res is None:
            continue
        hit = next((c for c in ((res.sensitivity or {}).get("controls") or []) if c["control"] == row["control"]), None)
        row["gate_effect"] = ({"now": res.gate, "if_lost": hit["to"]["gate"], "moves_gate": hit["flips"] == "gate"} if hit is not None
                              else {"now": res.gate, "if_lost": res.gate, "moves_gate": False})       # nothing else holds the result up on it
