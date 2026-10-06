"""
Agent design-time RCR: requirement registries and scoring (API for rcr_engine.py).

A requirement's status comes from one of two places:
  * a design check (a condition on the agent design, rule_checks.py): the design
    itself supplies the status and the evidence ("Approval step in the design");
  * a declaration the author makes for this design: status, evidence, and for a
    veto requirement the name of the reviewer who signed it off.
Sign-off is a typed name until sign-in exists (Task 8), which will require a
real reviewer. Either way the engine, not the page, decides what each
requirement counts as.
"""
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from compliance_engine import to_design_graph
from compliance_schema import DesignGraphIn
from db.models import RcrProfile, RcrRequirement
from db.session import get_session
from rcr_engine import COVERED, STATUSES, RcrError, Requirement, score, validate_registry
from rule_checks import CheckConfigError, evaluate_graph_rule

router = APIRouter(prefix="/api/rcr", tags=["rcr"])


class RequirementOut(BaseModel):
    key: str
    name: str
    instrument: str
    cls: str
    w: int
    phi: Optional[float]
    derived: bool                    # status comes from the design, not from a declaration
    default_declaration: Optional[Dict[str, str]]


class ProfileOut(BaseModel):
    key: str
    name: str
    partial_credit: float
    requirements: List[RequirementOut]
    blocked_line: Optional[float]
    watch_line: Optional[float]
    valid: bool
    error: Optional[str]


def _profile(session: Session, key: str) -> RcrProfile:
    profile = session.scalar(select(RcrProfile).where(RcrProfile.profile_key == key))
    if profile is None:
        raise HTTPException(status_code=422, detail=f"Unknown RCR profile: {key!r}")
    return profile


def _requirements(session: Session, profile: RcrProfile) -> List[RcrRequirement]:
    return list(session.scalars(
        select(RcrRequirement).where(RcrRequirement.profile_id == profile.id).order_by(RcrRequirement.position)))


@router.get("/profiles", response_model=List[ProfileOut])
def profiles(session: Session = Depends(get_session)) -> List[ProfileOut]:
    out = []
    for p in session.scalars(select(RcrProfile).order_by(RcrProfile.position)):
        rows = _requirements(session, p)
        reqs = [Requirement(r.req_key, r.name, r.instrument, r.cls, r.weight, r.phi) for r in rows]
        error = None
        try:
            validate_registry(reqs, p.partial_credit)
        except RcrError as exc:
            error = str(exc)
        floors = [r.phi for r in reqs if r.cls == "veto"]
        out.append(ProfileOut(
            key=p.profile_key, name=p.name, partial_credit=p.partial_credit,
            requirements=[RequirementOut(
                key=r.req_key, name=r.name, instrument=r.instrument, cls=r.cls, w=r.weight, phi=r.phi,
                derived=r.design_check is not None, default_declaration=r.default_declaration) for r in rows],
            blocked_line=100 * min(floors) if floors else None,
            watch_line=100 * (1 - p.partial_credit) * min(floors) if floors else None,
            valid=error is None, error=error))
    return out


class Declaration(BaseModel):
    status: Optional[str] = None
    evidence: str = ""
    signed_off_by: str = ""


class RcrRequest(BaseModel):
    profile: str
    graph: DesignGraphIn
    declarations: Dict[str, Declaration] = Field(default_factory=dict)


class RowOut(BaseModel):
    key: str
    name: str
    instrument: str
    cls: str
    w: int
    phi: Optional[float]
    derived: bool
    declared: str
    counted: str
    c: float
    reason: str
    note: str
    evidence: str
    signed_off_by: str
    awaiting_signoff: bool


class InstrumentOut(BaseModel):
    instrument: str
    uncovered: float
    total: float
    g: float


class RcrOut(BaseModel):
    profile: str
    partial_credit: float
    score: float
    G: float
    F: float
    floor_key: Optional[str]
    floor_name: Optional[str]
    worst_instrument: Optional[str]
    instruments: List[InstrumentOut]
    blocked_line: float
    watch_line: float
    lines_derived: bool
    band: str
    gate: str
    binding: str
    covered: int
    rows: List[RowOut]
    notes: List[str]


@router.post("/score", response_model=RcrOut)
def score_agent(req: RcrRequest, session: Session = Depends(get_session)) -> RcrOut:
    profile = _profile(session, req.profile)
    graph = to_design_graph(req.graph)
    requirements: List[Requirement] = []
    notes: Dict[str, str] = {}
    derived: Dict[str, bool] = {}

    for r in _requirements(session, profile):
        decl = req.declarations.get(r.req_key, Declaration())
        default = r.default_declaration or {}
        signed = decl.signed_off_by or default.get("signed_off_by", "")
        if r.design_check is not None:
            try:
                outcome = evaluate_graph_rule(graph, r.design_check, "RED")
            except CheckConfigError as exc:
                raise HTTPException(status_code=500, detail=f"Requirement {r.req_key} has an invalid design check: {exc}")
            ok = outcome.status == "GREEN"
            status, evidence = (COVERED, outcome.message) if ok else (r.unsatisfied_declared, "")
            notes[r.req_key], derived[r.req_key] = outcome.message, True
        else:
            if req.declarations.get(r.req_key) is not None and decl.status is not None:
                status, evidence = decl.status, decl.evidence
            else:
                status, evidence = default.get("status", "Unmapped"), default.get("evidence", "")
            notes[r.req_key], derived[r.req_key] = evidence, False
        if status not in STATUSES:
            raise HTTPException(status_code=422, detail=f"{r.req_key}: status must be one of {', '.join(STATUSES)}")
        requirements.append(Requirement(
            r.req_key, r.name, r.instrument, r.cls, r.weight, r.phi, status, evidence, signed if r.cls == "veto" else ""))

    try:
        result = score(requirements, profile.partial_credit)
    except RcrError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    floor = next((x for x in result.rows if x.key == result.floor_key), None)
    return RcrOut(
        profile=profile.profile_key, partial_credit=result.partial_credit, score=round(result.score, 4),
        G=result.G, F=result.F, floor_key=result.floor_key, floor_name=floor.name if floor else None,
        worst_instrument=result.worst_instrument,
        instruments=[InstrumentOut(**vars(i)) for i in result.instruments],
        blocked_line=result.blocked_line, watch_line=result.watch_line, lines_derived=result.lines_derived,
        band=result.band, gate=result.gate, binding=result.binding, covered=result.covered, notes=result.notes,
        rows=[RowOut(
            key=x.key, name=x.name, instrument=x.instrument, cls=x.cls, w=x.w, phi=x.phi, derived=derived[x.key],
            declared=x.declared, counted=x.counted, c=x.c, reason=x.reason, note=notes[x.key], evidence=x.evidence,
            signed_off_by=x.signed_off_by, awaiting_signoff=x.awaiting_signoff) for x in result.rows],
    )
