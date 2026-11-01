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
from datetime import date
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

import method
from compliance_engine import to_design_graph
from compliance_schema import DesignGraphIn
from db.models import RcrProfile, RcrRequirement
from evidence import attested_keys, gate_basis
from db.session import get_session
from rcr_engine import COVERED, GAP, PARTIAL, STATUSES, UNMAPPED, RcrError, Requirement, score, validate_registry
from schema import is_placeholder_evidence, names_a_record
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
    valid_until: Optional[date] = None      # the evidence stops counting after this day

    @field_validator("valid_until", mode="before")
    @classmethod
    def blank_is_none(cls, v):
        return None if v in ("", None) else v


class RcrRequest(BaseModel):
    profile: str
    graph: DesignGraphIn
    declarations: Dict[str, Declaration] = Field(default_factory=dict)
    design_key: Optional[str] = None       # the saved design, so its attested evidence records can be read


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
    evidence_placeholder: bool = False   # declared on words that stand in for a record: it earns no credit
    evidence_expired: bool = False       # the evidence passed its valid-until day: it no longer counts
    evidence_names_record: bool = True   # the evidence says where the record is kept
    evidence_attested: Optional[bool] = None   # an attested record is kept for it (None: not asked, or the design is not saved)


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
    # The design scored three ways: with no controls, with only the controls whose evidence names a record that is still valid, and as declared.
    levels: Optional[Dict[str, Any]] = None
    # The method the score was made under (method.py).
    method: Optional[Dict[str, Any]] = None
    # What the score rests on: each requirement that counts, taken away on its own.
    sensitivity: Optional[Dict[str, Any]] = None


def _sensitivity(requirements, result, level, derived, names, declarations, limit: int = 12) -> Optional[Dict[str, Any]]:
    """What the score rests on. Each requirement that counts is set to a gap on its own and the design scored again; the ones whose loss moves the gate or the band, or raises the
    risk most, come first, with the day the evidence expires when it does. A requirement whose loss changes nothing is left out: it is not holding the result up."""
    try:
        rows: List[Dict[str, Any]] = []
        for q in requirements:
            if q.declared not in (COVERED, PARTIAL):
                continue
            lost = level({q.key: GAP}, requirements)
            delta = round(lost["score"] - round(result.score, 4), 4)
            flips = "gate" if lost["gate"] != result.gate else "band" if lost["band"] != result.band else None
            if delta <= 0 and flips is None:
                continue
            until = (declarations.get(q.key) or Declaration()).valid_until
            rows.append({"control": q.key, "name": q.name, "kind": "design" if derived[q.key] else "declared", "flips": flips, "delta": delta, "to": lost,
                         "has_record": True if derived[q.key] else names.get(q.key, False), "expires": until.isoformat() if until else None})
        rows.sort(key=lambda x: (0 if x["flips"] == "gate" else 1 if x["flips"] == "band" else 2, -x["delta"], x["control"]))
        return {"now": {"score": round(result.score, 4), "band": result.band, "gate": result.gate}, "controls": rows[:limit], "decisive": sum(1 for x in rows if x["flips"]), "counted": len(rows)}
    except Exception:           # the score stands on its own; this is an addition
        return None


@router.post("/score", response_model=RcrOut)
def score_agent(req: RcrRequest, session: Session = Depends(get_session)) -> RcrOut:
    profile = _profile(session, req.profile)
    graph = to_design_graph(req.graph)
    requirements: List[Requirement] = []
    notes: Dict[str, str] = {}
    derived: Dict[str, bool] = {}
    placeholder: Dict[str, bool] = {}
    names: Dict[str, bool] = {}
    expired: Dict[str, bool] = {}

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
                if status in (COVERED, PARTIAL) and is_placeholder_evidence(evidence):
                    placeholder[r.req_key] = True
                    status = UNMAPPED          # words like "test" are not evidence: no credit
                elif status in (COVERED, PARTIAL) and decl.valid_until is not None and decl.valid_until < date.today():
                    expired[r.req_key] = True
                    status = GAP                # the evidence passed its valid-until day: it no longer counts
                elif status in (COVERED, PARTIAL):
                    names[r.req_key] = names_a_record(evidence)
            else:
                status, evidence = default.get("status", "Unmapped"), default.get("evidence", "")
            notes[r.req_key], derived[r.req_key] = ("The evidence is a placeholder, not a record of how it is met." if placeholder.get(r.req_key)
                                                   else f"The evidence expired on {decl.valid_until.isoformat()}: it no longer counts." if expired.get(r.req_key) else evidence), False
        if status not in STATUSES:
            raise HTTPException(status_code=422, detail=f"{r.req_key}: status must be one of {', '.join(STATUSES)}")
        requirements.append(Requirement(
            r.req_key, r.name, r.instrument, r.cls, r.weight, r.phi, status, evidence, signed if r.cls == "veto" else ""))

    attested = attested_keys(session, req.design_key)         # None: no saved design to look at, so the evidence text is read instead
    on_verified = gate_basis(session) == "verified" and attested is not None
    recorded = {k: (k in attested if attested is not None else v) for k, v in names.items()}

    def level(statuses: Dict[str, str], base=None) -> Dict[str, Any]:
        res = score([Requirement(q.key, q.name, q.instrument, q.cls, q.w, q.phi, statuses.get(q.key, q.declared), q.evidence, q.signed_off_by) for q in (base or requirements)], profile.partial_credit)
        return {"score": round(res.score, 4), "band": res.band, "gate": res.gate}

    credited = (COVERED, PARTIAL)
    inherent = {q.key: GAP for q in requirements}
    verified = {q.key: (q.declared if derived[q.key] or (q.declared not in credited) or (recorded.get(q.key, False) and not expired.get(q.key) and not placeholder.get(q.key)) else UNMAPPED)
                for q in requirements}
    # What decides the gate: the declared design, or, when the organisation has chosen it and the server has looked at the records, only what has an attested record behind it.
    scored = [Requirement(q.key, q.name, q.instrument, q.cls, q.w, q.phi, verified[q.key], q.evidence, q.signed_off_by) for q in requirements] if on_verified else requirements
    try:
        result = score(scored, profile.partial_credit)
    except RcrError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    levels = {"inherent": level(inherent), "verified": level(verified), "declared": level({}),
              "basis": "verified" if on_verified else "declared", "attested": attested is not None,
              "unverified": sorted(q.key for q in requirements if not derived[q.key] and q.declared in credited and not recorded.get(q.key, False)),
              "expired": sorted(k for k, v in expired.items() if v)}

    sensitivity = _sensitivity(scored, result, level, derived, recorded, req.declarations)
    floor = next((x for x in result.rows if x.key == result.floor_key), None)
    return RcrOut(
        profile=profile.profile_key, partial_credit=result.partial_credit, score=round(result.score, 4),
        G=result.G, F=result.F, floor_key=result.floor_key, floor_name=floor.name if floor else None,
        worst_instrument=result.worst_instrument,
        instruments=[InstrumentOut(**vars(i)) for i in result.instruments],
        blocked_line=result.blocked_line, watch_line=result.watch_line, lines_derived=result.lines_derived,
        band=result.band, gate=result.gate, binding=result.binding, covered=result.covered, notes=result.notes, levels=levels, method=method.stamp(session), sensitivity=sensitivity,
        rows=[RowOut(
            key=x.key, name=x.name, instrument=x.instrument, cls=x.cls, w=x.w, phi=x.phi, derived=derived[x.key],
            declared=x.declared, counted=x.counted, c=x.c, reason=x.reason, note=notes[x.key], evidence=x.evidence,
            signed_off_by=x.signed_off_by, awaiting_signoff=x.awaiting_signoff, evidence_placeholder=placeholder.get(x.key, False), evidence_expired=expired.get(x.key, False),
            evidence_names_record=names.get(x.key, True),
            evidence_attested=(x.key in attested) if attested is not None and not derived[x.key] and x.declared in credited else None) for x in result.rows],
    )
