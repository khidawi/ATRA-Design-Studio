"""
Design-time Regulatory Compliance Risk (RCR) for AI agents.

An implementation of "RCR_Algorithm_Step_by_Step" (ST-AI / ASTRA, Task 1.4), step
for step. This is the agent design-phase assessment. It shares no code with the
PCS score that ST-AI uses for AI models, or with the model studio's rule checks,
and the runtime assessment will be separate again.

    Step 1  coverage c(r): Covered=1, Partial=c_p, Gap=0, Unmapped=0
            a veto requirement is Covered only with evidence AND reviewer sign-off;
            evidence without sign-off counts as Partial; a claimed Covered with no
            evidence counts as Gap
    Step 2  breadth  G_f = sum w(1-c) / sum w per instrument;  G = max_f G_f
    Step 3  depth    F = max over veto requirements of phi * (1-c)
    Step 4  RCR = 100 * max(G, F)
    Step 5  band lines derived from the registry:
            B = 100*phi_min,  W = 100*(1-c_p)*phi_min
            valid only if (1-c_p)*phi_max < phi_min, otherwise the registry is rejected
    Step 6  score < W Clear/APPROVE;  W <= score < B Watch/REVIEW;  score >= B Blocked/BLOCK

The weights, floors and partial credit are judgement-assigned and not yet calibrated
against assessor ratings. A Clear result means the declared requirements are
covered; it does not certify that the system is compliant.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

COVERED, PARTIAL, GAP, UNMAPPED = "Covered", "Partial", "Gap", "Unmapped"
STATUSES = (COVERED, PARTIAL, GAP, UNMAPPED)
DEFAULT_PARTIAL_CREDIT = 0.5
# Used only when a registry has no veto requirement, so there is no phi to derive the lines from:
# the document's convention of 80% / 40% of a regulation's weight uncovered.
FALLBACK_BLOCKED, FALLBACK_WATCH = 80.0, 40.0


class RcrError(ValueError):
    """The registry or its inputs are not valid."""


@dataclass
class Requirement:
    key: str
    name: str
    instrument: str
    cls: str                      # "veto" or "ordinary"
    w: int                        # 3 statutory obligation, 2 binding control, 1 supporting item
    phi: Optional[float] = None   # veto only: lowest score the requirement can contribute fully open
    declared: str = UNMAPPED
    evidence: str = ""
    signed_off_by: str = ""


@dataclass
class RowResult:
    key: str
    name: str
    instrument: str
    cls: str
    w: int
    phi: Optional[float]
    declared: str
    counted: str
    c: float
    reason: str
    evidence: str
    signed_off_by: str
    awaiting_signoff: bool


@dataclass
class InstrumentBreadth:
    instrument: str
    uncovered: float
    total: float
    g: float


@dataclass
class RcrResult:
    rows: List[RowResult]
    instruments: List[InstrumentBreadth]
    G: float
    F: float
    floor_key: Optional[str]
    worst_instrument: Optional[str]
    score: float
    blocked_line: float
    watch_line: float
    lines_derived: bool
    band: str                     # clear | watch | blocked
    gate: str                     # APPROVE | REVIEW | BLOCK
    binding: str                  # depth | breadth
    partial_credit: float
    covered: int = 0
    notes: List[str] = field(default_factory=list)


def validate_registry(reqs: List[Requirement], cp: float) -> None:
    if not 0 < cp < 1:
        raise RcrError("partial credit must be between 0 and 1")
    seen = set()
    for r in reqs:
        if r.key in seen:
            raise RcrError(f"requirement {r.key!r} appears twice")
        seen.add(r.key)
        if r.cls not in ("veto", "ordinary"):
            raise RcrError(f"{r.key}: class must be 'veto' or 'ordinary'")
        if r.w not in (1, 2, 3):
            raise RcrError(f"{r.key}: weight must be 1, 2 or 3")
        if r.cls == "veto" and not (r.phi is not None and 0 < r.phi <= 1):
            raise RcrError(f"{r.key}: a critical requirement needs a floor between 0 and 1")
    floors = [r.phi for r in reqs if r.cls == "veto"]
    if floors and not (1 - cp) * max(floors) < min(floors):
        raise RcrError(
            f"Registry rejected: (1 - c_p) x phi_max = {(1 - cp) * max(floors):.3f} must be below phi_min = "
            f"{min(floors):.3f}, otherwise a half-handled critical requirement could reach the Blocked line."
        )


def count(r: Requirement, cp: float):
    """Step 1: what a requirement counts as, and why."""
    if r.declared not in STATUSES:
        raise RcrError(f"{r.key}: status must be one of {', '.join(STATUSES)}")
    has_evidence = bool(r.evidence and r.evidence.strip())
    signed = bool(r.signed_off_by and r.signed_off_by.strip())
    if r.declared == UNMAPPED:
        return UNMAPPED, "Not assessed yet"
    if r.declared == GAP:
        return GAP, "Declared as a gap"
    if not has_evidence:
        return GAP, f"Declared {r.declared.lower()} but no evidence is recorded, so it counts as a gap"
    if r.cls == "veto" and r.declared == COVERED:
        if signed:
            return COVERED, f"Evidence recorded and signed off by {r.signed_off_by.strip()}"
        return PARTIAL, "Evidence recorded, awaiting reviewer sign-off, so it counts as partial"
    return r.declared, "Evidence recorded"


def score(reqs: List[Requirement], cp: float = DEFAULT_PARTIAL_CREDIT) -> RcrResult:
    validate_registry(reqs, cp)
    value = {COVERED: 1.0, PARTIAL: cp, GAP: 0.0, UNMAPPED: 0.0}

    rows: List[RowResult] = []
    for r in reqs:
        counted, reason = count(r, cp)
        rows.append(RowResult(
            key=r.key, name=r.name, instrument=r.instrument, cls=r.cls, w=r.w, phi=r.phi, declared=r.declared,
            counted=counted, c=value[counted], reason=reason, evidence=r.evidence or "",
            signed_off_by=r.signed_off_by or "",
            awaiting_signoff=r.cls == "veto" and r.declared == COVERED and counted == PARTIAL,
        ))

    # Step 2: breadth, per instrument, then the worst instrument
    instruments: List[InstrumentBreadth] = []
    for name in dict.fromkeys(r.instrument for r in rows):
        mine = [r for r in rows if r.instrument == name]
        total = float(sum(r.w for r in mine))
        uncovered = sum(r.w * (1 - r.c) for r in mine)
        instruments.append(InstrumentBreadth(name, uncovered, total, uncovered / total if total else 0.0))
    worst = max(instruments, key=lambda i: i.g, default=None)
    G = worst.g if worst else 0.0

    # Step 3: depth, the most open veto requirement
    F, floor_key = 0.0, None
    for r in rows:
        if r.cls == "veto":
            depth = r.phi * (1 - r.c)
            if depth > F:
                F, floor_key = depth, r.key

    # Step 4
    raw = 100 * max(G, F)

    # Step 5: lines derived from the floors
    floors = [r.phi for r in rows if r.cls == "veto"]
    derived = bool(floors)
    blocked = 100 * min(floors) if derived else FALLBACK_BLOCKED
    watch = 100 * (1 - cp) * min(floors) if derived else FALLBACK_WATCH

    # Step 6
    if raw >= blocked:
        band, gate = "blocked", "BLOCK"
    elif raw >= watch:
        band, gate = "watch", "REVIEW"
    else:
        band, gate = "clear", "APPROVE"

    notes = []
    if not derived:
        notes.append("No critical requirement, so the band lines use the 40 / 80 convention instead of being derived.")
    return RcrResult(
        rows=rows, instruments=instruments, G=G, F=F, floor_key=floor_key,
        worst_instrument=worst.instrument if worst else None, score=raw, blocked_line=blocked, watch_line=watch,
        lines_derived=derived, band=band, gate=gate, binding="depth" if F > 0 and F >= G else "breadth",
        partial_credit=cp, covered=sum(1 for r in rows if r.counted == COVERED), notes=notes,
    )
