"""
ST-AI release gate, revised formal model (v2.5).

This module is the executable form of the gate and the status rules of the revised ST-AI model. It is pure: no database, no web framework, no clock unless the
caller passes one. It replaces the old PCS gate decision (the old score stays visible while the interval rule that will replace it is not yet wired).

What it implements
  * Effective applicability and status: a constraint is judged SATISFIED, VIOLATED or UNKNOWN; NOT_APPLICABLE is a status of its own and exists only when
    the constraint is declared not applicable AND a valid rationale is recorded. An unknown never counts in favour of release.
  * Gate precedence: INVALID_MODEL, BLOCKED, REQUIRES_REVIEW, APPROVED.
  * Which review triggers a review can resolve, and which need a missing fact recorded first (the Releasable predicate).
  * The interval rule for one risk criterion (blocked / overlap / pass / unresolved).
  * Independence of two people over a declared reporting structure at the level PERSON, REPORTING_LINE or UNIT, with the head rule.
  * Well-formedness of a design graph (references resolve, identifiers are unique).

What it does not implement yet: the bounded residual estimate and the ratchet, allocated tolerances, permissions and delegation, and the transition system. The
quantitative criterion is therefore supplied by the caller (the bridge feeds the legacy score as a temporary stand-in).

tests/test_st_ai_gate.py checks this module against the reference gate in the paper's supplementary package (13,500 combinations).
"""
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

SPEC = "ST-AI v2.5"

# ── statuses ────────────────────────────────────────────────────────────────────────────────────────────────────────────
APP_TRUE, APP_FALSE, APP_UNKNOWN = "TRUE", "FALSE", "UNKNOWN"
SATISFIED, VIOLATED, UNKNOWN, NOT_APPLICABLE = "SATISFIED", "VIOLATED", "UNKNOWN", "NOT_APPLICABLE"

INVALID_MODEL, BLOCKED, REQUIRES_REVIEW, APPROVED = "INVALID_MODEL", "BLOCKED", "REQUIRES_REVIEW", "APPROVED"
GATE_RANK = {APPROVED: 0, REQUIRES_REVIEW: 1, BLOCKED: 2, INVALID_MODEL: 3}

# review trigger codes; the first three can be resolved by a review, the others need a missing fact recorded
T_APP_UNKNOWN = "applicability_unknown"
T_REVIEW_CLASS = "review_class_shortfall"
T_OVERLAP = "interval_overlap"
T_NO_ASSESSMENT = "no_qualitative_assessment"
T_UNACC_REVIEW = "unacceptable_review_class"
T_RISK_UNRESOLVED = "risk_unresolved"
RESOLVABLE = frozenset({T_REVIEW_CLASS, T_OVERLAP, T_UNACC_REVIEW})

HARD, REVIEW = "hard", "review"


def worse(a: str, b: str) -> str:
    """The stricter of two gate outcomes."""
    return a if GATE_RANK[a] >= GATE_RANK[b] else b


# ── applicability and status ─────────────────────────────────────────────────────────────────────────────────────────────
def effective_applicability(app_raw: str, rationale_valid: bool) -> Tuple[str, str]:
    """(App, status shown when the constraint is not evaluated). A declared FALSE is not enough: it takes a valid non-applicability rationale; otherwise the
    constraint is UNKNOWN (never silently dropped)."""
    if app_raw == APP_TRUE:
        return APP_TRUE, ""
    if app_raw == APP_FALSE and rationale_valid:
        return APP_FALSE, NOT_APPLICABLE
    return APP_UNKNOWN, UNKNOWN


@dataclass
class ConstraintInput:
    cid: str
    klass: str = HARD                    # HARD: a failure blocks release; REVIEW: a shortfall can be cleared by a review
    app_raw: str = APP_TRUE
    rationale_valid: bool = False
    sat: str = UNKNOWN                   # SATISFIED | VIOLATED | UNKNOWN, read from the evidence, only meaningful when App is TRUE

    @property
    def app(self) -> str:
        return effective_applicability(self.app_raw, self.rationale_valid)[0]

    @property
    def status(self) -> str:
        app, shown = effective_applicability(self.app_raw, self.rationale_valid)
        return self.sat if app == APP_TRUE else shown

    def passes(self) -> bool:
        """A hard constraint passes when it is applicable and satisfied, or validly not applicable."""
        return self.app == APP_FALSE or (self.app == APP_TRUE and self.sat == SATISFIED)


def rationale_valid(reason: str, author: str, reviewer: str, expires_on: Optional[date], today: Optional[date] = None) -> bool:
    """A non-applicability rationale counts only when it says why, names an author and an independent reviewer (a different person), and has not expired."""
    norm = lambda t: " ".join(str(t or "").split()).lower()          # noqa: E731
    if not norm(reason) or not norm(author) or not norm(reviewer) or norm(author) == norm(reviewer):
        return False
    if expires_on is None:
        return False                       # a rationale without an expiry never lapses by itself: it is not accepted
    return expires_on >= (today or date.today())


# ── the risk criterion (interval rule) ──────────────────────────────────────────────────────────────────────────────────
def interval_state(lower: Optional[float], upper: Optional[float], tolerance: Optional[float]) -> str:
    """blocked if the lower bound is above the tolerance, unresolved if the interval straddles it, pass only if the upper bound is within it. An interval with a missing
    bound, or a missing tolerance, is unresolved by a missing fact: 'unresolved' (a review cannot resolve it)."""
    if lower is None or upper is None or tolerance is None or lower > upper:
        return "unresolved"
    if lower > tolerance:
        return "block"
    if upper <= tolerance:
        return "pass"
    return "overlap"


@dataclass
class CriterionIn:
    """A risk criterion as stated by a design (see schema.RiskCriterionIn): an evidenced interval with a validity date, a bounded interval for when the effectiveness of the
    credited controls is not evidenced, and the tolerance allocated to the deployment."""
    rid: str
    tolerance: Optional[float] = None
    evidenced: Optional[Tuple[Optional[float], Optional[float]]] = None
    evidenced_valid_until: Optional[date] = None
    bounded: Optional[Tuple[Optional[float], Optional[float]]] = None


def criterion_state(c: "CriterionIn", today: Optional[date] = None) -> "RiskInput":
    """One criterion against its tolerance. The evidenced interval counts while its evidence is valid; afterwards the bounded interval counts (lower bound with the controls at
    maximum credit, upper bound with none). The ratchet: a criterion whose evidenced interval was blocked stays blocked while only the bounded interval is available, because
    losing evidence of poor effectiveness must never improve a result; a new evidenced interval releases it."""
    today = today or date.today()
    valid = c.evidenced is not None and (c.evidenced_valid_until is None or c.evidenced_valid_until >= today)
    iv, how = (c.evidenced, "evidenced") if valid else ((c.bounded, "bounded, effectiveness not evidenced") if c.bounded is not None else (None, ""))
    if c.tolerance is None:
        return RiskInput(c.rid, "unresolved", "no tolerance is allocated to this deployment for it")
    if iv is None:
        return RiskInput(c.rid, "unresolved", "no interval is recorded for it" if c.evidenced is None else "its evidenced interval has lapsed and no bounded interval is recorded")
    state = interval_state(iv[0], iv[1], c.tolerance)
    detail = f"{how} interval [{iv[0]}, {iv[1]}] against tolerance {c.tolerance:g}"
    if not valid and c.evidenced is not None and state != "block" and interval_state(c.evidenced[0], c.evidenced[1], c.tolerance) == "block":
        return RiskInput(c.rid, "block", detail + "; the last evidenced interval was blocked and stays so until a new estimate is recorded (ratchet)")
    return RiskInput(c.rid, state, detail)


@dataclass
class RiskInput:
    rid: str
    state: str                           # pass | overlap | block | unresolved
    detail: str = ""


@dataclass
class UnquantifiedInput:
    did: str
    assessment: str = "none"             # none | noQA | ACC (accepted) | UNACC (unacceptable)
    hard: bool = False


# ── the gate ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class Trigger:
    code: str
    detail: str
    resolvable: bool


@dataclass
class GateResult:
    result: str
    blockers: List[str] = field(default_factory=list)
    triggers: List[Trigger] = field(default_factory=list)
    wf_problems: List[str] = field(default_factory=list)

    @property
    def trigger_codes(self) -> Set[str]:
        return {t.code for t in self.triggers}

    def releasable(self, review_covers: Optional[Iterable[str]] = None) -> bool:
        return releasable(self.result, self.trigger_codes, None if review_covers is None else set(review_covers))

    def unresolvable(self) -> List[Trigger]:
        return [t for t in self.triggers if not t.resolvable]

    def as_dict(self) -> Dict[str, Any]:
        return {"spec": SPEC, "result": self.result, "blockers": list(self.blockers), "wf_problems": list(self.wf_problems),
                "triggers": [{"code": t.code, "detail": t.detail, "resolvable": t.resolvable} for t in self.triggers],
                "unresolvable": [t.code for t in self.unresolvable()]}


def evaluate_gate(constraints: Sequence[ConstraintInput], risks: Sequence[RiskInput] = (), prohibited: Sequence[str] = (),
                  unquantified: Sequence[UnquantifiedInput] = (), wf_problems: Sequence[str] = ()) -> GateResult:
    """Gate precedence. Unknowns are derived from the effective statuses; there is no free-form 'material unknown' flag."""
    if wf_problems:
        return GateResult(INVALID_MODEL, wf_problems=list(wf_problems))

    blockers: List[str] = [f"prohibited condition: {p}" for p in prohibited]
    for c in constraints:
        if c.klass == HARD and c.app == APP_TRUE and c.sat in (VIOLATED, UNKNOWN):
            blockers.append(f"hard constraint {c.cid} is {c.sat.lower()}")
    blockers += [f"risk criterion {r.rid} is blocked: {r.detail}".rstrip(": ") for r in risks if r.state == "block"]
    blockers += [f"unquantified harm dimension {u.did} has an unacceptable assessment" for u in unquantified if u.assessment == "UNACC" and u.hard]
    if blockers:
        return GateResult(BLOCKED, blockers=blockers)

    triggers: List[Trigger] = []
    for c in constraints:
        if c.app == APP_UNKNOWN:
            triggers.append(Trigger(T_APP_UNKNOWN, f"{c.cid}: applicability is unknown (declared not applicable without a valid rationale, or not stated)", False))
        elif c.klass == REVIEW and c.app == APP_TRUE and c.sat != SATISFIED:
            triggers.append(Trigger(T_REVIEW_CLASS, f"{c.cid}: review-class constraint is {c.sat.lower()}", True))
    for r in risks:
        if r.state == "overlap":
            triggers.append(Trigger(T_OVERLAP, f"{r.rid}: the uncertainty interval straddles the tolerance. {r.detail}".strip(), True))
        elif r.state == "unresolved":
            triggers.append(Trigger(T_RISK_UNRESOLVED, f"{r.rid}: a bound or tolerance is missing. {r.detail}".strip(), False))
    for u in unquantified:
        if u.assessment == "noQA":
            triggers.append(Trigger(T_NO_ASSESSMENT, f"{u.did}: the dimension has no valid qualitative assessment", False))
        elif u.assessment == "UNACC" and not u.hard:
            triggers.append(Trigger(T_UNACC_REVIEW, f"{u.did}: unacceptable assessment of a review-class dimension", True))
    return GateResult(REQUIRES_REVIEW if triggers else APPROVED, triggers=triggers)


def releasable(result: str, trigger_codes: Set[str], review_covers: Optional[Set[str]] = None) -> bool:
    """APPROVED, or REQUIRES_REVIEW where every trigger is of a kind a review can resolve and a review covers it. A review never resolves BLOCKED, INVALID_MODEL,
    an unknown applicability, or a missing assessment: the missing fact has to be recorded, which changes the result."""
    if result == APPROVED:
        return True
    if result != REQUIRES_REVIEW:
        return False
    covers = trigger_codes if review_covers is None else review_covers
    return trigger_codes <= RESOLVABLE and trigger_codes <= covers


# ── independence over a reporting structure ──────────────────────────────────────────────────────────────────────────────
LEVEL_PERSON, LEVEL_REPORTING_LINE, LEVEL_UNIT = "PERSON", "REPORTING_LINE", "UNIT"
T, F, U = "T", "F", "U"


@dataclass
class Structure:
    parent: Dict[str, Optional[str]] = field(default_factory=dict)       # unit -> parent unit
    head: Dict[str, Optional[str]] = field(default_factory=dict)         # unit -> person heading it
    unit_of: Dict[str, Optional[str]] = field(default_factory=dict)      # person -> primary unit

    def chain(self, unit: Optional[str]) -> Optional[List[str]]:
        """The unit and its ancestors, or None if the structure is cyclic or refers to a unit it does not declare."""
        out: List[str] = []
        while unit is not None:
            if unit in out or unit not in self.parent:
                return None
            out.append(unit)
            unit = self.parent[unit]
        return out

    def head_rule_holds(self) -> bool:
        """The primary unit of a unit's head must be that unit or an ancestor of it. Without this two people can each head a unit above the other's primary unit."""
        for u, h in self.head.items():
            if h is None:
                continue
            ch = self.chain(u)
            hu = self.unit_of.get(h)
            if ch is None or hu is None or hu not in ch:
                return False
        return True


def _norm(p: Optional[str]) -> str:
    return " ".join(str(p or "").split()).lower()


def supervises(a: str, b: str, s: Structure) -> str:
    """T if a heads a unit at or above b's primary unit; F if that is established not to hold; U if the data are missing or contradictory."""
    if _norm(a) == _norm(b):
        return F
    ub = s.unit_of.get(b)
    ch = s.chain(ub) if ub is not None else None
    if ch is None:
        return U
    unknown = False
    for u in ch:
        h = s.head.get(u)
        if h is None:
            unknown = True
        elif _norm(h) == _norm(a):
            return T
    return U if unknown else F


def independent(a: Optional[str], b: Optional[str], level: str, s: Optional[Structure] = None) -> str:
    """T, F or U. U when membership, head or reporting data are missing or contradictory, and a U never meets a requirement."""
    if not _norm(a) or not _norm(b):
        return U
    if _norm(a) == _norm(b):
        return F
    if level == LEVEL_PERSON:
        return T
    if s is None or not s.head_rule_holds():
        return U
    if level not in (LEVEL_REPORTING_LINE, LEVEL_UNIT):
        return U
    sab, sba = supervises(a, b, s), supervises(b, a, s)
    if T in (sab, sba):
        return F
    if U in (sab, sba):
        return U
    if level == LEVEL_UNIT:
        ua, ub = s.unit_of.get(a), s.unit_of.get(b)
        if ua is None or ub is None:
            return U
        return F if ua == ub else T
    return T


def meets(requirement_result: str) -> bool:
    return requirement_result == T


# ── well-formedness of a design graph ────────────────────────────────────────────────────────────────────────────────────
def well_formed_graph(graph: Optional[Dict[str, Any]]) -> List[str]:
    """What makes a design graph not well-formed: duplicate identifiers and edges that refer to an element that is not there. Returns the problems (empty: well-formed)."""
    if not graph:
        return []
    problems: List[str] = []
    ids: Set[str] = set()
    for n in graph.get("nodes", []) or []:
        i = str(n.get("id", ""))
        if not i:
            continue                       # an element the caller did not identify cannot be referred to; only duplicates and dangling links are problems
        if i in ids:
            problems.append(f"the identifier {i} is used by more than one element")
        ids.add(i)
    for e in graph.get("edges", []) or []:
        for keys in (("source", "from_id", "from"), ("target", "to_id", "to")):
            end = next((e.get(k) for k in keys if e.get(k) is not None), "")
            if str(end) not in ids:
                problems.append(f"the link {e.get('id', '?')} ({e.get('type') or e.get('label') or ''}) refers to an element that is not in the design ({end})")
    return problems
