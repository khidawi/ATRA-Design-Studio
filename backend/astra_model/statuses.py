"""
Control statuses, evidence and expiry (paper section 3.2).

A control is a pair (kind, agent). Its status is one of SAT (satisfied), UNV (unverified), VIO (violated) or NA (not applicable), ordered VIO < UNV < SAT.
A control that was never assessed is UNV: nothing is satisfied by default. A SAT status is only fresh until its evidence expires, and reads as UNV after that.

Evidence has a polarity. Adverse evidence can only lower a status. Supportive evidence can raise it, but only from four sources (a passed Probe scenario, an
attestation, a human adjudication, a new contract version). A learned detector is never one of them: it can only move the baseline control to UNV.
"""
from typing import Dict, Tuple

SAT, UNV, VIO, NA = "SAT", "UNV", "VIO", "NA"
GOOD = {VIO: 0, UNV: 1, SAT: 2}
SUPPORT_SOURCES = frozenset({"probe_pass", "attestation", "human", "new_contract"})
Control = Tuple[str, str]


class State:
    """Statuses of controls, the time until which a SAT status is fresh, and the rationale recorded for a NOT_APPLICABLE status."""

    def __init__(self) -> None:
        self.st: Dict[Control, str] = {}
        self.fresh: Dict[Control, float] = {}
        self.rationale: Dict[Control, str] = {}

    def copy(self) -> "State":
        s = State()
        s.st, s.fresh, s.rationale = dict(self.st), dict(self.fresh), dict(self.rationale)
        return s

    def status(self, c: Control, now: float = 0) -> str:
        v = self.st.get(c, UNV)
        if v == SAT and now > self.fresh.get(c, float("inf")):
            return UNV
        return v


def worse(a: str, b: str) -> str:
    return a if GOOD[a] <= GOOD[b] else b


def adverse(S: State, c: Control, level: str) -> None:
    """Adverse evidence: the status can only go down."""
    if level not in (UNV, VIO):
        raise ValueError(f"adverse evidence has level UNV or VIO, not {level!r}")
    S.st[c] = worse(S.st.get(c, UNV), level)


def support(S: State, c: Control, source: str, now: float, ttl: float = float("inf")) -> None:
    """Supportive evidence: the control becomes SAT, fresh until now + ttl. Only the four permitted sources may do this."""
    if source not in SUPPORT_SOURCES:
        raise ValueError(f"{source!r} cannot support a control")
    S.st[c] = SAT
    S.fresh[c] = now + ttl


def mark_not_applicable(S: State, c: Control, rationale: str) -> None:
    """NOT_APPLICABLE is accepted only with a recorded rationale, so a control cannot be removed by declaring it inapplicable."""
    if not rationale or not rationale.strip():
        raise ValueError("a control is not applicable only with a recorded rationale")
    S.st[c] = NA
    S.rationale[c] = rationale.strip()


def learned_evidence(S: State, agent: str, score: float, theta: float) -> None:
    """A baseline, TGN or GNN flag: when the score reaches the threshold the baseline control becomes UNV. Never VIO, never SAT."""
    if score >= theta:
        adverse(S, ("base", agent), UNV)


def probe_result(S: State, c: Control, passed: bool, now: float, ttl: float) -> None:
    """A passed scenario is supportive evidence with a lifetime; a missed attack shows the control does not work."""
    if passed:
        support(S, c, "probe_pass", now, ttl)
    else:
        adverse(S, c, VIO)
