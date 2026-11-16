"""
The gate (paper section 3.3).

The verdict of a path depends on the worst status among its required controls and on the impact tier of the resource at its end, compared with the tolerance
of that resource's department:

    worst SAT                          APPROVED
    worst UNV, tier <= tolerance       APPROVED          (the department accepts it)
    worst UNV, tier  > tolerance       REQUIRES_REVIEW
    worst VIO, tier <= tolerance       REQUIRES_REVIEW
    worst VIO, tier  > tolerance       BLOCKED

The gate is the lowest verdict over all paths (APPROVED when there is none), and INVALID_CONTRACT outranks everything. Verdicts are ordered
INVALID_CONTRACT < BLOCKED < REQUIRES_REVIEW < APPROVED. At runtime APPROVED is shown as CONFORMING and BLOCKED as DIVERGENT.

The gate is monotone in the control statuses (Lemma 1): worse evidence can never improve the verdict.
"""
from typing import Dict

from . import exposure
from .estate import Estate
from .statuses import NA, SAT, UNV, VIO, State

INVALID_CONTRACT, BLOCKED, REQUIRES_REVIEW, APPROVED = 0, 1, 2, 3
VERDICT_NAME = {INVALID_CONTRACT: "INVALID_CONTRACT", BLOCKED: "BLOCKED", REQUIRES_REVIEW: "REQUIRES_REVIEW", APPROVED: "APPROVED"}
RUNTIME_NAME = {INVALID_CONTRACT: "INVALID_CONTRACT", BLOCKED: "DIVERGENT", REQUIRES_REVIEW: "REQUIRES_REVIEW", APPROVED: "CONFORMING"}


def path_verdict(E: Estate, S: State, now: float, p: exposure.Path) -> int:
    sts = [S.status(c, now) for c in exposure.required(E, p)]
    tier = E.res[p[2]][1]
    tau = E.tau[E.res[p[2]][0]]
    if VIO in sts:
        return BLOCKED if tier > tau else REQUIRES_REVIEW
    if UNV in sts:
        return REQUIRES_REVIEW if tier > tau else APPROVED
    return APPROVED


def gate(E: Estate, S: State, now: float = 0, contract_ok: bool = True) -> int:
    if not contract_ok:
        return INVALID_CONTRACT
    return min([path_verdict(E, S, now, p) for p in exposure.paths(E)] or [APPROVED])


def department_risk(E: Estate, S: State, now: float = 0) -> Dict[str, int]:
    """The risk vector: for each department, the highest impact tier among open paths into it (0 if none). A vector, not a sum."""
    out = {d: 0 for d in E.tau}
    for p in exposure.paths(E):
        if any(S.status(c, now) not in (SAT, NA) for c in exposure.required(E, p)):
            d, tier, _ = E.res[p[2]]
            out[d] = max(out[d], tier)
    return out
