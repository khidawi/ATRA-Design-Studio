"""
Exposure: attack paths and the controls each path needs (paper section 3.3).

An attack path is (input, chain, resource, mode): an untrusted input read by the first agent of a delegation chain, the chain itself (no agent twice, at most
the first agent's depth bound in delegations), and a resource in the scope of the last agent. The set is finite and, for a fixed depth bound, polynomial in the
size of the estate.
"""
from typing import List, Set, Tuple

from .estate import Estate
from .statuses import Control

Path = Tuple[str, Tuple[str, ...], str, str]


def chains(E: Estate, a0: str) -> List[Tuple[str, ...]]:
    out = [(a0,)]
    frontier = [(a0,)]
    for _ in range(E.agents[a0].max_depth):
        nxt = []
        for ch in frontier:
            for b in sorted(E.agents[ch[-1]].may_delegate_to):
                if b in E.agents and b not in ch:
                    nxt.append(ch + (b,))
        out += nxt
        frontier = nxt
    return out


def paths(E: Estate) -> List[Path]:
    out: List[Path] = []
    for a0 in sorted(E.agents):
        for i in sorted(E.agents[a0].inputs):
            for ch in chains(E, a0):
                ak = ch[-1]
                for r, mode in sorted(E.agents[ak].resources.items()):
                    if r in E.res:
                        out.append((i, ch, r, mode))
    return out


def required(E: Estate, p: Path) -> Set[Control]:
    """The controls the threat catalogue places on a path."""
    i, ch, r, mode = p
    c: Set[Control] = {("iso", ch[0])}
    for a in ch:
        ag = E.agents[a]
        c |= {("least", a), ("ident", a), ("life", a), ("supply", a)}
        if ag.baseline_monitored:
            c.add(("base", a))
        if ag.may_spawn:
            c.add(("spawn", a))
    for a, _b in zip(ch, ch[1:]):
        c.add(("deleg", a))
        if E.agents[a].auth_required:
            c.add(("auth", a))
    ak = ch[-1]
    _dept, tier, kind = E.res[r]
    if mode == "write" and tier >= 3:
        c.add(("hitl", ak))
    if kind == "memory":
        c.add(("memval", ak))
    if E.agents[ak].runs_code:
        c.add(("sandbox", ak))
    return c


def all_controls(E: Estate) -> List[Control]:
    cs: Set[Control] = set()
    for p in paths(E):
        cs |= required(E, p)
    return sorted(cs)
