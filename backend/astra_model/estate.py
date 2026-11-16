"""
The estate model (paper section 3.1): departments, agents, resources, delegation, and the tolerance of each department.

Plain data. Nothing here reads a database; building an estate from a design and the organisation graph is a later phase.
"""
import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Agent:
    name: str
    dept: str
    autonomy: str = "approve"                       # suggest | approve | auto
    expires: int = 10 ** 9
    status: str = "production"
    identity: Optional[str] = None
    tools: Dict[str, Dict[str, Tuple[int, int]]] = field(default_factory=dict)   # tool -> parameter bounds (inclusive)
    write_tools: Set[str] = field(default_factory=set)
    hitl_tools: Set[str] = field(default_factory=set)                            # tools that need human confirmation
    prohibited_chains: Set[Tuple[str, str]] = field(default_factory=set)
    resources: Dict[str, str] = field(default_factory=dict)                      # resource -> read | write
    validated_memory: bool = True
    provenance_required: bool = True
    long_term_memory: bool = False
    may_delegate_to: Set[str] = field(default_factory=set)
    accepts_from: Set[str] = field(default_factory=set)
    deleg_mode: str = "execution"
    max_depth: int = 2
    auth_required: bool = True
    sandbox: bool = True
    runs_code: bool = False
    egress: Set[str] = field(default_factory=set)
    may_spawn: Set[str] = field(default_factory=set)
    components: Dict[str, bool] = field(default_factory=dict)                    # the inventory: component -> signature required
    inputs: Set[str] = field(default_factory=set)                                # untrusted inputs the agent reads
    baseline_monitored: bool = False

    def __post_init__(self) -> None:
        if self.identity is None:
            self.identity = self.name


@dataclass
class Estate:
    agents: Dict[str, Agent]
    res: Dict[str, Tuple[str, int, str]]            # resource -> (department, impact tier 1..4, kind data|memory)
    tau: Dict[str, int]                             # department -> the highest tier of an open path it tolerates
    inventory: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not self.inventory:
            self.inventory = set(self.agents)


def problems(E: Estate) -> List[str]:
    """What makes an estate unusable by the gate. An empty list means the estate is well-formed."""
    out: List[str] = []
    for r, (dept, tier, kind) in sorted(E.res.items()):
        if dept not in E.tau:
            out.append(f"resource {r!r} is in department {dept!r}, which has no tolerance")
        if not 1 <= tier <= 4:
            out.append(f"resource {r!r} has impact tier {tier}, which is not between 1 and 4")
        if kind not in ("data", "memory"):
            out.append(f"resource {r!r} has kind {kind!r}")
    for d, t in sorted(E.tau.items()):
        if not 0 <= t <= 4:
            out.append(f"department {d!r} has tolerance {t}, which is not between 0 and 4")
    for n, a in sorted(E.agents.items()):
        if a.name != n:
            out.append(f"agent key {n!r} differs from its name {a.name!r}")
        for r in a.resources:
            if r not in E.res:
                out.append(f"agent {n!r} reaches resource {r!r}, which is not in the estate")
        for b in a.may_delegate_to:
            if b not in E.agents:
                out.append(f"agent {n!r} may delegate to {b!r}, which is not in the estate")
        if a.autonomy not in ("suggest", "approve", "auto"):
            out.append(f"agent {n!r} has autonomy {a.autonomy!r}")
    return out


def validate(E: Estate) -> None:
    p = problems(E)
    if p:
        raise ValueError("; ".join(p))


def narrow(E: Estate, op: Tuple[str, ...]) -> Estate:
    """A copy with one capability removed: ('res', agent, resource) or ('del', agent, target)."""
    E2 = copy.deepcopy(E)
    if op[0] == "res":
        E2.agents[op[1]].resources.pop(op[2], None)
    elif op[0] == "del":
        E2.agents[op[1]].may_delegate_to.discard(op[2])
    else:
        raise ValueError(f"unknown narrowing {op[0]!r}")
    return E2
