"""
Reference semantics of the ASTRA formal model for AI agents (small, executable, dependency-free).

It implements the definitions of the paper:
  * the estate model E (departments, agents, capability providers, resources, delegation, controls),
  * exposure: attack paths from an untrusted input through a delegation chain to a resource,
  * statuses SAT / UNV / VIO / NA, evidence with polarity and expiry,
  * the gate (design time) and its re-run on live evidence (runtime): INVALID_CONTRACT < BLOCKED < REQUIRES_REVIEW < APPROVED,
  * the typed divergence classes DVG-* and the conformity predicate Conforms(e, C, h),
  * the contract: canonical form, hash, signature, validity.

`DEFECTS` is a set of planted defects. The sensitivity checks switch one on at a time and verify that some
property fails. With DEFECTS empty the module is the intended semantics.
"""
import copy
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

DEFECTS: Set[str] = set()

SAT, UNV, VIO, NA = "SAT", "UNV", "VIO", "NA"
GOOD = {VIO: 0, UNV: 1, SAT: 2}
V_INVALID, V_BLOCKED, V_REVIEW, V_APPROVED = 0, 1, 2, 3
VNAME = {0: "INVALID_CONTRACT", 1: "BLOCKED", 2: "REQUIRES_REVIEW", 3: "APPROVED"}

# ---------------------------------------------------------------- the divergence classes (from the specification)
# id: (control kind it protects, detection basis, default severity, event kind)
CLASSES: Dict[str, Tuple[str, str, str, str]] = {
    "DVG-GOAL-01": ("iso", "semantic", "High", "goal_set"),
    "DVG-GOAL-02": ("iso", "semantic", "Critical", "goal_set"),
    "DVG-TOOL-01": ("least", "policy", "High", "tool_call"),
    "DVG-TOOL-02": ("least", "policy", "High", "tool_call"),
    "DVG-TOOL-03": ("least", "policy", "High", "tool_call"),
    "DVG-EXEC-01": ("sandbox", "policy", "Critical", "exec"),
    "DVG-RES-01": ("least", "policy", "High", "res_access"),
    "DVG-MEM-01": ("memval", "policy", "High", "mem_write"),
    "DVG-MEM-02": ("memval", "policy", "Medium", "mem_write"),
    "DVG-DEL-01": ("deleg", "policy", "High", "deleg_out"),
    "DVG-DEL-02": ("deleg", "policy", "High", "deleg_in"),
    "DVG-DEL-03": ("deleg", "policy", "High", "deleg_out"),
    "DVG-COMM-01": ("auth", "cryptographic", "High", "msg"),
    "DVG-AUT-01": ("hitl", "policy", "High", "tool_call"),
    "DVG-AUT-02": ("hitl", "policy", "Critical", "tool_call"),
    "DVG-AUT-03": ("hitl", "policy", "Critical", "tool_call"),
    "DVG-ID-01": ("ident", "policy", "High", "id"),
    "DVG-LIFE-01": ("life", "policy", "Medium", "life"),
    "DVG-BASE-01": ("base", "baseline", "Medium", "score"),
    "DVG-SPAWN-01": ("spawn", "policy", "High", "spawn"),
    "DVG-SUP-01": ("supply", "cryptographic", "Critical", "component"),
    "DVG-SUP-02": ("supply", "policy", "High", "component"),
}
SEV_LEVEL = {"High": VIO, "Critical": VIO, "Medium": UNV}
KIND_CONTROL = {"goal_set": "iso", "tool_call": "least", "exec": "sandbox", "res_access": "least", "mem_write": "memval",
                "deleg_out": "deleg", "deleg_in": "deleg", "msg": "auth", "id": "ident", "life": "life", "spawn": "spawn",
                "component": "supply"}
REQUIRED = {"goal_set": ["goal", "source"], "tool_call": ["tool"], "exec": ["sandboxed"], "res_access": ["resource", "mode"],
            "mem_write": ["validated", "provenance"], "deleg_out": ["target", "mode"], "deleg_in": ["source"],
            "msg": ["verified"], "id": ["claimed"], "life": ["now_t"], "spawn": ["child", "inventoried"],
            "component": ["name", "signed", "in_aibom"]}
SUPPORT_SOURCES = {"probe_pass", "attestation", "human", "new_contract"}   # a learned detector is never one of these


# ---------------------------------------------------------------- the estate model
@dataclass
class Agent:
    name: str
    dept: str
    autonomy: str = "approve"                       # suggest | approve | auto
    expires: int = 10 ** 9
    status: str = "production"
    identity: Optional[str] = None
    tools: Dict[str, Dict[str, Tuple[int, int]]] = field(default_factory=dict)   # tool -> parameter bounds
    write_tools: Set[str] = field(default_factory=set)
    hitl_tools: Set[str] = field(default_factory=set)
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
    components: Dict[str, bool] = field(default_factory=dict)                    # AIBOM: component -> signature required
    inputs: Set[str] = field(default_factory=set)                                # untrusted inputs the agent reads
    baseline_monitored: bool = False

    def __post_init__(self):
        if self.identity is None:
            self.identity = self.name


@dataclass
class Estate:
    agents: Dict[str, Agent]
    res: Dict[str, Tuple[str, int, str]]            # resource -> (department, impact tier 1..4, kind data|memory)
    tau: Dict[str, int]                             # department -> highest tolerated open-path tier
    inventory: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if not self.inventory:
            self.inventory = set(self.agents)


# ---------------------------------------------------------------- exposure: attack paths and required controls
def chains(E: Estate, a0: str) -> List[Tuple[str, ...]]:
    bound = E.agents[a0].max_depth + (3 if "ignore_depth" in DEFECTS else 0)
    out = [(a0,)]
    frontier = [(a0,)]
    for _ in range(bound):
        nxt = []
        for ch in frontier:
            for b in sorted(E.agents[ch[-1]].may_delegate_to):
                if b in E.agents and b not in ch:
                    nxt.append(ch + (b,))
        out += nxt
        frontier = nxt
    return out


def paths(E: Estate) -> List[Tuple[str, Tuple[str, ...], str, str]]:
    out = []
    for a0 in sorted(E.agents):
        for i in sorted(E.agents[a0].inputs):
            for ch in chains(E, a0):
                ak = ch[-1]
                for r, mode in sorted(E.agents[ak].resources.items()):
                    if r in E.res:
                        out.append((i, ch, r, mode))
    return out


def required(E: Estate, p) -> Set[Tuple[str, str]]:
    i, ch, r, mode = p
    c = {("iso", ch[0])}
    for a in ch:
        ag = E.agents[a]
        c |= {("least", a), ("ident", a), ("life", a), ("supply", a)}
        if ag.baseline_monitored:
            c.add(("base", a))
        if ag.may_spawn:
            c.add(("spawn", a))
    for a, b in zip(ch, ch[1:]):
        c.add(("deleg", a))
        if E.agents[a].auth_required:
            c.add(("auth", a))
    ak = ch[-1]
    dept, tier, kind = E.res[r]
    if mode == "write" and tier >= 3:
        c.add(("hitl", ak))
    if kind == "memory":
        c.add(("memval", ak))
    if E.agents[ak].runs_code:
        c.add(("sandbox", ak))
    return c


# ---------------------------------------------------------------- statuses, evidence, expiry
class State:
    """Control statuses with the time until which a SAT status is fresh. Unassessed controls are UNV (fail-closed)."""

    def __init__(self):
        self.st: Dict[Tuple[str, str], str] = {}
        self.fresh: Dict[Tuple[str, str], float] = {}

    def copy(self) -> "State":
        s = State()
        s.st, s.fresh = dict(self.st), dict(self.fresh)
        return s

    def status(self, c, now=0) -> str:
        v = self.st.get(c, UNV)
        if v == SAT and "ignore_expiry" not in DEFECTS and now > self.fresh.get(c, float("inf")):
            return UNV
        return v


def worse(a: str, b: str) -> str:
    return a if GOOD[a] <= GOOD[b] else b


def adverse(S: State, c, level: str) -> None:
    S.st[c] = worse(S.st.get(c, UNV), level)


def support(S: State, c, source: str, now: float, ttl: float = float("inf")) -> None:
    """Supportive evidence. A learned detector can never be a source."""
    if source not in SUPPORT_SOURCES and "learned_supportive" not in DEFECTS:
        raise ValueError(f"{source} cannot support a control")
    S.st[c] = SAT
    S.fresh[c] = now + ttl


def learned_evidence(S: State, agent: str, score: float, theta: float) -> None:
    """Advisory evidence from a baseline, TGN or GNN: it can only move the baseline control to UNV."""
    if score >= theta:
        adverse(S, ("base", agent), UNV)
    elif "learned_supportive" in DEFECTS:
        S.st[("base", agent)] = SAT


def probe_result(S: State, c, passed: bool, now: float, ttl: float) -> None:
    if passed:
        support(S, c, "probe_pass", now, ttl)
    elif "probe_fail_ignored" not in DEFECTS:
        adverse(S, c, VIO)                                  # a missed attack shows the control is not effective


# ---------------------------------------------------------------- the gate
def path_verdict(E: Estate, S: State, now: float, p) -> int:
    ctl = required(E, p)
    sts = [S.status(c, now) for c in ctl]
    has_vio = VIO in sts
    has_unv = UNV in sts and "ignore_unv" not in DEFECTS
    tier = E.res[p[2]][1]
    tau = E.tau[E.res[p[2]][0]]
    if has_vio:
        if "vio_tolerated" in DEFECTS and tier <= tau:
            return V_APPROVED
        return V_BLOCKED if tier > tau else V_REVIEW
    if has_unv:
        return V_REVIEW if tier > tau else V_APPROVED
    return V_APPROVED


def gate(E: Estate, S: State, now: float = 0, contract_ok: bool = True) -> int:
    v = min([path_verdict(E, S, now, p) for p in paths(E)] or [V_APPROVED])
    if not contract_ok:
        if "invalid_not_top" in DEFECTS and v < V_REVIEW:
            return v
        return V_INVALID
    return v


def department_risk(E: Estate, S: State, now: float = 0) -> Dict[str, int]:
    """Risk vector: for each department, the highest impact tier among open paths into it (0 if none)."""
    out = {d: 0 for d in E.tau}
    for p in paths(E):
        if any(S.status(c, now) != SAT and S.status(c, now) != NA for c in required(E, p)):
            d, tier, _ = E.res[p[2]]
            out[d] = max(out[d], tier)
    return out


def all_controls(E: Estate) -> List[Tuple[str, str]]:
    cs: Set[Tuple[str, str]] = set()
    for p in paths(E):
        cs |= required(E, p)
    return sorted(cs)


# ---------------------------------------------------------------- the conformity predicate
def conforms(E: Estate, ev: Dict[str, Any], hist: Tuple[Dict[str, Any], ...] = ()) -> Dict[str, Any]:
    """CONFORMS | DIVERGES(classes) | UNVERIFIED(missing) | PENDING(semantic classes) | ADVISORY(baseline)."""
    kind = ev["kind"]
    a = E.agents.get(ev.get("agent"))
    if a is None:
        return dict(outcome="UNVERIFIED", classes=[], missing=["agent"])
    missing = [k for k in REQUIRED.get(kind, []) if k not in ev]
    if kind == "tool_call" and ev.get("tool") in a.tools and a.tools[ev["tool"]] and "params" not in ev:
        missing.append("params")
    if kind == "tool_call" and ev.get("tool") in a.hitl_tools:
        if "confirmed" not in ev:
            missing.append("confirmed")
        elif ev["confirmed"] and ("presented_hash" not in ev or "executed_hash" not in ev):
            missing += [k for k in ("presented_hash", "executed_hash") if k not in ev]
    if missing and "ignore_missing" not in DEFECTS:
        return dict(outcome="UNVERIFIED", classes=[], missing=missing)
    v: List[str] = []
    if kind == "goal_set":
        sem = ev.get("semantic")
        if sem == "out_of_scope":
            v.append("DVG-GOAL-01")
        elif sem == "integrity":
            v.append("DVG-GOAL-02")
    elif kind == "tool_call":
        t = ev["tool"]
        if t not in a.tools:
            v.append("DVG-TOOL-01")
        else:
            for p, val in (ev.get("params") or {}).items():
                if p in a.tools[t]:
                    lo, hi = a.tools[t][p]
                    if "off_by_one_bound" in DEFECTS:
                        bad = val <= lo or val >= hi
                    else:
                        bad = val < lo or val > hi
                    if bad:
                        v.append("DVG-TOOL-02")
                        break
        if ev.get("prev_tool") and (ev["prev_tool"], t) in a.prohibited_chains:
            v.append("DVG-TOOL-03")
        if t in a.write_tools:
            if a.autonomy == "suggest":
                v.append("DVG-AUT-01")
            elif t in a.hitl_tools:
                if not ev.get("confirmed") and "hitl_bypass" not in DEFECTS:
                    v.append("DVG-AUT-02")
                elif ev.get("confirmed") and ev.get("presented_hash") != ev.get("executed_hash"):
                    v.append("DVG-AUT-03")
    elif kind == "exec":
        if (a.sandbox and not ev["sandboxed"]) or (ev.get("host") is not None and ev["host"] not in a.egress):
            v.append("DVG-EXEC-01")
    elif kind == "res_access":
        r, m = ev["resource"], ev["mode"]
        if r not in a.resources or (m == "write" and a.resources[r] != "write"):
            v.append("DVG-RES-01")
    elif kind == "mem_write":
        if (a.validated_memory and not ev["validated"]) or (ev.get("scope") == "long_term" and not a.long_term_memory):
            v.append("DVG-MEM-01")
        if a.provenance_required and not ev["provenance"]:
            v.append("DVG-MEM-02")
    elif kind == "deleg_out":
        if ev["target"] not in a.may_delegate_to or ev.get("depth", 1) > a.max_depth:
            v.append("DVG-DEL-01")
        if ev["mode"] != a.deleg_mode:
            v.append("DVG-DEL-03")
    elif kind == "deleg_in":
        if ev["source"] not in a.accepts_from:
            v.append("DVG-DEL-02")
    elif kind == "msg":
        if a.auth_required and not ev["verified"]:
            v.append("DVG-COMM-01")
    elif kind == "id":
        if ev["claimed"] != a.identity:
            v.append("DVG-ID-01")
    elif kind == "life":
        if ev["now_t"] > a.expires or a.status != "production":
            v.append("DVG-LIFE-01")
    elif kind == "spawn":
        if "drop_class_spawn" not in DEFECTS and (ev["child"] not in a.may_spawn or not ev["inventoried"]):
            v.append("DVG-SPAWN-01")
    elif kind == "component":
        if not ev["signed"] and a.components.get(ev["name"], True):       # signature required unless the AIBOM says otherwise
            v.append("DVG-SUP-01")
        if not ev["in_aibom"]:
            v.append("DVG-SUP-02")
    elif kind == "score":
        if ev.get("score", 0) >= ev.get("theta", 1.0):
            return dict(outcome="ADVISORY", classes=["DVG-BASE-01"], missing=[])
        return dict(outcome="CONFORMS", classes=[], missing=[])
    else:
        raise ValueError(f"unknown event kind {kind!r}")
    if not v:
        return dict(outcome="CONFORMS", classes=[], missing=[])
    sem = [c for c in v if CLASSES[c][1] == "semantic"]
    if sem and "semantic_deterministic" not in DEFECTS:
        return dict(outcome="PENDING", classes=sem, missing=[])
    return dict(outcome="DIVERGES", classes=sorted(v), missing=[])


def apply_event(E: Estate, S: State, ev: Dict[str, Any], hist=()) -> Dict[str, Any]:
    """Turn the outcome for one event into adverse evidence on the controls it concerns."""
    res = conforms(E, ev, hist)
    ag = ev.get("agent")
    if res["outcome"] == "DIVERGES":
        for c in res["classes"]:
            adverse(S, (CLASSES[c][0], ag), SEV_LEVEL[CLASSES[c][2]])
    elif res["outcome"] == "UNVERIFIED":
        adverse(S, (KIND_CONTROL.get(ev["kind"], "least"), ag), UNV)
    elif res["outcome"] == "PENDING":
        adverse(S, ("iso", ag), UNV)                         # stays UNV until a person adjudicates (supportive evidence "human")
    elif res["outcome"] == "ADVISORY":
        adverse(S, ("base", ag), UNV)
    return res


# ---------------------------------------------------------------- the contract: canonical form, hash, signature, validity
def contract_of(E: Estate) -> Dict[str, Any]:
    ag = {}
    for n, a in sorted(E.agents.items()):
        ag[n] = dict(dept=a.dept, autonomy=a.autonomy, expires=a.expires, tools={t: {p: list(b) for p, b in bs.items()} for t, bs in sorted(a.tools.items())},
                     resources=dict(sorted(a.resources.items())), may_delegate_to=sorted(a.may_delegate_to), accepts_from=sorted(a.accepts_from),
                     deleg_mode=a.deleg_mode, max_depth=a.max_depth, hitl_tools=sorted(a.hitl_tools), prohibited_chains=sorted(list(x) for x in a.prohibited_chains),
                     components=dict(sorted(a.components.items())), may_spawn=sorted(a.may_spawn))
    return dict(schema_version="0.1", agents=ag, resources={r: list(v) for r, v in sorted(E.res.items())}, tau=dict(sorted(E.tau.items())))


def canonical(doc: Dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(doc: Dict[str, Any], key: bytes, not_before: int, expires: int) -> Dict[str, Any]:
    h = hashlib.sha256(canonical(doc)).hexdigest()
    sig = hmac.new(key, f"{h}|{not_before}|{expires}".encode(), hashlib.sha256).hexdigest()   # stand-in for an asymmetric signature
    return dict(document=doc, hash=h, signature=sig, not_before=not_before, expires=expires, status="ACTIVE")


def valid(c: Dict[str, Any], key: bytes, now: int) -> bool:
    try:
        doc = c["document"]
        if doc.get("schema_version") is None or "agents" not in doc:
            return False
        if hashlib.sha256(canonical(doc)).hexdigest() != c["hash"]:
            return False
        if "skip_signature" not in DEFECTS:
            exp = hmac.new(key, f"{c['hash']}|{c['not_before']}|{c['expires']}".encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(exp, c["signature"]):
                return False
        return c["status"] == "ACTIVE" and c["not_before"] <= now <= c["expires"]
    except Exception:
        return False


# ---------------------------------------------------------------- narrowing (used by the admission check)
def narrow(E: Estate, op: Tuple[str, ...]) -> Estate:
    """Remove one capability: ('res', agent, resource) or ('del', agent, target)."""
    if "narrowing_noop" in DEFECTS:
        return copy.deepcopy(E)
    E2 = copy.deepcopy(E)
    if op[0] == "res":
        E2.agents[op[1]].resources.pop(op[2], None)
    elif op[0] == "del":
        E2.agents[op[1]].may_delegate_to.discard(op[2])
    return E2
