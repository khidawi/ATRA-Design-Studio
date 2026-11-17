"""
Real traces for the graph model (ASTRA phase 17): train and judge the GNN on a company's own events, against what its own signed contracts permit.

The graph model answers a question the temporal network does not: is this agent doing something that is ALLOWED but unlike what its peers do? Two things in the simulator made that question
answerable, and both have to come from the company here:

    peers         the agents of the same department (the stream carries each agent's department). An agent with no peer in its department is never attacked with a peer-based family, and a
                  department the platform does not know ("(unassigned)") has no peers at all.
    permissions   what each agent's ACTIVE signed contract lets it do (tools, data stores, delegations, MCP servers), read from the platform's own contract view, the one the SDK enforces
                  with (GET /api/runtime/contract/{key}). Every attack injected here uses only targets the contract permits, so the exact reachability check detects none of them by
                  construction, and the evaluation fails if one is not permitted. An agent with no active contract has no defined permissions: its events are left out and it is named.

As for the temporal network (learned/real.py) the result is SEMI-SYNTHETIC: real normal traffic, injected attacks (simulated=false, with a data summary), never a result against real attacks; the
platform recomputes the decision with floors the service cannot lower. A graph model has to clear one more bar than the temporal network: it must catch attacks that neither the baseline nor the
exact reachability check catches. On a small estate (a few agents, one department) that is often not possible, and the refusal says why instead of passing.

Attack families (dev choose settings, test judge; training sees none):
    DEV   rare_resource    reads a permitted data store that none of its peers read
          rare_delegate    delegates to a permitted agent that none of its peers use
    TEST  cross_peer_read  reads a permitted data store that only other departments read
          volume_shift     its own normal actions at five times the rate
          mix_shift        its own normal targets, almost all on one
"""
import hashlib
import json
import math
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from ..real import MAX_EVENTS, MIN_ACTIVE_WINDOWS, MIN_AGENT_TRAIN_EVENTS, MIN_EVENTS, MIN_VICTIMS, DataError
from ..tgn import schema
from . import graph as G
from . import simulate as S

WINDOW = S.WINDOW
DEV_FAMILIES = ("rare_resource", "rare_delegate")
TEST_FAMILIES = ("cross_peer_read", "volume_shift", "mix_shift")
MIN_AGENTS = 2                    # contract-holding agents with events: a graph model compares an agent with others
MAX_SLOTS = 300                   # distinct tools, stores and agents; beyond this the feature layout is too wide for this model
UNASSIGNED = "(unassigned)"
Perm = Set[Tuple[str, str]]


def permitted_of(allowed: Dict[str, Any]) -> Perm:
    """What an active contract lets an agent do, in the event vocabulary (the platform's own contract view: tools, data stores, delegations, MCP servers)."""
    return ({("tool_call", t["name"]) for t in allowed.get("tools") or []} | {("data_access", d) for d in allowed.get("data") or []} | {("delegation", d) for d in allowed.get("delegates_to") or []}
            | {("mcp_connect", m["name"]) for m in allowed.get("mcp_servers") or []})


def _use(train: List[Dict[str, Any]]) -> Dict[str, Set[Tuple[str, str]]]:
    out: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
    for e in train:
        out[e["agent"]].add((e["kind"], e["target"]))
    return out


class Context:
    """What the attacks are made from, learned from the training span only: who uses what, and who the peers are."""

    def __init__(self, train: List[Dict[str, Any]], dept: Dict[str, str], perms: Dict[str, Perm]):
        self.use, self.dept, self.perms = _use(train), dept, perms

    def peers(self, agent: str) -> List[str]:
        d = self.dept.get(agent)
        return [] if not d or d == UNASSIGNED else sorted(a for a in self.perms if a != agent and self.dept.get(a) == d and self.use.get(a))

    def peer_use(self, agent: str) -> Set[Tuple[str, str]]:
        return {p for a in self.peers(agent) for p in self.use[a]}

    def other_dept_use(self, agent: str) -> Set[Tuple[str, str]]:
        return {p for a, u in self.use.items() if a != agent and self.dept.get(a) != self.dept.get(agent) for p in u}


def attack_window(events: List[Dict[str, Any]], agent: str, w: int, family: str, seed: int, ctx: Context) -> List[Dict[str, Any]]:
    """The stream with one agent's events in one window replaced by a permitted-but-unusual pattern. Every event added is permitted by the agent's contract. Raises ValueError when this
    agent cannot host the family (no peers, nothing permitted that its peers never use)."""
    rng = random.Random(f"{seed}/{agent}/{w}/{family}")
    perm = ctx.perms[agent]
    start = w * WINDOW
    mine = [e for e in events if e["agent"] == agent and S.window_of(e["t"]) == w]
    keep = [e for e in events if not (e["agent"] == agent and S.window_of(e["t"]) == w)]
    dept, tier = (mine[-1]["dept"], mine[-1]["tier"]) if mine else (ctx.dept.get(agent, UNASSIGNED), 4)

    def ev(t: float, kind: str, target: str) -> Dict[str, Any]:
        return {"t": t, "agent": agent, "kind": kind, "target": target, "dept": dept, "tier": tier}

    def ts(k: int) -> List[float]:
        return [start + 2 + (WINDOW - 4) * i / max(k, 1) for i in range(k)]

    own = [(e["kind"], e["target"]) for e in mine if (e["kind"], e["target"]) in perm]       # its own normal behaviour, permitted only: an attack never adds a violation
    n = min(max(len(mine), 5), 40)
    peer_use = ctx.peer_use(agent)
    if family in ("rare_resource", "rare_delegate", "cross_peer_read"):
        if not ctx.peers(agent):
            raise ValueError("a peer-based family needs another agent with history in the same department")
        kind = "delegation" if family == "rare_delegate" else "data_access"
        pool = sorted(p for p in perm if p[0] == kind and p not in peer_use and (family != "cross_peer_read" or p in ctx.other_dept_use(agent)))
        if not pool:
            raise ValueError(f"nothing this agent is permitted to do is {'used only by other departments' if family == 'cross_peer_read' else 'unused by its peers'} ({kind})")
        new = [ev(tt, *rng.choice(pool)) for tt in ts(max(n, 6) if kind == "data_access" else max(4, n - 1))]
    elif family == "volume_shift":
        base = own
        if len(base) < 2:
            raise ValueError("the window has too few permitted events of its own to speed up")
        k = 5 * max(len(base), 2)
        new = [ev(start + 1 + (WINDOW - 2) * i / k, *base[i % len(base)]) for i in range(k)]
        new = [e for e in new if e["t"] < start + WINDOW]
    elif family == "mix_shift":
        base = sorted(set(own))
        if not base:
            raise ValueError("the window has no permitted event of its own to concentrate")
        heavy = rng.choice(base)
        new = [ev(tt, *heavy) for tt in ts(max(n + 4, 9))]
    else:
        raise ValueError(f"unknown attack family {family!r}")
    return sorted(keep + new, key=lambda e: (e["t"], e["agent"]))


def layout(events: List[Dict[str, Any]], perms: Dict[str, Perm]) -> G.Layout:
    """The slots: everything seen in training and everything a contract permits, so a permitted target nobody used yet still has its own slot."""
    tools = {e["target"] for e in events if e["kind"] == "tool_call"} | {t for p in perms.values() for k, t in p if k == "tool_call"}
    res = {e["target"] for e in events if e["kind"] == "data_access"} | {t for p in perms.values() for k, t in p if k == "data_access"}
    agents = set(perms) | {e["agent"] for e in events} | {e["target"] for e in events if e["kind"] == "delegation"} | {t for p in perms.values() for k, t in p if k == "delegation"}
    depts = {e["dept"] for e in events}
    lay = G.Layout(sorted(tools), sorted(res), sorted(agents), sorted(depts))
    if lay.slots > MAX_SLOTS:
        raise DataError(f"the estate has {lay.slots - 1} distinct tools, data stores and agents; this model handles at most {MAX_SLOTS - 1}. Evaluate a part of the estate")
    return lay


def make_dataset(raw: List[Dict[str, Any]], permissions: Dict[str, Perm], seed: int = 11, episodes: int = 14, train_frac: float = 0.6, val_frac: float = 0.2) -> Dict[str, Any]:
    """The company's normal traffic split by time and, for each family, a stream with attack episodes in the validation (DEV) or test (TEST) span. `permissions` maps an agent key to what its
    active contract permits; an agent not in it has its events left out. Raises DataError, with the reason, when the history cannot support a held-out evaluation."""
    ev_all = schema.dataset(raw)["events"]
    no_contract = sorted({e["agent"] for e in ev_all} - set(permissions))
    ev = [e for e in ev_all if e["agent"] in permissions]
    if len(ev) < MIN_EVENTS:
        why = f" ({len(no_contract)} agent(s) without an active contract were left out: {', '.join(no_contract)})" if no_contract else ""
        raise DataError(f"only {len(ev)} events of agents with an active contract were found{why}; at least {MIN_EVENTS} are needed, and several days of normal traffic are better")
    if len(ev) > MAX_EVENTS:
        raise DataError(f"{len(ev)} events is more than the {MAX_EVENTS} this service replays; use fewer days")
    agents = sorted({e["agent"] for e in ev})
    if len(agents) < MIN_AGENTS:
        raise DataError(f"only {len(agents)} agent with an active contract produced events: a graph model compares an agent with its peers and needs at least {MIN_AGENTS}")
    lo = math.floor(ev[0]["t"] / WINDOW) * WINDOW
    hi = math.ceil((ev[-1]["t"] + 1e-6) / WINDOW) * WINDOW
    span = hi - lo
    v0 = lo + math.floor(span * train_frac / WINDOW) * WINDOW
    t0 = v0 + math.floor(span * val_frac / WINDOW) * WINDOW
    split = {"train": [e for e in ev if e["t"] < v0], "val": [e for e in ev if v0 <= e["t"] < t0], "test": [e for e in ev if e["t"] >= t0]}
    train_count: Dict[str, int] = defaultdict(int)
    for e in split["train"]:
        train_count[e["agent"]] += 1
    if not any(c >= MIN_AGENT_TRAIN_EVENTS for c in train_count.values()):
        raise DataError(f"no agent has the {MIN_AGENT_TRAIN_EVENTS} events in the training span (the first {int(train_frac * 100)}% of the history) that a model needs to learn what is normal")
    cold = sorted(a for a in agents if train_count[a] < MIN_AGENT_TRAIN_EVENTS)
    dept: Dict[str, str] = {}
    for e in ev:
        dept[e["agent"]] = e["dept"]
    perms = {a: set(permissions[a]) for a in agents}
    ctx = Context(split["train"], dept, perms)

    def active(a_lo: float, a_hi: float) -> Dict[Tuple[str, int], int]:
        c: Dict[Tuple[str, int], int] = defaultdict(int)
        for e in ev:
            if a_lo <= e["t"] < a_hi:
                c[(e["agent"], S.window_of(e["t"]))] += 1
        return c

    act_val, act_test = active(v0, t0), active(t0, hi)
    if len(act_val) < MIN_ACTIVE_WINDOWS or len(act_test) < MIN_ACTIVE_WINDOWS:
        raise DataError(f"the held-out spans have {len(act_val)} (validation) and {len(act_test)} (test) active agent-windows of {int(WINDOW)} s; at least {MIN_ACTIVE_WINDOWS} of each are needed. "
                        f"The history is {span / 3600:.1f} hours; more days of normal traffic are needed")
    lay = layout(split["train"], perms)
    rng = random.Random(f"{seed}/episodes")
    attacks: Dict[str, Dict[str, Any]] = {}
    skipped: Dict[str, str] = {}
    for fam in DEV_FAMILIES + TEST_FAMILIES:
        role, cnt = ("dev", act_val) if fam in DEV_FAMILIES else ("test", act_test)
        cands = sorted(k for k, c in cnt.items() if c >= 3)
        rng.shuffle(cands)
        stream, victims, last = list(ev), [], ""
        for agent, w in cands:
            if len(victims) >= episodes:
                break
            try:
                stream = attack_window(stream, agent, w, fam, seed, ctx)
                victims.append((agent, w))
            except ValueError as exc:
                last = str(exc)
        if len(victims) < MIN_VICTIMS:
            skipped[fam] = f"only {len(victims)} usable episode(s); at least {MIN_VICTIMS} are needed" + (f" ({last})" if last else "")
            continue
        attacks[fam] = {"role": role, "events": stream, "victims": sorted(victims)}
    if not [f for f in DEV_FAMILIES if f in attacks]:
        raise DataError("no development attack family could be built, so the model's settings cannot be chosen apart from the families that judge it. " + "; ".join(f"{f}: {w}" for f, w in skipped.items() if f in DEV_FAMILIES)
                        + ". The development families compare an agent with its peers: at least two agents with history in one department (the stream's department), each with a permitted data store or delegation that its peers never use")
    h = hashlib.sha256(json.dumps([[round(e["t"], 3), e["agent"], e["kind"], e["target"]] for e in ev], separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"schema": schema.SCHEMA_VERSION, "hash": h, "seed": seed, "train": split["train"], "val": split["val"], "test": split["test"], "attacks": attacks, "layout": lay,
            "spans": {"train": [lo, v0], "val": [v0, t0], "test": [t0, hi]}, "simulated": False, "permitted": perms, "cold": cold,
            "dev_families": list(DEV_FAMILIES), "test_families": list(TEST_FAMILIES),
            "data": {"kind": "real normal traffic with injected attacks", "events": len(ev), "days": round(span / 86400, 3), "agents": agents, "agents_without_contract": no_contract, "late_agents": cold,
                     "departments": sorted({dept[a] for a in agents}), "active_windows": {"val": len(act_val), "test": len(act_test)}, "window_seconds": int(WINDOW),
                     "families_measured": sorted(attacks), "families_skipped": skipped}}


def summary(ds: Dict[str, Any]) -> str:
    d = ds["data"]
    lines = [f"real traces: {d['events']} events over {d['days']} days, {len(d['agents'])} agent(s) with an active contract in {len(d['departments'])} department(s) ({', '.join(d['departments'])})"]
    if d["agents_without_contract"]:
        lines.append(f"  left out (no active contract, so no defined permissions): {', '.join(d['agents_without_contract'])}")
    if d["late_agents"]:
        lines.append(f"  little or no training history (judged against peers only): {', '.join(d['late_agents'])}")
    lines.append(f"  held-out active agent-windows: {d['active_windows']['val']} validation, {d['active_windows']['test']} test")
    lines.append(f"  attack families measured: {', '.join(d['families_measured']) or 'none'}")
    for f, why in d["families_skipped"].items():
        lines.append(f"  not measured: {f}: {why}")
    return "\n".join(lines)
