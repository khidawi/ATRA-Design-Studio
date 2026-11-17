"""
A simulated estate with peers, and attacks that are permitted but unusual (ASTRA phase 11, step 11a/11b data).

The exact reachability check of the platform already answers "can this agent reach that resource, through any chain of delegations?". Whatever the contract does not allow is caught there. What it
cannot see is a flow that is allowed but unlike what the agent's peers do. So every attack in this module uses only targets the estate permits; the evaluation checks that, and measures what
the reachability check, the per-agent baseline and the graph model each catch.

The estate is a set of roles with several agents each, so there are peers to compare with:

    support-1..3      support agents (search, notify, refund; the CRM and tickets; they may also delegate to payments)
    payments-1,2      payments agents (pay, receipt; the ledger and invoices)
    hr-1              one HR agent
    reporting-1,2     reporting agents (aggregate, export; the ledger and invoices)
    support-4, payments-3     two agents that join late: no history at all before validation. A per-agent baseline has nothing to calibrate from; a peer comparison does.

The permissions are deliberately wider than the normal use (a support agent may read invoices and a payments agent may read the CRM), as in a real estate that grew organically.

Attack families (DEV choose settings, TEST judge, as for the temporal network; training sees none):
    DEV   rare_resource     reads a permitted resource that none of its peers ever reads
          rare_delegate     delegates to a permitted agent that its peers never use
    TEST  cross_peer_read   a reporting or payments agent reads the CRM (permitted, never done by peers)
          volume_shift      its own normal actions at five times the rate
          mix_shift         its normal targets, but in a proportion no peer shows (almost all on one)
          hub_access        an HR agent reads tickets (permitted, never done by anyone in HR)
"""
import math
import random
from typing import Any, Dict, List, Set, Tuple

WINDOW = 120.0
DEV_FAMILIES = ("rare_resource", "rare_delegate")
TEST_FAMILIES = ("cross_peer_read", "volume_shift", "mix_shift", "hub_access")

ROLES: Dict[str, Dict[str, Any]] = {
    "support": {"dept": "Customer", "tier": 2, "tools": {"search", "notify", "refund"}, "res": {"crm", "tickets", "invoices"}, "delegates": {"payments-1", "payments-2"},
                "flows": [(0.5, [("tool_call", "search"), ("data_access", "crm"), ("tool_call", "notify")]), (0.3, [("tool_call", "search"), ("data_access", "tickets"), ("tool_call", "notify")]),
                          (0.2, [("tool_call", "search"), ("data_access", "crm"), ("tool_call", "refund"), ("delegation", "payments-1")])], "think": 4.0, "rest": 18.0},
    "payments": {"dept": "Finance", "tier": 4, "tools": {"pay", "receipt", "notify"}, "res": {"ledger", "invoices", "crm"}, "delegates": set(),
                 "flows": [(0.6, [("tool_call", "pay"), ("data_access", "ledger")]), (0.4, [("data_access", "invoices"), ("tool_call", "pay"), ("tool_call", "receipt")])], "think": 3.0, "rest": 22.0},
    "hr": {"dept": "HR", "tier": 3, "tools": {"hris", "notify"}, "res": {"hr_db", "tickets"}, "delegates": set(),
           "flows": [(0.7, [("tool_call", "hris"), ("data_access", "hr_db")]), (0.3, [("tool_call", "hris"), ("data_access", "hr_db"), ("tool_call", "notify")])], "think": 5.0, "rest": 24.0},
    "reporting": {"dept": "Finance", "tier": 3, "tools": {"aggregate", "export", "notify"}, "res": {"ledger", "invoices", "crm"}, "delegates": set(),
                  "flows": [(0.6, [("data_access", "ledger"), ("tool_call", "aggregate"), ("tool_call", "export")]), (0.4, [("data_access", "invoices"), ("tool_call", "aggregate")])],
                  "think": 2.5, "rest": 28.0},
}
AGENTS: Dict[str, str] = {"support-1": "support", "support-2": "support", "support-3": "support", "support-4": "support", "payments-1": "payments", "payments-2": "payments", "payments-3": "payments",
                          "hr-1": "hr", "reporting-1": "reporting", "reporting-2": "reporting"}
COLD = ("support-4", "payments-3")                                  # agents with no events before validation


def info(agent: str) -> Dict[str, Any]:
    return ROLES[AGENTS[agent]]


def allowed(agent: str) -> Set[Tuple[str, str]]:
    """The exact reachability check, as the platform has it: what the contract lets this agent do. Anything else is a violation."""
    r = info(agent)
    return {("tool_call", t) for t in r["tools"]} | {("data_access", x) for x in r["res"]} | {("delegation", d) for d in r["delegates"]}


def violates(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e for e in events if (e["kind"], e["target"]) not in allowed(e["agent"])]


def _gap(rng: random.Random, mean: float) -> float:
    return rng.lognormvariate(math.log(mean), 0.4)


def normal_traffic(seed: int, minutes: float, cold_from: float) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    end = minutes * 60
    for name in sorted(AGENTS):
        r = info(name)
        rng = random.Random(f"{seed}/{name}")
        t = (cold_from if name in COLD else 0.0) + rng.uniform(0, r["rest"])
        while t < end:
            flow = rng.choices([f for _, f in r["flows"]], weights=[p for p, _ in r["flows"]])[0]
            for kind, target in flow:
                if t >= end:
                    break
                out.append({"t": t, "agent": name, "kind": kind, "target": target, "dept": r["dept"], "tier": r["tier"]})
                t += _gap(rng, r["think"])
            t += rng.expovariate(1.0 / r["rest"])
    return sorted(out, key=lambda e: (e["t"], e["agent"]))


def window_of(t: float) -> int:
    return int(t // WINDOW)


def attack_window(events: List[Dict[str, Any]], agent: str, w: int, family: str, seed: int) -> List[Dict[str, Any]]:
    """The stream with one agent's events in one window replaced by a permitted-but-unusual pattern. Every event it adds is allowed by the estate."""
    rng = random.Random(f"{seed}/{agent}/{w}/{family}")
    r = info(agent)
    start = w * WINDOW
    mine = [e for e in events if e["agent"] == agent and window_of(e["t"]) == w]
    keep = [e for e in events if not (e["agent"] == agent and window_of(e["t"]) == w)]
    role_peers = [a for a, role in AGENTS.items() if role == AGENTS[agent] and a != agent]
    peer_use = {(e["kind"], e["target"]) for e in events if e["agent"] in role_peers}

    def ev(t: float, kind: str, target: str) -> Dict[str, Any]:
        return {"t": t, "agent": agent, "kind": kind, "target": target, "dept": r["dept"], "tier": r["tier"]}

    def ts(k: int) -> List[float]:
        """k times spread evenly inside the window, so an attack never spills into the next one."""
        return [start + 2 + (WINDOW - 4) * i / max(k, 1) for i in range(k)]

    permitted = sorted(allowed(agent))
    unusual = [p for p in permitted if p not in peer_use and p[0] != "tool_call"] or [p for p in permitted if p not in peer_use] or permitted
    n = max(len(mine), 5)
    if family == "rare_resource":
        res = [p for p in unusual if p[0] == "data_access"] or unusual
        new = [ev(tt, *rng.choice(res)) for tt in ts(max(n, 6))]
    elif family == "rare_delegate":
        dels = sorted(d for d in permitted if d[0] == "delegation") or [p for p in permitted if p[0] == "data_access"]
        pick = [d for d in dels if d not in peer_use] or dels
        new = [ev(tt, *rng.choice(pick)) for tt in ts(max(4, n - 1))]
    elif family == "cross_peer_read":
        pick = [("data_access", "crm")] if ("data_access", "crm") in set(permitted) else unusual
        new = [ev(tt, *pick[0]) for tt in ts(max(n, 6))]
    elif family == "volume_shift":
        base = [(e["kind"], e["target"]) for e in mine] or [p for p in permitted if p in peer_use] or permitted
        new = [ev(start + 1 + (WINDOW - 2) * i / (5 * max(len(base), 2)), *base[i % len(base)]) for i in range(5 * max(len(base), 2))]
        new = [e for e in new if e["t"] < start + WINDOW]
    elif family == "mix_shift":
        base = sorted({(e["kind"], e["target"]) for e in mine}) or [p for p in permitted if p in peer_use] or permitted
        heavy = rng.choice(base)
        new = [ev(tt, *heavy) for tt in ts(max(n + 4, 9))]
    elif family == "hub_access":
        pick = [("data_access", "tickets")] if ("data_access", "tickets") in set(permitted) and ("data_access", "tickets") not in peer_use else unusual
        new = [ev(tt, *pick[0]) for tt in ts(max(n, 5))]
    else:
        raise ValueError(f"unknown attack family {family!r}")
    return sorted(keep + new, key=lambda e: (e["t"], e["agent"]))


def make_dataset(seed: int = 11, train_minutes: float = 120, val_minutes: float = 40, test_minutes: float = 40, episodes: int = 16) -> Dict[str, Any]:
    """Normal traffic split by time; the late agents start at the beginning of validation. Attack episodes go into validation (DEV families) or test (TEST families), never both."""
    total = train_minutes + val_minutes + test_minutes
    v0, t0 = train_minutes * 60, (train_minutes + val_minutes) * 60
    normal = normal_traffic(seed, total, cold_from=v0)
    split = {"train": [e for e in normal if e["t"] < v0], "val": [e for e in normal if v0 <= e["t"] < t0], "test": [e for e in normal if e["t"] >= t0]}
    rng = random.Random(f"{seed}/episodes")
    attacks: Dict[str, Dict[str, Any]] = {}
    for fam in DEV_FAMILIES + TEST_FAMILIES:
        lo, hi, role = (window_of(v0), window_of(t0), "dev") if fam in DEV_FAMILIES else (window_of(t0), window_of(total * 60), "test")
        stream = list(normal)
        cands = sorted({(e["agent"], window_of(e["t"])) for e in stream if lo <= window_of(e["t"]) < hi})
        if fam == "hub_access":
            cands = [c for c in cands if AGENTS[c[0]] == "hr"]
        if fam == "cross_peer_read":
            cands = [c for c in cands if AGENTS[c[0]] in ("reporting", "payments")]
        victims = sorted(rng.sample(cands, min(episodes, len(cands))))
        for a, w in victims:
            stream = attack_window(stream, a, w, fam, seed)
        attacks[fam] = {"role": role, "events": stream, "victims": victims}
    import hashlib
    import json
    h = hashlib.sha256(json.dumps([[round(e["t"], 6), e["agent"], e["kind"], e["target"]] for e in normal], separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"schema": "tgn-events-v1", "hash": h, "seed": seed, "train": split["train"], "val": split["val"], "test": split["test"], "attacks": attacks,
            "spans": {"train": [0, v0], "val": [v0, t0], "test": [t0, total * 60]}, "simulated": True}
