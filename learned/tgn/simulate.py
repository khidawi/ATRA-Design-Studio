"""
A normal-traffic simulator and labelled attack traces (ASTRA phase 10, step 10a).

There are no real traces yet, so the data is simulated, and what is learned from simulated data is simulator evidence: the evaluation says so wherever it is shown.

The simulator and the detector must not share generation rules, so this module does not know how the model represents anything. It is a small process model of an estate:

    * four agents in three departments, each running workflows (a fixed sequence of steps with branches and probabilities) and, in one case, a periodic batch;
    * the gap between steps is log-normal, the gap between workflow runs exponential;
    * a delegation makes the next agent run a step of its own a moment later.

Attack traces are made by perturbing that traffic, in families. A family is a way of misbehaving, and the evaluation splits by family: the families used to choose settings (DEV) are never the ones used
to judge the detector (TEST), and nothing about an attack is ever used in training, which sees normal traffic only.

    DEV   order_swap      the same steps in a reversed order
          burst_repeat    one action repeated many times within seconds
          novel_target    a tool the agent has never used
    TEST  metronome       the normal actions at an exactly regular, machine-like pace
          lateral_chain   a delegation to an agent it never delegates to, then that agent's resource
          slow_drip       the normal order, spread very thin over the window
          kind_switch     a kind of action the agent never performs (memory writes)
"""
import math
import random
from typing import Any, Dict, List, Tuple

from . import schema

WINDOW = 60.0
DEV_FAMILIES = ("order_swap", "burst_repeat", "novel_target")
TEST_FAMILIES = ("metronome", "lateral_chain", "slow_drip", "kind_switch")

# agent -> department, impact tier, workflows: (probability, [(kind, target)...])
ESTATE: Dict[str, Dict[str, Any]] = {
    "support": {"dept": "Customer", "tier": 2, "flows": [
        (0.5, [("tool_call", "search"), ("data_access", "crm"), ("tool_call", "notify")]),
        (0.3, [("tool_call", "search"), ("data_access", "crm"), ("tool_call", "refund"), ("tool_call", "notify")]),
        (0.2, [("tool_call", "search"), ("data_access", "crm"), ("delegation", "payments")])], "think": 4.0, "rest": 14.0},
    "payments": {"dept": "Finance", "tier": 4, "flows": [
        (0.6, [("tool_call", "pay"), ("data_access", "ledger")]),
        (0.4, [("data_access", "ledger"), ("tool_call", "pay"), ("tool_call", "receipt")])], "think": 3.0, "rest": 18.0},
    "hr": {"dept": "HR", "tier": 3, "flows": [
        (0.7, [("tool_call", "hris"), ("data_access", "hr_db")]),
        (0.3, [("tool_call", "hris"), ("tool_call", "hris"), ("data_access", "hr_db"), ("tool_call", "notify")])], "think": 5.0, "rest": 20.0},
    "reporting": {"dept": "Finance", "tier": 3, "flows": [
        (1.0, [("data_access", "ledger"), ("tool_call", "aggregate"), ("tool_call", "export")])], "think": 2.0, "rest": 25.0},
}


def _gap(rng: random.Random, mean: float) -> float:
    return rng.lognormvariate(math.log(mean), 0.4)


def normal_traffic(seed: int, minutes: float, t0: float = 0.0) -> List[Dict[str, Any]]:
    """Time-ordered normal events of every agent over `minutes` minutes."""
    out: List[Dict[str, Any]] = []
    for name, a in sorted(ESTATE.items()):
        rng = random.Random(f"{seed}/{name}")
        t = t0 + rng.uniform(0, a["rest"])
        end = t0 + minutes * 60
        while t < end:
            flow = rng.choices([f for _, f in a["flows"]], weights=[p for p, _ in a["flows"]])[0]
            for kind, target in flow:
                if t >= end:
                    break
                out.append({"t": t, "agent": name, "kind": kind, "target": target, "dept": a["dept"], "tier": a["tier"]})
                t += _gap(rng, a["think"])
            t += rng.expovariate(1.0 / a["rest"])
    return sorted(out, key=lambda e: (e["t"], e["agent"]))


def window_of(t: float) -> int:
    return int(t // WINDOW)


def windows_of(events: List[Dict[str, Any]], agent: str, w: int) -> List[Dict[str, Any]]:
    return [e for e in events if e["agent"] == agent and window_of(e["t"]) == w]


def attack_window(events: List[Dict[str, Any]], agent: str, w: int, family: str, seed: int) -> List[Dict[str, Any]]:
    """The stream with the agent's events in one window replaced by an attack of the given family. Other agents and other windows are untouched."""
    rng = random.Random(f"{seed}/{agent}/{w}/{family}")
    a = ESTATE[agent]
    start = w * WINDOW
    mine = windows_of(events, agent, w)
    keep = [e for e in events if not (e["agent"] == agent and window_of(e["t"]) == w)]

    def ev(t: float, kind: str, target: str) -> Dict[str, Any]:
        return {"t": t, "agent": agent, "kind": kind, "target": target, "dept": a["dept"], "tier": a["tier"]}

    own = sorted({(e["kind"], e["target"]) for f in a["flows"] for e in [dict(kind=k, target=t) for k, t in f[1]]})
    n = max(len(mine), 6)
    new: List[Dict[str, Any]] = []
    if family == "order_swap":
        seq = [(e["kind"], e["target"]) for e in mine][::-1] or own[::-1]
        ts = sorted(e["t"] for e in mine) or [start + 5 * i for i in range(len(seq))]
        new = [ev(t, k, x) for t, (k, x) in zip(ts, seq)]
    elif family == "burst_repeat":
        k, x = rng.choice(own)
        new = [ev(start + 2 + 0.25 * i, k, x) for i in range(60)]
    elif family == "novel_target":
        new = [ev(e["t"], e["kind"], e["target"]) for e in mine] + [ev(start + 10 + 3 * i, "tool_call", rng.choice(["shell.exec", "external_api", "pastebin"])) for i in range(8)]
    elif family == "metronome":
        seq = [rng.choice(own) for _ in range(n)]
        new = [ev(start + 2 + 2.0 * i, k, x) for i, (k, x) in enumerate(seq)]
    elif family == "lateral_chain":
        other = rng.choice([o for o in ESTATE if o != agent and o not in {t for k, t in own if k == "delegation"}])
        new = [ev(start + 5, "delegation", other), ev(start + 7, "data_access", {"hr": "hr_db", "payments": "ledger", "reporting": "ledger", "support": "crm"}[other]),
               ev(start + 9, "data_access", {"hr": "hr_db", "payments": "ledger", "reporting": "ledger", "support": "crm"}[other]), ev(start + 12, "tool_call", "export")]
    elif family == "slow_drip":
        seq = [(e["kind"], e["target"]) for e in mine][:3] or own[:3]
        new = [ev(start + 8 + 18 * i, k, x) for i, (k, x) in enumerate(seq)]
    elif family == "kind_switch":
        new = [ev(start + 3 + 5 * i, "memory_write", rng.choice(["notes", "profile"])) for i in range(n)]
    else:
        raise ValueError(f"unknown attack family {family!r}")
    return sorted(keep + new, key=lambda e: (e["t"], e["agent"]))


def make_dataset(seed: int = 7, train_minutes: float = 90, val_minutes: float = 30, test_minutes: float = 30, episodes: int = 14) -> Dict[str, Any]:
    """Normal traffic split by time into train, validation and test, and for each family a copy of the stream with attack episodes in the validation (DEV families) or the test (TEST families)
    span. Returns the splits, the labelled attack streams and the dataset hash. Families never cross: a DEV family is never injected into the test span and a TEST family never into validation."""
    total = train_minutes + val_minutes + test_minutes
    normal = normal_traffic(seed, total)
    v0, t0 = train_minutes * 60, (train_minutes + val_minutes) * 60
    split = {"train": [e for e in normal if e["t"] < v0], "val": [e for e in normal if v0 <= e["t"] < t0], "test": [e for e in normal if e["t"] >= t0]}
    rng = random.Random(f"{seed}/episodes")
    attacks: Dict[str, Dict[str, Any]] = {}
    for fam in DEV_FAMILIES + TEST_FAMILIES:
        lo, hi, role = (window_of(v0), window_of(t0), "dev") if fam in DEV_FAMILIES else (window_of(t0), window_of(total * 60), "test")
        stream = list(normal)
        victims: List[Tuple[str, int]] = []
        cands = [(a, w) for a in sorted(ESTATE) for w in range(lo, hi) if windows_of(stream, a, w)]
        for a, w in rng.sample(cands, min(episodes, len(cands))):
            stream = attack_window(stream, a, w, fam, seed)
            victims.append((a, w))
        attacks[fam] = {"role": role, "events": stream, "victims": sorted(victims)}
    ds = schema.dataset(normal)
    return {"schema": ds["schema"], "hash": ds["hash"], "seed": seed, "train": split["train"], "val": split["val"], "test": split["test"], "attacks": attacks,
            "spans": {"train": [0, v0], "val": [v0, t0], "test": [t0, total * 60]}, "simulated": True}
