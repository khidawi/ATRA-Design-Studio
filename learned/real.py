"""
Real traces (ASTRA phase 16): train and judge the temporal graph network on a company's own events, not on the simulator's.

Until now the only data was simulated, so a model the service trained had the simulator's agents in its vocabulary and could not score anybody else's. This module builds the same kind of
dataset from the events the platform streams (learned/stream): a company's real normal traffic, split by time into train, validation and test, and, for each attack family, a copy of the stream with
attack episodes injected into the held-out windows of that real traffic. Nothing about an attack is ever used in training, which sees normal traffic only; the families that choose the settings (DEV)
are never the ones that judge the model (TEST); and the platform recomputes the adoption decision from the numbers, with the same floors, whatever this service claims.

What the result is, and is not. It is a SEMI-SYNTHETIC evaluation: the normal behaviour is the company's own, the attacks are injected by this module from that company's own agents, tools and
targets. It says how well the network separates that company's normal from a stated set of misbehaviours, against the statistical baseline, at a stated false-positive budget. It is not a
measurement against real attacks, because there are none in the data. The evaluation records that (simulated = false, with the data summary) and does not call itself a field result.

A company with too little history is refused with the reason, not given a verdict: the baseline needs about 50 events to calibrate, a network needs far more, and a few days of traffic from a
single agent cannot support a held-out test. The refusal names what is missing.
"""
import hashlib
import json
import math
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .tgn import schema
from .tgn import simulate as S

WINDOW = S.WINDOW
MIN_EVENTS = 300                 # in the whole stream
MIN_AGENT_TRAIN_EVENTS = 40      # an agent with less history in the training span is not scored or attacked
MIN_ACTIVE_WINDOWS = 10          # active (agent, window) pairs needed in each of validation and test
MIN_VICTIMS = 3                  # a family with fewer episodes than this is not measured
MAX_EVENTS = 250_000             # the replay is plain Python; beyond this, use fewer days
NOVEL_TOOLS = ("shell.exec", "external_api", "pastebin")


class DataError(ValueError):
    """There is not enough, or not the right, data to judge a model. The message says what is missing."""


def profiles(train: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """What each agent normally does, from the training span only: the basis the attacks are made from."""
    by: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in train:
        by[e["agent"]].append(e)
    out: Dict[str, Dict[str, Any]] = {}
    for a, ev in by.items():
        if len(ev) < MIN_AGENT_TRAIN_EVENTS:
            continue
        own = sorted({(e["kind"], e["target"]) for e in ev})
        out[a] = {"dept": ev[-1]["dept"], "tier": ev[-1]["tier"], "own": own, "dels": sorted({t for k, t in own if k == "delegation"}),
                  "res": sorted({t for k, t in own if k == "data_access"}), "tools": sorted({t for k, t in own if k == "tool_call"})}
    return out


def attack_window(events: List[Dict[str, Any]], agent: str, w: int, family: str, seed: int, prof: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The stream with one agent's events in one window replaced by an attack of the family, built from that agent's own normal and the other agents' real targets. Other agents and other windows
    are untouched. Raises ValueError when the estate cannot host the family (for example a lateral chain needs a second agent)."""
    rng = random.Random(f"{seed}/{agent}/{w}/{family}")
    a = prof[agent]
    start = w * WINDOW
    mine = [e for e in events if e["agent"] == agent and S.window_of(e["t"]) == w]
    keep = [e for e in events if not (e["agent"] == agent and S.window_of(e["t"]) == w)]

    def ev(t: float, kind: str, target: str) -> Dict[str, Any]:
        return {"t": t, "agent": agent, "kind": kind, "target": target, "dept": a["dept"], "tier": a["tier"]}

    own = a["own"]
    n = min(max(len(mine), 6), 25)                       # an attack never spills into the next window
    if family == "order_swap":
        seq = [(e["kind"], e["target"]) for e in mine][::-1] or own[::-1]
        ts = sorted(e["t"] for e in mine) or [start + 5 * i for i in range(len(seq))]
        new = [ev(t, k, x) for t, (k, x) in zip(ts, seq)]
    elif family == "burst_repeat":
        k, x = rng.choice(own)
        new = [ev(start + 2 + 0.25 * i, k, x) for i in range(60)]
    elif family == "novel_target":
        fresh = [t for t in NOVEL_TOOLS if ("tool_call", t) not in set(own)] or list(NOVEL_TOOLS)
        new = [ev(e["t"], e["kind"], e["target"]) for e in mine] + [ev(start + 10 + 3 * i, "tool_call", rng.choice(fresh)) for i in range(8)]
    elif family == "metronome":
        seq = [rng.choice(own) for _ in range(n)]
        new = [ev(start + 2 + 2.0 * i, k, x) for i, (k, x) in enumerate(seq)]
    elif family == "lateral_chain":
        others = [o for o in sorted(prof) if o != agent and o not in set(a["dels"])]
        if not others:
            raise ValueError("a lateral chain needs a second agent that this one never delegates to")
        other = rng.choice(others)
        res = prof[other]["res"] or [t for _, t in prof[other]["own"]]
        tool = (a["tools"] or ["export"])[-1]
        new = [ev(start + 5, "delegation", other), ev(start + 7, "data_access", res[0]), ev(start + 9, "data_access", res[0]), ev(start + 12, "tool_call", tool)]
    elif family == "slow_drip":
        seq = [(e["kind"], e["target"]) for e in mine][:3] or own[:3]
        new = [ev(start + 8 + 18 * i, k, x) for i, (k, x) in enumerate(seq)]
    elif family == "kind_switch":
        new = [ev(start + 3 + 5 * i, "memory_write", rng.choice(["notes", "profile"])) for i in range(min(n, 10))]
    else:
        raise ValueError(f"unknown attack family {family!r}")
    return sorted(keep + new, key=lambda e: (e["t"], e["agent"]))


def make_dataset(raw: List[Dict[str, Any]], seed: int = 7, episodes: int = 14, train_frac: float = 0.6, val_frac: float = 0.2) -> Dict[str, Any]:
    """The company's normal traffic split by time, and for each family a stream with attack episodes in the validation (DEV families) or test (TEST families) span. Raises DataError, with
    the reason, when the history cannot support a held-out evaluation."""
    ev = schema.dataset(raw)["events"]
    if len(ev) < MIN_EVENTS:
        raise DataError(f"only {len(ev)} events were found; at least {MIN_EVENTS} are needed, and several days of normal traffic are better")
    if len(ev) > MAX_EVENTS:
        raise DataError(f"{len(ev)} events is more than the {MAX_EVENTS} this service replays; use fewer days")
    lo = math.floor(ev[0]["t"] / WINDOW) * WINDOW
    hi = math.ceil((ev[-1]["t"] + 1e-6) / WINDOW) * WINDOW
    span = hi - lo
    v0 = lo + math.floor(span * train_frac / WINDOW) * WINDOW
    t0 = v0 + math.floor(span * val_frac / WINDOW) * WINDOW
    split = {"train": [e for e in ev if e["t"] < v0], "val": [e for e in ev if v0 <= e["t"] < t0], "test": [e for e in ev if e["t"] >= t0]}
    prof = profiles(split["train"])
    if not prof:
        raise DataError(f"no agent has the {MIN_AGENT_TRAIN_EVENTS} events in the training span (the first {int(train_frac * 100)}% of the history) that a model needs to learn what is normal for it")
    dropped = sorted({e["agent"] for e in ev} - set(prof))

    def active(events: List[Dict[str, Any]], a_lo: float, a_hi: float) -> Dict[Tuple[str, int], int]:
        c: Dict[Tuple[str, int], int] = defaultdict(int)
        for e in events:
            if a_lo <= e["t"] < a_hi and e["agent"] in prof:
                c[(e["agent"], S.window_of(e["t"]))] += 1
        return c

    act_val, act_test = active(ev, v0, t0), active(ev, t0, hi)
    if len(act_val) < MIN_ACTIVE_WINDOWS or len(act_test) < MIN_ACTIVE_WINDOWS:
        raise DataError(f"the held-out spans have {len(act_val)} (validation) and {len(act_test)} (test) active agent-minutes; at least {MIN_ACTIVE_WINDOWS} of each are needed. "
                        f"The history is {span / 3600:.1f} hours; more days of normal traffic are needed")
    rng = random.Random(f"{seed}/episodes")
    attacks: Dict[str, Dict[str, Any]] = {}
    skipped: Dict[str, str] = {}
    for fam in S.DEV_FAMILIES + S.TEST_FAMILIES:
        role, cnt = ("dev", act_val) if fam in S.DEV_FAMILIES else ("test", act_test)
        cands = sorted(k for k, c in cnt.items() if c >= 3)
        picked = rng.sample(cands, min(episodes, len(cands)))
        stream, victims = list(ev), []
        for agent, w in picked:
            try:
                stream = attack_window(stream, agent, w, fam, seed, prof)
                victims.append((agent, w))
            except ValueError as exc:
                skipped[fam] = str(exc)
                break
        if len(victims) < MIN_VICTIMS:
            skipped.setdefault(fam, f"only {len(victims)} usable episode(s); at least {MIN_VICTIMS} are needed")
            continue
        attacks[fam] = {"role": role, "events": stream, "victims": sorted(victims)}
    h = hashlib.sha256(json.dumps([[round(e["t"], 3), e["agent"], e["kind"], e["target"]] for e in ev], separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"schema": schema.SCHEMA_VERSION, "hash": h, "seed": seed, "train": split["train"], "val": split["val"], "test": split["test"], "attacks": attacks,
            "spans": {"train": [lo, v0], "val": [v0, t0], "test": [t0, hi]}, "simulated": False,
            "data": {"kind": "real normal traffic with injected attacks", "events": len(ev), "days": round(span / 86400, 3), "agents": sorted(prof), "agents_without_history": dropped,
                     "active_windows": {"val": len(act_val), "test": len(act_test)}, "families_measured": sorted(attacks), "families_skipped": skipped}}


def summary(ds: Dict[str, Any]) -> str:
    d = ds["data"]
    lines = [f"real traces: {d['events']} events over {d['days']} days, {len(d['agents'])} agent(s) with enough history ({', '.join(d['agents'])})"]
    if d["agents_without_history"]:
        lines.append(f"  not enough history to score: {', '.join(d['agents_without_history'])}")
    lines.append(f"  held-out active agent-minutes: {d['active_windows']['val']} validation, {d['active_windows']['test']} test")
    lines.append(f"  attack families measured: {', '.join(d['families_measured']) or 'none'}")
    for f, why in d["families_skipped"].items():
        lines.append(f"  not measured: {f}: {why}")
    return "\n".join(lines)
