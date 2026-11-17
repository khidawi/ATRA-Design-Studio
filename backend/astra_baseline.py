"""
The statistical behavioural baseline of an agent (ASTRA phase 9): plain Python, no dependency, no database.

An agent's normal behaviour is learned from what it did while its events conformed to its contract: for fixed time windows, how many events of each kind it produced (rates), and which tool
followed which (tool-sequence transition counts). A new window is scored by how far it is from that normal:

    rate score      the largest deviation, in standard deviations, of the count of any kind of event from its calibrated mean (a kind never seen counts as a deviation of its count)
    sequence score  how surprising the window's tool transitions are under the calibrated transition probabilities, in standard deviations of the calibration windows
    score           the larger of the two. It reaches the threshold (default 4.0) when something is far from normal.

What a score may do is decided elsewhere and is deliberately little (statuses.learned_evidence, Lemma 3): at most move the baseline control to UNVERIFIED. This module only measures.

Calibration is a small state machine:

    COLLECTING   not enough conforming events or windows yet (the reason says how many are missing)
    READY        enough to calibrate; no model yet
    CALIBRATED   a model is active and scores windows
    RETIRED      the model was replaced or switched off

The baseline control of a monitored agent starts UNVERIFIED and stays so until a Probe pass or an attestation validates the calibration (a rule of the model, enforced where statuses are built).
"""
import math
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_WINDOW_SECONDS = 3600
DEFAULT_THRESHOLD = 4.0
MIN_EVENTS, MIN_WINDOWS = 200, 24
FLOORS = {"events": 50, "windows": 6, "window_seconds": 60}
ALPHA = 0.5
SIGMA_FLOOR = 0.25
KINDS_IGNORED = ("heartbeat",)
COLLECTING, READY, CALIBRATED, RETIRED = "COLLECTING", "READY", "CALIBRATED", "RETIRED"

Event = Tuple[float, str, str]                 # (time in seconds, kind of event, name)


def feature(kind: str, name: str) -> str:
    """The thing whose rate is counted: a tool call by tool, anything else by kind and name."""
    return f"{kind}:{name}" if name else kind


def bucket(t: float, window: int) -> int:
    return int(t // window)


def _by_window(events: Iterable[Event], window: int) -> Dict[int, List[Event]]:
    out: Dict[int, List[Event]] = defaultdict(list)
    for e in sorted(events, key=lambda x: x[0]):
        if e[1] not in KINDS_IGNORED:
            out[bucket(e[0], window)].append(e)
    return out


def calibration_state(n_events: int, n_windows: int, has_model: bool, retired: bool = False, min_events: int = MIN_EVENTS, min_windows: int = MIN_WINDOWS) -> Dict[str, Any]:
    """Where an agent is in calibration, and what is still missing."""
    if has_model:
        return {"state": CALIBRATED, "missing": []}
    if retired:
        return {"state": RETIRED, "missing": []}
    missing = []
    if n_events < min_events:
        missing.append(f"{min_events - n_events} more conforming events")
    if n_windows < min_windows:
        missing.append(f"{min_windows - n_windows} more windows with activity")
    return {"state": READY if not missing else COLLECTING, "missing": missing}


def _mean_std(xs: List[float]) -> Tuple[float, float]:
    if not xs:
        return 0.0, 0.0
    m = sum(xs) / len(xs)
    return m, math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


def _tools(evs: List[Event]) -> List[str]:
    return [e[2] for e in evs if e[1] == "tool_call" and e[2]]


def _surprise(seq: List[str], trans: Dict[str, int], frm: Dict[str, int], vocab_size: int) -> Optional[Tuple[float, List[str]]]:
    """Mean negative log-probability of the window's tool transitions, and the transitions that were never seen. None when the window has fewer than two tool calls."""
    if len(seq) < 2:
        return None
    total, unseen = 0.0, []
    for a, b in zip(seq, seq[1:]):
        p = (trans.get(f"{a}|{b}", 0) + ALPHA) / (frm.get(a, 0) + ALPHA * (vocab_size + 1))
        total += -math.log(p)
        if trans.get(f"{a}|{b}", 0) == 0:
            unseen.append(f"{a} -> {b}")
    return total / (len(seq) - 1), unseen


def train(events: Iterable[Event], window_seconds: int = DEFAULT_WINDOW_SECONDS, threshold: float = DEFAULT_THRESHOLD) -> Dict[str, Any]:
    """The parameters of the baseline, from the events of the calibration period. Windows without any event inside the period count as zeros: silence is part of normal."""
    ws = _by_window(events, window_seconds)
    if not ws:
        raise ValueError("there are no events to calibrate from")
    first, last = min(ws), max(ws)
    span = range(first, last + 1)
    kinds = sorted({feature(e[1], e[2]) for evs in ws.values() for e in evs})
    stats = {}
    for k in kinds:
        counts = [float(sum(1 for e in ws.get(w, []) if feature(e[1], e[2]) == k)) for w in span]
        m, s = _mean_std(counts)
        stats[k] = [round(m, 6), round(s, 6)]
    trans: Counter = Counter()
    frm: Counter = Counter()
    vocab = set()
    for w in ws.values():
        seq = _tools(w)
        vocab.update(seq)
        for a, b in zip(seq, seq[1:]):
            trans[f"{a}|{b}"] += 1
            frm[a] += 1
    surprises = []
    for w in ws.values():
        r = _surprise(_tools(w), trans, frm, len(vocab))
        if r is not None:
            surprises.append(r[0])
    sm, ss = _mean_std(surprises)
    return {"window_seconds": window_seconds, "threshold": threshold, "alpha": ALPHA, "rates": stats, "vocab": sorted(vocab), "transitions": dict(trans), "from": dict(frm),
            "surprise_mean": round(sm, 6), "surprise_std": round(ss, 6), "windows": len(span), "windows_with_events": len(ws), "events": sum(len(v) for v in ws.values())}


def score_window(params: Dict[str, Any], evs: List[Event]) -> Dict[str, Any]:
    """How far one window is from the calibrated normal. Returns the score and what drove it."""
    counts = Counter(feature(e[1], e[2]) for e in evs if e[1] not in KINDS_IGNORED)
    rate_z, worst_k, worst = 0.0, None, 0.0
    for k in set(counts) | set(params["rates"]):
        m, s = params["rates"].get(k, [0.0, 0.0])
        eff = max(s, math.sqrt(m), 1.0)                                  # a floor, so a very steady agent does not turn one extra call into a huge deviation
        z = abs(counts.get(k, 0) - m) / eff
        if z > worst:
            worst, worst_k = z, k
    rate_z = worst
    seq_z, unseen = 0.0, []
    r = _surprise(_tools(evs), params["transitions"], params["from"], len(params["vocab"]))
    if r is not None:
        seq_z = max(0.0, (r[0] - params["surprise_mean"]) / max(params["surprise_std"], SIGMA_FLOOR))
        unseen = r[1]
    score = max(rate_z, seq_z)
    why = []
    if rate_z >= seq_z and worst_k is not None and rate_z > 0:
        m = params["rates"].get(worst_k, [0.0, 0.0])[0]
        why.append(f"{worst_k}: {counts.get(worst_k, 0)} in the window, normally about {m:.1f}")
    if seq_z > 0 and seq_z >= rate_z:
        why.append("tool order unlike normal" + (f" (never seen: {', '.join(unseen[:3])})" if unseen else ""))
    return {"score": round(score, 4), "rate_z": round(rate_z, 4), "sequence_z": round(seq_z, 4), "events": len(evs), "why": why, "unseen_transitions": unseen[:5]}


def score_windows(params: Dict[str, Any], events: Iterable[Event], after_window: Optional[int] = None, before_window: Optional[int] = None) -> List[Tuple[int, Dict[str, Any]]]:
    """Score every window that has events, from the window after `after_window` up to (not including) `before_window`: the windows that are complete."""
    out = []
    for w, evs in sorted(_by_window(events, params["window_seconds"]).items()):
        if (after_window is not None and w <= after_window) or (before_window is not None and w >= before_window):
            continue
        out.append((w, score_window(params, evs)))
    return out
