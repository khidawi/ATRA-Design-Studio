"""
Scoring windows and the evaluation gate (ASTRA phase 10, steps 10b and 10c).

A window score is the mean surprise of an agent's events in one window, normalised against that agent's own validation windows (how many standard deviations above its normal). The threshold is
not chosen to look good: it is the value that a stated false-positive budget allows on validation traffic that was normal.

The gate compares the network with the statistical baseline of phase 9 (astra_baseline) on attack families that were never used to train or to choose settings, at the same false-positive
budget, and writes down the outcome either way. Both outcomes are valid: it passes only if the network detects clearly more than the baseline on the held-out families, with a false-positive
rate that stays within twice the budget on held-out normal traffic, on at least two held-out families. Otherwise it stays off.

Everything here is measured on simulated traffic (simulate.py). That is simulator evidence, and the result says so.
"""
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import astra_baseline as BL

from . import model as M
from . import simulate as S

BUDGET = 0.05
MARGIN = 0.05
MIN_TEST_FAMILIES = 2
Key = Tuple[str, int]


def _windows(events: List[Dict[str, Any]], lo: float, hi: float) -> Dict[Key, List[int]]:
    out: Dict[Key, List[int]] = defaultdict(list)
    for i, e in enumerate(events):
        if lo <= e["t"] < hi:
            out[(e["agent"], S.window_of(e["t"]))].append(i)
    return out


def tgn_window_means(model: M.TGN, vocab: M.Vocab, events: List[Dict[str, Any]], lo: float, hi: float) -> Dict[Key, float]:
    """Mean surprise per (agent, window) of the windows in [lo, hi), the whole stream replayed so the memory knows what came before."""
    sp = M.surprises(model, vocab, events)
    return {k: sum(sp[i] for i in idx) / len(idx) for k, idx in _windows(events, lo, hi).items()}


def normalisation(means: Dict[Key, float]) -> Dict[str, List[float]]:
    by: Dict[str, List[float]] = defaultdict(list)
    for (a, _), v in means.items():
        by[a].append(v)
    out = {}
    for a, xs in by.items():
        m = sum(xs) / len(xs)
        sd = math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))
        out[a] = [round(m, 6), round(max(sd, 0.05), 6)]
    return out


def z(means: Dict[Key, float], norm: Dict[str, List[float]]) -> Dict[Key, float]:
    return {k: (v - norm[k[0]][0]) / norm[k[0]][1] for k, v in means.items() if k[0] in norm}


def quantile(xs: List[float], q: float) -> float:
    s = sorted(xs)
    if not s:
        raise ValueError("no validation windows to set a threshold from")
    return s[min(len(s) - 1, int(math.ceil(q * len(s))) - 1)]


def threshold_for(scores: List[float], budget: float) -> float:
    """The smallest value that at most `budget` of the normal validation windows reach: the false-positive budget, spent on data that was normal."""
    s = sorted(scores)
    k = int(math.floor(budget * len(s)))
    return s[len(s) - k - 1] + 1e-9 if len(s) > k else s[-1] + 1e-9


def baseline_models(train: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    by: Dict[str, List[Tuple[float, str, str]]] = defaultdict(list)
    for e in train:
        by[e["agent"]].append((e["t"], e["kind"], e["target"]))
    return {a: BL.train(ev, int(S.WINDOW), BL.DEFAULT_THRESHOLD) for a, ev in by.items()}


def baseline_scores(models: Dict[str, Dict[str, Any]], events: List[Dict[str, Any]], lo: float, hi: float) -> Dict[Key, float]:
    by: Dict[Key, List[Tuple[float, str, str]]] = defaultdict(list)
    for e in events:
        if lo <= e["t"] < hi and e["agent"] in models:
            by[(e["agent"], S.window_of(e["t"]))].append((e["t"], e["kind"], e["target"]))
    return {k: BL.score_window(models[k[0]], ev)["score"] for k, ev in by.items()}


def _rate(scores: Dict[Key, float], victims: List[Key], thr: float) -> Optional[float]:
    seen = [scores[v] for v in victims if v in scores]
    return None if not seen else sum(1 for x in seen if x >= thr) / len(seen)


def evaluate(ds: Dict[str, Any], model: M.TGN, vocab: M.Vocab, budget: float = BUDGET, margin: float = MARGIN) -> Dict[str, Any]:
    """Everything the gate needs, for the network and for the baseline, on the same windows."""
    v0, v1 = ds["spans"]["val"]
    t0, t1 = ds["spans"]["test"]
    normal = sorted(ds["train"] + ds["val"] + ds["test"], key=lambda e: (e["t"], e["agent"]))
    means_n = tgn_window_means(model, vocab, normal, v0, t1)
    norm = normalisation({k: v for k, v in means_n.items() if v0 <= k[1] * S.WINDOW < v1})
    zn = z(means_n, norm)
    val_z = [v for k, v in zn.items() if v0 <= k[1] * S.WINDOW < v1]
    thr = threshold_for(val_z, budget)
    test_z = [v for k, v in zn.items() if t0 <= k[1] * S.WINDOW < t1]
    bm = baseline_models(ds["train"])
    bn = baseline_scores(bm, normal, v0, t1)
    bval = [v for k, v in bn.items() if v0 <= k[1] * S.WINDOW < v1]
    bthr = threshold_for(bval, budget)
    btest = [v for k, v in bn.items() if t0 <= k[1] * S.WINDOW < t1]
    out: Dict[str, Any] = {"simulated": ds.get("simulated", True), "dataset_hash": ds["hash"], "seed": ds["seed"], "budget_fpr": budget, "margin": margin, "spans_seconds": ds["spans"],
                           "windows": {"val": len(val_z), "test_normal": len(test_z)},
                           "tgn": {"threshold": round(thr, 4), "fpr_test": round(sum(1 for x in test_z if x >= thr) / len(test_z), 4), "tpr": {}},
                           "baseline": {"threshold": round(bthr, 4), "fpr_test": round(sum(1 for x in btest if x >= bthr) / len(btest), 4), "tpr": {}},
                           "families": {"dev": list(S.DEV_FAMILIES), "test": list(S.TEST_FAMILIES)}, "normalisation": norm}
    if ds.get("data"):
        out["data"] = ds["data"]                                  # real traces: what the evaluation was made from (learned/real.py)
    for fam, info in ds["attacks"].items():
        lo, hi = (v0, v1) if info["role"] == "dev" else (t0, t1)
        tz = z(tgn_window_means(model, vocab, info["events"], lo, hi), norm)
        bs = baseline_scores(bm, info["events"], lo, hi)
        victims = [tuple(v) for v in info["victims"]]
        out["tgn"]["tpr"][fam] = _rate(tz, victims, thr)
        out["baseline"]["tpr"][fam] = _rate(bs, victims, bthr)
    for det in ("tgn", "baseline"):
        for role, fams in (("dev", S.DEV_FAMILIES), ("test", S.TEST_FAMILIES)):
            xs = [out[det]["tpr"][f] for f in fams if out[det]["tpr"].get(f) is not None]
            out[det][f"macro_{role}"] = round(sum(xs) / len(xs), 4) if xs else None
    out["decision"] = decide(out)
    return out


def decide(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """The adoption rule, from the numbers alone. The backend applies the same rule to what a service reports, so a service cannot pass itself."""
    reasons: List[str] = []
    fams = [f for f in metrics["families"]["test"] if metrics["tgn"]["tpr"].get(f) is not None and metrics["baseline"]["tpr"].get(f) is not None]
    if set(metrics["families"]["dev"]) & set(metrics["families"]["test"]):
        reasons.append("the families used to choose settings and the families used to judge overlap")
    if len(fams) < MIN_TEST_FAMILIES:
        reasons.append(f"fewer than {MIN_TEST_FAMILIES} held-out attack families were measured")
    t, b = metrics["tgn"].get("macro_test"), metrics["baseline"].get("macro_test")
    if t is None or b is None or t - b < metrics["margin"]:
        reasons.append(f"on held-out families the network detects {t} and the baseline {b}: the network is not clearly better (it must beat the baseline by {metrics['margin']})")
    if metrics["tgn"]["fpr_test"] > 2 * metrics["budget_fpr"]:
        reasons.append(f"the false-positive rate on held-out normal traffic is {metrics['tgn']['fpr_test']}, above twice the budget of {metrics['budget_fpr']}")
    return {"passed": not reasons, "reasons": reasons}
