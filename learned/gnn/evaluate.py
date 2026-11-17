"""
Scoring and the go or no-go evaluation of the graph model (ASTRA phase 11, step 11c).

The graph model has to clear the same bar as the temporal network, and one more, because the platform already has an exact check that costs nothing: the reachability check (what the contract
lets an agent do) and a per-agent baseline. So there are two questions, both measured on attack families that were not used to choose settings, at the same false-positive budget:

    1. does it detect clearly more than the baseline, with false positives inside twice the budget?
    2. does it catch things that the reachability check and the baseline both miss? It must do so, for at least a quarter of the attacks, on at least two held-out families.

Every attack in the simulator is something the contract permits (checked: the evaluation fails if one is not), so the reachability check detects none of them by construction and the second
question is about what the model adds over the baseline. Agents that joined late have no history, so the baseline cannot judge them; the model can compare them with their peers. If the model does
not clear both, it is not adopted, and the reason is recorded. Everything is measured on simulated traffic.
"""
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import astra_baseline as BL

from ..tgn.evaluate import threshold_for
from . import graph as G
from . import model as M
from . import simulate as S

BUDGET = 0.05
MARGIN = 0.05
NOVEL_MIN = 0.25
MIN_TEST_FAMILIES = 2
MIN_WINDOWS_PER_AGENT = 6
Key = Tuple[str, int]


def raw_scores(model: M.SAGE, lay: G.Layout, events: List[Dict[str, Any]], lo: float, hi: float) -> Dict[Key, float]:
    out: Dict[Key, float] = {}
    for w, evs in G.by_window(events, S.WINDOW, lo, hi).items():
        for a, err in M.agent_errors(model, G.build(evs, lay)).items():
            out[(a, w)] = err
    return out


def norms(raw: Dict[Key, float], lo_w: int, hi_w: int) -> Dict[str, List[float]]:
    by: Dict[str, List[float]] = defaultdict(list)
    for (a, w), v in raw.items():
        if lo_w <= w < hi_w:
            by[a].append(v)
    return {a: M.robust_norm(v) for a, v in by.items() if len(v) >= MIN_WINDOWS_PER_AGENT}


def z(raw: Dict[Key, float], nm: Dict[str, List[float]]) -> Dict[Key, float]:
    return {k: (v - nm[k[0]][0]) / nm[k[0]][1] for k, v in raw.items() if k[0] in nm}


def baseline_models(train: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    by: Dict[str, List[Tuple[float, str, str]]] = defaultdict(list)
    for e in train:
        by[e["agent"]].append((e["t"], e["kind"], e["target"]))
    return {a: BL.train(ev, int(S.WINDOW), BL.DEFAULT_THRESHOLD) for a, ev in by.items() if len(ev) >= 20}


def baseline_scores(models: Dict[str, Dict[str, Any]], events: List[Dict[str, Any]], lo: float, hi: float) -> Dict[Key, float]:
    out: Dict[Key, float] = {}
    for w, evs in G.by_window(events, S.WINDOW, lo, hi).items():
        by: Dict[str, List[Tuple[float, str, str]]] = defaultdict(list)
        for e in evs:
            by[e["agent"]].append((e["t"], e["kind"], e["target"]))
        for a, ev in by.items():
            if a in models:
                out[(a, w)] = BL.score_window(models[a], ev)["score"]
    return out


def reach_flags(events: List[Dict[str, Any]], lo: float, hi: float) -> Dict[Key, bool]:
    out: Dict[Key, bool] = {}
    for w, evs in G.by_window(events, S.WINDOW, lo, hi).items():
        for a in {e["agent"] for e in evs}:
            out[(a, w)] = bool(S.violates([e for e in evs if e["agent"] == a]))
    return out


def evaluate(ds: Dict[str, Any], model: M.SAGE, lay: G.Layout, budget: float = BUDGET, margin: float = MARGIN) -> Dict[str, Any]:
    v0, v1 = ds["spans"]["val"]
    t0, t1 = ds["spans"]["test"]
    normal = sorted(ds["train"] + ds["val"] + ds["test"], key=lambda e: (e["t"], e["agent"]))
    raw_n = raw_scores(model, lay, normal, v0, t1)
    nm = norms(raw_n, int(v0 // S.WINDOW), int(v1 // S.WINDOW))
    zn = z(raw_n, nm)
    in_val = lambda k: v0 <= k[1] * S.WINDOW < v1        # noqa: E731
    in_test = lambda k: t0 <= k[1] * S.WINDOW < t1       # noqa: E731
    thr = threshold_for([v for k, v in zn.items() if in_val(k)], budget)
    test_z = [v for k, v in zn.items() if in_test(k)]
    bm = baseline_models(ds["train"])
    bn = baseline_scores(bm, normal, v0, t1)
    bthr = threshold_for([v for k, v in bn.items() if in_val(k)], budget)
    btest = [v for k, v in bn.items() if in_test(k)]
    rn = reach_flags(normal, t0, t1)
    out: Dict[str, Any] = {"simulated": True, "dataset_hash": ds["hash"], "seed": ds["seed"], "budget_fpr": budget, "margin": margin, "novel_min": NOVEL_MIN, "spans_seconds": ds["spans"],
                           "windows": {"val": sum(1 for k in zn if in_val(k)), "test_normal": len(test_z)},
                           "gnn": {"threshold": round(thr, 4), "fpr_test": round(sum(1 for x in test_z if x >= thr) / len(test_z), 4), "tpr": {}, "novel": {}, "tpr_late": {}},
                           "baseline": {"threshold": round(bthr, 4), "fpr_test": round(sum(1 for x in btest if x >= bthr) / max(len(btest), 1), 4), "tpr": {}, "tpr_late": {}, "agents_modelled": sorted(bm)},
                           "reachability": {"fpr_test": round(sum(1 for v in rn.values() if v) / max(len(rn), 1), 4), "tpr": {}},
                           "families": {"dev": list(S.DEV_FAMILIES), "test": list(S.TEST_FAMILIES)}, "normalisation": nm, "attack_events_not_permitted": 0}
    for fam, info in ds["attacks"].items():
        lo, hi = (v0, v1) if info["role"] == "dev" else (t0, t1)
        victims = [tuple(v) for v in info["victims"]]
        out["attack_events_not_permitted"] += sum(len(S.violates([e for e in info["events"] if (e["agent"], S.window_of(e["t"])) == v])) for v in victims)
        gz = z(raw_scores(model, lay, info["events"], lo, hi), nm)
        bs = baseline_scores(bm, info["events"], lo, hi)
        rf = reach_flags(info["events"], lo, hi)
        g_hit = {v: v in gz and gz[v] >= thr for v in victims}
        b_hit = {v: v in bs and bs[v] >= bthr for v in victims}
        r_hit = {v: bool(rf.get(v)) for v in victims}
        n = len(victims) or 1
        late = [v for v in victims if v[0] in S.COLD]
        out["gnn"]["tpr"][fam] = round(sum(g_hit.values()) / n, 4)
        out["baseline"]["tpr"][fam] = round(sum(b_hit.values()) / n, 4)
        out["reachability"]["tpr"][fam] = round(sum(r_hit.values()) / n, 4)
        out["gnn"]["novel"][fam] = round(sum(1 for v in victims if g_hit[v] and not b_hit[v] and not r_hit[v]) / n, 4)
        out["gnn"]["tpr_late"][fam] = round(sum(g_hit[v] for v in late) / len(late), 4) if late else None
        out["baseline"]["tpr_late"][fam] = round(sum(b_hit[v] for v in late) / len(late), 4) if late else None
    for det in ("gnn", "baseline"):
        for role, fams in (("dev", S.DEV_FAMILIES), ("test", S.TEST_FAMILIES)):
            xs = [out[det]["tpr"][f] for f in fams]
            out[det][f"macro_{role}"] = round(sum(xs) / len(xs), 4)
    out["decision"] = decide(out)
    return out


def decide(m: Dict[str, Any]) -> Dict[str, Any]:
    """The adoption rule for the graph model. The platform applies the same rule to what the service reports."""
    reasons: List[str] = []
    if set(m["families"]["dev"]) & set(m["families"]["test"]):
        reasons.append("the families used to choose settings and the families used to judge overlap")
    if m.get("attack_events_not_permitted"):
        reasons.append(f"{m['attack_events_not_permitted']} attack events were not permitted by the estate: those are the reachability check's job, not this model's")
    fams = list(m["families"]["test"])
    if len([f for f in fams if m["gnn"]["tpr"].get(f) is not None]) < MIN_TEST_FAMILIES:
        reasons.append(f"fewer than {MIN_TEST_FAMILIES} held-out attack families were measured")
    t, b = m["gnn"].get("macro_test"), m["baseline"].get("macro_test")
    if t is None or b is None or t - b < m["margin"]:
        reasons.append(f"on held-out families the model detects {t} and the baseline {b}: the model is not clearly better (it must beat the baseline by {m['margin']})")
    if m["gnn"]["fpr_test"] > 2 * m["budget_fpr"]:
        reasons.append(f"the false-positive rate on held-out normal traffic is {m['gnn']['fpr_test']}, above twice the budget of {m['budget_fpr']}")
    novel = [f for f in fams if (m["gnn"]["novel"].get(f) or 0) >= m["novel_min"]]
    if len(novel) < MIN_TEST_FAMILIES:
        reasons.append(f"it catches at least {m['novel_min']:.0%} of the attacks that neither the reachability check nor the baseline catch on only {len(novel)} held-out families (needs {MIN_TEST_FAMILIES}): "
                       "it does not add enough to what the platform already has")
    return {"passed": not reasons, "reasons": reasons}
