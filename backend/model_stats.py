"""
Distribution statistics for watching an AI model in production. Pure functions: no database, no network.

What production monitoring needs is how the model's inputs and outputs *behave*, not the inputs and outputs themselves. So this module never
keeps a record. Each record is folded into running aggregates: a histogram per numeric input, category counts per categorical one, the length
distribution of a text input (never the text), the output the same way, a histogram of the model's confidence, latency buckets, an error count, how
often the model was right once the true answer is known, and the rate of a good outcome per group. A window of aggregates (an hour) is a few kilobytes
whatever the traffic, and it holds nothing that could identify a person.

The first records are the **baseline**: what normal looks like. Everything after is compared with it:
  * Population Stability Index (PSI) per input and for the output: below 0.1 stable, 0.1 to 0.25 a shift worth watching, above 0.25 drift.
  * Out-of-domain inputs: a value outside the minimum or maximum the owner declared for a feature is a domain violation.
  * Performance once labels arrive: accuracy (classification) or RMSE (regression) against the baseline.
  * Fairness: the rate of the favourable outcome by group; the lowest group's rate over the highest, flagged below 0.9 and breached below 0.8
    (the four-fifths rule of thumb).
  * Errors, latency and named flags the serving code sets (a refusal, a blocked output) against the baseline.
The result is a status (OK, WATCH, DRIFT) with the reasons in words, and the signals the ST-AI score understands: drift detected and of which kind, bias
breach, domain violation.

The thresholds are common rules of thumb, not calibrated to any one model; they can be changed per monitor.
"""
import bisect
import math
import random
from typing import Any, Dict, List, Optional, Tuple

EPS = 1e-4
from llm_safety import SAFETY_FLAGS  # noqa: E402
LATENCY_EDGES = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000]               # milliseconds; one more bucket above the last edge
TEXT_EDGES = [0, 10, 50, 200, 1000, 5000]                                    # characters
CONF_BINS = 10
RESERVOIR = 1000
MAX_CATEGORIES = 50
MAX_FEATURES = 60
KINDS = ("numeric", "categorical", "boolean", "text")
DEFAULT_THRESHOLDS = {
    "psi_watch": 0.10, "psi_drift": 0.25, "min_n": 100, "min_labels": 30, "min_group": 30,
    "perf_drop_watch": 0.05, "perf_drop_drift": 0.10, "rmse_ratio_watch": 1.25, "rmse_ratio_drift": 1.5,
    "parity_watch": 0.90, "parity_breach": 0.80, "error_watch": 0.02, "error_drift": 0.05,
    "flag_watch": 0.05, "flag_drift": 0.10, "latency_ratio_watch": 2.0, "latency_ratio_drift": 4.0,
    "violation_min": 5, "eval_hours": 24,
}


# ── Population Stability Index ──────────────────────────────────────────────

def _norm(counts: List[float]) -> List[float]:
    total = float(sum(counts))
    return [c / total for c in counts] if total > 0 else [0.0 for _ in counts]


def psi(expected: List[float], actual: List[float]) -> float:
    """PSI between two distributions given as proportions (or counts) over the same bins. 0 means identical."""
    e, a = _norm(expected), _norm(actual)
    out = 0.0
    for pe, pa in zip(e, a):
        pe, pa = max(pe, EPS), max(pa, EPS)
        out += (pa - pe) * math.log(pa / pe)
    return round(out, 5)


def level_of(value: float, watch: float, drift: float) -> Optional[str]:
    return "drift" if value >= drift else ("watch" if value >= watch else None)


# ── Folding one record into aggregates ──────────────────────────────────────

def new_feature(kind: str) -> Dict[str, Any]:
    if kind == "numeric":
        return {"n": 0, "missing": 0, "sum": 0.0, "sumsq": 0.0, "min": None, "max": None, "viol": 0, "hist": None, "sample": [], "seen": 0}
    if kind == "text":
        return {"n": 0, "missing": 0, "empty": 0, "len": [0] * (len(TEXT_EDGES) + 1), "sum": 0.0}
    return {"n": 0, "missing": 0, "cat": {}, "other": 0, "viol": 0}


def new_acc(schema: Dict[str, Any], baseline: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """An empty set of aggregates for one window. With a baseline the numeric histograms use the baseline's bin edges; without one (the learning
    phase) numeric values go into a bounded random sample instead, from which the edges are later chosen."""
    acc: Dict[str, Any] = {"n": 0, "errors": 0, "features": {}, "confidence": {"hist": [0] * CONF_BINS, "n": 0, "sum": 0.0},
                           "latency": {"b": [0] * (len(LATENCY_EDGES) + 1), "n": 0, "sum": 0.0}, "labelled": {"n": 0, "correct": 0, "sq": 0.0, "abs": 0.0},
                           "segments": {}, "flags": {}}
    for f in schema["features"]:
        acc["features"][f["name"]] = new_feature(f["kind"])
    out = schema["output"]
    acc["output"] = new_feature(out["kind"])
    acc["output"]["pos"] = 0
    if baseline:
        for name, f in acc["features"].items():
            b = baseline["features"].get(name)
            if b and b.get("edges") is not None:
                f["hist"] = [0] * (len(b["edges"]) + 1)
        b = baseline.get("output") or {}
        if b.get("edges") is not None:
            acc["output"]["hist"] = [0] * (len(b["edges"]) + 1)
    return acc


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or v is None:
        return None
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) else None


def _fold(f: Dict[str, Any], kind: str, v: Any, spec: Dict[str, Any], edges: Optional[List[float]], rng: random.Random) -> None:
    f["n"] += 1
    if v is None or v == "":
        f["missing"] += 1
        return
    if kind == "numeric":
        x = _num(v)
        if x is None:
            f["missing"] += 1
            return
        f["sum"] += x
        f["sumsq"] += x * x
        f["min"] = x if f["min"] is None else min(f["min"], x)
        f["max"] = x if f["max"] is None else max(f["max"], x)
        if (spec.get("min") is not None and x < spec["min"]) or (spec.get("max") is not None and x > spec["max"]):
            f["viol"] += 1
        if edges is not None and f["hist"] is not None:
            f["hist"][bisect.bisect_left(edges, x)] += 1
        else:                                                              # learning: a uniform random sample of everything seen
            f["seen"] += 1
            if len(f["sample"]) < RESERVOIR:
                f["sample"].append(x)
            else:
                j = rng.randrange(f["seen"])
                if j < RESERVOIR:
                    f["sample"][j] = x
    elif kind == "text":
        n = len(str(v))
        f["len"][bisect.bisect_left(TEXT_EDGES, n)] += 1
        f["sum"] += n
        if n == 0:
            f["empty"] += 1
    else:
        key = str(v).lower() if kind == "boolean" or isinstance(v, bool) else str(v)[:80]
        if kind == "boolean" or isinstance(v, bool):
            key = "true" if v in (True, 1, "1", "true", "True", "yes") else "false"
        allowed = spec.get("allowed")
        if allowed and key not in [str(a) for a in allowed]:
            f["viol"] += 1
        if key in f["cat"] or len(f["cat"]) < MAX_CATEGORIES:
            f["cat"][key] = f["cat"].get(key, 0) + 1
        else:
            f["other"] += 1


def fold_record(acc: Dict[str, Any], schema: Dict[str, Any], baseline: Optional[Dict[str, Any]], rec: Dict[str, Any], rng: random.Random) -> None:
    """Adds one record to a window's aggregates. Nothing of the record is kept except what these counters hold."""
    acc["n"] += 1
    inputs = rec.get("inputs") or {}
    for spec in schema["features"]:
        b = (baseline or {}).get("features", {}).get(spec["name"]) or {}
        _fold(acc["features"][spec["name"]], spec["kind"], inputs.get(spec["name"]), spec, b.get("edges"), rng)
    out_spec = schema["output"]
    out = rec.get("output")
    out_acc = acc["output"]
    _fold(out_acc, out_spec["kind"], out, out_spec, ((baseline or {}).get("output") or {}).get("edges"), rng)
    positive = _is_positive(out_spec, out)
    if positive:
        out_acc["pos"] += 1
    conf = _num(rec.get("confidence"))
    if conf is not None:
        c = acc["confidence"]
        c["hist"][min(CONF_BINS - 1, max(0, int(conf * CONF_BINS)))] += 1
        c["n"] += 1
        c["sum"] += conf
    lat = _num(rec.get("latency_ms"))
    if lat is not None and lat >= 0:
        l = acc["latency"]
        l["b"][bisect.bisect_left(LATENCY_EDGES, lat)] += 1
        l["n"] += 1
        l["sum"] += lat
    if rec.get("error"):
        acc["errors"] += 1
    label = rec.get("label")
    if label is not None and label != "":
        lab = acc["labelled"]
        if out_spec["kind"] == "numeric":
            y, p = _num(label), _num(out)
            if y is not None and p is not None:
                lab["n"] += 1
                lab["sq"] += (y - p) ** 2
                lab["abs"] += abs(y - p)
        else:
            lab["n"] += 1
            lab["correct"] += 1 if str(label) == str(out) else 0
    for attr in schema.get("segments") or []:
        v = (rec.get("segments") or {}).get(attr)
        if v is None or v == "":
            continue
        groups = acc["segments"].setdefault(attr, {})
        key = str(v)[:60]
        if key not in groups and len(groups) >= MAX_CATEGORIES:
            continue
        g = groups.setdefault(key, {"n": 0, "pos": 0})
        g["n"] += 1
        g["pos"] += 1 if positive else 0
    for name in schema.get("flags") or []:
        if (rec.get("flags") or {}).get(name):
            acc["flags"][name] = acc["flags"].get(name, 0) + 1


def _is_positive(out_spec: Dict[str, Any], out: Any) -> bool:
    pos = out_spec.get("positive")
    if pos is None or out is None:
        return False
    if out_spec["kind"] == "numeric":
        x = _num(out)
        return x is not None and x >= float(pos)
    return str(out).lower() == str(pos).lower()


# ── Merging windows ─────────────────────────────────────────────────────────

def merge(a: Any, b: Any) -> Any:
    """The sum of two aggregates of the same shape (counters add, histograms add bin by bin, min and max combine)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            if k not in out:
                out[k] = v
            elif k == "min" and out[k] is not None and v is not None:
                out[k] = min(out[k], v)
            elif k == "max" and out[k] is not None and v is not None:
                out[k] = max(out[k], v)
            elif k in ("min", "max"):
                out[k] = out[k] if v is None else v
            elif k == "sample":
                out[k] = (out[k] + v)[:RESERVOIR]
            else:
                out[k] = merge(out[k], v)
        return out
    if isinstance(a, list) and isinstance(b, list) and a and isinstance(a[0], (int, float)):
        return [x + y for x, y in zip(a, b)]
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a + b
    return a if b is None else b


# ── The baseline ────────────────────────────────────────────────────────────

def _quantile_edges(values: List[float], bins: int = 10) -> List[float]:
    v = sorted(values)
    if not v:
        return []
    edges: List[float] = []
    for i in range(1, bins):
        q = v[min(len(v) - 1, int(i * len(v) / bins))]
        if not edges or q > edges[-1]:
            edges.append(q)
    return edges or [v[0]]


def _props_numeric(values: List[float], edges: List[float]) -> List[float]:
    counts = [0] * (len(edges) + 1)
    for x in values:
        counts[bisect.bisect_left(edges, x)] += 1
    return _norm(counts)


def _profile(kind: str, f: Dict[str, Any]) -> Dict[str, Any]:
    n = max(1, f["n"])
    base: Dict[str, Any] = {"kind": kind, "missing_rate": round(f["missing"] / n, 5)}
    if kind == "numeric":
        vals = f["sample"]
        edges = _quantile_edges(vals)
        k = len(vals)
        mean = (f["sum"] / max(1, f["n"] - f["missing"]))
        var = max(0.0, f["sumsq"] / max(1, f["n"] - f["missing"]) - mean * mean)
        base.update({"edges": edges, "props": _props_numeric(vals, edges) if k else [], "min": f["min"], "max": f["max"], "mean": round(mean, 6), "sd": round(math.sqrt(var), 6)})
    elif kind == "text":
        base.update({"props": _norm(f["len"]), "mean_len": round(f["sum"] / max(1, f["n"] - f["missing"]), 2)})
    else:
        total = sum(f["cat"].values()) + f["other"]
        base["props"] = {k: round(v / total, 6) for k, v in sorted(f["cat"].items(), key=lambda kv: -kv[1])} if total else {}
        if total and f["other"]:
            base["props"]["__other__"] = round(f["other"] / total, 6)
        base["high_cardinality"] = bool(total and f["other"] / total > 0.25)       # an identifier, not a category: its values are not compared
    return base


def percentile(buckets: List[int], q: float, edges: List[float] = LATENCY_EDGES) -> Optional[float]:
    total = sum(buckets)
    if total == 0:
        return None
    target, run = q * total, 0
    for i, c in enumerate(buckets):
        run += c
        if run >= target:
            return float(edges[i]) if i < len(edges) else float(edges[-1]) * 2
    return None


def _perf(acc: Dict[str, Any], kind: str) -> Dict[str, Any]:
    lab = acc["labelled"]
    if not lab["n"]:
        return {}
    if kind == "numeric":
        return {"n": lab["n"], "rmse": round(math.sqrt(lab["sq"] / lab["n"]), 6), "mae": round(lab["abs"] / lab["n"], 6)}
    return {"n": lab["n"], "accuracy": round(lab["correct"] / lab["n"], 5)}


def build_baseline(schema: Dict[str, Any], buf: Dict[str, Any]) -> Dict[str, Any]:
    """From what the learning phase accumulated: the bin edges and the proportions that everything later is compared with."""
    n = max(1, buf["n"])
    base: Dict[str, Any] = {"n": buf["n"], "features": {f["name"]: _profile(f["kind"], buf["features"][f["name"]]) for f in schema["features"]}}
    base["output"] = _profile(schema["output"]["kind"], buf["output"])
    base["output"]["positive_rate"] = round(buf["output"]["pos"] / n, 5)
    c = buf["confidence"]
    base["confidence"] = {"props": _norm(c["hist"]), "mean": round(c["sum"] / c["n"], 5) if c["n"] else None, "n": c["n"]}
    lat = buf["latency"]
    base["latency"] = {"p50": percentile(lat["b"], 0.5), "p95": percentile(lat["b"], 0.95), "n": lat["n"]}
    base["error_rate"] = round(buf["errors"] / n, 5)
    base["performance"] = _perf(buf, schema["output"]["kind"])
    base["flags"] = {k: round(v / n, 5) for k, v in buf["flags"].items()}
    base["segments"] = {a: {g: {"n": s["n"], "rate": round(s["pos"] / s["n"], 5)} for g, s in groups.items() if s["n"]} for a, groups in buf["segments"].items()}
    return base


def check_profile(schema: Dict[str, Any], profile: Dict[str, Any]) -> Optional[str]:
    """A baseline supplied by the owner (statistics of the training data) must have the shape the monitor expects."""
    try:
        for f in schema["features"]:
            p = profile["features"][f["name"]]
            if f["kind"] == "numeric":
                edges, props = p["edges"], p["props"]
                if not edges or len(props) != len(edges) + 1 or any(b <= a for a, b in zip(edges, edges[1:])) or abs(sum(props) - 1) > 0.02:
                    return f"{f['name']}: edges must increase and props must have one more entry than edges and sum to 1"
            elif f["kind"] == "text":
                if len(p["props"]) != len(TEXT_EDGES) + 1:
                    return f"{f['name']}: props must have {len(TEXT_EDGES) + 1} entries"
            else:
                if not isinstance(p["props"], dict) or (not p["props"] and not p.get("high_cardinality")) or (p["props"] and abs(sum(p["props"].values()) - 1) > 0.02):
                    return f"{f['name']}: props must map each category to its share, summing to 1"
        o = profile["output"]
        if schema["output"]["kind"] == "numeric":
            if not o["edges"] or len(o["props"]) != len(o["edges"]) + 1:
                return "output: edges and props do not match"
        elif not isinstance(o["props"], dict) or not o["props"]:
            return "output: props must map each value to its share"
    except (KeyError, TypeError):
        return "The profile is missing a feature or the output."
    return None


# ── Judging a window against the baseline ───────────────────────────────────

def _compare(kind: str, base: Dict[str, Any], cur: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    """PSI between a baseline profile and current aggregates, plus the two distributions for display."""
    if kind == "numeric":
        counts = cur.get("hist") or []
        labels = _bin_labels(base["edges"])
        return psi(base["props"], counts), {"labels": labels, "base": [round(x, 4) for x in base["props"]], "now": [round(x, 4) for x in _norm(counts)]}
    if kind == "text":
        return psi(base["props"], cur["len"]), {"labels": ["0", "1-10", "11-50", "51-200", "201-1000", "1001-5000", "5000+"], "base": [round(x, 4) for x in base["props"]], "now": [round(x, 4) for x in _norm(cur["len"])]}
    cats = list(base["props"].keys())
    now = dict(cur["cat"])
    new = sum(v for k, v in now.items() if k not in base["props"]) + cur.get("other", 0)
    exp = [base["props"][k] for k in cats] + [0.0]
    act = [now.get(k, 0) for k in cats] + [new]
    if "__other__" in base["props"]:                       # the baseline already had a tail of rare values: anything unseen belongs to it
        i = cats.index("__other__")
        act[i] += act[-1]
        act[-1] = 0
    show = list(range(min(len(cats), 8)))
    return psi(exp, act), {"labels": [cats[i] for i in show] + (["(new or other)"]), "base": [round(exp[i], 4) for i in show] + [0.0], "now": [round(x, 4) for x in _norm(act)][:len(show)] + [round(_norm(act)[-1], 4)]}


def _bin_labels(edges: List[float]) -> List[str]:
    f = lambda x: f"{x:.3g}"
    return [f"≤{f(edges[0])}"] + [f"{f(a)}–{f(b)}" for a, b in zip(edges, edges[1:])] + [f">{f(edges[-1])}"]


def evaluate(schema: Dict[str, Any], baseline: Dict[str, Any], acc: Dict[str, Any], thr: Dict[str, Any]) -> Dict[str, Any]:
    """Compares a window of aggregates with the baseline. Returns the metrics, the reasons and the status."""
    t = {**DEFAULT_THRESHOLDS, **(thr or {})}
    n = acc["n"]
    reasons: List[Dict[str, Any]] = []
    res: Dict[str, Any] = {"n": n, "features": [], "reasons": reasons}

    def reason(level: Optional[str], kind: str, subject: str, value: float, threshold: float, text: str) -> None:
        if level:
            reasons.append({"level": level, "kind": kind, "subject": subject, "value": round(value, 4), "threshold": threshold, "text": text})

    if n < t["min_n"]:
        res.update({"status": "LOW_VOLUME", "message": f"{n} records in the window; at least {t['min_n']} are needed to judge it."})
        return res
    for spec in schema["features"]:
        name, f = spec["name"], acc["features"][spec["name"]]
        b = baseline["features"][name]
        miss = f["missing"] / max(1, f["n"])
        if b.get("high_cardinality"):
            res["features"].append({"name": name, "kind": spec["kind"], "psi": 0.0, "missing_rate": round(miss, 4), "base_missing_rate": b["missing_rate"], "violations": f.get("viol", 0),
                                    "skipped": "A field with a different value in almost every record (an identifier): it is counted, not compared.", "dist": {"labels": [], "base": [], "now": []}})
            continue
        value, dist = _compare(spec["kind"], b, f)
        entry = {"name": name, "kind": spec["kind"], "psi": value, "missing_rate": round(miss, 4), "base_missing_rate": b["missing_rate"], "violations": f.get("viol", 0), "dist": dist}
        if spec["kind"] == "numeric" and f["n"] - f["missing"] > 0:
            entry["mean"], entry["base_mean"] = round(f["sum"] / (f["n"] - f["missing"]), 5), b.get("mean")
        res["features"].append(entry)
        lv = level_of(value, t["psi_watch"], t["psi_drift"])
        reason(lv, "DATA_DRIFT", name, value, t["psi_drift"] if lv == "drift" else t["psi_watch"], f"The input {name} has shifted from its baseline (PSI {value:.2f}).")
        lv = level_of(miss - b["missing_rate"], 0.05, 0.15)
        reason(lv, "DATA_DRIFT", name, miss, 0.15 if lv == "drift" else 0.05, f"{name} is missing in {miss:.0%} of records, against {b['missing_rate']:.0%} at the baseline.")
        if f.get("viol", 0) >= t["violation_min"] or (f.get("viol", 0) and f["viol"] / max(1, f["n"]) >= 0.01):
            reason("drift", "DOMAIN_VIOLATION", name, f["viol"], t["violation_min"], f"{f['viol']} records had {name} outside the range the model is declared to work in.")
    ob = baseline["output"]
    o = acc["output"]
    value, dist = _compare(schema["output"]["kind"], ob, o)
    res["output"] = {"name": schema["output"]["name"], "kind": schema["output"]["kind"], "psi": value, "dist": dist, "positive_rate": round(o["pos"] / n, 5), "base_positive_rate": ob.get("positive_rate")}
    lv = level_of(value, t["psi_watch"], t["psi_drift"])
    reason(lv, "PREDICTION_DRIFT", schema["output"]["name"], value, t["psi_drift"] if lv == "drift" else t["psi_watch"], f"The model's output has shifted from its baseline (PSI {value:.2f}).")
    c, cb = acc["confidence"], baseline["confidence"]
    if c["n"] >= t["min_n"] and cb.get("props") and cb.get("n", 0) >= t["min_n"]:
        cv = psi(cb["props"], c["hist"])
        res["confidence"] = {"psi": cv, "mean": round(c["sum"] / c["n"], 4), "base_mean": cb.get("mean"), "now": [round(x, 4) for x in _norm(c["hist"])], "base": [round(x, 4) for x in cb["props"]]}
        lv = level_of(cv, t["psi_watch"], t["psi_drift"])
        reason(lv, "PREDICTION_DRIFT", "confidence", cv, t["psi_drift"] if lv == "drift" else t["psi_watch"], f"The model's confidence has shifted from its baseline (PSI {cv:.2f}).")
    lat = acc["latency"]
    res["latency"] = {"p50": percentile(lat["b"], 0.5), "p95": percentile(lat["b"], 0.95), "base_p95": baseline["latency"].get("p95"), "n": lat["n"]}
    bp, cp = baseline["latency"].get("p95"), res["latency"]["p95"]
    if bp and cp and lat["n"] >= t["min_n"] and cp > 100:
        lv = level_of(cp / bp, t["latency_ratio_watch"], t["latency_ratio_drift"])
        reason("watch" if lv else None, "LATENCY", "latency", cp / bp, t["latency_ratio_watch"], f"Response time (p95 {cp:.0f} ms) is {cp / bp:.1f} times the baseline.")
    er = acc["errors"] / n
    res["error_rate"], res["base_error_rate"] = round(er, 5), baseline.get("error_rate")
    lv = level_of(er, t["error_watch"], t["error_drift"])
    reason(lv, "MODEL_FAILURE", "errors", er, t["error_drift"] if lv == "drift" else t["error_watch"], f"{er:.1%} of requests ended in an error.")
    perf, bperf = _perf(acc, schema["output"]["kind"]), baseline.get("performance") or {}
    res["performance"] = {**perf, "base": bperf}
    if perf.get("n", 0) >= t["min_labels"] and bperf:
        if "accuracy" in perf and "accuracy" in bperf:
            drop = bperf["accuracy"] - perf["accuracy"]
            lv = level_of(drop, t["perf_drop_watch"], t["perf_drop_drift"])
            reason(lv, "PERFORMANCE_DRIFT", "accuracy", drop, t["perf_drop_drift"] if lv == "drift" else t["perf_drop_watch"], f"Accuracy fell from {bperf['accuracy']:.1%} to {perf['accuracy']:.1%} on {perf['n']} records with a known answer.")
        if "rmse" in perf and bperf.get("rmse"):
            ratio = perf["rmse"] / bperf["rmse"]
            lv = level_of(ratio, t["rmse_ratio_watch"], t["rmse_ratio_drift"])
            reason(lv, "PERFORMANCE_DRIFT", "rmse", ratio, t["rmse_ratio_drift"] if lv == "drift" else t["rmse_ratio_watch"], f"The error (RMSE) is {ratio:.2f} times the baseline on {perf['n']} records with a known answer.")
    res["fairness"] = []
    if schema["output"].get("positive") is not None:
        for attr, groups in acc["segments"].items():
            rows = [{"group": g, "n": s["n"], "rate": round(s["pos"] / s["n"], 5)} for g, s in sorted(groups.items()) if s["n"] >= t["min_group"]]
            if len(rows) < 2:
                res["fairness"].append({"attribute": attr, "groups": rows, "ratio": None})
                continue
            hi, lo = max(rows, key=lambda r: r["rate"]), min(rows, key=lambda r: r["rate"])
            ratio = (lo["rate"] / hi["rate"]) if hi["rate"] > 0 else 1.0
            res["fairness"].append({"attribute": attr, "groups": rows, "ratio": round(ratio, 4), "lowest": lo["group"], "highest": hi["group"]})
            if ratio < t["parity_breach"]:
                reason("drift", "BIAS_BREACH", attr, ratio, t["parity_breach"], f"The favourable outcome rate for {lo['group']} ({lo['rate']:.0%}) is {ratio:.2f} of the rate for {hi['group']} ({hi['rate']:.0%}), below the {t['parity_breach']:.2f} limit.")
            elif ratio < t["parity_watch"]:
                reason("watch", "BIAS_BREACH", attr, ratio, t["parity_watch"], f"The favourable outcome rate for {lo['group']} is {ratio:.2f} of the rate for {hi['group']}.")
    res["flags"] = []
    for name in schema.get("flags") or []:
        if name in SAFETY_FLAGS:                                    # judged by their own rules (llm_safety.py), not against a baseline
            continue
        rate, base = acc["flags"].get(name, 0) / n, (baseline.get("flags") or {}).get(name, 0.0)
        res["flags"].append({"name": name, "rate": round(rate, 5), "base_rate": base})
        lv = level_of(rate - base, t["flag_watch"], t["flag_drift"])
        reason(lv, "PREDICTION_DRIFT", name, rate, t["flag_drift"] if lv == "drift" else t["flag_watch"], f"{name} is set on {rate:.0%} of requests, against {base:.0%} at the baseline.")
    levels = {r["level"] for r in reasons}
    res["status"] = "DRIFT" if "drift" in levels else ("WATCH" if "watch" in levels else "OK")
    return res


def signals(reasons: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What the ST-AI score understands from the reasons: drift (and its kind), a bias breach, a domain violation."""
    drift = [r for r in reasons if r["level"] == "drift"]
    kinds = {r["kind"] for r in drift}
    dtype = "PERFORMANCE_DRIFT" if "PERFORMANCE_DRIFT" in kinds else ("PREDICTION_DRIFT" if "PREDICTION_DRIFT" in kinds else ("DATA_DRIFT" if "DATA_DRIFT" in kinds else None))
    return {"drift_detected": dtype is not None, "drift_type": dtype, "bias_breach_detected": "BIAS_BREACH" in kinds, "domain_violation_occurred": "DOMAIN_VIOLATION" in kinds}
