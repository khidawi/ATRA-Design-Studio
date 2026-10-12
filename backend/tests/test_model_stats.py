"""
Tests for model_stats.py: folding records into aggregates and judging them against a baseline.

    docker compose exec backend python -m tests.test_model_stats
"""
import json
import random
import sys

import model_stats as ms

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


SCHEMA = {"task": "classification",
          "features": [{"name": "age", "kind": "numeric", "min": 18, "max": 100}, {"name": "income", "kind": "numeric"}, {"name": "plan", "kind": "categorical"},
                       {"name": "notes", "kind": "text"}],
          "output": {"name": "decision", "kind": "categorical", "positive": "approve"}, "segments": ["gender"], "flags": ["refusal"]}
rng = random.Random(7)


def make(n, age_mu=45, plans=(0.6, 0.3, 0.1), approve=0.5, correct=0.9, female_approve=None, male_approve=None, missing_age=0.0, note_len=40, bad_age=0.0, new_plan=0.0, refusal=0.02):
    out = []
    for _ in range(n):
        g = rng.choice(["F", "M"])
        p = {"F": female_approve, "M": male_approve}[g] if female_approve is not None else approve
        d = "approve" if rng.random() < p else "deny"
        label = d if rng.random() < correct else ("deny" if d == "approve" else "approve")
        age = rng.gauss(age_mu, 8)
        if bad_age and rng.random() < bad_age:
            age = rng.choice([-5, 150, 300])
        plan = rng.choices(["a", "b", "c"], plans)[0]
        if new_plan and rng.random() < new_plan:
            plan = "zz-new"
        out.append({"inputs": {"age": None if rng.random() < missing_age else age, "income": rng.gauss(50000, 12000), "plan": plan, "notes": "x" * int(rng.gauss(note_len, 5))},
                    "output": d, "confidence": min(0.999, max(0.01, rng.gauss(0.8 if d == "approve" else 0.7, 0.1))), "latency_ms": abs(rng.gauss(60, 15)),
                    "error": rng.random() < 0.003, "label": label, "segments": {"gender": g}, "flags": {"refusal": rng.random() < refusal}})
    return out


def fold(records, baseline=None):
    acc = ms.new_acc(SCHEMA, baseline)
    r = random.Random(1)
    for rec in records:
        ms.fold_record(acc, SCHEMA, baseline, rec, r)
    return acc


# ── learning phase and the baseline
buf = fold(make(5000))
check("the learning phase keeps a bounded sample, not the records", len(buf["features"]["age"]["sample"]) == ms.RESERVOIR and buf["n"] == 5000)
base = ms.build_baseline(SCHEMA, buf)
check("a baseline has edges and proportions that sum to one", abs(sum(base["features"]["age"]["props"]) - 1) < 1e-6 and len(base["features"]["age"]["edges"]) >= 8
      and abs(sum(base["features"]["plan"]["props"].values()) - 1) < 0.01 and base["features"]["age"]["mean"] > 40)
check("the baseline records performance, latency, errors, confidence and flags", 0.85 < base["performance"]["accuracy"] < 0.95 and base["latency"]["p95"] and base["error_rate"] < 0.02 and base["confidence"]["mean"] and "refusal" in base["flags"])
check("a baseline passes its own shape check", ms.check_profile(SCHEMA, base) is None)
check("a malformed supplied baseline is refused", ms.check_profile(SCHEMA, {"features": {}, "output": {}}) is not None and ms.check_profile(SCHEMA, {**base, "features": {**base["features"], "age": {**base["features"]["age"], "props": [0.5, 0.2]}}}) is not None)

# ── a window of the same traffic is stable
stable = ms.evaluate(SCHEMA, base, fold(make(1500), base), {})
check("traffic like the baseline is OK", stable["status"] == "OK", [r["text"] for r in stable["reasons"]])
check("and its PSI is small", all(f["psi"] < 0.1 for f in stable["features"]) and stable["output"]["psi"] < 0.1, [(f["name"], f["psi"]) for f in stable["features"]])
check("nothing is signalled", not any(ms.signals(stable["reasons"]).values()) or ms.signals(stable["reasons"])["drift_type"] is None)

# ── each kind of change is caught
d = ms.evaluate(SCHEMA, base, fold(make(1500, age_mu=62), base), {})
check("a shifted numeric input is drift, named, with its kind", d["status"] == "DRIFT" and any(r["kind"] == "DATA_DRIFT" and r["subject"] == "age" and r["level"] == "drift" for r in d["reasons"]), d["reasons"])
check("it becomes the drift signal", ms.signals(d["reasons"])["drift_detected"] and ms.signals(d["reasons"])["drift_type"] == "DATA_DRIFT")
d = ms.evaluate(SCHEMA, base, fold(make(1500, plans=(0.15, 0.25, 0.6)), base), {})
check("a shifted category mix is drift", any(r["subject"] == "plan" and r["level"] == "drift" for r in d["reasons"]))
d = ms.evaluate(SCHEMA, base, fold(make(1500, new_plan=0.3), base), {})
check("a category never seen before is counted as new and noticed", any(r["subject"] == "plan" for r in d["reasons"]) and d["features"][2]["dist"]["labels"][-1] == "(new or other)" and d["features"][2]["dist"]["now"][-1] > 0.2)
d = ms.evaluate(SCHEMA, base, fold(make(1500, approve=0.85), base), {})
check("a shifted output is prediction drift", any(r["kind"] == "PREDICTION_DRIFT" and r["subject"] == "decision" for r in d["reasons"]) and ms.signals(d["reasons"])["drift_type"] == "PREDICTION_DRIFT")
d = ms.evaluate(SCHEMA, base, fold(make(1500, correct=0.65), base), {})
check("accuracy falling once answers are known is performance drift, and wins over the other kinds", any(r["kind"] == "PERFORMANCE_DRIFT" and r["level"] == "drift" for r in d["reasons"]) and ms.signals(d["reasons"])["drift_type"] == "PERFORMANCE_DRIFT", d["reasons"])
d = ms.evaluate(SCHEMA, base, fold(make(1500, female_approve=0.55, male_approve=0.30), base), {})
check("unequal favourable outcomes by group is a bias breach", any(r["kind"] == "BIAS_BREACH" and r["level"] == "drift" and r["subject"] == "gender" for r in d["reasons"]) and ms.signals(d["reasons"])["bias_breach_detected"], d["fairness"])
d = ms.evaluate(SCHEMA, base, fold(make(1500, female_approve=0.5, male_approve=0.5), base), {})
check("equal outcomes by group is fine", not any(r["kind"] == "BIAS_BREACH" for r in d["reasons"]) and d["fairness"][0]["ratio"] > 0.9, d["fairness"])
d = ms.evaluate(SCHEMA, base, fold(make(1500, bad_age=0.05), base), {})
check("values outside the declared range are a domain violation", any(r["kind"] == "DOMAIN_VIOLATION" and r["subject"] == "age" for r in d["reasons"]) and ms.signals(d["reasons"])["domain_violation_occurred"], d["reasons"])
d = ms.evaluate(SCHEMA, base, fold(make(1500, missing_age=0.4), base), {})
check("an input that goes missing is noticed", any(r["subject"] == "age" and "missing" in r["text"] for r in d["reasons"]))
d = ms.evaluate(SCHEMA, base, fold(make(1500, note_len=400), base), {})
check("the length of a text input is monitored, never its content", any(r["subject"] == "notes" for r in d["reasons"]) and "xxxx" not in json.dumps(fold(make(50), base)))
d = ms.evaluate(SCHEMA, base, fold(make(1500, refusal=0.25), base), {})
check("a flag the serving code sets is watched against its baseline rate", any(r["subject"] == "refusal" and r["level"] == "drift" for r in d["reasons"]))
low = ms.evaluate(SCHEMA, base, fold(make(40, age_mu=90), base), {})
check("too few records is not judged", low["status"] == "LOW_VOLUME" and low["reasons"] == [])
d = ms.evaluate(SCHEMA, base, fold(make(1500, age_mu=56), base), {"psi_watch": 5, "psi_drift": 9})
check("thresholds can be changed", all(r["kind"] != "DATA_DRIFT" or r["subject"] != "age" for r in d["reasons"]))

# ── the arithmetic
check("PSI of a distribution with itself is 0, and it grows with the shift", ms.psi([0.5, 0.5], [0.5, 0.5]) == 0 and ms.psi([0.5, 0.5], [0.7, 0.3]) < ms.psi([0.5, 0.5], [0.9, 0.1]))
check("an empty bin does not break PSI", ms.psi([0.5, 0.5, 0], [0.5, 0.3, 0.2]) > 0)
a, b = fold(make(300)), fold(make(300))
m = ms.merge(a, b)
check("merging windows adds the counters and the histograms", m["n"] == 600 and m["output"]["cat"]["approve"] == a["output"]["cat"]["approve"] + b["output"]["cat"]["approve"] and m["latency"]["n"] == a["latency"]["n"] + b["latency"]["n"])
w1, w2 = fold(make(300), base), fold(make(300), base)
mm = ms.merge(w1, w2)
check("merged windows keep histograms bin by bin and min/max", mm["features"]["age"]["hist"] == [x + y for x, y in zip(w1["features"]["age"]["hist"], w2["features"]["age"]["hist"])] and mm["features"]["age"]["min"] == min(w1["features"]["age"]["min"], w2["features"]["age"]["min"]))
check("percentiles come from the latency buckets", ms.percentile([0, 0, 90, 10, 0, 0, 0, 0, 0, 0], 0.5) == 50 and ms.percentile([0, 0, 90, 10, 0, 0, 0, 0, 0, 0], 0.95) == 100 and ms.percentile([0] * 10, 0.5) is None)
cats = ms.new_acc({"features": [{"name": "id", "kind": "categorical"}], "output": {"name": "y", "kind": "categorical"}})
r = random.Random(3)
for i in range(300):
    ms.fold_record(cats, {"features": [{"name": "id", "kind": "categorical"}], "output": {"name": "y", "kind": "categorical"}}, None, {"inputs": {"id": f"user-{i}"}, "output": "x"}, r)
check("a high-cardinality category is capped, so identifiers are not stored", len(cats["features"]["id"]["cat"]) == ms.MAX_CATEGORIES and cats["features"]["id"]["other"] == 250)

# ── an identifier is counted, not compared
IDS = {"task": "classification", "features": [{"name": "uid", "kind": "categorical"}, {"name": "x", "kind": "numeric"}], "output": {"name": "y", "kind": "categorical"}}
r = random.Random(9)
gen = lambda n: [{"inputs": {"uid": f"u{r.randrange(10 ** 6)}", "x": r.gauss(0, 1)}, "output": "a"} for _ in range(n)]
ba = ms.new_acc(IDS)
[ms.fold_record(ba, IDS, None, x, random.Random(1)) for x in gen(600)]
ib = ms.build_baseline(IDS, ba)
wa = ms.new_acc(IDS, ib)
[ms.fold_record(wa, IDS, ib, x, random.Random(1)) for x in gen(600)]
ev = ms.evaluate(IDS, ib, wa, {})
check("a field with a new value in almost every record is flagged as an identifier and not compared", ib["features"]["uid"]["high_cardinality"] is True and ev["status"] == "OK" and ev["features"][0].get("skipped"), [x["text"] for x in ev["reasons"]])
check("such a baseline still passes its own check", ms.check_profile(IDS, ib) is None)

# ── regression
RS = {"task": "regression", "features": [{"name": "x", "kind": "numeric"}], "output": {"name": "y", "kind": "numeric"}}
r = random.Random(5)
mk = lambda n, noise: [{"inputs": {"x": r.gauss(0, 1)}, "output": (v := r.gauss(10, 2)), "label": v + r.gauss(0, noise)} for _ in range(n)]
fr = lambda recs, bl=None: (lambda a: ([ms.fold_record(a, RS, bl, x, random.Random(1)) for x in recs], a)[1])(ms.new_acc(RS, bl))
rb = ms.build_baseline(RS, fr(mk(3000, 1.0)))
check("a regression baseline records RMSE", rb["performance"]["rmse"] > 0.8 and ms.check_profile(RS, rb) is None)
d = ms.evaluate(RS, rb, fr(mk(500, 2.5), rb), {})
check("a growing error is performance drift", any(x["kind"] == "PERFORMANCE_DRIFT" and x["level"] == "drift" for x in d["reasons"]), d["reasons"])
d = ms.evaluate(RS, rb, fr(mk(500, 1.0), rb), {})
check("a steady error is fine", d["status"] == "OK", [x["text"] for x in d["reasons"]])

sys.exit(1 if fails else 0)
