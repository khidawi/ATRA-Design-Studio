import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

d = Path(sys.argv[1])
rows = [r for r in json.load(open(d / "mad_bench.json")) if "skipped" not in r]
for r in rows:
    r["rev3"] = 1 if r["v3"] != "APPROVED" else 0


def rank(xs):
    idx = sorted(range(len(xs)), key=lambda i: xs[i])
    out = [0.0] * len(xs)
    i = 0
    while i < len(idx):
        j = i
        while j + 1 < len(idx) and xs[idx[j + 1]] == xs[idx[i]]:
            j += 1
        for k in range(i, j + 1):
            out[idx[k]] = (i + j) / 2 + 1
        i = j + 1
    return out


def resid(y, z):
    n = len(y); my, mz = sum(y) / n, sum(z) / n
    sz = sum((a - mz) ** 2 for a in z)
    b = sum((a - mz) * (c - my) for a, c in zip(z, y)) / sz if sz else 0.0
    return [c - my - b * (a - mz) for a, c in zip(z, y)]


def corr(a, b):
    n = len(a); ma, mb = sum(a) / n, sum(b) / n
    sa, sb = sum((x - ma) ** 2 for x in a) ** 0.5, sum((x - mb) ** 2 for x in b) ** 0.5
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / (sa * sb) if sa and sb else None


def partial(rs, xname, perms=5000, seed=1):
    """Spearman partial correlation of the design variable with the number of failure modes, removing run length. Freedman-Lane permutation of the outcome residuals."""
    x, y, z = rank([r[xname] for r in rs]), rank([r["n_modes"] for r in rs]), rank([r["steps"] for r in rs])
    if len(set(x)) < 2:
        return None, None
    rx, ry = resid(x, z), resid(y, z)
    r0 = corr(rx, ry)
    rng, ge = random.Random(seed), 0
    for _ in range(perms):
        p = ry[:]
        rng.shuffle(p)
        c = corr(rx, p)
        if c is not None and abs(c) >= abs(r0) - 1e-12:
            ge += 1
    return r0, (ge + 1) / (perms + 1)


out = {"n": len(rows), "frameworks": {}}
for fw in sorted({r["fw"] for r in rows}):
    rs = [r for r in rows if r["fw"] == fw]
    e = {"n": len(rs), "mean_modes": sum(r["n_modes"] for r in rs) / len(rs), "median_steps": sorted(r["steps"] for r in rs)[len(rs) // 2],
         "v3": dict(Counter(r["v3"] for r in rs)), "agents": dict(Counter(r["agents"] for r in rs)), "partial": {}}
    for xn in ("rev3", "paths", "agents"):
        e["partial"][xn] = partial(rs, xn)
    out["frameworks"][fw] = e
# pooled within frameworks: rank inside each framework, then stratified permutation
pool = {}
for xn in ("rev3", "paths", "agents"):
    rx_all, ry_all, strata = [], [], []
    for fw in {r["fw"] for r in rows}:
        rs = [r for r in rows if r["fw"] == fw]
        if len(rs) < 30 or len({r[xn] for r in rs}) < 2:
            continue
        x, y, z = rank([r[xn] for r in rs]), rank([r["n_modes"] for r in rs]), rank([r["steps"] for r in rs])
        rx_all.append(resid(x, z)); ry_all.append(resid(y, z)); strata.append(fw)
    flat_x = [v for s in rx_all for v in s]; flat_y = [v for s in ry_all for v in s]
    r0 = corr(flat_x, flat_y); rng = random.Random(2); ge = 0
    for _ in range(3000):
        py = []
        for s in ry_all:
            t = s[:]; rng.shuffle(t); py += t
        c = corr(flat_x, py)
        if c is not None and abs(c) >= abs(r0) - 1e-12:
            ge += 1
    pool[xn] = {"rho": r0, "p": (ge + 1) / 3001, "frameworks": sorted(strata), "n": len(flat_x)}
out["pooled"] = pool
# between- versus within-framework share of the design variation (eta squared of rev3)
m = sum(r["rev3"] for r in rows) / len(rows)
tot = sum((r["rev3"] - m) ** 2 for r in rows)
by = defaultdict(list)
for r in rows:
    by[r["fw"]].append(r["rev3"])
bet = sum(len(v) * (sum(v) / len(v) - m) ** 2 for v in by.values())
out["eta2_rev3"] = bet / tot if tot else None
# failure-mode coverage
NAMES = {"1.1": "Disobey task specification", "1.2": "Disobey role specification", "1.3": "Step repetition", "1.4": "Loss of conversation history", "1.5": "Unaware of termination conditions",
         "2.1": "Conversation reset", "2.2": "Fail to ask for clarification", "2.3": "Task derailment", "2.4": "Information withholding", "2.5": "Ignored other agent's input",
         "2.6": "Reasoning-action mismatch", "3.1": "Premature termination", "3.2": "No or incomplete verification", "3.3": "Incorrect verification"}
TAG = {"1.2": "covered", "2.3": "covered", "1.1": "adjacent", "3.1": "adjacent", "3.2": "adjacent", "3.3": "adjacent"}
modes = Counter()
for r in rows:
    modes.update(r["modes"])
out["modes"] = {k: {"name": NAMES[k], "count": modes.get(k, 0), "tag": TAG.get(k, "outside")} for k in NAMES}
tot_modes = sum(modes.values())
out["coverage"] = {t: sum(v["count"] for v in out["modes"].values() if v["tag"] == t) for t in ("covered", "adjacent", "outside")}
out["coverage"]["total"] = tot_modes
json.dump(out, open(d / "mad_analysis.json", "w"), indent=1)
print("n", out["n"], "eta2 of the review verdict explained by framework:", round(out["eta2_rev3"], 3))
for fw, e in out["frameworks"].items():
    print(f"{fw:10s} n={e['n']:4d} modes={e['mean_modes']:.2f} v3={e['v3']} agents={e['agents']}")
    for xn, v in e["partial"].items():
        print(f"      partial rho ({xn} vs failure modes | steps): {'n/a (no variation)' if v[0] is None else f'{v[0]:+.3f}  p={v[1]:.4f}'}")
print("pooled", {k: (round(v['rho'], 3), round(v['p'], 4), v['frameworks']) for k, v in pool.items()})
print("coverage", out["coverage"])
print(sorted(((v["count"], k, v["name"], v["tag"]) for k, v in out["modes"].items()), reverse=True))
