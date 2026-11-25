import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

d = Path(sys.argv[1])
rows = [r for r in json.load(open(d / "mad_bench.json")) if "skipped" not in r]
A = json.load(open(d / "mad_analysis_strata.json"))
GREEN, AMB, RED, GREY, BLUE = "#2f855a", "#d69e2e", "#c53030", "#cbd5e0", "#2b6cb0"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9.5, "axes.spines.top": False, "axes.spines.right": False})
for r in rows:
    r["stratum"] = r["fw"] + "/" + r["bench"]
strata = sorted({r["stratum"] for r in rows}, key=lambda s: (-sum(1 for r in rows if r["stratum"] == s)))

# M1: design verdict by framework and benchmark
fig, ax = plt.subplots(figsize=(10.4, 4.8))
for i, s in enumerate(strata):
    rs = [r for r in rows if r["stratum"] == s]; c = Counter(r["v3"] for r in rs); n = len(rs); bottom = 0
    for k, col in (("APPROVED", GREEN), ("REQUIRES_REVIEW", AMB)):
        v = c.get(k, 0) / n
        ax.bar(i, v, bottom=bottom, color=col, width=0.7); bottom += v
    ax.text(i, 1.02, f"n={n}", ha="center", fontsize=8)
ax.set_xticks(range(len(strata))); ax.set_xticklabels([s.replace("/", "\n") for s in strata], fontsize=7.8); ax.set_ylim(0, 1.1); ax.set_ylabel("Share of traces")
ax.legend(handles=[Patch(color=GREEN, label="approved"), Patch(color=AMB, label="requires review")], frameon=False, ncol=2, loc="lower center", bbox_to_anchor=(0.5, -0.3))
ax.set_title(f"Design-time verdict by framework and benchmark ({A['eta2_rev3_by_stratum'] * 100:.0f}% of its variation lies between these groups)", loc="left", fontweight="bold", fontsize=10.5)
fig.tight_layout(); fig.savefig(d / "figM1_verdict_by_framework.png", dpi=200); plt.close(fig)

# M2: partial correlation within strata
items = [(s, e["partial"]["paths"]) for s, e in A["frameworks"].items() if e["partial"]["paths"][0] is not None]
items.sort(key=lambda t: t[1][0])
fig, ax = plt.subplots(figsize=(9.4, 4.4))
y = np.arange(len(items) + 1)
vals = [v[0] for _, v in items] + [A["pooled"]["paths"]["rho"]]
labs = [s.replace("/", " / ") + f"  (n={A['frameworks'][s]['n']})" for s, _ in items] + ["All strata pooled"]
cols = [GREY] * len(items) + [BLUE]
ax.barh(y, vals, color=cols, height=0.6)
for i, (v, lab) in enumerate(zip(vals, labs)):
    p = items[i][1][1] if i < len(items) else A["pooled"]["paths"]["p"]
    ax.text(v + (0.012 if v >= 0 else -0.012), i, f"{v:+.2f}  (p={p:.2f})", va="center", ha="left" if v >= 0 else "right", fontsize=8.5)
ax.axvline(0, color="#4a5568", lw=1); ax.set_yticks(y); ax.set_yticklabels(labs); ax.invert_yaxis(); ax.set_xlim(-0.65, 0.3)
ax.set_xlabel("Spearman correlation: design exposure (attack paths) with failure modes, run length removed")
none = sum(1 for e in A["frameworks"].values() if e["partial"]["paths"][0] is None)
ax.set_title("Does more design exposure mean more failures? No." + chr(10) + f"{none} of {len(A['frameworks'])} framework-benchmark groups have no design variation to test", loc="left", fontweight="bold", fontsize=10)
fig.tight_layout(); fig.savefig(d / "figM2_exposure_vs_failures.png", dpi=200); plt.close(fig)

# M3: coverage of failure modes by the 22 classes
items = sorted(A["modes"].items(), key=lambda kv: kv[1]["count"])
colmap = {"covered": GREEN, "adjacent": AMB, "outside": GREY}
fig, ax = plt.subplots(figsize=(9.4, 5.2))
ax.barh([f"{k}  {v['name']}" for k, v in items], [v["count"] for _, v in items], color=[colmap[v["tag"]] for _, v in items])
for i, (_, v) in enumerate(items):
    ax.text(v["count"] + 8, i, str(v["count"]), va="center", fontsize=8.5)
cc = A["coverage"]
ax.legend(handles=[Patch(color=GREEN, label=f"covered by a class: {cc['covered']} ({100 * cc['covered'] / cc['total']:.0f}%)"), Patch(color=AMB, label=f"adjacent: {cc['adjacent']} ({100 * cc['adjacent'] / cc['total']:.0f}%)"),
                   Patch(color=GREY, label=f"outside the design model: {cc['outside']} ({100 * cc['outside'] / cc['total']:.0f}%)")], frameon=False, loc="lower right")
ax.set_xlabel(f"Occurrences in {A['n']:,} traces"); ax.set_title("Failure modes in the data against the 22 ASTRA classes (one rater's judgement)", loc="left", fontweight="bold", fontsize=10.5)
fig.tight_layout(); fig.savefig(d / "figM3_failure_mode_coverage.png", dpi=200); plt.close(fig)
print("ok")
