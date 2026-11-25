import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

d = Path(sys.argv[1])
runs = [{"seed": 7, "metrics": json.load(open(d / "tgn_metrics.json"))}] + [json.load(open(p)) for p in sorted(d.glob("seed_*.json"))]
seeds = [r["seed"] for r in runs]
fam = ["order_swap", "burst_repeat", "novel_target", "metronome", "lateral_chain", "slow_drip", "kind_switch"]
BLUE, ORANGE, GREY = "#2b6cb0", "#dd8a3e", "#9aa5b1"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})


def tpr(r, who, f):
    v = r["metrics"][who]["tpr"].get(f)
    return np.nan if v is None else v


# Fig 1: detection by family, mean over seeds with the range
fig, ax = plt.subplots(figsize=(9, 4.4)); x = np.arange(len(fam)); w = 0.38
for i, (who, col, lab) in enumerate([("tgn", BLUE, "Temporal graph network"), ("baseline", ORANGE, "Statistical baseline")]):
    a = np.array([[tpr(r, who, f) for f in fam] for r in runs])
    m, lo, hi = np.nanmean(a, 0), np.nanmin(a, 0), np.nanmax(a, 0)
    ax.bar(x + (i - 0.5) * w, m, w, color=col, label=lab, yerr=[m - lo, hi - m], capsize=3, error_kw={"lw": 1, "ecolor": "#495057"})
ax.set_xticks(x); ax.set_xticklabels([f.replace("_", chr(10)) for f in fam]); ax.set_ylim(0, 1.12); ax.set_ylabel("Share of injected attacks detected")
ax.legend(frameon=False, loc="upper left", ncol=2); ax.set_title(f"Detection by attack family on public agent traces ({len(runs)} seeds, bars = mean, whiskers = range)", loc="left", fontweight="bold", fontsize=10.5)
fig.tight_layout(); fig.savefig(d / "figA_detection_by_family.png", dpi=200); plt.close(fig)

# Fig 2: macro detection per seed
fig, ax = plt.subplots(figsize=(7.4, 4.2)); x = np.arange(len(seeds))
t = [r["metrics"]["tgn"]["macro_test"] for r in runs]; b = [r["metrics"]["baseline"]["macro_test"] for r in runs]
ax.bar(x - 0.2, t, 0.4, color=BLUE, label="Temporal graph network"); ax.bar(x + 0.2, b, 0.4, color=ORANGE, label="Statistical baseline")
for i, (u, v) in enumerate(zip(t, b)):
    ax.text(i - 0.2, u + 0.015, f"{u:.2f}", ha="center", fontsize=8.5); ax.text(i + 0.2, v + 0.015, f"{v:.2f}", ha="center", fontsize=8.5)
ax.set_xticks(x); ax.set_xticklabels([f"seed {s}" for s in seeds]); ax.set_ylim(0, 1.0); ax.set_ylabel("Average detection over the test families")
ax.legend(frameon=False, loc="upper right"); ax.set_title("Stability across seeds", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(d / "figB_macro_by_seed.png", dpi=200); plt.close(fig)

# Fig 3: false alarms against the budget
fig, ax = plt.subplots(figsize=(7.4, 4.0))
ax.bar(x - 0.2, [r["metrics"]["tgn"]["fpr_test"] for r in runs], 0.4, color=BLUE, label="Temporal graph network")
ax.bar(x + 0.2, [r["metrics"]["baseline"]["fpr_test"] for r in runs], 0.4, color=ORANGE, label="Statistical baseline")
bud = runs[0]["metrics"]["budget_fpr"]; ax.axhline(bud, color="#495057", ls="--", lw=1); ax.text(len(seeds) - 0.5, bud + 0.003, f"false-alarm budget {bud:.0%}", ha="right", fontsize=9, color="#495057")
ax.set_xticks(x); ax.set_xticklabels([f"seed {s}" for s in seeds]); ax.set_ylabel("False alarms on normal test traffic"); ax.legend(frameon=False, loc="upper left")
ax.set_title("False alarms against the budget", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(d / "figC_false_alarms.png", dpi=200); plt.close(fig)

rows = [(r["seed"], r["metrics"]["tgn"]["macro_test"], r["metrics"]["baseline"]["macro_test"], r["metrics"]["tgn"]["fpr_test"], r["metrics"]["baseline"]["fpr_test"], r.get("decision", {}).get("passed", "seed 7 run: passed"), r.get("victims")) for r in runs]
for row in rows:
    print(row)
print("mean TGN", np.mean(t), "range", min(t), max(t), "| mean baseline", np.mean(b), "range", min(b), max(b))
