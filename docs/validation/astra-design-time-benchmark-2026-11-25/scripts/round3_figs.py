import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Rectangle

root = Path(sys.argv[1])                         # the benchmark folder
SUF = sys.argv[2] if len(sys.argv) > 2 else ""                 # "" for the final results, "_before_fixes" for the first run
r = json.load(open(root / "results" / ("seeded3_before_fixes.json" if SUF else "seeded3.json")))
GREEN, AMB, RED, GREY, BLUE = "#2f855a", "#d69e2e", "#c53030", "#cbd5e0", "#2b6cb0"
VCOL = {"APPROVED": GREEN, "REQUIRES_REVIEW": AMB, "BLOCKED": RED}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9.5})
fl = r["flaws"]
rows = list(fl.items())

# Fig R3a: each flaw, the forecast, what happened
fig, ax = plt.subplots(figsize=(10.6, 8.4)); ax.axis("off"); ax.set_xlim(0, 10.6); ax.set_ylim(len(rows) + 2.3, -0.2)
ax.text(0, 0.15, "Flaw (should not be approved)", fontweight="bold"); ax.text(5.55, 0.15, "Forecast", fontweight="bold", ha="center"); ax.text(7.35, 0.15, "Verdict", fontweight="bold", ha="center"); ax.text(9.35, 0.15, "Outcome", fontweight="bold", ha="center")
for i, (k, v) in enumerate(rows, start=1):
    ax.text(0, i, f"{k}  {v['desc']}", va="center", fontsize=8.8)
    ax.add_patch(Rectangle((4.85, i - 0.36), 1.4, 0.72, color=VCOL[v["forecast"][0]], alpha=0.55)); ax.text(5.55, i, v["forecast"][0].replace("_", " ").lower(), ha="center", va="center", fontsize=7.8)
    ax.add_patch(Rectangle((6.65, i - 0.36), 1.4, 0.72, color=VCOL[v["verdict"]])); ax.text(7.35, i, v["verdict"].replace("_", " ").lower(), ha="center", va="center", color="white", fontsize=7.8)
    ax.text(9.35, i, ("caught" if v["caught"] else "missed") + ("" if v["forecast_ok"] else "  (not as forecast)"), ha="center", va="center", fontsize=8.2, color=GREEN if v["caught"] else RED, fontweight="bold")
caught = sum(v["caught"] for v in fl.values()); ok = sum(v["forecast_ok"] for v in fl.values())
nn = r["neutral"]; nok = sum(v["approved"] for v in nn.values())
ax.text(0, len(rows) + 1.2, f"Caught {caught} of {len(fl)} flaws.  Forecast right on {ok} of {len(fl)} flaws.  Neutral designs approved: {nok} of {len(nn)}.", fontweight="bold")
ax.text(0, len(rows) + 1.9, ("Before the fixes: seven misses were forecast limits; three were findings (R5, R8, and R4 caught for a side effect)." if SUF else "After the fixes: R8 is now caught, R4 is no longer caught for a side effect, R5 now reaches the contract. Seven forecast limits remain."), fontsize=8.5, color="#4a5568")
ax.set_title("Round 3: harder flaws against the fixed pipeline", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(root / "figures" / f"figR3a_flaws{SUF}.png", dpi=200); plt.close(fig)

# Fig R3b: metamorphic relations
m = r["metamorphic"]["relations"]
names = list(m)
fig, ax = plt.subplots(figsize=(9.6, 5.2))
ax.barh(range(len(names)), [m[n]["applicable"] for n in names], color=BLUE, height=0.65)
for i, n in enumerate(names):
    ax.text(m[n]["applicable"] + 40, i, f"{m[n]['applicable']:,} cases, {m[n]['violations']} violations", va="center", fontsize=8.8)
ax.set_yticks(range(len(names))); ax.set_yticklabels(names); ax.invert_yaxis(); ax.set_xlim(0, 4300); ax.set_xlabel("Random designs on which the relation was checked (of 3,000)")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
d = r["metamorphic"]["verdict_distribution"]
ax.set_title(f"Metamorphic test: 14 relations, 0 violations (base verdicts: {d.get('3', 0)} approved, {d.get('2', 0)} review, {d.get('1', 0)} blocked)", loc="left", fontweight="bold", fontsize=10.2)
fig.tight_layout(); fig.savefig(root / "figures" / f"figR3b_metamorphic{SUF}.png", dpi=200); plt.close(fig)
print("ok", caught, ok, nok)
