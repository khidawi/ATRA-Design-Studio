import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Rectangle

out = Path(sys.argv[1])
GREEN, AMB, RED, GREY, BLUE, ORANGE = "#2f855a", "#d69e2e", "#c53030", "#cbd5e0", "#2b6cb0", "#dd8a3e"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})

# V1: mutation testing of three modules
rows = [("Formal model core\n(gate, statuses, exposure, contract)\nunchanged", 88, [("existing tests", 63, GREY), ("plus extended suite", 86, BLUE)]),
        ("Runtime checks\n(events.py)\nnew this round", 93, [("existing tests", 93, BLUE)]),
        ("Estate builder\n(astra_estate.py)\nchanged this round", 171, [("before new tests", 101, GREY), ("after new tests", 153, BLUE)])]
fig, ax = plt.subplots(figsize=(9.4, 4.8))
y = 0
ticks, labels = [], []
for name, total, bars in rows:
    ys = []
    for lab, v, col in bars:
        ax.barh(y, v / total * 100, color=col, height=0.7)
        ax.text(v / total * 100 + 1, y, f"{v} of {total}  ({100 * v / total:.0f}%)  {lab}", va="center", fontsize=9)
        ys.append(y)
        y += 1
    ticks.append(np.mean(ys)); labels.append(name)
    y += 0.7
ax.set_yticks(ticks); ax.set_yticklabels(labels); ax.invert_yaxis(); ax.set_xlim(0, 150); ax.set_xticks([0, 25, 50, 75, 100]); ax.set_xlabel("Deliberate code changes caught (%)")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.set_title("Mutation testing: how many deliberate code changes the tests notice", loc="left", fontweight="bold")
fig.text(0.01, 0.01, "Estate builder: the new tests were written after seeing the survivors, so the gain is a hardening of the tests, not independent evidence.", fontsize=8, color="#4a5568")
fig.tight_layout(rect=(0, 0.04, 1, 1)); fig.savefig(out / "figV1_mutation_scores.png", dpi=200); plt.close(fig)

# V2: the designed-against flaws before and after the fixes
cells = [("F9 over-broad data access", "APPROVED", "REQUIRES_REVIEW"), ("F11 delegation, reach unknown", "APPROVED", "REQUIRES_REVIEW"),
         ("F12 no rate limit, delegating agent", "APPROVED", "BLOCKED"), ("F13 no AI disclosure", "APPROVED", "APPROVED (advisory)"),
         ("F14 code tool, no sandbox", "not expressible", "BLOCKED"), ("F10 delegation, authentication", "REQUIRES_REVIEW", "REQUIRES_REVIEW")]
COL = {"APPROVED": GREEN, "REQUIRES_REVIEW": AMB, "BLOCKED": RED, "not expressible": GREY, "APPROVED (advisory)": "#68a07d"}
fig, ax = plt.subplots(figsize=(9.4, 4.4)); ax.axis("off"); ax.set_xlim(0, 10); ax.set_ylim(len(cells) + 1, -0.2)
ax.text(5.1, 0.1, "Verdict before the fixes", ha="center", fontweight="bold"); ax.text(8.1, 0.1, "Verdict after the fixes", ha="center", fontweight="bold")
for i, (n, a, b) in enumerate(cells, start=1):
    ax.text(0, i, n, va="center", fontsize=9.5)
    for x0, v in ((4.1, a), (7.1, b)):
        ax.add_patch(Rectangle((x0, i - 0.4), 2.0, 0.8, color=COL[v])); ax.text(x0 + 1.0, i, v.replace("_", " ").lower(), ha="center", va="center", color="white" if v != "not expressible" else "#2d3748", fontsize=9)
ax.set_title("Flaws that depended on the fixes: before and after", loc="left", fontweight="bold")
fig.text(0.01, 0.01, "F12 with delegation was not run before the fix: its 'before' verdict is inferred, because the rate-limit check did not reach the gate.", fontsize=8, color="#4a5568")
fig.tight_layout(rect=(0, 0.04, 1, 1)); fig.savefig(out / "figV2_flaws_before_after.png", dpi=200); plt.close(fig)

# V3: the whole validation at a glance
items = [("Formal model core: checks, enumeration, oracle, mutation", "86 of 88 caught; 2 equivalent", "unchanged", GREEN),
         ("Extended suite E1 to E6 (re-run)", "all six pass, 0 violations", "re-run", GREEN),
         ("Runtime checks (events.py) mutation", "93 of 93 caught", "new", GREEN),
         ("Estate builder mutation", "153 of 171; 17 of 18 survivors cosmetic", "new, tests hardened", AMB),
         ("Seeded flaws, round 1", "11 of 13 caught; 0 of 7 false alarms", "found 4 gaps", AMB),
         ("Seeded flaws, round 2", "32 of 32 as predicted; 66 of 66 pairs monotone", "regression check only", AMB),
         ("Whole backend test suite", "64 modules pass, 2 fixed (1 environment artefact)", "re-run", GREEN)]
fig, ax = plt.subplots(figsize=(9.8, 4.8)); ax.axis("off"); ax.set_xlim(-0.4, 10.6); ax.set_ylim(len(items) + 1, -0.2)
ax.text(-0.1, 0.1, "Layer", fontweight="bold"); ax.text(4.9, 0.1, "Result", fontweight="bold"); ax.text(8.9, 0.1, "Status", fontweight="bold")
for i, (a, b, c, col) in enumerate(items, start=1):
    ax.add_patch(Rectangle((-0.35, i - 0.42), 0.14, 0.84, color=col)); ax.text(-0.1, i, a, va="center", fontsize=9); ax.text(4.9, i, b, va="center", fontsize=8.6); ax.text(8.9, i, c, va="center", fontsize=8.6)
ax.set_title("Validation round 3 at a glance (green: independent of the fixes; amber: author-written)", loc="left", fontweight="bold", fontsize=10.5)
fig.tight_layout(); fig.savefig(out / "figV3_validation_overview.png", dpi=200); plt.close(fig)
print("ok")
