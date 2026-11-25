import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch, Rectangle

d = Path(sys.argv[1])
r = json.load(open(d / "seeded.json"))
GREEN, AMB, RED, GREY, BLUE = "#2f855a", "#d69e2e", "#c53030", "#cbd5e0", "#2b6cb0"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})
VCOL = {"APPROVED": GREEN, "REQUIRES_REVIEW": AMB, "BLOCKED": RED}
flaws, neutral = r["flaws"], r["neutral"]


def check_flag(v):
    return bool(set(v["rows_changed"]) - {"ASI07"})          # ASI07 changes only because a delegation now exists (it is satisfied whenever declared)


# Fig E1: what each layer says about each seeded flaw and each neutral change
rows = [(k, v, True) for k, v in flaws.items()] + [(k, v, False) for k, v in neutral.items()]
fig, ax = plt.subplots(figsize=(9.6, 7.4))
ax.set_xlim(0, 10); ax.set_ylim(len(rows) + 1.2, -0.2); ax.axis("off")
ax.text(4.55, 0.1, "OWASP check\nflags it", ha="center", va="center", fontsize=9.5, fontweight="bold")
ax.text(6.35, 0.1, "Gate verdict", ha="center", va="center", fontsize=9.5, fontweight="bold")
ax.text(8.45, 0.1, "Outcome", ha="center", va="center", fontsize=9.5, fontweight="bold")
for i, (name, v, is_flaw) in enumerate(rows, start=1):
    y = i
    ax.text(0.0, y, name, va="center", fontsize=9.5)
    cf = check_flag(v)
    ax.add_patch(Rectangle((3.85, y - 0.4), 1.4, 0.8, color=(RED if cf else GREY) if is_flaw else (RED if cf else GREEN), alpha=0.9))
    ax.text(4.55, y, "yes" if cf else "no", ha="center", va="center", color="white" if (cf or not is_flaw) else "#2d3748", fontsize=9)
    ax.add_patch(Rectangle((5.5, y - 0.4), 1.7, 0.8, color=VCOL[v["verdict"]]))
    ax.text(6.35, y, v["verdict"].replace("_", " ").lower(), ha="center", va="center", color="white", fontsize=9)
    caught = (v["verdict"] != "APPROVED" or cf) if is_flaw else (v["verdict"] == "APPROVED" and not cf)
    ax.text(8.45, y, ("caught" if caught else "missed") if is_flaw else ("correctly left alone" if caught else "false alarm"), ha="center", va="center", fontsize=9, color=GREEN if caught else RED, fontweight="bold")
ax.text(0.0, len(rows) + 0.9, "F14 code execution: cannot be written in the design vocabulary (not run)", fontsize=8.5, color="#4a5568")
ax.set_title("Seeded flaws and neutral changes: what the design-time assessment says", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(d / "figE1_flaw_matrix.png", dpi=200); plt.close(fig)

# Fig E2: detection by layer
nf = len(flaws)
chk = sum(check_flag(v) for v in flaws.values())
gt = sum(v["verdict"] != "APPROVED" for v in flaws.values())
either = sum((v["verdict"] != "APPROVED") or check_flag(v) for v in flaws.values())
fa = sum((v["verdict"] != "APPROVED") or check_flag(v) for v in neutral.values())
fig, ax = plt.subplots(figsize=(7.6, 4.2))
labels = ["OWASP checks", "Gate verdict", "Either"]; vals = [chk, gt, either]
b = ax.bar(labels, vals, color=[BLUE, "#2c5282", GREEN], width=0.55)
ax.axhline(nf, color="#4a5568", ls="--", lw=1); ax.text(-0.45, nf + 0.25, f"{nf} seeded flaws", fontsize=9, color="#4a5568")
for rect, v in zip(b, vals):
    ax.text(rect.get_x() + rect.get_width() / 2, v - 0.5, f"{v} of {nf}", ha="center", va="top", color="white", fontweight="bold", fontsize=11)
ax.set_ylim(0, nf + 2); ax.set_ylabel("Seeded flaws flagged")
ax.set_title(f"Sensitivity by layer (false alarms on neutral changes: {fa} of {len(neutral)})", loc="left", fontweight="bold", fontsize=10.5)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
fig.tight_layout(); fig.savefig(d / "figE2_detection_by_layer.png", dpi=200); plt.close(fig)

# Fig E3: the runtime contract inherits the flaw
rt = r["runtime"]
fig, ax = plt.subplots(figsize=(8.6, 3.9)); ax.axis("off"); ax.set_xlim(0, 10); ax.set_ylim(len(rt) + 1, -0.3)
ax.text(4.9, 0.15, "Contract of the sound design", ha="center", fontsize=9.5, fontweight="bold"); ax.text(8.3, 0.15, "Contract of the flawed design", ha="center", fontsize=9.5, fontweight="bold")
for i, (name, v) in enumerate(rt.items(), start=1):
    ax.text(0.0, i, name, va="center", fontsize=9.5)
    for x0, outc, cls in ((0, v["sound_contract"], v["sound_classes"]), (3.45, v["flawed_contract"], v["flawed_classes"])):
        pass
    ax.add_patch(Rectangle((4.2, i - 0.4), 1.4, 0.8, color=RED if v["sound_contract"] == "DIVERGES" else GREEN)); ax.text(4.9, i, "flags it\n" + ", ".join(v["sound_classes"]) if v["sound_classes"] else "accepts it", ha="center", va="center", color="white", fontsize=7.8)
    ax.add_patch(Rectangle((7.6, i - 0.4), 1.4, 0.8, color=RED if v["flawed_contract"] == "DIVERGES" else GREEN)); ax.text(8.3, i, "flags it" if v["flawed_classes"] else "accepts it", ha="center", va="center", color="white", fontsize=8.5)
ax.set_title("An exploit of each flaw: the runtime contract only catches it if the design did not allow it", loc="left", fontweight="bold", fontsize=10.5)
fig.tight_layout(); fig.savefig(d / "figE3_runtime_inherits_flaw.png", dpi=200); plt.close(fig)
print(dict(flaws=nf, checks=chk, gate=gt, either=either, neutral_false_alarms=fa, pairs=len(r["pairs"]), monotone=sum(p.get("monotone", False) for p in r["pairs"])))
