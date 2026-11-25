import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

d = Path(sys.argv[1])
b = json.load(open(d / "public_data" / "bench.json")); A, B = b["A"], b["B"]
tg = {7: json.load(open(d / "public_data" / "tgn_metrics.json"))}
for s in (11, 12, 13, 14):
    tg[s] = json.load(open(d / "public_data" / f"seed_{s}.json"))["metrics"]
BLUE, GREEN, ORANGE, GREY, RED, AMB = "#2b6cb0", "#2f855a", "#dd8a3e", "#cbd5e0", "#c53030", "#d69e2e"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9.5, "axes.spines.top": False, "axes.spines.right": False})
fig, ax = plt.subplots(2, 2, figsize=(11.6, 7.6))

# A: mutation testing
a = ax[0, 0]
names = ["Model core", "Runtime checks", "Estate builder"]
tot = [88, 93, 171]; caught = [86, 93, 153]
a.barh(names, [100 * c / t for c, t in zip(caught, tot)], color=[GREEN, GREEN, BLUE], height=0.55)
for i, (c, t) in enumerate(zip(caught, tot)):
    a.text(100 * c / t + 1.5, i, f"{c} of {t}", va="center", fontsize=9.5, fontweight="bold")
a.set_xlim(0, 125); a.set_xticks([0, 50, 100]); a.invert_yaxis(); a.set_xlabel("Deliberate code changes caught (%)" + chr(10) + "Estate builder: 101 of 171 before the tests were hardened", fontsize=9)
a.set_title("1  Mutation testing of the code", loc="left", fontweight="bold")

# B: seeded flaws
bx = ax[0, 1]
labels = ["Round 1\n(first assessment)", "Round 2\n(after four fixes)"]
vals = [(11, 2), (32, 0)]
bx.bar(labels, [v[0] for v in vals], color=[AMB, GREEN], width=0.5, label="as expected")
bx.bar(labels, [v[1] for v in vals], bottom=[v[0] for v in vals], color=RED, width=0.5, label="missed")
bx.text(0, 14.2, "11 of 13 flaws caught", ha="center", fontsize=9.5, fontweight="bold"); bx.text(0, 17.2, "0 of 7 false alarms", ha="center", fontsize=8.5, color="#4a5568")
bx.text(1, 32.8, "32 of 32 as predicted", ha="center", fontsize=9.5, fontweight="bold"); bx.text(1, 36.2, "19 flaws, 2 advisory, 11 neutral", ha="center", fontsize=8.5, color="#4a5568")
bx.set_ylim(0, 42); bx.set_ylabel("Variants of a sound design"); bx.legend(frameon=False, loc="upper left", fontsize=8.5)
bx.set_title("2  Seeded flaws in the design-time assessment", loc="left", fontweight="bold")

# C: public traces
c = ax[1, 0]
fam = ["novel\ntarget", "kind\nswitch", "lateral\nchain", "order\nswap", "burst\nrepeat", "metronome", "slow\ndrip"]
key = ["novel_target", "kind_switch", "lateral_chain", "order_swap", "burst_repeat", "metronome", "slow_drip"]
def share(s, f):
    v = A["seeds"][str(s)]["families"].get(f)
    return None if v is None else v["flagged"] / v["episodes"]
con = [np.nanmean([share(s, f) if share(s, f) is not None else np.nan for s in tg]) for f in key]
tgn = [np.nanmean([tg[s]["tgn"]["tpr"].get(f) if tg[s]["tgn"]["tpr"].get(f) is not None else np.nan for s in tg]) for f in key]
x = np.arange(len(key)); w = 0.38
c.bar(x - w / 2, con, w, color=GREEN, label="Design contract (rules)"); c.bar(x + w / 2, tgn, w, color=BLUE, label="Learned detector (TGN)")
c.axvline(2.5, color="#4a5568", ls=":", lw=1); c.text(1, 1.09, "structural", ha="center", fontsize=8.5, color="#4a5568"); c.text(4.5, 1.09, "behavioural", ha="center", fontsize=8.5, color="#4a5568")
c.set_xticks(x); c.set_xticklabels(fam, fontsize=8); c.set_ylim(0, 1.5); c.set_yticks([0, 0.25, 0.5, 0.75, 1.0]); c.set_ylabel("Injected attacks flagged"); c.legend(frameon=False, loc="upper center", fontsize=8.2, ncol=2, bbox_to_anchor=(0.5, 1.0))
c.set_title("3  Public multi-agent traces, 5 runs", loc="left", fontweight="bold")
c.text(0, -0.36, "Contract: 0 false alarms on 3,290 normal windows.", transform=c.transAxes, fontsize=8, color="#4a5568")

# D: failure modes
dd = ax[1, 1]
rho = [B["corr"]["steps"]["spearman"], B["corr"]["n_paths"]["spearman"]]
dd.bar(["Run length", "Design exposure\n(attack paths)"], rho, color=[GREY, BLUE], width=0.5)
dd.text(0, rho[0] + 0.03, f"{rho[0]:.2f}\np < 0.001", ha="center", fontsize=9); dd.text(1, rho[1] + 0.03, f"{rho[1]:.2f}\np = {B['corr']['n_paths']['p_perm']:.2f}\n(2 distinct values)", ha="center", fontsize=9)
dd.set_ylim(0, 1.0); dd.set_ylabel("Spearman correlation with\nlabelled failure modes")
dd.set_title("4  Design verdict against failure modes", loc="left", fontweight="bold")
dd.text(0, -0.30, "No relation: task failures are not security exposure. Reported as a scope result.", transform=dd.transAxes, fontsize=8, color="#4a5568")

fig.suptitle("ASTRA, design-time assessment: what the tests show so far", x=0.01, ha="left", fontweight="bold", fontsize=13)
fig.text(0.01, 0.005, "Attacks are injected; tiers, tolerances and timestamps are assigned; fixes and flaws share an author; no independent pilot yet.", fontsize=8.5, color="#4a5568")
fig.tight_layout(rect=(0, 0.03, 1, 0.95)); fig.savefig(d / "email_summary.png", dpi=200); print("ok")
