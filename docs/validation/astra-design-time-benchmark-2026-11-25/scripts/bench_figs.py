import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

d = Path(sys.argv[1])
b = json.load(open(d / "bench.json")); A, B = b["A"], b["B"]
tg = {7: json.load(open(d / "tgn_metrics.json"))}
for s in (11, 12, 13, 14):
    tg[s] = json.load(open(d / f"seed_{s}.json"))["metrics"]
BLUE, ORANGE, GREY, GREEN, RED, AMB = "#2b6cb0", "#dd8a3e", "#9aa5b1", "#2f855a", "#c53030", "#d69e2e"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
fam = ["novel_target", "kind_switch", "lateral_chain", "order_swap", "burst_repeat", "metronome", "slow_drip"]
structural = {"novel_target", "kind_switch", "lateral_chain"}


def share(seed, f):
    v = A["seeds"][str(seed)]["families"].get(f)
    return None if v is None else v["flagged"] / v["episodes"]


# Fig D1: design contract vs learned detectors by family
fig, ax = plt.subplots(figsize=(9.6, 4.6)); x = np.arange(len(fam)); w = 0.27
for i, (lab, col, fn) in enumerate([("Design-time contract (rules)", GREEN, lambda s, f: share(s, f)),
                                    ("Temporal graph network", BLUE, lambda s, f: tg[s]["tgn"]["tpr"].get(f)),
                                    ("Statistical baseline", ORANGE, lambda s, f: tg[s]["baseline"]["tpr"].get(f))]):
    m = []
    for f in fam:
        v = [fn(s, f) for s in tg if fn(s, f) is not None]
        m.append(np.mean(v) if v else np.nan)
    ax.bar(x + (i - 1) * w, m, w, color=col, label=lab)
ax.axvline(2.5, color="#495057", ls=":", lw=1)
ax.text(1.0, 1.13, "Structural attacks (outside the design)", ha="center", fontsize=9, color="#495057")
ax.text(4.5, 1.13, "Behavioural attacks (allowed actions, odd pattern)", ha="center", fontsize=9, color="#495057")
ax.set_xticks(x); ax.set_xticklabels([f.replace("_", chr(10)) for f in fam]); ax.set_ylim(0, 1.22); ax.set_ylabel("Share of injected attacks flagged (mean of 5 seeds)")
ax.legend(frameon=False, loc="upper right", fontsize=9, bbox_to_anchor=(1.0, 0.93))
ax.set_title("Design-time contract and learned detectors catch different attacks", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(d / "figD1_design_vs_learned.png", dpi=200); plt.close(fig)

# Fig D2: verdict after replaying one window, starting from a fully satisfied (APPROVED) design
tot = defaultdict(Counter)
for s in A["seeds"].values():
    tot["normal traffic"].update(s["normal"]["verdicts"])
    for f, v in s["families"].items():
        tot[f].update(v["verdicts"])
order = ["normal traffic"] + fam
fig, ax = plt.subplots(figsize=(9.2, 4.3)); bottom = np.zeros(len(order))
for name, col in [("APPROVED", GREEN), ("REQUIRES_REVIEW", AMB), ("BLOCKED", RED)]:
    vals = np.array([tot[o][name] / max(1, sum(tot[o].values())) for o in order])
    ax.bar(range(len(order)), vals, bottom=bottom, color=col, label=name.replace("_", " ").lower()); bottom += vals
for i, o in enumerate(order):
    ax.text(i, 1.02, f"n={sum(tot[o].values())}", ha="center", fontsize=8.5, color="#495057")
ax.set_xticks(range(len(order))); ax.set_xticklabels([o.replace("_", chr(10)) for o in order]); ax.set_ylim(0, 1.1); ax.set_ylabel("Share of windows by resulting verdict")
ax.legend(frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5, -0.32))
ax.set_title("Verdict of an approved design after replaying real and attacked windows (5 seeds pooled)", loc="left", fontweight="bold", fontsize=10.5)
fig.tight_layout(); fig.savefig(d / "figD2_verdict_after_replay.png", dpi=200); plt.close(fig)

# Fig D3: design verdict against labelled failure modes (HyperAgent) and run length confound
H = B["hyperagent"]
fig, (a1, a2) = plt.subplots(1, 2, figsize=(10.4, 4.3), gridspec_kw={"width_ratios": [1.25, 1]})
for key, col, lab in [(("Editor", "Executor", "Navigator"), BLUE, "all three interns engaged"), (("Editor", "Navigator"), ORANGE, "Executor not engaged")]:
    pts = [(r["steps"], r["n_modes"]) for r in H if tuple(r["engaged"]) == key]
    jit = np.random.RandomState(1).uniform(-0.12, 0.12, len(pts))
    a1.scatter([p[0] for p in pts], np.array([p[1] for p in pts]) + jit, color=col, s=34, label=f"{lab} (n={len(pts)})", alpha=0.85)
rho = B["corr"]["steps"]["spearman"]; p = B["corr"]["steps"]["p_perm"]
a1.set_xscale("log"); a1.set_ylim(-0.5, 7.2); a1.set_xlabel("Run length (logged steps, log scale)"); a1.set_ylabel("Human-labelled failure modes in the run"); a1.legend(frameon=False, fontsize=8.5, loc="upper left", bbox_to_anchor=(0.0, 1.0))
a1.set_title(f"Length drives failures (Spearman {rho:.2f}, p<0.001)", loc="left", fontweight="bold", fontsize=10)
cnt = {t: Counter(r[f"verdict_tau{t}"] for r in H) for t in (2, 3, 4)}
bt = np.zeros(3)
for name, col in [("APPROVED", GREEN), ("REQUIRES_REVIEW", AMB), ("BLOCKED", RED)]:
    v = np.array([cnt[t][name] for t in (2, 3, 4)], float); a2.bar(["tolerance 2", "tolerance 3", "tolerance 4"], v, bottom=bt, color=col, label=name.replace("_", " ").lower()); bt += v
a2.set_ylabel("Runs (design-time verdict)"); a2.legend(frameon=False, fontsize=8.5, loc="upper center", ncol=3, columnspacing=0.8, handlelength=1.2)
a2.set_ylim(0, 36); a2.set_title("Verdict follows tolerance, not the run", loc="left", fontweight="bold", fontsize=10)
fig.tight_layout(); fig.savefig(d / "figD3_verdict_vs_failures.png", dpi=200); plt.close(fig)

# Fig D4: coverage of labelled failure modes by the 22 ASTRA classes (the author's judgement)
cov = {"Derailing from task objectives": "covered", "Blurring role": "covered",
       "Poor adherence to specified constraints": "adjacent", "No attempt to verify outcome": "adjacent", "Claiming that a task is done while it is not true.": "adjacent", "Evaluator agent fails to be critical": "adjacent"}
modes = Counter()
for r in B["hyperagent"] + B["ag2"]:
    modes.update(r["modes"])
items = sorted(modes.items(), key=lambda kv: kv[1])
colmap = {"covered": GREEN, "adjacent": AMB, "outside": GREY}
fig, ax = plt.subplots(figsize=(9.2, 5.6))
ax.barh([k[:52] for k, _ in items], [v for _, v in items], color=[colmap[cov.get(k, "outside")] for k, _ in items])
for i, (_, v) in enumerate(items):
    ax.text(v + 0.3, i, str(v), va="center", fontsize=8.5)
tot_m = sum(modes.values()); cc = Counter()
for k, v in modes.items():
    cc[cov.get(k, "outside")] += v
ax.set_xlabel("Occurrences in the 61 human-labelled runs")
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=GREEN, label=f"covered by a class ({cc['covered']} of {tot_m})"), Patch(color=AMB, label=f"adjacent ({cc['adjacent']})"), Patch(color=GREY, label=f"outside the design model ({cc['outside']})")], frameon=False, loc="lower right")
ax.set_title("Failure modes in the data against the 22 ASTRA classes (one rater's judgement)", loc="left", fontweight="bold", fontsize=10.5)
fig.tight_layout(); fig.savefig(d / "figD4_failure_mode_coverage.png", dpi=200); plt.close(fig)

# numbers for the write-up
agg = {}
for f in fam:
    ep = sum(A["seeds"][s]["families"][f]["episodes"] for s in A["seeds"] if f in A["seeds"][s]["families"])
    fl = sum(A["seeds"][s]["families"][f]["flagged"] for s in A["seeds"] if f in A["seeds"][s]["families"])
    agg[f] = (fl, ep)
print("flagged/episodes", agg)
print("normal", sum(s["normal"]["flagged"] for s in A["seeds"].values()), "of", sum(s["normal"]["windows"] for s in A["seeds"].values()))
print("coverage", dict(cc), tot_m, "modes", len(modes))
g3 = [r["n_modes"] for r in H if len(r["engaged"]) == 3]; g2 = [r["n_modes"] for r in H if len(r["engaged"]) == 2]
print("mean modes 3 interns", np.mean(g3), len(g3), "2 interns", np.mean(g2), len(g2))
print("AG2 with >=1 mode", sum(1 for r in B["ag2"] if r["n_modes"] > 0), "of", len(B["ag2"]), "all APPROVED", all(r["verdict"] == "APPROVED" for r in B["ag2"]))
