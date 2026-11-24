import json, re, sys
from collections import Counter, defaultdict
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
out = Path(sys.argv[1]); ext = Path(sys.argv[2]); log1 = Path(sys.argv[3])
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
BLUE, ORANGE, GREY, GREEN = "#2b6cb0", "#dd8a3e", "#9aa5b1", "#2f855a"
mut = json.load(open(ext / "mutation.json")); full = json.load(open(ext / "ext_full.json"))
# first run: the existing test against every mutant
first = defaultdict(lambda: [0, 0])
for ln in open(log1, encoding="utf-8"):
    m = re.match(r"(existing test kills|STILL SURVIVES)\s+(\w+\.py):", ln)
    if m: first[m.group(2)][0 if m.group(1) == "existing test kills" else 1] += 1
ex_kill = sum(v[0] for v in first.values()); total = len(mut)
ext_kill = sum(1 for r in mut if r["killed"]); both = ext_kill + sum(1 for r in mut if not r["killed"] and r.get("killed_by_existing"))
equiv = total - both
# Fig 6: mutation score
fig, ax = plt.subplots(figsize=(7.6, 4.2))
vals = [ex_kill, ext_kill, both]; labels = ["Existing test\n(test_astra_model)", "Extended suite\n(E1 to E6)", "Both together"]
b = ax.bar(labels, vals, color=[GREY, BLUE, GREEN], width=0.55)
ax.axhline(total, color="#495057", lw=1, ls="--"); ax.text(-0.45, total + 1.5, f"all {total} mutants", ha="left", fontsize=9, color="#495057")
ax.axhline(total - equiv, color=ORANGE, lw=1, ls=":"); ax.text(-0.45, total - equiv - 5, f"{total - equiv} once {equiv} equivalent mutants are removed", fontsize=9, color=ORANGE)
for r, v in zip(b, vals): ax.text(r.get_x() + r.get_width() / 2, v - 3, f"{v} of {total}" + chr(10) + f"{100 * v / total:.0f}%", ha="center", va="top", fontsize=11, fontweight="bold", color="white")
ax.set_ylim(0, total + 12); ax.set_ylabel("Mutants caught (code changes that break the model)")
ax.set_title("Mutation testing of the production model: 88 deliberate code changes", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(out / "fig6_mutation_score.png", dpi=200); plt.close(fig)
# Fig 7: by file
files = ["gate.py", "statuses.py", "exposure.py", "contract.py"]
c1 = [sum(1 for r in mut if r["file"] == f and r["killed"]) for f in files]
c2 = [sum(1 for r in mut if r["file"] == f and not r["killed"] and r.get("killed_by_existing")) for f in files]
c3 = [sum(1 for r in mut if r["file"] == f and not r["killed"] and not r.get("killed_by_existing")) for f in files]
fig, ax = plt.subplots(figsize=(7.6, 4.2)); x = np.arange(len(files))
ax.bar(x, c1, color=BLUE, label="caught by the extended suite"); ax.bar(x, c2, bottom=c1, color=GREEN, label="caught only by the existing test")
ax.bar(x, c3, bottom=np.array(c1) + np.array(c2), color=ORANGE, label="survived both (equivalent changes)")
for i in range(len(files)):
    t = c1[i] + c2[i] + c3[i]; ax.text(i, t + 0.4, f"{c1[i] + c2[i]} of {t}", ha="center", fontsize=9)
ax.set_xticks(x); ax.set_xticklabels(files); ax.set_ylabel("Mutants"); ax.legend(frameon=False, fontsize=9, loc="upper left")
ax.set_ylim(0, max(np.array(c1) + np.array(c2) + np.array(c3)) + 8)
ax.set_title("Where the mutants were caught", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(out / "fig7_mutants_by_file.png", dpi=200); plt.close(fig)
# Fig 8: scale of the extended checks
f = {r["name"][:2]: r for r in full}
rows = [("E1 exhaustive gate: every status assignment", f["E1"]["counts"]["assignments"]), ("E2 evidence: event orderings tried", f["E2"]["counts"]["orderings"]),
        ("E3 attack paths: random estates compared", f["E3"]["counts"]["estates"]), ("E4 contract: tamper and malformed cases", sum(f["E4"]["counts"].values())),
        ("E5 learned evidence: exhaustive cases", f["E5"]["counts"]["cases"]), ("E6 boundaries: targeted cases", f["E6"]["counts"]["cases"])]
fig, ax = plt.subplots(figsize=(8.2, 3.8)); y = np.arange(len(rows))
ax.barh(y, [v for _, v in rows], color=BLUE); ax.set_xscale("log"); ax.set_yticks(y); ax.set_yticklabels([n for n, _ in rows]); ax.invert_yaxis()
for i, (_, v) in enumerate(rows): ax.text(v * 1.15, i, f"{v:,}", va="center", fontsize=9)
ax.set_xlim(10, 2e6); ax.set_xlabel("Cases (log scale); 0 violations in every row")
ax.set_title("Extended suite: size of each check, all pass", loc="left", fontweight="bold")
fig.tight_layout(); fig.savefig(out / "fig8_extended_checks.png", dpi=200); plt.close(fig)
print(dict(total=total, existing=ex_kill, extended=ext_kill, both=both, equivalent=equiv, by_file=list(zip(files, c1, c2, c3))))
