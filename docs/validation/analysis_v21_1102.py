"""Checks of version 2.1 of the research specification: (A) its gate semantics by exhaustive enumeration, (B) the review burden of its interval-based risk rule (illustrative parameters)."""
import itertools
import json

import numpy as np

OUT = r"C:\Users\KHAOUL~1\AppData\Local\Temp\claude\C--Users-khaoula-Hidawi-PycharmProjects-Ailifeapp\34ed2835-bd76-43c0-981a-e7dfc0d451fa\scratchpad\v21_results.json"
rng = np.random.default_rng(20261102)
R = {}

# ───────── A. Gate, literal reading of section 3.6 ─────────
T_, F_, U_ = "T", "F", "U"
S_, V_ = "S", "V"
# one constraint: (App, rationale, Sat)   rationale only for App=F ; Sat only for App=T ; otherwise None
cstates = [(T_, None, S_), (T_, None, V_), (T_, None, U_), (U_, None, None), (F_, True, None), (F_, False, None)]
ORDER = {"APPROVED": 0, "REVIEW": 1, "BLOCKED": 2}


def gate(h1, h2, r1, stop, risk, wf, literal_unrationalised):
    if not wf:
        return "INVALID"
    hard = [h1, h2]
    blocked = stop or risk == "block" or any(c[0] == T_ and c[2] in (V_, U_) for c in hard)
    if blocked:
        return "BLOCKED"
    app_unknown = any(c[0] == U_ for c in (h1, h2, r1))
    unrationalised = any(c[0] == F_ and not c[1] for c in (h1, h2, r1))
    review_unmet = r1[0] == T_ and r1[2] != S_
    if literal_unrationalised is False and unrationalised:
        app_unknown = True                                         # completion: App=FALSE without a rationale counts as UNKNOWN
    if app_unknown or review_unmet or risk == "review":
        return "REVIEW"
    hard_ok = all((c[0] == T_ and c[2] == S_) or (c[0] == F_ and c[1]) for c in hard)
    review_ok = (r1[0] == F_) or (r1[0] == T_ and r1[2] == S_)
    if hard_ok and review_ok and risk == "pass":
        return "APPROVED"
    return "UNDEFINED"


cells = list(itertools.product(cstates, cstates, cstates, [False, True], ["pass", "review", "block"], [True]))
res = {}
for literal in (True, False):
    counts = {"APPROVED": 0, "REVIEW": 0, "BLOCKED": 0, "UNDEFINED": 0}
    approved_with_unrationalised = 0
    approved_with_unknown = 0
    gate_of = {}
    for c in cells:
        g = gate(*c, literal)
        gate_of[c] = g
        counts[g] += 1
        if g == "APPROVED":
            if any(x[0] == F_ and not x[1] for x in c[:3]):
                approved_with_unrationalised += 1
            if any(x[0] == U_ or (x[0] == T_ and x[2] == U_) for x in c[:3]):
                approved_with_unknown += 1
    worse_when_improved = 0
    improved_pairs = 0
    improve = {(T_, None, V_): (T_, None, S_), (T_, None, U_): (T_, None, S_), (F_, False, None): (F_, True, None)}
    for c, g in gate_of.items():
        for idx in range(3):
            nxt = improve.get(c[idx])
            if nxt is not None:
                c2 = list(c)
                c2[idx] = nxt
                g2 = gate_of[tuple(c2)]
                improved_pairs += 1
                rank = lambda z: 1.5 if z == "UNDEFINED" else ORDER[z]                              # noqa: E731
                if rank(g2) > rank(g):
                    worse_when_improved += 1
    # replacing a satisfied applicable constraint by an unknown one must never improve the gate
    improved_by_unknown = 0
    for c, g in gate_of.items():
        for idx in range(3):
            if c[idx] == (T_, None, S_):
                c2 = list(c)
                c2[idx] = (T_, None, U_)
                g2 = gate_of[tuple(c2)]
                if (1.5 if g2 == "UNDEFINED" else ORDER[g2]) < (1.5 if g == "UNDEFINED" else ORDER[g]):
                    improved_by_unknown += 1
    res["literal" if literal else "unrationalised_not_applicable_treated_as_unknown"] = {**counts, "approved_with_unrationalised_not_applicable": approved_with_unrationalised, "approved_with_unknown_inside": approved_with_unknown,
                                                                                         "improving_evidence_worsens_gate": worse_when_improved, "improving_pairs": improved_pairs, "unknown_improves_gate": improved_by_unknown}
R["gate_v21"] = {"states": len(cells), "variants": res}

# ───────── B. Review burden of the interval rule (illustrative) ─────────
def post_interval(x, n, a=0.5, b=0.5, draws=400):
    s = rng.beta(a + x, b + n - x, size=draws)
    return np.percentile(s, [2.5, 97.5])


B = []
n_dep = 600
p_true = np.exp(rng.normal(np.log(0.01), 0.8, size=n_dep))      # true annual probability per deployment (illustrative)
tol = 0.02                                                       # tolerance on the annual probability (illustrative; loss fixed at 1 unit)
for n in (10, 100, 1000, 10000, 100000):
    block = review = passed = false_approve = false_block = 0
    for p in p_true:
        x = int(rng.binomial(n, p))
        lo, hi = post_interval(x, n)
        if lo > tol:
            block += 1
            false_block += p <= tol
        elif hi <= tol:
            passed += 1
            false_approve += p > tol
        else:
            review += 1
    B.append({"n": n, "blocked": block / n_dep, "review": review / n_dep, "pass": passed / n_dep, "false_approvals_among_passed": (false_approve / passed) if passed else None,
              "false_blocks_among_blocked": (false_block / block) if block else None})
R["review_burden"] = {"deployments": n_dep, "tolerance": tol, "true_p_median": float(np.median(p_true)), "share_truly_above_tolerance": float((p_true > tol).mean()), "rows": B}

# prior sensitivity of the gate: same data, four defensible priors
priors = {"uniform": (1, 1), "Jeffreys": (0.5, 0.5), "optimistic": (0.1, 9.9), "pessimistic": (1, 19)}
disagree = {}
for n in (100, 1000):
    d = 0
    for p in p_true[:300]:
        x = int(rng.binomial(n, p))
        outs = set()
        for a, b in priors.values():
            lo, hi = post_interval(x, n, a, b)
            outs.add("block" if lo > tol else "pass" if hi <= tol else "review")
        d += len(outs) > 1
    disagree[n] = d / 300
R["prior_sensitive_share"] = disagree
json.dump(R, open(OUT, "w", encoding="utf-8"), indent=1, default=str)
print("done")
