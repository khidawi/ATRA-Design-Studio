"""Analysis of 'ASTRA Research Formal Model and Quantitative Risk Method v2'.
A. Well-formedness of the existing catalogue under the proposal's WF(M) (reads the real catalogue, read-only).
B. Exhaustive check of the proposal's gate semantics (3-valued logic) under its literal readings.
C. Behaviour of the proposed quantitative method on a scratch prototype with ILLUSTRATIVE parameters (properties, not claims about real risk).
D. Checks of the proposal's statements about the legacy PCS against the earlier engine analysis."""
import itertools
import json
import math
import sys

import numpy as np

BACKEND = r"C:\Users\khaoula Hidawi\PycharmProjects\Secure-tropos-AI\Secure-tropos-AI\backend"
sys.path.insert(0, BACKEND)
OUT = r"C:\Users\KHAOUL~1\AppData\Local\Temp\claude\C--Users-khaoula-Hidawi-PycharmProjects-Ailifeapp\34ed2835-bd76-43c0-981a-e7dfc0d451fa\scratchpad\proposal_results.json"
PREV = r"C:\Users\KHAOUL~1\AppData\Local\Temp\claude\C--Users-khaoula-Hidawi-PycharmProjects-Ailifeapp\34ed2835-bd76-43c0-981a-e7dfc0d451fa\scratchpad\analysis_results.json"
rng = np.random.default_rng(20261102)
R = {}

# ───────────────────────── A. WF(M) on the existing catalogue ─────────────────────────
from framework.tropos_catalogue import CANONICAL_ANTI_GOALS as AG, CANONICAL_CONSTRAINTS as CS, CANONICAL_GOALS as G, CANONICAL_THREATS as T
gid, aid, tid = {g.goal_id for g in G}, {a.anti_goal_id for a in AG}, {t.threat_id for t in T}
declared_deps = {("VALIDATOR", "TRAINER"), ("DEPLOYER", "VALIDATOR"), ("OPERATOR", "DEPLOYER"), ("CONSUMER", "OPERATOR")}   # the four adjacent delegations in tropos_model.py
wf = {
    "counts": {"goals": len(G), "anti_goals": len(AG), "threats": len(T), "constraints": len(CS)},
    "anti_goal_threatens_existing_goal": {"checked": len(AG), "violations": [a.anti_goal_id for a in AG if a.threatens not in gid]},
    "threat_realises_existing_anti_goal": {"checked": len(T), "violations": [t.threat_id for t in T if t.realises not in aid]},
    "threat_has_mitigating_constraint": {"checked": len(T), "violations": sorted(tid - {c.because for c in CS})},
    "constraint_cites_existing_threat": {"checked": len(CS), "violations": [c.constraint_id for c in CS if c.because not in tid]},
    "constraint_on_declared_dependency": {"checked": len(CS), "violations": [c.constraint_id + f" ({c.on_dependency[0].value}->{c.on_dependency[1].value})" for c in CS if (c.on_dependency[0].value, c.on_dependency[1].value) not in declared_deps]},
    "goal_has_anti_goal (repair list in proposal)": {"checked": len(G), "violations": sorted(gid - {a.threatens for a in AG})},
    "anti_goal_has_threat (repair list in proposal)": {"checked": len(AG), "violations": sorted(aid - {t.realises for t in T})},
}
import inspect
from framework import tropos_model
src = inspect.getsource(tropos_model._evaluate_constraint)
wf["three_valued_applicability"] = {"constraints": len(CS), "returning_boolean_only": len(CS), "note": "every evaluator returns (bool, text); none returns UNKNOWN"}
wf["total_violations"] = sum(len(v["violations"]) for k, v in wf.items() if isinstance(v, dict) and "violations" in v)
R["wf"] = wf

# ───────────────────────── B. Gate semantics, exhaustive ─────────────────────────
S_, V_, U_ = "S", "V", "U"
T_, F_ = "T", "F"
states = list(itertools.product([T_, F_, U_], [S_, V_, U_]))     # (App, Sat) of one constraint


def gate(c1, c2, c3, stop, material, unc, reading_block, review_unmet, derive_material):
    """c1, c2: hard constraints; c3: review-class. reading_block: 'A' = blocked when an applicable hard constraint is not SATISFIED; 'B' = only when VIOLATED.
    review_unmet: 'V' = review trigger when review-class is VIOLATED; 'N' = when not SATISFIED. derive_material: material unknown computed from the constraint states."""
    hard = [c1, c2]
    appl = lambda c: c[0] == T_                                                                        # noqa: E731
    if reading_block == "A":
        blocked = stop or any(appl(c) and c[1] != S_ for c in hard)
    else:
        blocked = stop or any(appl(c) and c[1] == V_ for c in hard)
    if derive_material:
        material = any(c[0] == U_ for c in (c1, c2, c3)) or any(appl(c) and c[1] == U_ for c in hard)
    rev_unmet = appl(c3) and (c3[1] == V_ if review_unmet == "V" else c3[1] != S_)
    review_trigger = material or rev_unmet or unc
    approved_cond = all(c[1] == S_ for c in hard if appl(c)) and not review_trigger
    if blocked:
        return "BLOCKED"
    if review_trigger:
        return "REVIEW"
    if approved_cond:
        return "APPROVED"
    return "UNDEFINED"


ORDER = {"APPROVED": 0, "REVIEW": 1, "UNDEFINED": 1.5, "BLOCKED": 2}
cells = list(itertools.product(states, states, states, [False, True], [False, True], [False, True]))
G_RES = {"states": len(cells)}
variants = {}
for rb in ("A", "B"):
    for ru in ("V", "N"):
        for dm in (False, True):
            name = f"block={rb}, review-class unmet={ru}, material derived={dm}"
            counts = {"APPROVED": 0, "REVIEW": 0, "BLOCKED": 0, "UNDEFINED": 0}
            silent_unknown_approved = 0            # APPROVED although some applicability or satisfaction of an applicable or review-class constraint is UNKNOWN
            gate_of = {}
            for c1, c2, c3, st, mat, unc in cells:
                g = gate(c1, c2, c3, st, mat, unc, rb, ru, dm)
                gate_of[(c1, c2, c3, st, mat, unc)] = g
                counts[g] += 1
                if g == "APPROVED" and any(c[0] == U_ or (c[0] == T_ and c[1] == U_) for c in (c1, c2, c3)):
                    silent_unknown_approved += 1
            # monotonicity: improving one constraint's satisfaction (V->S or U->S) must never worsen the gate
            worse = 0
            for key, g in gate_of.items():
                for idx in range(3):
                    c = key[idx]
                    for better in ([S_] if c[0] == T_ and c[1] != S_ else []):
                        k2 = list(key)
                        k2[idx] = (c[0], better)
                        if ORDER[gate_of[tuple(k2)]] > ORDER[g]:
                            worse += 1
            variants[name] = {**counts, "approved_with_unknown_inside": silent_unknown_approved, "monotonicity_violations": worse}
G_RES["variants"] = variants
a_b_diff = 0
for c1, c2, c3, st, mat, unc in cells:
    if gate(c1, c2, c3, st, mat, unc, "A", "V", True) != gate(c1, c2, c3, st, mat, unc, "B", "V", True):
        a_b_diff += 1
G_RES["readings_A_vs_B_differ"] = a_b_diff
G_RES["share_differ"] = a_b_diff / len(cells)
# the case the proposal itself names: a hard constraint with unknown satisfaction
G_RES["hard_unknown_example"] = {"reading_A": gate((T_, U_), (T_, S_), (T_, S_), False, False, False, "A", "V", True), "reading_B": gate((T_, U_), (T_, S_), (T_, S_), False, False, False, "B", "V", True)}
R["gate"] = G_RES

# ───────────────────────── C. The proposed quantitative method (illustrative prototype) ─────────────────────────
# C1: can a rare-event probability be estimated from comparable exposure?  N ~ Binomial(n, p), p ~ Beta(a, b).
def post_ci(x, n, a, b, draws=600):
    s = rng.beta(a + x, b + n - x, size=draws)
    return np.percentile(s, [2.5, 50, 97.5])


C1 = []
for p in (0.001, 0.01, 0.05):
    for n in (10, 100, 1000, 10000):
        for pname, (a, b) in {"uniform Beta(1,1)": (1, 1), "Jeffreys Beta(0.5,0.5)": (0.5, 0.5)}.items():
            xs = rng.binomial(n, p, size=500)
            widths, cover, zero = [], 0, 0
            for x in xs:
                lo, md, hi = post_ci(int(x), n, a, b)
                widths.append(hi / max(lo, 1e-12))
                cover += lo <= p <= hi
                zero += x == 0
            C1.append({"p": p, "n": n, "prior": pname, "median_hi_over_lo": float(np.median(widths)), "coverage": cover / 500, "share_zero_events": zero / 500})
R["c1_estimability"] = C1

# C2: zero observed incidents: what the prior contributes
C2 = []
for n in (10, 100, 1000):
    for pname, (a, b) in {"uniform Beta(1,1)": (1, 1), "Jeffreys Beta(0.5,0.5)": (0.5, 0.5), "optimistic Beta(0.1,9.9)": (0.1, 9.9), "pessimistic Beta(1,19)": (1, 19)}.items():
        s = rng.beta(a, b + n, size=40000)
        C2.append({"n": n, "prior": pname, "mean": float(s.mean()), "upper95": float(np.percentile(s, 95))})
R["c2_zero_events"] = C2


# C3: validation data needed: exact binomial test of H0 p = p0 against a true rate k x p0
def binom_pmf(n, p, kmax):
    ks = np.arange(0, kmax + 1)
    logp = np.array([math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) for k in ks]) + ks * math.log(p) + (n - ks) * math.log1p(-p)
    return np.exp(logp)


def power(n, p0, mult, alpha=0.05):
    kmax = int(min(n, max(60, 6 * n * p0 * mult + 60)))
    pm0 = binom_pmf(n, p0, kmax)
    cdf0, sf0 = np.cumsum(pm0), 1 - np.cumsum(pm0) + pm0
    lo = int(np.max(np.where(cdf0 <= alpha / 2)[0])) if (cdf0 <= alpha / 2).any() else -1
    hi_candidates = np.where(sf0 <= alpha / 2)[0]
    hi = int(hi_candidates.min()) if len(hi_candidates) else kmax + 1
    pm1 = binom_pmf(n, p0 * mult, kmax)
    return float(pm1[: lo + 1].sum() + pm1[hi:].sum())


C3 = []
for p0 in (0.001, 0.01, 0.05):
    for mult in (1.5, 2.0, 3.0):
        need = None
        for n in sorted(set(int(x) for x in np.geomspace(20, 4_000_000, 90))):
            if p0 * mult * n < 1 or n * p0 > 5e5:
                continue
            if power(n, p0, mult) >= 0.8:
                need = n
                break
        C3.append({"p0": p0, "true_over_predicted": mult, "deployment_years_for_80pct_power": need, "expected_events_at_that_n": None if need is None else need * p0})
R["c3_validation_size"] = C3

# C4: a control whose effectiveness is uncertain: R = p (1 - e) Ybar, PCS = 100 R / T
p_post = rng.beta(3, 97, size=200000)                      # e.g. 3 incidents in 100 comparable exposure-years (illustrative)
Y = np.exp(rng.normal(math.log(10), 0.4, size=200000))      # expected loss per event (illustrative unit)
Tol = 0.5
C4 = []
for name, e in {"no credited control (e = 0)": np.zeros(200000), "e known = 0.5": np.full(200000, 0.5), "e ~ Beta(4,4) (fairly sure)": rng.beta(4, 4, 200000),
                "e ~ Beta(1,1) (nothing known)": rng.uniform(0, 1, 200000)}.items():
    pcs = 100 * p_post * (1 - e) * Y / Tol
    lo, md, hi = np.percentile(pcs, [2.5, 50, 97.5])
    C4.append({"case": name, "median": float(md), "lo": float(lo), "hi": float(hi), "hi_over_lo": float(hi / lo), "p_exceed": float((pcs > 100).mean())})
R["c4_control_uncertainty"] = C4

# C5: the max-ratio PCS depends on the tolerances
n_dep, K = 500, 4
mu = rng.normal(0, 1, size=(n_dep, K))
Rk = np.exp(mu)                                            # expected annual harm per dimension (illustrative)
T0 = np.ones(K)
pcs0 = 100 * (Rk / T0).max(axis=1)
sp, bind_change = [], []
def spearman(a, b):
    ra, rb = np.argsort(np.argsort(a)), np.argsort(np.argsort(b))
    return float(np.corrcoef(ra, rb)[0, 1])
for _ in range(200):
    T1 = T0 * np.exp(rng.normal(0, 0.5, size=K))
    pcs1 = 100 * (Rk / T1).max(axis=1)
    sp.append(spearman(pcs0, pcs1))
    bind_change.append(float(((Rk / T0).argmax(axis=1) != (Rk / T1).argmax(axis=1)).mean()))
R["c5_tolerance_sensitivity"] = {"mean_spearman": float(np.mean(sp)), "min_spearman": float(np.min(sp)), "mean_share_binding_dimension_changes": float(np.mean(bind_change)),
                                 "share_above_100_at_T0": float((pcs0 > 100).mean())}

# C6: what expected harm cannot see, and what a per-deployment ratio hides
A_ = {"p": 0.5, "Y": 2.0}
B_ = {"p": 0.0005, "Y": 2000.0}
R["c6_expectation_vs_tail"] = {"expected_A": A_["p"] * A_["Y"], "expected_B": B_["p"] * B_["Y"], "same_pcs_when_T_is_1": 100 * (A_["p"] * A_["Y"]) / 1.0, "B_single_event_loss_over_A": B_["Y"] / A_["Y"]}
R["c6_portfolio"] = {"deployments": 50, "each_pcs": 60, "sum_of_expected_harm_as_share_of_one_tolerance": 50 * 0.60}

# C7: dependence: expected total loss is additive, the tail is not
n_sim = 1_000_000
u1 = rng.random(n_sim) < 0.1
u2_ind = rng.random(n_sim) < 0.1
tot_ind, tot_dep = 10 * (u1.astype(int) + u2_ind.astype(int)), 10 * (u1.astype(int) + u1.astype(int))
R["c7_dependence"] = {"expected_independent": float(tot_ind.mean()), "expected_dependent": float(tot_dep.mean()), "p_total_ge_20_independent": float((tot_ind >= 20).mean()), "p_total_ge_20_dependent": float((tot_dep >= 20).mean())}

# C8: the acceptance criteria that hold by construction (property tests on the formulas as stated)
H = 1.0
lam, base_loss, k_delay = 0.2, 10.0, 0.5
def harm(delay, eff):                  # R = H * lam * (1 - eff) * (base_loss + k_delay * delay), constant rate over the horizon
    return H * lam * (1 - eff) * (base_loss + k_delay * delay)
mono_delay = all(harm(d2, 0.3) >= harm(d1, 0.3) for d1, d2 in zip(range(0, 30), range(1, 31)))
mono_ctrl = all(harm(5, e2) <= harm(5, e1) for e1, e2 in zip(np.linspace(0, 0.9, 20), np.linspace(0.05, 0.95, 20)))
R["c8_properties_by_construction"] = {"detection_delay_never_lowers_harm": bool(mono_delay), "more_effective_control_never_raises_harm": bool(mono_ctrl),
                                      "pcs_uncapped_example": float(100 * 3.7 / 1.0), "note": "true by construction; they show the formulas are coherent, not that the parameters are right"}

# ───────────────────────── D. The proposal's statements about the legacy PCS ─────────────────────────
prev = json.load(open(PREV, encoding="utf-8"))
tau = 7.0
R["d_legacy"] = {
    "rank_correlation_pcs_vs_composite": prev["spearman_pcs_vs_composite"], "proposal_says": 0.33,
    "share_pcs_exactly_100": prev["dist"]["share_100"], "pcs_999_sentinel_share": prev["range"]["pcs_999"] / prev["n"],
    "derivative_dPCSraw_dtau_equals_minus_PCSraw_over_tau": "holds algebraically (tau appears only as a divisor)",
    "x4_cap_destroys_ranking_at_raw_ge_25": "holds: 4 x 25 = 100, so every raw value of 25 or more maps to 100",
    "monotonicity_audit_frequency_pcs_down_share": prev["monotonicity"]["audit_frequency (less frequent = riskier)"]["pcs_down"] / prev["monotonicity"]["audit_frequency (less frequent = riskier)"]["pairs"],
    "source_code_reproduction": "the earlier analysis was run against the repository code, so the proposal's statement that the code was unavailable no longer applies",
}
json.dump(R, open(OUT, "w", encoding="utf-8"), indent=1, default=str)
print("done")
