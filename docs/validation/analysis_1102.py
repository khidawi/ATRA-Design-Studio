"""Read-only validation analysis of the PCS engine (framework/rule_engine.py). Nothing in the repository is changed:
variants of the engine are built in memory from its source text."""
import itertools
import json
import random
import sys
import time
import types

import numpy as np

BACKEND = r"C:\Users\khaoula Hidawi\PycharmProjects\Secure-tropos-AI\Secure-tropos-AI\backend"
sys.path.insert(0, BACKEND)
from framework.enums import (AICriticalityEnum as CR, AISystemTypeEnum as ST, AuditFrequencyEnum as AF, BiasMetricEnum, ConsumptionRoleEnum as CO, DataConsentEnum as DC,
                             ExperienceLevelEnum as EX, FeedbackLoopEnum as FL, GovernanceMaturityEnum as GM, InsiderRoleEnum as IR, LawTypeEnum as LT, ModelTypeEnum as MT,
                             SensitivityEnum as SE, SilentFailureEnum as SF, VectorTypeEnum as VT)
from framework.registry import RegistryState
import framework.rule_engine as live

OUT = r"C:\Users\KHAOUL~1\AppData\Local\Temp\claude\C--Users-khaoula-Hidawi-PycharmProjects-Ailifeapp\34ed2835-bd76-43c0-981a-e7dfc0d451fa\scratchpad\analysis_results.json"
GATE = {"APPROVED": 0, "REQUIRES_REVIEW": 1, "BLOCKED": 2}
TIER = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}
BIAS = list(BiasMetricEnum)[0]

CONTROLS = ["dpia_approved", "hitl_formally_specified", "right_to_challenge_documented", "liability_boundary_declared", "hallucination_constraint_declared",
            "output_validation_gate_configured", "model_card_approved", "operator_training_complete", "hitl_verified_substantive", "policy_hallucination_acknowledged",
            "signed_at_collection"]

FACTORS = {
    "model_type": list(MT), "system_type": list(ST), "ai_criticality": list(CR), "data_sensitivity": list(SE), "consumption_role": list(CO), "feedback_loop": list(FL),
    "audit_frequency": list(AF), "silent": [[], [SF.PERFORMANCE_DRIFT], [SF.BIAS_DRIFT], [SF.DATA_LEAK]], "domain_law": [None] + list(LT), "governance_maturity": list(GM),
    "experience_level": list(EX), "data_consent": [DC.EXPLICIT, DC.IMPLIED],
}


def sample(rng):
    kw = {k: rng.choice(v) for k, v in FACTORS.items()}
    for c in CONTROLS:
        kw[c] = rng.random() < 0.5
    kw["bias_metric"] = BIAS if rng.random() < 0.5 else None
    kw["chained"] = rng.random() < 0.25
    kw["supply"] = rng.random() < 0.25
    kw["data_engineer"] = rng.random() < 0.25
    kw["tv"], kw["vd"], kw["td"] = (rng.random() < 0.2 for _ in range(3))
    kw["comp"] = rng.choice([0, 0, 1])
    kw["misuse"] = rng.choice([0, 0, 0, 1, 3])
    kw["drift"] = rng.random() < 0.15
    return kw


def build(kw):
    av = ([VT.CHAINED_AI] if kw["chained"] else []) + ([VT.SUPPLY_CHAIN] if kw["supply"] else [])
    return RegistryState(
        model_type=kw["model_type"], system_type=kw["system_type"], ai_criticality=kw["ai_criticality"], data_sensitivity=kw["data_sensitivity"], consumption_role=kw["consumption_role"],
        feedback_loop=kw["feedback_loop"], audit_frequency=kw["audit_frequency"], silent_failures=list(kw["silent"]), domain_law=kw["domain_law"],
        governance_maturity=kw["governance_maturity"], experience_level=kw["experience_level"], data_consent=kw["data_consent"], bias_metric=kw["bias_metric"],
        attack_vectors=av, insider_roles=[IR.DATA_ENGINEER] if kw["data_engineer"] else [], trainer_is_validator=kw["tv"], validator_is_deployer=kw["vd"],
        trainer_is_deployer=kw["td"], compensating_controls=kw["comp"], misuse_incident_count=kw["misuse"], drift_detected=kw["drift"], **{c: kw[c] for c in CONTROLS})


def run(kw, engine=live):
    t = engine.derive_terms(build(kw))
    rv = t.risk_vector
    return {"pcs": t.pcs_score, "tier": TIER[t.tier.value], "gate": GATE[t.gate_decision.value], "comp": rv.composite if rv else 0.0,
            "pillars": [rv.likelihood, rv.severity, rv.vulnerability, rv.uncertainty, rv.autonomy, rv.evolution] if rv else [0] * 6, "nb": len(t.blockers), "nw": len(t.warnings)}


def variant(replacements):
    src = open(BACKEND + r"\framework\rule_engine.py", encoding="utf-8").read()
    for a, b in replacements:
        assert src.count(a) >= 1, a
        src = src.replace(a, b)
    m = types.ModuleType("framework.rule_engine_variant")
    m.__package__ = "framework"
    exec(compile(src, "rule_engine_variant", "exec"), m.__dict__)
    return m


R = {}
rng = random.Random(20261102)
N = 12000
t0 = time.time()
S = [sample(rng) for _ in range(N)]
res = [run(k) for k in S]
R["timing_s"] = round(time.time() - t0, 1)
R["n"] = N

# ── 1. Verification-type checks: determinism, ranges ──
R["deterministic"] = all(run(S[i]) == res[i] for i in range(0, N, 60))
pcs = np.array([r["pcs"] for r in res])
R["range"] = {"pcs_over_100": int((pcs > 100).sum()), "pcs_999": int((pcs == 999).sum()), "pcs_below_0": int((pcs < 0).sum()),
              "pillar_out_of_range": int(sum(1 for r in res for p in r["pillars"] if p < 0 or p > 100))}
R["pcs_999_examples"] = [{"model": S[i]["model_type"].value, "domain": None if S[i]["domain_law"] is None else S[i]["domain_law"].value} for i in range(N) if res[i]["pcs"] == 999][:3]

# ── 2. Distribution and resolution ──
fin = pcs[pcs <= 100]
R["dist"] = {"share_100": float((pcs == 100).mean()), "share_ge60": float((pcs >= 60).mean()), "share_30_60": float(((pcs >= 30) & (pcs < 60)).mean()), "share_10_30": float(((pcs >= 10) & (pcs < 30)).mean()),
             "share_lt10": float((pcs < 10).mean()), "median": float(np.median(fin)), "distinct_values": int(len(set(np.round(fin, 1)))), "min": float(fin.min())}
g = np.array([r["gate"] for r in res])
R["gate_share"] = {"APPROVED": float((g == 0).mean()), "REQUIRES_REVIEW": float((g == 1).mean()), "BLOCKED": float((g == 2).mean())}
comp = np.array([r["comp"] for r in res])
R["comp_dist"] = {"median": float(np.median(comp)), "max": float(comp.max()), "share_ge60": float((comp >= 60).mean()), "share_ge30": float((comp >= 30).mean())}
for i, name in enumerate(["likelihood", "severity", "vulnerability", "uncertainty", "autonomy", "evolution"]):
    col = np.array([r["pillars"][i] for r in res])
    R.setdefault("pillar_stats", {})[name] = {"median": round(float(np.median(col)), 1), "p95": round(float(np.percentile(col, 95)), 1), "max": round(float(col.max()), 1)}


def ranks(a):
    order = np.argsort(a, kind="mergesort")
    r = np.empty(len(a))
    r[order] = np.arange(len(a))
    for v in np.unique(a):
        idx = np.where(a == v)[0]
        if len(idx) > 1:
            r[idx] = r[idx].mean()
    return r


ok = pcs <= 100
R["spearman_pcs_vs_composite"] = float(np.corrcoef(ranks(pcs[ok]), ranks(comp[ok]))[0, 1])
tiers_pcs = np.array([r["tier"] for r in res])
tiers_comp = np.array([0 if c < 10 else 1 if c < 30 else 2 if c < 60 else 3 for c in comp])
R["tier_disagree"] = {"differ": float((tiers_pcs != tiers_comp).mean()), "by_two_or_more": float((abs(tiers_pcs - tiers_comp) >= 2).mean()),
                      "pcs_critical_comp_below_30": float(((tiers_pcs == 3) & (comp < 30)).mean())}

# ── 3. Limiting cases ──
best = dict(model_type=MT.CNN, system_type=ST.TYPE_1_INHOUSE, ai_criticality=CR.ADVISORY, data_sensitivity=SE.PUBLIC, consumption_role=CO.ADVISORY_READER, feedback_loop=FL.NONE,
            audit_frequency=AF.CONTINUOUS, silent=[], domain_law=None, governance_maturity=GM.OPTIMISING, experience_level=EX.SENIOR, data_consent=DC.EXPLICIT, bias_metric=BIAS,
            chained=False, supply=False, data_engineer=False, tv=False, vd=False, td=False, comp=0, misuse=0, drift=False, **{c: True for c in CONTROLS})
worst = dict(best, model_type=MT.LLM, system_type=ST.TYPE_3_THIRDPARTY_API, ai_criticality=CR.SAFETY_CRITICAL, data_sensitivity=SE.SPECIAL_CATEGORY, consumption_role=CO.AUTOMATED_EXECUTOR,
             feedback_loop=FL.AUTOMATED, audit_frequency=AF.QUARTERLY, silent=[SF.BIAS_DRIFT], domain_law=LT.CLINICAL_SAFETY, governance_maturity=GM.AD_HOC, experience_level=EX.NOVICE,
             data_consent=DC.IMPLIED, bias_metric=None, chained=True, supply=True, data_engineer=True, tv=True, vd=True, td=True, misuse=3, drift=True, **{c: False for c in CONTROLS})
R["best_case"] = run(best)
R["worst_case"] = run(worst)
# best declared controls but an inherently risky deployment
risky_good = dict(worst, **{c: True for c in CONTROLS}, bias_metric=BIAS, tv=False, vd=False, td=False, data_consent=DC.EXPLICIT, drift=False, misuse=0)
R["risky_but_all_controls"] = run(risky_good)
low_risk_nocontrols = dict(best, **{c: False for c in CONTROLS}, bias_metric=None)
R["lowrisk_no_controls_advisory"] = run(low_risk_nocontrols)
R["lowrisk_no_controls_operational"] = run(dict(low_risk_nocontrols, ai_criticality=CR.OPERATIONAL))

# ── 4. Monotonicity ──
ORDERS = {
    "audit_frequency (less frequent = riskier)": ("audit_frequency", [AF.CONTINUOUS, AF.DAILY, AF.WEEKLY, AF.QUARTERLY]),
    "feedback_loop (none to automated)": ("feedback_loop", [FL.NONE, FL.HUMAN_REVIEWED, FL.AUTOMATED]),
    "system_type (in-house to third party)": ("system_type", [ST.TYPE_1_INHOUSE, ST.TYPE_2_FINETUNED, ST.TYPE_3_THIRDPARTY_API]),
    "ai_criticality (advisory to safety critical)": ("ai_criticality", [CR.ADVISORY, CR.OPERATIONAL, CR.CRITICAL, CR.SAFETY_CRITICAL]),
    "consumption_role (reader to automated executor)": ("consumption_role", [CO.ADVISORY_READER, CO.DECISION_MAKER, CO.AUTOMATED_EXECUTOR]),
    "data_sensitivity (public to special category)": ("data_sensitivity", [SE.PUBLIC, SE.INTERNAL, SE.CONFIDENTIAL, SE.SENSITIVE_PERSONAL, SE.SPECIAL_CATEGORY]),
    "governance_maturity (optimising to ad hoc)": ("governance_maturity", [GM.OPTIMISING, GM.MEASURED, GM.MANAGED, GM.DOCUMENTED, GM.AD_HOC]),
    "experience_level (senior to novice)": ("experience_level", [EX.SENIOR, EX.JUNIOR, EX.NOVICE]),
    "data_consent (explicit to implied)": ("data_consent", [DC.EXPLICIT, DC.IMPLIED]),
    "silent failure (none, performance, bias)": ("silent", [[], [SF.PERFORMANCE_DRIFT], [SF.BIAS_DRIFT]]),
    "misuse incidents (0, 1, 3)": ("misuse", [0, 1, 3]),
    "runtime drift (no to yes)": ("drift", [False, True]),
    "chained-AI vector (absent to present)": ("chained", [False, True]),
    "supply-chain vector (absent to present)": ("supply", [False, True]),
    "role consolidation trainer=validator (no to yes)": ("tv", [False, True]),
    "compensating controls (1 to 0)": ("comp", [1, 0]),
}
for c in CONTROLS:
    ORDERS[f"control {c} (declared to missing)"] = (c, [True, False])
ORDERS["bias metric (declared to missing)"] = ("bias_metric", [BIAS, None])
M = {}
base = S[:2500]
for label, (key, levels) in ORDERS.items():
    n = pcs_down = gate_better = comp_down = pcs_flat = pcs_up = 0
    for b in base:
        prev = None
        for lv in levels:
            r = run(dict(b, **{key: lv}))
            if prev is not None and r["pcs"] <= 100 and prev["pcs"] <= 100:
                n += 1
                if r["pcs"] < prev["pcs"] - 1e-9:
                    pcs_down += 1
                elif r["pcs"] > prev["pcs"] + 1e-9:
                    pcs_up += 1
                else:
                    pcs_flat += 1
                if r["gate"] < prev["gate"]:
                    gate_better += 1
                if r["comp"] < prev["comp"] - 1e-9:
                    comp_down += 1
            prev = r
    M[label] = {"pairs": n, "pcs_up": pcs_up, "pcs_flat": pcs_flat, "pcs_down": pcs_down, "gate_improved": gate_better, "composite_down": comp_down}
R["monotonicity"] = M

# ── 5. Global sensitivity: first-order variance share (eta squared) ──
def eta2(values, y):
    values = list(values)
    groups = {}
    for v, yy in zip(values, y):
        groups.setdefault(v, []).append(yy)
    mu = y.mean()
    between = sum(len(g_) * (np.mean(g_) - mu) ** 2 for g_ in groups.values())
    return float(between / ((y - mu) ** 2).sum())


y_pcs = np.where(pcs <= 100, pcs, 100)
y_blk = (g == 2).astype(float)
E2 = {}
keys = {k: [str(getattr(s[k], "value", s[k])) for s in S] for k in list(FACTORS) + CONTROLS + ["bias_metric", "chained", "supply", "data_engineer", "tv", "vd", "td", "comp", "misuse", "drift"]}
keys["silent"] = [",".join(x.value for x in s["silent"]) for s in S]
for k, vals in keys.items():
    E2[k] = {"pcs": round(eta2(vals, y_pcs), 4), "blocked": round(eta2(vals, y_blk), 4)}
R["eta2"] = E2

# ── 6. Sensitivity to constants and to assumptions (in-memory variants) ──
def compare(variant_engine, name, n=5000):
    dg = dt = 0
    dp = []
    appr = [0, 0]
    for s, r0 in zip(S[:n], res[:n]):
        r1 = run(s, variant_engine)
        dg += r1["gate"] != r0["gate"]
        dt += r1["tier"] != r0["tier"]
        if r0["pcs"] <= 100 and r1["pcs"] <= 100:
            dp.append(abs(r1["pcs"] - r0["pcs"]))
        appr[0] += r0["gate"] == 0
        appr[1] += r1["gate"] == 0
    return {"name": name, "gate_changed": dg / n, "tier_changed": dt / n, "mean_abs_dpcs": float(np.mean(dp)), "approved_before": appr[0] / n, "approved_after": appr[1] / n}


V = []
V.append(compare(variant([("raw * 4.0", "raw * 3.0")]), "scaling factor 4 to 3"))
V.append(compare(variant([("raw * 4.0", "raw * 5.0")]), "scaling factor 4 to 5"))
V.append(compare(variant([("t.pcs_score >= 60: t.tier", "t.pcs_score >= 50: t.tier")]), "CRITICAL cut-off 60 to 50"))
V.append(compare(variant([("t.pcs_score >= 60: t.tier", "t.pcs_score >= 70: t.tier")]), "CRITICAL cut-off 60 to 70"))
V.append(compare(variant([("t.pcs_score >= 30: t.tier", "t.pcs_score >= 25: t.tier")]), "HIGH cut-off 30 to 25"))
V.append(compare(variant([("t.pcs_score >= 30: t.tier", "t.pcs_score >= 35: t.tier")]), "HIGH cut-off 30 to 35"))
V.append(compare(variant([("_floor = min(100.0, 30.0 + _veto_weights)", "_floor = min(100.0, 20.0 + _veto_weights)")]), "veto floor base 30 to 20"))
V.append(compare(variant([("_floor = min(100.0, 30.0 + _veto_weights)", "_floor = min(100.0, 40.0 + _veto_weights)")]), "veto floor base 30 to 40"))
V.append(compare(variant([("_floor = min(100.0, 30.0 + _veto_weights)", "_floor = 0.0")]), "assumption relaxed: no veto floor"))
V.append(compare(variant([("    if _crit_blocks_apply:\n        # SC-HITL-1 \u2192 Autonomy (via ACM)", "    if False:\n        # SC-HITL-1 \u2192 Autonomy (via ACM)")]), "assumption relaxed: no constraint penalties"))
R["variants"] = V

# ── 7. Exhaustive property checks on a discrete sub-space ──
base_cfg = dict(best, system_type=ST.TYPE_2_FINETUNED, consumption_role=CO.DECISION_MAKER, audit_frequency=AF.WEEKLY, governance_maturity=GM.MANAGED)
P = {"runs": 0, "p1_violations": 0, "p2_violations": 0, "p3_pairs": 0, "p3_gate_worse": 0, "p3_pcs_up": 0}
reach = {}
p1_examples, p3_examples = [], []
cache = {}
combos = list(itertools.product([True, False], repeat=len(CONTROLS)))
for crit in CR:
    for sens in (SE.SPECIAL_CATEGORY, SE.INTERNAL):
        for mt in (MT.LLM, MT.CNN):
            for bm in (BIAS, None):
                cell = dict(base_cfg, ai_criticality=crit, data_sensitivity=sens, model_type=mt, bias_metric=bm)
                key = (crit.value, sens.value, mt.value, bm is not None)
                results = {}
                for combo in combos:
                    kw = dict(cell, **dict(zip(CONTROLS, combo)))
                    r = run(kw)
                    results[combo] = r
                    P["runs"] += 1
                    blocked_by_veto = False
                    if crit != CR.ADVISORY:
                        c = dict(zip(CONTROLS, combo))
                        applies_map = sens == SE.SPECIAL_CATEGORY or crit in (CR.CRITICAL, CR.SAFETY_CRITICAL)
                        blocked_by_veto = (not c["hitl_formally_specified"]) or (sens == SE.SPECIAL_CATEGORY and not c["dpia_approved"]) or (not c["right_to_challenge_documented"]) \
                            or (not c["liability_boundary_declared"]) or (mt == MT.LLM and not c["hallucination_constraint_declared"]) \
                            or (applies_map and (bm is None or not c["output_validation_gate_configured"]))
                    if blocked_by_veto and r["gate"] != 2:
                        P["p1_violations"] += 1
                        if len(p1_examples) < 3:
                            p1_examples.append(key)
                    if r["pcs"] >= 60 and r["pcs"] <= 100 and r["gate"] != 2:
                        P["p2_violations"] += 1
                for combo, r in results.items():
                    for i, v in enumerate(combo):
                        if not v:
                            better = list(combo)
                            better[i] = True
                            r2 = results[tuple(better)]
                            P["p3_pairs"] += 1
                            if r2["gate"] > r["gate"]:
                                P["p3_gate_worse"] += 1
                                if len(p3_examples) < 3:
                                    p3_examples.append((key, CONTROLS[i]))
                            if r2["pcs"] > r["pcs"] + 1e-9:
                                P["p3_pcs_up"] += 1
                gs = [r["gate"] for r in results.values()]
                reach[key] = {"APPROVED": gs.count(0), "REQUIRES_REVIEW": gs.count(1), "BLOCKED": gs.count(2), "min_pcs": min(r["pcs"] for r in results.values()),
                              "pcs_at_all_controls": results[tuple([True] * len(CONTROLS))]["pcs"], "gate_at_all_controls": results[tuple([True] * len(CONTROLS))]["gate"]}
R["properties"] = P
R["p1_examples"], R["p3_examples"] = p1_examples, p3_examples
R["reach"] = {"|".join(map(str, k)): v for k, v in reach.items()}

# ── 8. How much can declared controls change the outcome? ──
irreducible = 0
reduce_frac = []
for s, r in zip(S[:4000], res[:4000]):
    if r["pcs"] > 100:
        continue
    allc = run(dict(s, **{c: True for c in CONTROLS}, bias_metric=BIAS, comp=1, tv=False, vd=False, td=False, data_consent=DC.EXPLICIT))
    nonec = run(dict(s, **{c: False for c in CONTROLS}, bias_metric=None))
    if allc["gate"] == 2:
        irreducible += 1
    if nonec["pcs"] > 0 and nonec["pcs"] <= 100:
        reduce_frac.append((nonec["pcs"] - allc["pcs"]) / nonec["pcs"])
R["controls_effect"] = {"still_blocked_with_every_control": irreducible / 4000, "mean_reduction_fraction": float(np.mean(reduce_frac)), "median_reduction_fraction": float(np.median(reduce_frac))}

# ── 9. Parameter inventory ──
import re
src = open(BACKEND + r"\framework\rule_engine.py", encoding="utf-8").read()
enums_src = open(BACKEND + r"\framework\enums.py", encoding="utf-8").read()
start = src.index("def derive_terms")
end = src.index("def _tier_for")
body = src[start:end]
body_nocomment = "\n".join(l.split("#")[0] for l in body.splitlines())
nums = re.findall(r"(?<![\w.])\d+\.?\d*(?![\w])", body_nocomment)
R["inventory"] = {"numeric_literals_in_derive_terms": len(nums), "distinct": len(set(nums)), "lines_of_derive_terms": body.count("\n"),
                  "log_statements": body.count("log.append"), "tables_in_enums": len(re.findall(r"^[A-Z_]+ = \{", enums_src, re.M))}

# ── 10. Does the engine crash on any declared input? ──
crash = {}
for cons in (DC.NONE, DC.UNKNOWN):
    bad = 0
    for s_ in S[:300]:
        try:
            run(dict(s_, data_consent=cons))
        except Exception as exc:
            bad += 1
            crash[cons.value] = type(exc).__name__ + ": " + str(exc)[:120]
    crash[cons.value + "_failures_of_300"] = bad
R["crash_test"] = crash
json.dump(R, open(OUT, "w", encoding="utf-8"), indent=1, default=str)
print("done", R["timing_s"], "s")
