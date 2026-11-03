"""Model check of ASTRA research specification v2.5, part 2: the modules that are not in the TLA+ model.
(1) the gate with Releasable and review, and the six-case applicability function; (2) independence with obligations; (3) delegation and organisation
modules and quantitative identities (unchanged from the v2.4 check, run again); (4) static audit of the specification text: state components written,
predicates defined or declared, quantifier binding of every property. The TLA+ model is checked separately with TLC (docs/validation/AstraV25.tla)."""
import itertools
import json
import re
import zipfile
from collections import deque

import numpy as np

SCR = r"C:\Users\KHAOUL~1\AppData\Local\Temp\claude\C--Users-khaoula-Hidawi-PycharmProjects-Ailifeapp\34ed2835-bd76-43c0-981a-e7dfc0d451fa\scratchpad"
DOCS = r"C:\Users\khaoula Hidawi\PycharmProjects\Secure-tropos-AI\Secure-tropos-AI\docs"
OUT = DOCS + r"\validation\modelcheck_results_v25.json"
SPEC25 = DOCS + r"\ASTRA-Research-Formal-Modelv2.5-body.docx"
SPEC24 = DOCS + r"\ASTRA-Research-Formal-Modelv2.4-before-appendix-B.docx"
ACTIONS = json.load(open(DOCS + r"\validation\actions_v25.json", encoding="utf-8"))
R = {}

# ───────── reuse of the unchanged v2.4 modules (bfs, M2 delegation, organisation, quantitative identities) ─────────
v24 = open(SCR + r"\modelcheck_v24.py", encoding="utf-8").read().split("\n")
ns = {"itertools": itertools, "np": np, "deque": deque, "R": {}}
for lo, hi in ((17, 31), (178, 284), (380, 432), (480, 548)):
    exec("\n".join(v24[lo:hi]), ns)
R["delegation"] = {"spec": ns["R"]["m2_spec"], "mutation_no_scope_check": ns["R"]["m2_mutation_no_scope_check"]}
R["quantitative"] = {k: v for k, v in ns["R"].items() if k.startswith("q")}
org = ns["org_check"]
bfs = ns["bfs"]
R["organisation"] = {"3 units, 3 actors, no head rule": org(3, 3, False), "3 units, 3 actors, head rule": org(3, 3, True),
                     "4 units, 3 actors, no head rule": org(4, 3, False), "4 units, 3 actors, head rule": org(4, 3, True)}

# ───────── (1) applicability function in text: six combinations, four cases ─────────
def applicability(appraw, rationale):
    if appraw == "TRUE":
        return ("TRUE", "evaluated", "Sat")
    if appraw == "UNKNOWN":
        return ("UNKNOWN", "not evaluated", "UNKNOWN")
    return ("FALSE", "undefined", "NOT_APPLICABLE") if rationale == "valid" else ("UNKNOWN", "not evaluated", "UNKNOWN")


combos = list(itertools.product(("TRUE", "FALSE", "UNKNOWN"), ("valid", "absent")))
table = {c: applicability(*c) for c in combos}
R["applicability"] = {"combinations": len(combos), "all_defined": all(v is not None for v in table.values()),
                      "not_applicable_only_when_false_and_valid": all((v[2] == "NOT_APPLICABLE") == (c == ("FALSE", "valid")) for c, v in table.items()),
                      "rationale_never_changes_true_or_unknown": table[("TRUE", "valid")] == table[("TRUE", "absent")] and table[("UNKNOWN", "valid")] == table[("UNKNOWN", "absent")],
                      "unknown_never_becomes_not_applicable": all(v[2] != "NOT_APPLICABLE" for c, v in table.items() if c[0] == "UNKNOWN")}

# ───────── (1) gate with Releasable and review ─────────
CS = [("T", "S"), ("T", "V"), ("T", "U"), ("U", None), ("NA", None)]    # hard constraint states: App=TRUE with Sat, App=UNKNOWN, NOT_APPLICABLE
UNQ = ["none", "noQA_hard", "noQA_review", "ACC", "UNACC_hard", "UNACC_review"]
ORD = {"APPROVED": 0, "REVIEW": 1, "BLOCKED": 2}
RESOLVABLE = {"rc", "overlap", "unacc_review"}


def gate(h1, h2, r1, stop, rr, rq, unq):
    """returns (result, triggers)"""
    if stop or any(c[0] == "T" and c[1] in ("V", "U") for c in (h1, h2)) or "block" in (rr, rq) or unq == "UNACC_hard":
        return "BLOCKED", set()
    trig = set()
    if any(c[0] == "U" for c in (h1, h2, r1)):
        trig.add("appunk")
    if r1[0] == "T" and r1[1] != "S":
        trig.add("rc")
    if "overlap" in (rr, rq):
        trig.add("overlap")
    if unq in ("noQA_hard", "noQA_review"):
        trig.add("unq_noQA")
    if unq == "UNACC_review":
        trig.add("unacc_review")
    if trig:
        return "REVIEW", trig
    return "APPROVED", set()


def releasable(res, trig, review_covers):
    return res == "APPROVED" or (res == "REVIEW" and trig <= RESOLVABLE and trig <= review_covers)


cells = list(itertools.product(CS, CS, CS, [False, True], ["pass", "overlap", "block"], ["pass", "overlap", "block"], UNQ))
G = {c: gate(*c) for c in cells}
counts = {k: sum(1 for v in G.values() if v[0] == k) for k in ORD}
# a review covering exactly the triggers is available in every state; the strongest review cannot release anything that is not releasable by design
rel_with_best_review = {c: releasable(g[0], g[1], g[1]) for c, g in G.items()}
blocked_released = sum(1 for c, g in G.items() if g[0] == "BLOCKED" and rel_with_best_review[c])
unresolvable_released = sum(1 for c, g in G.items() if g[0] == "REVIEW" and (g[1] - RESOLVABLE) and rel_with_best_review[c])
review_states = [c for c, g in G.items() if g[0] == "REVIEW"]
review_resolvable = sum(1 for c in review_states if rel_with_best_review[c])
# the Approve guard of v2.4 (hard pass and risk pass only) versus the gate
v24_guard = lambda c: all((x[0] == "T" and x[1] == "S") or x[0] == "NA" for x in c[:2]) and not c[3] and c[4] == "pass" and c[5] == "pass" and c[6] in ("none", "ACC")
v24_stuck = sum(1 for c in review_states if v24_guard(c))
# release safety: guard strength (Releasable) implies gate APPROVED or a REVIEW result whose triggers are all resolvable
rs_viol = sum(1 for c, g in G.items() if rel_with_best_review[c] and not (g[0] == "APPROVED" or (g[0] == "REVIEW" and g[1] <= RESOLVABLE)))
# monotonicity: improving a hard-constraint status (V or U to S) never worsens the result; an unknown never improves it
imp = {("T", "V"): ("T", "S"), ("T", "U"): ("T", "S")}
worse = pairs = 0
for c, g in G.items():
    for idx in range(3):
        if c[idx] in imp:
            c2 = list(c); c2[idx] = imp[c[idx]]; pairs += 1
            worse += ORD[G[tuple(c2)][0]] > ORD[g[0]]
unk = sum(1 for c, g in G.items() for idx in range(3) if c[idx] == ("T", "S") and ORD[G[tuple(c[:idx]) + (("T", "U"),) + tuple(c[idx + 1:])][0]] < ORD[g[0]])
undefined = sum(1 for g in G.values() if g[0] not in ORD)
R["gate"] = {"states": len(cells), **counts, "undefined": undefined, "improving_pairs": pairs, "improvement_worsens_gate": worse, "unknown_improves_gate": unk,
             "blocked_states_released_by_best_review": blocked_released, "unresolvable_trigger_states_released_by_best_review": unresolvable_released,
             "review_states": len(review_states), "review_states_releasable_by_a_covering_review": review_resolvable, "review_states_needing_a_recorded_fact_first": len(review_states) - review_resolvable,
             "v24_approve_guard_enabled_but_gate_REVIEW": v24_stuck, "v25_release_safety_violations": rs_viol}

# ───────── (2) independence with obligations (CONTINUING) ─────────
def check_m4_v25(level, mode):
    """state: (struct, st, approved, prod, obl); struct 1 = approver supervises owner. Flag is urgent: time is not modelled, so the property is that production does not run
    with the requirement unmet and no obligation open once urgent actions have been taken."""
    def indep(struct):
        return True if level == "PERSON" else struct == 0

    def cp(s):
        struct, st, ap, prod, obl = s
        return ap == 1 and (mode == "AT_ACT" or indep(struct))

    def step(s):
        struct, st, ap, prod, obl = s
        out = [(("Reorganise",), (1 - struct, st, ap, prod, obl))]
        if st == 0:
            out.append((("Submit",), (struct, 1, ap, prod, obl)))
        if st == 1 and indep(struct):
            out.append((("Approve",), (struct, 2, 1, prod, obl)))
        if st == 2 and ap == 1 and cp(s):
            out.append((("Deploy",), (struct, 3, ap, 1, obl)))
        if prod == 1 and not cp(s) and obl == 0:
            out.append((("Flag",), (struct, st, ap, prod, 1)))
        if prod == 1 and obl == 1:
            out.append((("Suspend",), (struct, 4, ap, 0, 0)))
        if obl == 1 and (prod == 0 or cp(s)):
            out.append((("CloseObligation",), (struct, st, ap, prod, 0)))
        return out

    states, edges = bfs((0, 0, 0, 0, 0), step)
    running_unmet_no_obligation_stable = sum(1 for s in states if s[3] == 1 and not cp(s) and s[4] == 0 and not any(l[0] == "Flag" for l, _ in edges[s]))
    deploy_without_cp = sum(1 for s in states for l, _ in edges[s] if l[0] == "Deploy" and not cp(s))
    running_unmet = sum(1 for s in states if s[3] == 1 and not cp(s))
    return {"states": len(states), "deploy_without_continuing_pass": deploy_without_cp, "production_running_with_requirement_unmet": running_unmet,
            "of_which_without_open_obligation_and_without_Flag_enabled": running_unmet_no_obligation_stable}


R["independence_with_obligations"] = {f"{l}|{m}": check_m4_v25(l, m) for l in ("PERSON", "REPORTING_LINE") for m in ("AT_ACT", "CONTINUING")}

# ───────── (4) static audit of the specification text ─────────
def para_text(path):
    x = zipfile.ZipFile(path).read("word/document.xml").decode("utf-8")
    out = []
    for p in re.findall(r"<w:p[ >].*?</w:p>", x, re.S):
        out.append("".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", p)).replace("&amp;", "&").replace("&gt;", ">").replace("&lt;", "<"))
    return out


def codes(path):
    """text of paragraphs plus the code runs separately (properties are in code runs)"""
    x = zipfile.ZipFile(path).read("word/document.xml").decode("utf-8")
    res = []
    for p in re.findall(r"<w:p[ >].*?</w:p>", x, re.S):
        full = "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", p)).replace("&amp;", "&").replace("&gt;", ">").replace("&lt;", "<")
        cs = [t.replace("&amp;", "&").replace("&gt;", ">").replace("&lt;", "<") for r in re.findall(r"<w:r>.*?</w:r>", p, re.S) if "Consolas" in r for t in re.findall(r"<w:t[^>]*>([^<]*)</w:t>", r)]
        res.append((full, cs))
    return res


def section(paras, start, stop):
    i = next(k for k, (t, _) in enumerate(paras) if t.startswith(start))
    j = next(k for k, (t, _) in enumerate(paras) if k > i and t.startswith(stop))
    return paras[i:j]


VARS = {"v", "v'", "d", "d'", "e", "c", "i", "a", "op", "s", "σ", "stage", "x", "j"}
BINDER = re.compile(r"∀\s*([A-Za-z'σ]+)")


def unbound(formula):
    bound = set(BINDER.findall(formula))
    formula = re.sub(r"F_\[0,[a-z_]+\]|d_c", " ", formula)               # time bounds are published constants, not variables
    toks = set(re.findall(r"[A-Za-zσ]+'?", formula))
    free = {t for t in toks if t in VARS} - bound
    return sorted(free)


def prop_formulas(path, start, stop):
    out = []
    for full, cs in section(codes(path), start, stop):
        for c in cs:
            if c.startswith("G(") or c.startswith("∀") or c.startswith("F("):
                out.append((full[:60], c))
    return out


p25 = prop_formulas(SPEC25, "3.5 Transition-system semantics", "3.5.1 Incidents")
p25 += prop_formulas(SPEC25, "3.5.1 Incidents", "3.5.2 Formal transition")
p25 += prop_formulas(SPEC25, "3.1.1 Organisational structure", "3.2 Goals")
p24 = prop_formulas(SPEC24, "3.5 Transition-system semantics", "3.5.1 Incidents")
p24 += prop_formulas(SPEC24, "3.5.1 Incidents", "3.5.2 Formal transition")
p24 += prop_formulas(SPEC24, "3.1.1 Organisational structure", "3.2 Goals")
R["quantifier_audit"] = {"v2.5": {"properties_checked": len(p25), "with_unbound_variables": [(f, unbound(f)) for _, f in p25 if unbound(f)]},
                         "v2.4": {"properties_checked": len(p24), "with_unbound_variables": [(f, unbound(f)) for _, f in p24 if unbound(f)]}}

# components and writers
paras25 = codes(SPEC25)
s352 = section(paras25, "3.5.2 Formal transition", "3.6 Gate semantics")
state_line = next(t for t, _ in s352 if t.startswith("States. A state is q = ("))
components = [c.strip() for c in re.search(r"q = \(([^)]*)\)", state_line).group(1).split(",")]
writes = set()
for a in ACTIONS:
    writes |= set(a["writes"])
comp_set = set(components) - {"last"}
R["components"] = {"state_tuple": components, "never_written": sorted(comp_set - writes), "written_but_not_in_tuple": sorted(writes - comp_set)}

# predicates used in properties versus defined or declared: a name counts only if the text gives a definition clause for it or declares it with a signature
fulltext = chr(10).join(t for t, _ in paras25)
DEF = r"\([^()]*\)[^.\n]{0,90}?(:| holds when| holds if| is | are | denotes |where | = |, taken)"
used = set()
for _, f in p25:
    used |= set(re.findall(r"\b([A-Z][A-Za-z_]+)\(", f))
action_names = {a["name"].split("(")[0] for a in ACTIONS}
used -= {"G", "F", "X", "Y"}
params = sorted(set(re.findall(r"\b([A-Z][A-Za-z]+)\([^()]*\) → (?:Bool|set of actors|runtime facts|structure)", fulltext)))
undef = sorted(n for n in used if n not in action_names and n not in params and not re.search(r"\b" + re.escape(n) + DEF, fulltext))
R["predicates"] = {"used_in_properties": sorted(used), "actions_among_them": sorted(used & action_names), "not_defined_or_declared": undef, "parameters_declared": params}

# v2.4 contrast: undefined predicates in the v2.4 properties
paras24 = codes(SPEC24)
s352_24 = section(paras24, "3.5.2 Formal transition", "3.6 Gate semantics")
text24 = "\n".join(t for t, _ in s352_24)
used24 = set()
for _, f in p24:
    used24 |= set(re.findall(r"\b([A-Z][A-Za-z_]+)\(", f))
used24 -= {"G", "F", "X", "Y"}
defd24 = set(re.findall(r"`?([A-Z][A-Za-z_]+)\(", text24.split("Action")[0]))
R["predicates_v24_contrast"] = sorted(n for n in used24 if not re.search(r"`" + re.escape(n) + r"[^`\n]{0,60}`[^\n]{0,40}(:|holds when|is the)", text24) and n not in {"Deploy", "Update", "Approve", "Revoke", "Alert"})[:40]

json.dump(R, open(OUT, "w", encoding="utf-8"), indent=1, default=str, ensure_ascii=False)
print(json.dumps({k: R[k] for k in ("applicability", "gate", "components", "quantifier_audit", "predicates")}, indent=1, default=str, ensure_ascii=False)[:6000])
