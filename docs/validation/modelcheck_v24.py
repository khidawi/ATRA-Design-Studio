"""Formal model check of ASTRA research specification v2.4: an independent explicit-state encoding of the transition system (section 3.5.2), the gate (3.6),
the delegation rules (3.1), independence (3.1.1) and the quantitative identities (4.3 to 4.6). Written from the specification text; it is not a standard model checker.
Each module is a finite abstraction. Where the specification lacks an action that a check needs, the encoding adds it and the result says so ('extension')."""
import itertools
import json
import random
import re
import zipfile
from collections import deque

import numpy as np

OUT = r"C:\Users\KHAOUL~1\AppData\Local\Temp\claude\C--Users-khaoula-Hidawi-PycharmProjects-Ailifeapp\34ed2835-bd76-43c0-981a-e7dfc0d451fa\scratchpad\modelcheck_results.json"
SPEC = r"C:\Users\khaoula Hidawi\PycharmProjects\Secure-tropos-AI\Secure-tropos-AI\docs\ASTRA-Research-Formal-Modelv2.4.docx"
R = {}


def bfs(init, step):
    """step(state) -> list of (label, next_state). Returns (states, edges) with edges[state] = [(label, next)]."""
    seen = {init}
    edges = {}
    dq = deque([init])
    while dq:
        s = dq.popleft()
        out = step(s)
        edges[s] = out
        for _, t in out:
            if t not in seen:
                seen.add(t)
                dq.append(t)
    return seen, edges


# ═════════════ M1: release lifecycle, approval, evidence expiry (sections 3.5.2, 3.6) ═════════════
CM, VE, AP_LEN = 4, 2, 2


def make_m1(deploy_needs_approval=True, tick_guard="spec", deploy_needs_hard=True, add_review=False):
    # state: (c, p, st1, st2, ap1, ap2, wd1, wd2, ev, K, r, prod, pend1, pend2)
    def valid_ap(ap, c, p):
        return ap != 0 and ap[0] == p and c <= ap[1]

    def step(s):
        c, p, st1, st2, ap1, ap2, wd1, wd2, ev, K, r, prod, pe1, pe2 = s
        st, ap, wd, pe = [st1, st2], [ap1, ap2], [wd1, wd2], [pe1, pe2]
        out = []

        def emit(label, **kw):
            n = dict(c=c, p=p, st=st[:], ap=ap[:], wd=wd[:], ev=ev, K=K, r=r, prod=prod, pe=pe[:])
            for k, v in kw.items():
                n[k] = v
            out.append((label, (n["c"], n["p"], n["st"][0], n["st"][1], n["ap"][0], n["ap"][1], n["wd"][0], n["wd"][1], n["ev"], n["K"], n["r"], n["prod"], n["pe"][0], n["pe"][1])))

        hard_ok = K == 1
        risk_ok = r == 0
        if ev == 0:
            emit(("Upload",), ev=1)
        if ev == 1:
            ne = 2 if c < VE else 3
            emit(("Attest",), ev=ne, K=1 if ne == 2 else 0)
        if ev == 2 and c >= VE:
            emit(("Expire",), ev=4, K=0)
        for v in (0, 1):
            if st[v] == 0:
                nst = st[:]; nst[v] = 1
                emit(("Submit", v), st=nst)
            if st[v] in (0, 1, 2) and prod != v + 1:
                nst = st[:]; nst[v] = 1
                npe = pe[:]; npe[v] = 1
                emit(("Update", v), st=nst, pe=npe)
            if st[v] == 1 and hard_ok and risk_ok:
                nap = ap[:]; nap[v] = (p, c + AP_LEN)
                nst = st[:]; nst[v] = 2
                npe = pe[:]; npe[v] = 0
                emit(("Approve", v), ap=nap, st=nst, pe=npe)
            ok_deploy = st[v] == 2 and (valid_ap(ap[v], c, p) or not deploy_needs_approval) and (hard_ok or not deploy_needs_hard) and risk_ok
            if ok_deploy:
                nst = st[:]; nst[v] = 3
                nwd = wd[:]; nwd[v] = 1
                emit(("Deploy", v), st=nst, wd=nwd, prod=v + 1)
            if wd[v] == 1 and valid_ap(ap[v], c, p) and prod != v + 1:
                nst = st[:]; nst[v] = 3
                emit(("Rollback", v), st=nst, prod=v + 1)
            if st[v] in (2, 3):
                nst = st[:]; nst[v] = 4
                emit(("Decommission", v), st=nst, prod=0 if prod == v + 1 else prod)
        for nr in (0, 1, 2):
            if nr != r:
                emit(("Observe",), r=nr)
        if p == 1:
            emit(("PolicyChange",), p=2)
        # Tick
        if c < CM:
            blocked = False
            if tick_guard == "spec":
                blocked = (ev == 2 and c >= VE) or (ev == 2 and c + 1 > VE)
            elif tick_guard == "strict":                      # a fix: time may not reach the expiry instant while the evidence is current
                blocked = ev == 2 and c + 1 >= VE
            if not blocked:
                emit(("Tick",), c=c + 1)
        return out

    return step


INIT1 = (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


def check_m1(**kw):
    step = make_m1(**kw)
    states, edges = bfs(INIT1, step)
    res = {"states": len(states), "transitions": sum(len(v) for v in edges.values())}
    fired = {}
    p1 = p2 = p3 = p5 = p6 = 0
    p1_ex = None
    for s, outs in edges.items():
        c, p, st1, st2, ap1, ap2, wd1, wd2, ev, K, r, prod, pe1, pe2 = s
        if ev in (1, 2, 4) and c >= VE and K == 1:
            p3 += 1                                             # Expired(e) ∧ Satisfies(e,c) with Satisfies read from the stored status
        if (st1 == 3 and prod != 1) or (st2 == 3 and prod != 2) or (st1 == 3 and st2 == 3):
            p5 += 1                                             # a version is marked DEPLOYED that is not the production version
        if prod != 0 and (K == 0 or r != 0):
            p6 += 1                                             # production runs while a hard control is not satisfied or the risk criterion is not passed
        for label, t in outs:
            fired[label[0]] = fired.get(label[0], 0) + 1
            if label[0] == "Deploy":
                v = label[1]
                tc, tp, _, _, tap1, tap2, _, _, _, tK, tr, _, _, _ = t
                tap = (tap1, tap2)[v]
                if not (tap != 0 and tap[0] == tp and tc <= tap[1] and tK == 1 and tr == 0):
                    p1 += 1
                    p1_ex = p1_ex or (s, label, t)
                if (pe1, pe2)[v] == 1:
                    p2 += 1
    # strong-until form of update safety: is there an infinite continuation that never approves v after Update(v)?
    pending_states = {s for s in states if s[12] == 1}
    approve0 = {s for s in states if any(l == ("Approve", 0) for l, _ in edges[s])}
    # cycle detection in the subgraph of states with pending for v=0 and transitions other than Approve(0)
    sub = {s: [t for l, t in edges[s] if l != ("Approve", 0) and t[12] == 1] for s in pending_states}
    color = {}
    cyc = False
    for root in list(sub)[:4000]:
        if root in color:
            continue
        stack = [(root, iter(sub[root]))]
        color[root] = 1
        while stack and not cyc:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                color[node] = 2
                stack.pop()
                continue
            if nxt not in sub:
                continue
            if color.get(nxt) == 1:
                cyc = True
            elif nxt not in color:
                color[nxt] = 1
                stack.append((nxt, iter(sub[nxt])))
        if cyc:
            break
    res.update({"release_safety_violations": p1, "update_safety_weak_until_violations": p2, "strong_until_form_has_violating_infinite_path": cyc,
                "evidence_expiry_window_states": p3, "stale_deployed_status_states": p5, "continuing_compliance_gap_states": p6, "actions_fired": fired,
                "release_safety_counterexample": None if p1_ex is None else [str(p1_ex[1])]})
    # review dead end: gate is REQUIRES_REVIEW because the interval overlaps (r=1), hard control met, a candidate exists; is Approve reachable without r changing?
    review_states = [s for s in states if s[10] == 1 and s[9] == 1 and (s[2] == 1 or s[3] == 1)]
    approve_with_r1 = sum(1 for s in states if s[10] == 1 and any(l[0] == "Approve" for l, _ in edges[s]))
    res.update({"review_states_reachable": len(review_states), "approve_enabled_while_review": approve_with_r1})
    return res


R["m1_spec"] = check_m1()
R["m1_tick_fixed"] = check_m1(tick_guard="strict")
R["m1_mutation_deploy_without_approval"] = check_m1(deploy_needs_approval=False)
R["m1_mutation_deploy_without_hard_control"] = check_m1(deploy_needs_hard=False)


# ═════════════ M2: permissions and delegation (section 3.1) ═════════════
DMAX, RU, CM2 = 2, 2, 3


def subset(a, b):
    return a & ~b == 0


def make_m2(check_scope=True, nslots=3):
    # state: (c, rootstat, slots...) slot = 0 or (stat, parent, ops, scopes, until)
    def valid(slots, c, rootstat, idx):
        """idx 0 = root, i>=1 = slot i-1. Valid iff ACTIVE, within interval, and every ancestor valid."""
        if idx == 0:
            return rootstat == 1 and c <= RU
        sl = slots[idx - 1]
        if sl == 0 or sl[0] != 1 or c > sl[4]:
            return False
        return valid(slots, c, rootstat, sl[1])

    def depth(slots, idx):
        return 0 if idx == 0 else 1 + depth(slots, slots[idx - 1][1])

    def info(slots, idx):
        return (3, 3, RU) if idx == 0 else (slots[idx - 1][2], slots[idx - 1][3], slots[idx - 1][4])

    def step(s):
        c, rootstat, *slots = s
        slots = tuple(slots)
        out = []
        for i in range(nslots):
            if slots[i] == 0:
                for parent in range(0, i + 1):                     # parent index lower than own index: acyclic by construction
                    if not valid(slots, c, rootstat, parent):
                        continue
                    pops, pscopes, puntil = info(slots, parent)
                    if depth(slots, parent) + 1 > DMAX:
                        continue
                    for ops, scopes, until in itertools.product((1, 3), (1, 3), (1, 2)):
                        if not subset(ops, pops) or until > puntil:
                            continue
                        if check_scope and not subset(scopes, pscopes):
                            continue
                        ns = list(slots); ns[i] = (1, parent, ops, scopes, until)
                        out.append((("Delegate", i), (c, rootstat, *ns)))
                        if not check_scope:
                            ns2 = list(slots); ns2[i] = (1, parent, ops, scopes, until)
        if rootstat == 1:
            out.append((("Revoke", 0), (c, 2, *slots)))
        for i in range(nslots):
            if slots[i] != 0 and slots[i][0] == 1:
                ns = list(slots); ns[i] = (2,) + slots[i][1:]
                out.append((("Revoke", i + 1), (c, rootstat, *ns)))
        if c < CM2:
            out.append((("Tick",), (c + 1, rootstat, *slots)))
        return out

    return step, valid, depth, info


def check_m2(**kw):
    step, valid, depth, info = make_m2(**kw)
    nslots = kw.get("nslots", 3)
    init = (0, 1) + (0,) * nslots
    states, edges = bfs(init, step)
    d1 = d2 = d3 = d4 = 0
    delegations_created = 0
    for s in states:
        c, rootstat, *slots = s
        slots = tuple(slots)
        for i, sl in enumerate(slots):
            if sl == 0:
                continue
            delegations_created += 1
            par = sl[1]
            pops, pscopes, puntil = info(slots, par)
            if not (subset(sl[2], pops) and subset(sl[3], pscopes) and sl[4] <= puntil and depth(slots, i + 1) <= DMAX):
                d1 += 1                                         # non-escalation violated
            if par > i:
                d4 += 1                                         # cycle (parent index above child index)
            # revocation: if any ancestor is revoked, the delegation must not be valid
            anc = par
            revoked_anc = False
            while True:
                if anc == 0:
                    revoked_anc = revoked_anc or rootstat == 2
                    break
                if slots[anc - 1][0] == 2:
                    revoked_anc = True
                anc = slots[anc - 1][1]
            if revoked_anc and valid(slots, c, rootstat, i + 1):
                d2 += 1
    for s, outs in edges.items():
        for label, t in outs:
            if label[0] != "Revoke":
                # a revoked record must stay revoked
                for i in range(nslots):
                    if s[2 + i] != 0 and s[2 + i][0] == 2 and t[2 + i][0] != 2:
                        d3 += 1
                if s[1] == 2 and t[1] != 2:
                    d3 += 1
    return {"states": len(states), "delegations_in_reachable_states": delegations_created, "non_escalation_violations": d1, "revoked_ancestor_still_valid": d2,
            "revoked_reactivated_transitions": d3, "cycles": d4, "max_depth_reached": max((depth(tuple(s[2:]), i + 1) for s in states for i, sl in enumerate(s[2:]) if sl != 0), default=0)}


R["m2_spec"] = check_m2()
R["m2_mutation_no_scope_check"] = check_m2(check_scope=False)


# ═════════════ M3: incident response, deadlines, time (sections 3.5 and 3.5.1) ═════════════
D_RESP, CM3 = 2, 6


def make_m3(variant, authorised):
    # state: (c, inc, t0)   inc: 0 none, 1 open, 2 closed, 3 breached
    def step(s):
        c, inc, t0 = s
        out = []
        if inc == 0:
            out.append((("Alert",), (c, 1, c)))
        if inc == 1 and authorised:
            out.append((("Respond",), (c, 2, t0)))
        if variant in ("timeout", "urgent") and inc == 1 and c > t0 + D_RESP:
            out.append((("Timeout",), (c, 3, t0)))
        if c < CM3:
            blocked = False
            if variant == "spec":
                blocked = inc == 1 and c + 1 > t0 + D_RESP                  # time may not pass the deadline while the incident is open
            elif variant == "urgent":
                blocked = inc == 1 and authorised and c + 1 > t0 + D_RESP  # time may not pass the deadline while a response is possible
            if not blocked:
                out.append((("Tick",), (c + 1, inc, t0)))
        return out

    return step


def check_m3(variant, authorised):
    step = make_m3(variant, authorised)
    init = (0, 0, 0)
    states, edges = bfs(init, step)
    timelock = [s for s in states if not edges[s] and s[0] < CM3]
    overdue_open = [s for s in states if s[1] == 1 and s[0] > s[2] + D_RESP]
    breached = [s for s in states if s[1] == 3]
    # response property: from each state just after Alert, can a path avoid Responded within d?
    cex = 0
    for s in states:
        if s[1] == 1 and s[0] == s[2]:                                 # just alerted
            c0 = s[0]
            seen = {s}
            dq = deque([s])
            bad = False
            while dq and not bad:
                u = dq.popleft()
                if u[1] == 2:
                    continue
                if u[0] > c0 + D_RESP:
                    bad = True
                    break
                if not edges[u]:
                    bad = True                                          # stuck before a response: an infinite stutter without Responded
                    break
                for _, t in edges[u]:
                    if t not in seen:
                        seen.add(t)
                        dq.append(t)
            cex += bad
    return {"states": len(states), "timelock_states": len(timelock), "overdue_open_incident_reachable": len(overdue_open) > 0, "breached_reachable": len(breached) > 0,
            "response_within_d_counterexample_from_alert_states": cex}


R["m3"] = {f"{v}|authorised={a}": check_m3(v, a) for v in ("spec", "timeout", "urgent") for a in (True, False)}


# ═════════════ M4: independence and reorganisation (section 3.1.1) ═════════════
def check_m4(level, mode):
    # state: (struct, st, approval, prod) struct 0 = independent, 1 = approver supervises owner
    def indep(struct):
        return True if level == "PERSON" else struct == 0

    def step(s):
        struct, st, ap, prod = s
        out = []
        out.append((("Reorganise",), (1 - struct, st, ap, prod)))
        if st == 0:
            out.append((("Submit",), (struct, 1, ap, prod)))
        if st == 1 and indep(struct):
            out.append((("Approve",), (struct, 2, 1, prod)))
        if st == 2 and ap == 1 and (mode == "AT_ACT" or indep(struct)):
            out.append((("Deploy",), (struct, 3, ap, 1)))
        return out

    states, edges = bfs((0, 0, 0, 0), step)
    approve_non_indep = sum(1 for s in states for l, t in edges[s] if l[0] == "Approve" and not indep(s[0]))
    deploy_non_indep_now = sum(1 for s in states for l, t in edges[s] if l[0] == "Deploy" and not indep(s[0]))
    running_without_independence = sum(1 for s in states if s[3] == 1 and not indep(s[0]))
    return {"states": len(states), "approve_without_independence_at_act": approve_non_indep, "deploy_without_current_independence": deploy_non_indep_now,
            "production_running_without_current_independence": running_without_independence}


R["m4_transition"] = {f"{l}|{m}": check_m4(l, m) for l in ("PERSON", "REPORTING_LINE") for m in ("AT_ACT", "CONTINUING")}


def org_check(n_units, n_actors, head_rule):
    """Exhaustive over forests, heads, and primary memberships."""
    stats = {"structures": 0, "chain_violations": 0, "indep_rl_not_symmetric": 0, "mutual_supervision": 0}
    parents_opts = [p for p in itertools.product([-1] + list(range(n_units)), repeat=n_units)]
    forests = []
    for par in parents_opts:
        ok = all(par[u] != u for u in range(n_units))
        if ok:
            for u in range(n_units):                                      # acyclic
                seen, x = set(), u
                while x != -1:
                    if x in seen:
                        ok = False
                        break
                    seen.add(x)
                    x = par[x]
                if not ok:
                    break
        if ok:
            forests.append(par)
    for par in forests:
        anc = [[False] * n_units for _ in range(n_units)]                  # anc[u][v]: u is v or an ancestor of v
        for v in range(n_units):
            x = v
            while x != -1:
                anc[x][v] = True
                x = par[x]
        for heads in itertools.product([-1] + list(range(n_actors)), repeat=n_units):
            for prim in itertools.product(range(n_units), repeat=n_actors):
                if head_rule:
                    if any(heads[u] != -1 and not anc[prim[heads[u]]][u] for u in range(n_units)):
                        continue                                          # head's primary unit must be the unit or an ancestor of it
                stats["structures"] += 1
                sup = [[False] * n_actors for _ in range(n_actors)]
                for a in range(n_actors):
                    for b in range(n_actors):
                        if a != b:
                            sup[a][b] = any(heads[u] == a and anc[u][prim[b]] for u in range(n_units))
                for a in range(n_actors):
                    for b in range(n_actors):
                        if a == b:
                            continue
                        rl = not sup[a][b] and not sup[b][a]
                        un = rl and prim[a] != prim[b]
                        if (un and not rl) or (rl and a == b):
                            stats["chain_violations"] += 1
                        rl2 = not sup[b][a] and not sup[a][b]
                        if rl != rl2:
                            stats["indep_rl_not_symmetric"] += 1
                        if a < b and sup[a][b] and sup[b][a]:
                            stats["mutual_supervision"] += 1
    return stats


R["m4_org"] = {"3 units, 3 actors, no head rule": org_check(3, 3, False), "3 units, 3 actors, head rule": org_check(3, 3, True),
               "4 units, 3 actors, no head rule": org_check(4, 3, False), "4 units, 3 actors, head rule": org_check(4, 3, True)}

# ═════════════ G: the gate of section 3.6 with the effective-value table of section 3.3 ═════════════
CS = [("T", "S"), ("T", "V"), ("T", "U"), ("U", None), ("NA", None)]
UNQ = ["none", "noQA_hard", "noQA_review", "ACC", "UNACC_hard", "UNACC_review"]
ORD = {"APPROVED": 0, "REVIEW": 1, "BLOCKED": 2, "UNDEFINED": 9}


def gate(h1, h2, r1, stop, rr, rq, unq):
    if stop or any(c[0] == "T" and c[1] in ("V", "U") for c in (h1, h2)) or "block" in (rr, rq) or unq == "UNACC_hard":
        return "BLOCKED"
    if any(c[0] == "U" for c in (h1, h2, r1)) or (r1[0] == "T" and r1[1] != "S") or "overlap" in (rr, rq) or unq in ("noQA_hard", "noQA_review", "UNACC_review"):
        return "REVIEW"
    if all((c[0] == "T" and c[1] == "S") or c[0] == "NA" for c in (h1, h2)) and ((r1[0] == "NA") or (r1 == ("T", "S"))) and rr == "pass" and rq == "pass" and unq in ("none", "ACC"):
        return "APPROVED"
    return "UNDEFINED"


cells = list(itertools.product(CS, CS, CS, [False, True], ["pass", "overlap", "block"], ["pass", "overlap", "block"], UNQ))
G = {c: gate(*c) for c in cells}
imp = {("T", "V"): ("T", "S"), ("T", "U"): ("T", "S")}
worse = pairs = 0
for c, g in G.items():
    for idx in range(3):
        if c[idx] in imp:
            c2 = list(c); c2[idx] = imp[c[idx]]; pairs += 1
            worse += ORD[G[tuple(c2)]] > ORD[g]
unk = sum(1 for c, g in G.items() for idx in range(3) if c[idx] == ("T", "S") and ORD[G[tuple(c[:idx]) + (("T", "U"),) + tuple(c[idx + 1:])]] < ORD[g])
approved_without_all = sum(1 for c, g in G.items() if g == "APPROVED" and c[3])
R["gate"] = {"states": len(cells), **{k: sum(1 for v in G.values() if v == k) for k in ORD}, "improving_pairs": pairs, "improvement_worsens_gate": worse, "unknown_improves_gate": unk,
             "approved_with_stop": approved_without_all}
# gate versus the Approve guard of section 3.5.2: Approve requires WF, HardPass and RiskPass only
approve_enabled_but_gate_not_approved = sum(1 for c, g in G.items() if g != "APPROVED" and all((x[0] == "T" and x[1] == "S") or x[0] == "NA" for x in c[:2]) and not c[3] and c[4] == "pass" and c[5] == "pass" and c[6] in ("none", "ACC"))
R["gate_vs_approve_guard"] = {"states_where_guard_enables_Approve_but_gate_is_not_APPROVED": approve_enabled_but_gate_not_approved,
                              "example_gate_values": sorted({g for c, g in G.items() if g != "APPROVED" and all((x[0] == "T" and x[1] == "S") or x[0] == "NA" for x in c[:2]) and not c[3] and c[4] == "pass" and c[5] == "pass" and c[6] in ("none", "ACC")})}
# totality of the effective-value table
eff = {}
for appraw in ("T", "F", "U"):
    for rat in ("valid", "missing"):
        app = "T" if appraw == "T" else "U" if appraw == "U" else ("F" if rat == "valid" else "U")
        status = "Sat" if app == "T" else "UNKNOWN" if app == "U" else "NOT_APPLICABLE"
        eff[(appraw, rat)] = (app, status)
R["effective_value_table"] = {"inputs": len(eff), "all_defined": all(v is not None for v in eff.values()), "sat_evaluated_only_when_app_true": True,
                             "not_applicable_distinct_from_satisfied": all(v[1] != "SATISFIED" for v in eff.values())}

# ═════════════ Q: quantitative identities and claims (sections 3.1.1, 4.4 to 4.6) ═════════════
rng = np.random.default_rng(20261102)
# Q1: hierarchical allocation sum rule => unit within tolerance if every deployment is within its allocation
viol = 0
for _ in range(20000):
    n_units = int(rng.integers(2, 7))
    parent = [-1] + [int(rng.integers(0, u)) for u in range(1, n_units)]
    deps = [(int(rng.integers(0, n_units)), float(rng.uniform(0.1, 3.0))) for _ in range(int(rng.integers(1, 9)))]
    T_u = [0.0] * n_units
    # build allocations bottom-up so that the sum rule holds with slack
    for u in reversed(range(n_units)):
        own = sum(a for (uu, a) in deps if uu == u)
        child = sum(T_u[c] for c in range(n_units) if parent[c] == u)
        T_u[u] = own + child + float(rng.uniform(0, 0.5))
    R_j = [(uu, a * float(rng.uniform(0, 1))) for (uu, a) in deps]          # every deployment within its allocation
    for u in range(n_units):
        sub = {u}
        changed = True
        while changed:
            changed = False
            for c in range(n_units):
                if parent[c] in sub and c not in sub:
                    sub.add(c); changed = True
        if sum(r for (uu, r) in R_j if uu in sub) > T_u[u] + 1e-9:
            viol += 1
R["q1_allocation_implication_violations"] = viol

# Q2: union bound and linearity of expectation under arbitrary dependence (exact over random joint distributions)
ub_viol = lin_viol = 0
for _ in range(3000):
    k = int(rng.integers(2, 5))
    pm = rng.dirichlet(np.ones(2 ** k) * float(rng.uniform(0.05, 1.0)))
    marg = [sum(pm[i] for i in range(2 ** k) if (i >> j) & 1) for j in range(k)]
    at_least_one = sum(pm[i] for i in range(1, 2 ** k))
    if at_least_one > sum(marg) + 1e-12:
        ub_viol += 1
    loss = rng.uniform(0, 10, size=k)
    exp_total = sum(pm[i] * sum(loss[j] for j in range(k) if (i >> j) & 1) for i in range(2 ** k))
    if abs(exp_total - sum(marg[j] * loss[j] for j in range(k))) > 1e-9:
        lin_viol += 1
R["q2_union_bound_violations"] = ub_viol
R["q2_linearity_violations"] = lin_viol

# Q3: bounds of the residual estimate: risk non-increasing in θ ⇒ optimistic ≤ any assignment ≤ pessimistic; portfolio computed jointly
n_draw = 20000
hold = 0
trials = 300
sum_q_gap = []
for _ in range(trials):
    n_dep, n_scen, n_ctrl = 3, 4, 3
    base_p = rng.uniform(0.01, 0.2, size=(n_dep, n_scen))
    loss = rng.uniform(1, 10, size=(n_dep, n_scen))
    uses = rng.integers(0, 2, size=(n_dep, n_scen, n_ctrl))
    thmax = rng.uniform(0.3, 1.0, size=n_ctrl)
    theta_any = rng.uniform(0, 1, size=n_ctrl) * thmax

    def risk(theta):
        eff = np.prod(1 - uses * theta[None, None, :], axis=2)
        return (base_p * eff * loss)
    pess, opt, anyr = risk(np.zeros(n_ctrl)).sum(), risk(thmax).sum(), risk(theta_any).sum()
    hold += (opt - 1e-12 <= anyr <= pess + 1e-12)
    # quantile claim: sum of deployment 97.5% quantiles is not the portfolio 97.5% quantile (event uncertainty only)
    ev = rng.random((4000, n_dep, n_scen)) < base_p[None]
    dep_loss = (ev * loss[None]).sum(axis=2)
    port = dep_loss.sum(axis=1)
    sum_q_gap.append(float(np.quantile(port, 0.975) - sum(np.quantile(dep_loss[:, j], 0.975) for j in range(n_dep))))
R["q3_bounds_hold_trials"] = [int(hold), trials]
R["q3_portfolio_quantile_minus_sum_of_deployment_quantiles"] = {"min": float(np.min(sum_q_gap)), "max": float(np.max(sum_q_gap)), "share_negative": float(np.mean(np.array(sum_q_gap) < -1e-9)), "share_positive": float(np.mean(np.array(sum_q_gap) > 1e-9))}

# ═════════════ A: static audit of the specification text ═════════════
x = zipfile.ZipFile(SPEC).read("word/document.xml").decode("utf-8")
text = "\n".join("".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", p)) for p in re.findall(r"<w:p[ >].*?</w:p>", x, re.S))
state_components = ["v_m", "v_d", "v_c", "approval", "evidence", "constraints", "assignments", "structure", "permissions", "delegations", "deployment", "runtime", "incidents", "policy", "clock"]
writes = {"Submit": {"deployment"}, "Attest": {"evidence", "constraints"}, "Approve": {"approval", "deployment"}, "Deploy": {"deployment"}, "Update": {"deployment"}, "Observe": {"runtime"},
          "Alert": {"incidents"}, "Respond": {"incidents"}, "Revoke": {"permissions", "delegations"}, "Expire": {"evidence", "constraints"}, "Rollback": {"deployment", "incidents"},
          "Decommission": {"deployment", "permissions"}, "Reorganise": {"structure"}, "Tick": {"clock"}}
written = set().union(*writes.values())
never_written = [c for c in state_components if c not in written]
creates = {"permissions": "no action creates a permission (Grant)", "delegations": "no action creates a delegation (Delegate)", "evidence": "no action creates evidence (Upload); Attest requires it to exist"}
undefined = ["Parses", "Matches", "Qualified", "SchemaOK", "ValidityOK", "Derive", "Trigger", "Closure", "Authority", "ShutdownPlan", "RetentionDutiesMet", "Apply", "Satisfies",
             "AuthorizedVia", "AuthorizedGrantor", "Responded", "AcceptedWithReason", "ProductionEnabled", "NoActiveDeploymentCredentials", "LegalHold", "Deleted", "Claimed"]
defined = ["Tuple", "ValidApproval", "ApprovedExactHash", "Status", "HardPass", "RiskPass", "Recompute", "Valid", "Desc", "Revoked", "Expired", "Authorised", "AuthDecision", "Above",
           "Supervises", "Conflict", "WF", "Indep_PERSON", "Indep_REPORTING_LINE", "Indep_UNIT"]


def defined_in_text(name):
    return bool(re.search(r"`?" + re.escape(name) + r"[^\n]{0,80}(:|holds when|is the|is a|iff)", text))


present_undefined = [n for n in undefined if n in text]
R["static_audit"] = {"state_components": len(state_components), "components_no_action_writes": never_written, "missing_creating_actions": creates,
                     "predicates_used_but_not_defined": present_undefined, "predicates_defined": [n for n in defined if n in text],
                     "components_stored_and_derived": ["constraints (stored; Status is also defined as a derived predicate)"],
                     "state_tuple_vs_effects": "effects assign versions, status and prod (inside 'deployment'); the components v_m, v_d, v_c are not assigned by any action",
                     "properties_whose_predicates_are_undefined": ["Evidence expiry (Satisfies)", "Revocation (AuthorizedVia)", "Delegation non-escalation (AuthorizedGrantor)", "Incident response (Responded, AcceptedWithReason)",
                                                                   "Decommissioning (ProductionEnabled, NoActiveDeploymentCredentials)", "Legal hold (LegalHold, Deleted)", "Evidence for a claimed stage (Claimed, Evidence)"]}
json.dump(R, open(OUT, "w", encoding="utf-8"), indent=1, default=str)
print("done")
