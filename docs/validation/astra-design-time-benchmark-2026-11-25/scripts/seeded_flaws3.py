"""Round 3 (see protocols/ROUND3_PROTOCOL.md): harder seeded flaws with a Truth column and a Forecast column, and a randomised metamorphic test.
Runs the platform's own pipeline on a scratch database. Expects the repo at /w and writes /data/seeded3.json."""
import copy
import json
import os
import random
import sys
from collections import Counter

sys.path.insert(0, "/w/backend")
from db.bootstrap import init_database                         # noqa: E402
from db.session import SessionLocal                            # noqa: E402

import astra_estate as AE                                      # noqa: E402
from astra_assessment_api import _rows                         # noqa: E402

init_database()
NAME, PAY = "Seeded baseline agent", "Payroll agent"
RANK = {"BLOCKED": 1, "REQUIRES_REVIEW": 2, "APPROVED": 3}
KINDS = ("iso", "hitl", "least", "supply", "memval", "deleg", "ident", "life")
EV1 = {f"astra:{k}": None for k in KINDS}
EV2 = dict(EV1, **{"astra:auth": None})
ROWS = {}


def rows_of(doc):
    key = json.dumps(doc, sort_keys=True)
    if key not in ROWS:
        with SessionLocal() as s:
            ROWS[key] = _rows(s, doc)
    return ROWS[key]


def node(i, t, name, p=None, primary=False):
    d = {"id": i, "type": t, "name": name, "p": p or {}}
    if primary:
        d["primary"] = True
    return d


def baseline():
    return {"nodes": [node("a1", "agent", NAME, {"owner": "Rhea", "auto": "approval"}, True), node("i1", "input", "customer email", {"untrusted": True}),
                      node("t1", "tool", "refund", {"write": True}), node("t2", "tool", "lookup", {}), node("d1", "data", "Ledger", {"purpose": "settle customer refunds"}),
                      node("ap1", "approval", "manager approval"), node("g1", "guardrail", "injection filter", {"kind": "injection"}),
                      node("g2", "guardrail", "rate limit", {"kind": "rate"}), node("g3", "guardrail", "AI disclosure", {"kind": "disclosure"}), node("h1", "human", "customer"),
                      node("m1", "memory", "case notes", {"long": True}), node("c1", "constraint", "retention", {"kind": "retention"}), node("s1", "mcp", "ticket server", {"signed": True})],
            "edges": [{"from": "i1", "to": "a1", "label": "feeds"}, {"from": "a1", "to": "t1", "label": "uses"}, {"from": "a1", "to": "t2", "label": "uses"},
                      {"from": "a1", "to": "d1", "label": "reads"}, {"from": "ap1", "to": "t1", "label": "gates"}, {"from": "g1", "to": "a1", "label": "limits"},
                      {"from": "a1", "to": "m1", "label": "stores"}, {"from": "a1", "to": "s1", "label": "connects"}]}


def agent_doc(name, delegates=(), reads=("Payroll",), code=False, sandbox=False, rate=False):
    d = {"nodes": [node("b1", "agent", name, {"owner": "Sam", "auto": "approval"}, True), node("bt", "tool", "lookup", {})], "edges": [{"from": "b1", "to": "bt", "label": "uses"}]}
    for i, r in enumerate(reads):
        d["nodes"].append(node(f"bd{i}", "data", r, {"purpose": "answer queries"})); d["edges"].append({"from": "b1", "to": f"bd{i}", "label": "reads"})
    for i, x in enumerate(delegates):
        d["nodes"].append(node(f"bx{i}", "agent", x, {"owner": "Sam"})); d["edges"].append({"from": "b1", "to": f"bx{i}", "label": "delegates"})
    if delegates or rate:
        d["nodes"].append(node("br", "guardrail", "rate limit", {"kind": "rate"})); d["edges"].append({"from": "br", "to": "b1", "label": "limits"})
    if code:
        d["nodes"].append(node("bc", "tool", "run report", {"code": True})); d["edges"].append({"from": "b1", "to": "bc", "label": "uses"})
    if sandbox:
        d["nodes"].append(node("bs", "constraint", "sandbox", {"kind": "sandbox"}))
    return d


def mkctx(tol_fin=2, tol_hr=1, tiers=None, others=None, unknown_primary=False):
    c = AE.Ctx(dept_names={"D-FIN": "Finance", "D-HR": "HR"}, tolerance={"D-FIN": tol_fin, "D-HR": tol_hr}, tiers=dict({"DS-LEDGER": 3, "DS-PAYROLL": 4, "DS-TREASURY": 3, "DS-ARCHIVE": 2}, **(tiers or {})))
    for k, ext, dept in (("ledger", "DS-LEDGER", "D-FIN"), ("payroll", "DS-PAYROLL", "D-HR"), ("treasury", "DS-TREASURY", "D-FIN"), ("archive", "DS-ARCHIVE", "D-FIN")):
        c.stores[k] = {"ext": ext, "department": dept}
    if not unknown_primary:
        c.dept_of_agent[AE._norm(NAME)] = "D-FIN"
    for name, (d, ev) in (others or {}).items():
        c.dept_of_agent[AE._norm(name)] = "D-HR"
        c.others[AE._norm(name)] = AE.Source(d, rows_of(d), dict(ev))
    return c


def verdict(doc, evidence, others=None, **kw):
    c = mkctx(others=others, **kw)
    b = AE.build(AE.Source(doc, rows_of(doc), dict(evidence)), c)
    return AE.describe(b, c, 0)["verdict"]


def drop_node(d, nid):
    d["nodes"] = [n for n in d["nodes"] if n["id"] != nid]
    d["edges"] = [e for e in d["edges"] if nid not in (e["from"], e["to"])]


def setp(d, nid, **kw):
    for n in d["nodes"]:
        if n["id"] == nid:
            n["p"].update(kw)


def add(d, n, e=None):
    d["nodes"].append(n)
    if e:
        d["edges"].append(e)


def delegate_to(d, name, nid):
    add(d, node(nid, "agent", name, {"owner": "Sam"}), {"from": "a1", "to": nid, "label": "delegates"})


def b1():
    return baseline(), {}, dict(EV1), {}


def b2(names=(PAY,)):
    d = baseline()
    others = {}
    for i, n in enumerate(names):
        delegate_to(d, n, f"x{i}")
        others[n] = (agent_doc(n), EV1)
    return d, others, dict(EV2), {}


def chain(k, evidence=EV1):
    """primary -> Hop1 -> ... -> Hopk, the last one reads the tier-4 payroll store."""
    d = baseline()
    delegate_to(d, "Hop1", "x0")
    others = {}
    for i in range(1, k + 1):
        nxt = (f"Hop{i + 1}",) if i < k else ()
        others[f"Hop{i}"] = (agent_doc(f"Hop{i}", delegates=nxt, reads=("Payroll",) if i == k else ()), EV2 if nxt else EV1)
    return d, others, dict(evidence), {}


# ---------------- Part 1: cases: (id, risk, base builder, change, truth_flag, forecast set) ----------------
def f_r1(c):
    drop_edge(c[0], "g1", "a1")


def drop_edge(d, a, b):
    d["edges"] = [e for e in d["edges"] if not (e["from"] == a and e["to"] == b)]


def f_r2(c):
    drop_edge(c[0], "g1", "a1"); c[0]["edges"].append({"from": "g1", "to": "x0", "label": "limits"})


def f_r3(c):
    for e in c[0]["edges"]:
        if e["from"] == "i1":
            e["to"] = "t1"


def f_r4(c):
    setp(c[0], "t1", write=False)


def f_r5(c):
    for e in c[0]["edges"]:
        if e["label"] == "gates":
            e["to"] = "a1"


def f_r6(c):
    setp(c[0], "a1", owner="   ")


def f_r7(c):
    add(c[0], node("d3", "data", "Treasury", {"purpose": "x"}), {"from": "a1", "to": "d3", "label": "reads"})


def f_r8(c):
    c[3]["unknown_primary"] = True


def f_r9(c):
    add(c[0], node("d4", "data", "Shadow spreadsheet", {"purpose": "reconcile"}), {"from": "a1", "to": "d4", "label": "reads"})


def f_r10(c):
    add(c[0], node("s2", "mcp", "wiki server", {"signed": False}), {"from": "a1", "to": "s2", "label": "connects"})


def f_r11(c):
    for n in c[0]["nodes"]:
        if n["id"] == "s1":
            n["p"].pop("signed", None)


def f_r12(c):
    add(c[0], node("m2", "memory", "scratch notes", {"long": True}), {"from": "a1", "to": "m2", "label": "stores"})


def f_r13(c):
    c[1][PAY] = (agent_doc(PAY, delegates=("Unknown helper",), reads=("Payroll",)), EV2)


def f_r17(c):
    setp(c[0], "g2", kind="injection")


def f_r18(c):
    drop_node(c[0], "g2")
    for i, n in enumerate(("Ops agent", "Audit agent"), start=1):
        delegate_to(c[0], n, f"x{i}"); c[1][n] = (agent_doc(n), EV1)


def f_r19(c):
    c[1][PAY] = (agent_doc(PAY), {})


def f_r20(c):
    c[2]["astra:hitl"] = -1


def f_r21(c):
    drop_node(c[0], "i1"); drop_node(c[0], "ap1")


def f_r1b(c):
    f_r1(c); c[3]["tol_fin"] = 4


FLAWS = [("R1", "ASI01 filter linked to nothing", b1, f_r1, {"BLOCKED"}), ("R2", "ASI01 filter limits only the delegate", b2, f_r2, {"BLOCKED"}),
         ("R3", "ASI01 untrusted input feeds the tool, not the agent", b1, f_r3, {"APPROVED"}), ("R4", "ASI02 write tool declared read-only", b1, f_r4, {"APPROVED"}),
         ("R5", "ASI02 approval edge goes to the agent", b1, f_r5, {"BLOCKED"}), ("R6", "ASI03 owner is only spaces", b1, f_r6, {"APPROVED"}),
         ("R7", "ASI03 second store, purpose is 'x'", b1, f_r7, {"APPROVED"}), ("R8", "ASI03 agent unknown to the organisation", b1, f_r8, {"REQUIRES_REVIEW"}),
         ("R9", "ASI03 store not in the organisation, with a purpose", b1, f_r9, {"APPROVED"}), ("R10", "ASI04 second MCP server unsigned", b1, f_r10, {"BLOCKED"}),
         ("R11", "ASI04 MCP server with no signed property", b1, f_r11, {"BLOCKED"}), ("R12", "ASI06 two long-term memories, one retention constraint", b1, f_r12, {"APPROVED"}),
         ("R13", "ASI07 delegate delegates to an unknown agent (2 hops)", b2, f_r13, {"REQUIRES_REVIEW"}),
         ("R14", "ASI07 three-hop chain to a tier-4 store", lambda: chain(3), lambda c: None, {"APPROVED"}), ("R15", "ASI07 five-hop chain to a tier-4 store", lambda: chain(5), lambda c: None, {"APPROVED"}),
         ("R16", "ASI07 two-hop chain, no authentication attested (control)", lambda: chain(2), lambda c: None, {"REQUIRES_REVIEW"}),
         ("R17", "ASI08 delegating agent, rate limit of the wrong kind", b2, f_r17, {"BLOCKED"}), ("R18", "ASI08 three delegates, no rate limit", b2, f_r18, {"BLOCKED"}),
         ("R19", "ASI10 delegate with no attested evidence", b2, f_r19, {"REQUIRES_REVIEW"}), ("R20", "ASI02 approval evidence has lapsed", b1, f_r20, {"REQUIRES_REVIEW"}),
         ("R21", "ASI02 no untrusted input declared, write tool ungated", b1, f_r21, {"APPROVED"})]


def n_rename(name):
    def f(c):
        for n in c[0]["nodes"]:
            if n["id"] == "d1":
                n["name"] = name
    return f


def n3(c):
    c[0]["edges"] = c[0]["edges"] + [dict(e) for e in c[0]["edges"]]


def n4(c):
    for i, (t, nm) in enumerate((("note", "design note"), ("goal", "settle refunds"), ("human", "finance clerk"))):
        add(c[0], node(f"z{i}", t, nm))


def n5(c):
    add(c[0], node("ap2", "approval", "second approval"), {"from": "ap2", "to": "t2", "label": "gates"})


def n6(c):
    for i, nm in enumerate(("prompt shield", "content filter")):
        add(c[0], node(f"gx{i}", "guardrail", nm, {"kind": "injection"}), {"from": f"gx{i}", "to": "a1", "label": "limits"})


def n7(c):
    setp(c[0], "d1", purpose="Settle customer refunds from the ledger. " * 40)


def n8(c):
    add(c[0], node("d4", "data", "Archive"), {"from": "a1", "to": "d4", "label": "reads"})


def n9(c):
    delegate_to(c[0], "Ops agent", "x9"); c[1]["Ops agent"] = (agent_doc("Ops agent"), EV1)


def n10(c):
    c[0]["nodes"] = [dict(n, name="Payroll helper") if n["id"] == "x0" else n for n in c[0]["nodes"]]
    c[1]["Payroll helper"] = (agent_doc("Payroll helper"), EV1); c[1].pop(PAY, None)


def n11(c):
    c[0]["nodes"].reverse(); c[0]["edges"].reverse()


def n12(c):
    add(c[0], node("c2", "constraint", "egress limit", {"kind": "egress"}))


def n13(c):
    setp(c[0], "a1", auto="autonomous")


def n14(c):
    drop_node(c[0], "c1"); setp(c[0], "m1", long=False)


def n15(c):
    drop_node(c[0], "g2")


def n16(c):
    for i in range(6):
        add(c[0], node(f"r{i}", "tool", f"read tool {i}"), {"from": "a1", "to": f"r{i}", "label": "uses"})


def n17(c):
    c[1][PAY] = (agent_doc(PAY, code=True, sandbox=True), dict(EV1, **{"astra:sandbox": None}))


def n18(c):
    pass


def n19(c):
    setp(c[0], "s1", registry="internal", version="2.1")


def n20(c):
    add(c[0], node("d4", "data", "Archive", {"purpose": "keep closed refunds"}), {"from": "a1", "to": "d4", "label": "reads"})


def n21(c):
    drop_node(c[0], "t1"); drop_node(c[0], "ap1")


NEUTRAL = [("N1", "store name in capitals", b1, n_rename("LEDGER")), ("N2", "store name with extra spaces", b1, n_rename("  Ledger   ")), ("N3", "duplicated edges", b1, n3),
           ("N4", "isolated note, goal and human nodes", b1, n4), ("N5", "second approval on a read-only tool", b1, n5), ("N6", "two more injection filters", b1, n6),
           ("N7", "a very long purpose", b1, n7), ("N8", "store within tolerance, no purpose", b1, n8), ("N9", "second sound saved delegate", b2, n9), ("N10", "delegate renamed", b2, n10),
           ("N11", "B2 reordered", b2, n11), ("N12", "extra egress constraint", b1, n12), ("N13", "autonomy autonomous, approval kept", b1, n13), ("N14", "session-only memory, no retention", b1, n14),
           ("N15", "no rate limit on a single agent (advisory)", b1, n15), ("N16", "six read-only tools", b1, n16), ("N17", "delegate with code tool, sandbox and attestation", b2, n17),
           ("N18", "sound two-hop chain with authentication attested", lambda: chain(2, EV2), n18), ("N19", "MCP server signed, extra properties", b1, n19), ("N20", "extra store within tolerance, with a purpose", b1, n20), ("N21", "a pure read-only agent (no write tool, no approval)", b1, n21)]


def run_case(builder, change):
    c = list(builder())
    c[0] = copy.deepcopy(c[0])
    change(c)
    return verdict(c[0], c[2], c[1], **c[3])


res = {"baselines": {}, "flaws": {}, "neutral": {}, "policy": {}}
for nm, bld in (("B1", b1), ("B2", b2)):
    d, o, e, kw = bld()
    res["baselines"][nm] = verdict(d, e, o, **kw)
    assert res["baselines"][nm] == "APPROVED", f"baseline {nm} is {res['baselines'][nm]}: the test is void"
for fid, desc, bld, ch, fc in FLAWS:
    v = run_case(bld, ch)
    res["flaws"][fid] = {"desc": desc, "verdict": v, "forecast": sorted(fc), "forecast_ok": v in fc, "caught": v != "APPROVED"}
for nid, desc, bld, ch in NEUTRAL:
    v = run_case(bld, ch)
    res["neutral"][nid] = {"desc": desc, "verdict": v, "forecast": ["APPROVED"], "forecast_ok": v == "APPROVED", "approved": v == "APPROVED"}
v = run_case(b1, f_r1b)
res["policy"]["P1"] = {"desc": "R1 with the department tolerance raised to 4", "verdict": v, "forecast": ["APPROVED"], "forecast_ok": v == "APPROVED"}

# the contract built from the R5 design (an approval on the agent) against the contract of the sound design
from astra_model import events as EV                           # noqa: E402


def estate_of(builder, change):
    c = list(builder()); c[0] = copy.deepcopy(c[0]); change(c)
    cx = mkctx(others=c[1], **c[3])
    return AE.build(AE.Source(c[0], rows_of(c[0]), dict(c[2])), cx).estate


ev = {"kind": "tool_call", "agent": NAME, "t": 1, "tool": "refund", "confirmed": False}
res["runtime_r5"] = {k: {"outcome": r["outcome"], "classes": r["classes"]} for k, r in (("sound", EV.conforms(estate_of(b1, lambda c: None), ev)), ("approval_on_the_agent", EV.conforms(estate_of(b1, f_r5), ev)))}

# ---------------- Part 2: metamorphic test ----------------
SAVED = {PAY: (agent_doc(PAY), EV1)}


def rand_case(rng):
    d = {"nodes": [node("a1", "agent", NAME, {"owner": rng.choice(["Rhea", "Rhea", ""]), "auto": rng.choice(["approval", "suggests", "autonomous"])}, True)], "edges": []}
    k = [0]

    def nid():
        k[0] += 1
        return f"n{k[0]}"

    def add_(n, e=None):
        d["nodes"].append(n)
        if e:
            d["edges"].append(e)
    for _ in range(rng.randint(0, 2)):
        i = nid()
        add_(node(i, "input", f"input {i}", {"untrusted": rng.random() < 0.8}), {"from": i, "to": "a1", "label": "feeds"} if rng.random() < 0.9 else None)
    writes = []
    sandbox = False
    for _ in range(rng.randint(1, 4)):
        i = nid()
        w, code = rng.random() < 0.5, rng.random() < 0.1
        add_(node(i, "tool", f"tool {i}", {"write": w, "code": code}), {"from": "a1", "to": i, "label": "uses"})
        if w:
            writes.append(i)
        sandbox = sandbox or code
    for t in writes:
        if rng.random() < 0.6:
            i = nid()
            add_(node(i, "approval", f"approval {i}"), {"from": i, "to": t, "label": "gates"})
    if sandbox and rng.random() < 0.5:
        add_(node(nid(), "constraint", "sandbox", {"kind": "sandbox"}))
    for kind, p in (("injection", 0.6), ("rate", 0.5), ("disclosure", 0.3)):
        if rng.random() < p:
            i = nid()
            add_(node(i, "guardrail", f"{kind} guard", {"kind": kind}), {"from": i, "to": "a1", "label": "limits"} if rng.random() < 0.9 else None)
    for nm in rng.sample(["Ledger", "Treasury", "Archive"], rng.randint(0, 3)):
        i = nid()
        add_(node(i, "data", nm, {"purpose": "needed for the task"} if rng.random() < 0.6 else {}), {"from": "a1", "to": i, "label": "reads"})
    retention = rng.random() < 0.5
    for _ in range(rng.randint(0, 2)):
        i = nid()
        add_(node(i, "memory", f"memory {i}", {"long": rng.random() < 0.6}), {"from": "a1", "to": i, "label": "stores"})
    if retention:
        add_(node(nid(), "constraint", "retention", {"kind": "retention"}))
    for _ in range(rng.randint(0, 2)):
        i = nid()
        add_(node(i, "mcp", f"server {i}", {"signed": rng.random() < 0.6}), {"from": "a1", "to": i, "label": "connects"})
    for nm in rng.sample([PAY, "Unknown helper"], rng.randint(0, 2)):
        i = nid()
        add_(node(i, "agent", nm, {"owner": "Sam"}), {"from": "a1", "to": i, "label": "delegates"})
    ev = {f"astra:{kk}": None for kk in KINDS + ("auth", "sandbox") if rng.random() < (0.6 if kk in KINDS else 0.3)}
    return {"doc": d, "ev": ev, "tol_fin": rng.randint(0, 4), "tol_hr": rng.randint(0, 3), "tiers": {"DS-LEDGER": rng.randint(1, 4), "DS-TREASURY": rng.randint(1, 4), "DS-ARCHIVE": rng.randint(1, 4)}}


def vr(c):
    others = {PAY: SAVED[PAY]} if any(n["name"] == PAY for n in c["doc"]["nodes"]) else {}
    return RANK[verdict(c["doc"], c["ev"], others, tol_fin=c["tol_fin"], tol_hr=c["tol_hr"], tiers=c["tiers"])]


def find(c, t, **kw):
    return [n for n in c["doc"]["nodes"] if n["type"] == t and all(n["p"].get(a) == b for a, b in kw.items())]


def t_perm(c, rng):
    ids = [n["id"] for n in c["doc"]["nodes"] if n["id"] != "a1"]
    new = {i: f"q{j}" for j, i in enumerate(rng.sample(ids, len(ids)))}
    for n in c["doc"]["nodes"]:
        n["id"] = new.get(n["id"], n["id"])
    for e in c["doc"]["edges"]:
        e["from"], e["to"] = new.get(e["from"], e["from"]), new.get(e["to"], e["to"])
    keep = c["doc"]["nodes"][0]
    rest = c["doc"]["nodes"][1:]; rng.shuffle(rest); c["doc"]["nodes"] = [keep] + rest; rng.shuffle(c["doc"]["edges"])
    return True


def t_same(c, rng):
    return True


def t_ro_tool(c, rng):
    add(c["doc"], node("zt", "tool", "extra read tool"), {"from": "a1", "to": "zt", "label": "uses"}); return True


def t_tol(c, rng):
    c["tol_fin"], c["tol_hr"] = min(4, c["tol_fin"] + 1), min(4, c["tol_hr"] + 1); return (c["tol_fin"], c["tol_hr"]) != (4, 4) or True


def t_tier(c, rng):
    c["tiers"] = {k: max(1, v - 1) for k, v in c["tiers"].items()}; return True


def t_add_ev(c, rng):
    miss = [f"astra:{k}" for k in KINDS + ("auth", "sandbox") if f"astra:{k}" not in c["ev"]]
    if not miss:
        return False
    c["ev"][rng.choice(miss)] = None; return True


def t_rm_ev(c, rng):
    if not c["ev"]:
        return False
    del c["ev"][rng.choice(sorted(c["ev"]))]; return True


def t_rm_approval(c, rng):
    a = find(c, "approval")
    if not a:
        return False
    drop_node(c["doc"], rng.choice(a)["id"]); return True


def t_rm_inj(c, rng):
    g = find(c, "guardrail", kind="injection")
    if not g:
        return False
    drop_node(c["doc"], g[0]["id"]); return True


def t_add_purpose(c, rng):
    d = find(c, "data")
    if not d:
        return False
    for n in d:
        n["p"]["purpose"] = "needed for the task"
    return True


def t_rm_purpose(c, rng):
    d = [n for n in find(c, "data") if n["p"].get("purpose")]
    if not d:
        return False
    for n in d:
        n["p"].pop("purpose")
    return True


def t_unsign(c, rng):
    m = find(c, "mcp", signed=True)
    if not m:
        return False
    m[0]["p"]["signed"] = False; return True


def t_add_input(c, rng):
    add(c["doc"], node("zi", "input", "new untrusted input", {"untrusted": True}), {"from": "zi", "to": "a1", "label": "feeds"}); return True


def t_rm_deleg(c, rng):
    e = [e for e in c["doc"]["edges"] if e["label"] == "delegates"]
    if not e:
        return False
    drop_node(c["doc"], e[0]["to"]); return True


RELATIONS = [("M1 reorder and rename ids", t_perm, "eq"), ("M2 determinism", t_same, "eq"), ("M3 add a read-only tool", t_ro_tool, "eq"), ("M4 raise the tolerances", t_tol, "ge"),
             ("M5 lower the store tiers", t_tier, "ge"), ("M6 add evidence", t_add_ev, "ge"), ("M7 remove evidence", t_rm_ev, "le"), ("M8 remove an approval", t_rm_approval, "le"),
             ("M9 remove an injection filter", t_rm_inj, "le"), ("M10 add a purpose to every store", t_add_purpose, "ge"), ("M11 remove the purposes", t_rm_purpose, "le"),
             ("M12 make an MCP server unsigned", t_unsign, "le"), ("M13 add an untrusted input", t_add_input, "le"), ("M14 remove a delegation", t_rm_deleg, "ge")]
rng = random.Random(2026)
meta = {name: {"applicable": 0, "violations": 0, "examples": [], "relation": rel} for name, _, rel in RELATIONS}
dist = Counter()
N = 3000
for _ in range(N):
    base = rand_case(rng)
    try:
        r0 = vr(base)
    except ValueError:
        continue
    dist[r0] += 1
    for name, fn, rel in RELATIONS:
        c2 = copy.deepcopy(base)
        if not fn(c2, rng):
            continue
        try:
            r1 = vr(c2)
        except ValueError:
            continue
        meta[name]["applicable"] += 1
        bad = (rel == "eq" and r1 != r0) or (rel == "ge" and r1 < r0) or (rel == "le" and r1 > r0)
        if bad:
            meta[name]["violations"] += 1
            if len(meta[name]["examples"]) < 3:
                meta[name]["examples"].append({"before": r0, "after": r1, "design": base["doc"], "changed_design": c2["doc"], "ev_before": sorted(base["ev"]), "ev_after": sorted(c2["ev"]),
                                               "tol": [base["tol_fin"], base["tol_hr"]], "tol_after": [c2["tol_fin"], c2["tol_hr"]], "tiers": base["tiers"], "tiers_after": c2["tiers"]})
res["metamorphic"] = {"designs": N, "verdict_distribution": {str(k): v for k, v in dist.items()}, "relations": meta}
json.dump(res, open(os.environ.get("OUT", "/data/seeded3.json"), "w"), indent=1)
print("written")
