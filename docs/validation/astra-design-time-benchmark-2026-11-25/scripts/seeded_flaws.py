"""Seeded-flaw test (see SEEDED_PROTOCOL.md). Runs the platform's own design-time assessment on a scratch database. Writes /data/seeded.json."""
import copy
import itertools
import json
import sys

sys.path.insert(0, "/w/backend")
from db.bootstrap import init_database                         # noqa: E402
from db.session import SessionLocal                            # noqa: E402

import astra_estate as AE                                      # noqa: E402
from astra_assessment_api import _rows                         # noqa: E402
from astra_model import events as EV                           # noqa: E402

init_database()
NAME, DELEGATE = "Seeded baseline agent", "Payroll agent"
RANK = {"INVALID_CONTRACT": 0, "BLOCKED": 1, "REQUIRES_REVIEW": 2, "APPROVED": 3}
KINDS = ("iso", "hitl", "least", "supply", "memval", "deleg", "ident", "life")
EVIDENCE = {f"astra:{k}": None for k in KINDS}


def node(i, t, name, p=None, primary=False):
    d = {"id": i, "type": t, "name": name, "p": p or {}}
    if primary:
        d["primary"] = True
    return d


def baseline():
    return {"nodes": [node("a1", "agent", NAME, {"owner": "Rhea", "auto": "approval"}, True), node("i1", "input", "customer email", {"untrusted": True}),
                      node("t1", "tool", "refund", {"write": True}), node("t2", "tool", "lookup", {}), node("d1", "data", "Ledger"),
                      node("ap1", "approval", "manager approval"), node("g1", "guardrail", "injection filter", {"kind": "injection"}),
                      node("g2", "guardrail", "rate limit", {"kind": "rate"}), node("g3", "guardrail", "AI disclosure", {"kind": "disclosure"}), node("h1", "human", "customer"),
                      node("m1", "memory", "case notes", {"long": True}), node("c1", "constraint", "retention", {"kind": "retention"}), node("s1", "mcp", "ticket server", {"signed": True})],
            "edges": [{"from": "i1", "to": "a1", "label": "feeds"}, {"from": "a1", "to": "t1", "label": "uses"}, {"from": "a1", "to": "t2", "label": "uses"},
                      {"from": "a1", "to": "d1", "label": "reads"}, {"from": "ap1", "to": "t1", "label": "gates"}, {"from": "g1", "to": "a1", "label": "limits"},
                      {"from": "a1", "to": "m1", "label": "stores"}, {"from": "a1", "to": "s1", "label": "connects"}]}


def delegate_doc():
    return {"nodes": [node("b1", "agent", DELEGATE, {"owner": "Sam", "auto": "approval"}, True), node("bt", "tool", "pay lookup", {}), node("bd", "data", "Payroll")],
            "edges": [{"from": "b1", "to": "bt", "label": "uses"}, {"from": "b1", "to": "bd", "label": "reads"}]}


def ctx(with_payroll=False, delegate_saved=False):
    c = AE.Ctx(dept_names={"D-FIN": "Finance", "D-HR": "HR"}, tolerance={"D-FIN": 2, "D-HR": 1}, tiers={"DS-LEDGER": 3, "DS-PAYROLL": 4})
    c.stores["ledger"] = {"ext": "DS-LEDGER", "department": "D-FIN"}
    c.stores["payroll"] = {"ext": "DS-PAYROLL", "department": "D-HR"}
    c.dept_of_agent[AE._norm(NAME)] = "D-FIN"
    c.dept_of_agent[AE._norm(DELEGATE)] = "D-HR"
    if delegate_saved:
        d = delegate_doc()
        with SessionLocal() as s:
            c.others[AE._norm(DELEGATE)] = AE.Source(d, _rows(s, d), dict(EVIDENCE))
    return c


def assess(doc, delegate_saved=False):
    with SessionLocal() as s:
        rows = _rows(s, doc)
    c = ctx(delegate_saved=delegate_saved)
    built = AE.build(AE.Source(doc, rows, dict(EVIDENCE)), c)
    out = AE.describe(built, c, 0)
    return out, rows, built


# ---- flaws: each takes a baseline document and returns (document, delegate_saved) ----
def drop_node(d, nid):
    d["nodes"] = [n for n in d["nodes"] if n["id"] != nid]
    d["edges"] = [e for e in d["edges"] if nid not in (e["from"], e["to"])]


def f1(d):
    drop_node(d, "ap1")


def f2(d):
    drop_node(d, "g1")


def f3(d):
    next(n for n in d["nodes"] if n["id"] == "s1")["p"]["signed"] = False


def f4(d):
    drop_node(d, "c1")


def f5(d):
    next(n for n in d["nodes"] if n["id"] == "a1")["p"]["owner"] = ""


def f6(d):
    d["nodes"].append(node("t3", "tool", "wire transfer", {"write": True}))
    d["edges"].append({"from": "a1", "to": "t3", "label": "uses"})


def f7(d):
    for e in d["edges"]:
        if e["label"] == "gates":
            e["to"] = "t2"


def f8(d):
    for n in d["nodes"]:                          # a pair that already removed the filter has nothing left to mislabel
        if n["id"] == "g1":
            n["p"]["kind"] = "rate"


def f9(d):
    d["nodes"].append(node("d2", "data", "Payroll"))
    d["edges"].append({"from": "a1", "to": "d2", "label": "reads"})


def f10(d):
    d["nodes"].append(node("x1", "agent", DELEGATE, {"owner": "Sam"}))
    d["edges"].append({"from": "a1", "to": "x1", "label": "delegates"})


def f11(d):
    d["nodes"].append(node("x1", "agent", "Unknown helper", {}))
    d["edges"].append({"from": "a1", "to": "x1", "label": "delegates"})


def f12(d):
    drop_node(d, "g2")


def f13(d):
    drop_node(d, "g3")


FLAWS = {"F1 no approval gate": (f1, False), "F2 no injection filter": (f2, False), "F3 unsigned MCP server": (f3, False), "F4 memory without retention": (f4, False),
         "F5 no named owner": (f5, False), "F6 second write tool, ungated": (f6, False), "F7 approval beside the route": (f7, False), "F8 wrong kind of filter": (f8, False),
         "F9 over-broad data access": (f9, False), "F10 over-broad delegation": (f10, True), "F11 delegation, reach unknown": (f11, False),
         "F12 no rate limit": (f12, False), "F13 no AI disclosure": (f13, False)}


def n1(d):
    for n in d["nodes"]:
        n["name"] = n["name"] + " (renamed)" if n["type"] in ("tool", "data", "guardrail") else n["name"]


def n2(d):
    d["nodes"].append(node("t4", "tool", "search", {}))
    d["edges"].append({"from": "a1", "to": "t4", "label": "uses"})


def n3(d):
    d["nodes"].append(node("g4", "guardrail", "second injection filter", {"kind": "injection"}))
    d["edges"].append({"from": "g4", "to": "a1", "label": "limits"})


def n4(d):
    d["nodes"].append(node("ap2", "approval", "second approval"))
    d["edges"].append({"from": "ap2", "to": "t1", "label": "gates"})


def n5(d):
    d["nodes"].append(node("i2", "input", "web page", {"untrusted": True}))
    d["edges"].append({"from": "i2", "to": "a1", "label": "feeds"})


def n6(d):
    d["nodes"].reverse()
    d["edges"].reverse()


def n7(d):
    d["nodes"].append(node("c2", "constraint", "retention 30 days", {"kind": "retention"}))


NEUTRAL = {"N1 renamed nodes": n1, "N2 added read-only tool": n2, "N3 second injection filter": n3, "N4 second approval": n4, "N5 second untrusted input": n5,
           "N6 reordered nodes and edges": n6, "N7 second retention constraint": n7}


def summary(out, rows, base_rows):
    changed = [r["id"] for r, b in zip(sorted(rows, key=lambda x: x["id"]), sorted(base_rows, key=lambda x: x["id"])) if r["status"] != b["status"]]
    viol = sorted({f"{c['kind']}:{c['agent']}" for p in out["paths"] for c in p["controls"] if c["status"] == "VIO"})
    return {"verdict": out["verdict"], "paths": len(out["paths"]), "rows_changed": changed, "violated": viol, "notes": out["notes"][:2]}


res = {}
base, brow, bbuilt = assess(baseline())
res["baseline"] = {"verdict": base["verdict"], "paths": len(base["paths"]), "rows": {r["id"]: r["status"] for r in brow}}
assert base["verdict"] == "APPROVED", f"baseline is {base['verdict']}: the test is void"
res["flaws"], res["neutral"], res["pairs"] = {}, {}, []
single = {}
for name, (fn, saved) in FLAWS.items():
    d = baseline()
    fn(d)
    out, rows, built = assess(d, saved)
    res["flaws"][name] = summary(out, rows, brow)
    single[name] = RANK[out["verdict"]]
for name, fn in NEUTRAL.items():
    d = baseline()
    fn(d)
    out, rows, built = assess(d)
    res["neutral"][name] = summary(out, rows, brow)
gate_flaws = [k for k in FLAWS if k.split()[0] in ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8")]
for a, b in itertools.combinations(gate_flaws, 2):
    d = baseline()
    FLAWS[a][0](d)
    FLAWS[b][0](d)
    try:
        out, rows, built = assess(d)
        v = RANK[out["verdict"]]
    except Exception as exc:
        v = None
        res["pairs"].append({"a": a, "b": b, "error": str(exc)[:120]})
        continue
    res["pairs"].append({"a": a, "b": b, "verdict": out["verdict"], "monotone": v <= min(single[a], single[b])})

# ---- runtime link: the contract of the sound design against the contract of the flawed design ----
def contract(doc, saved=False):
    out, rows, built = assess(doc, saved)
    return built.estate


sound = contract(delegate_with := baseline(), False)
exploits = {"F1 no approval gate": (f1, False, {"kind": "tool_call", "agent": NAME, "t": 1, "tool": "refund", "confirmed": False}),
            "F6 second write tool, ungated": (f6, False, {"kind": "tool_call", "agent": NAME, "t": 1, "tool": "wire transfer"}),
            "F9 over-broad data access": (f9, False, {"kind": "res_access", "agent": NAME, "t": 1, "resource": "DS-PAYROLL", "mode": "read"}),
            "F10 over-broad delegation": (f10, True, {"kind": "deleg_out", "agent": NAME, "t": 1, "target": DELEGATE, "mode": "execution", "depth": 1})}
# the sound contract for F10 must be built the same way (delegate saved), with the delegation absent
res["runtime"] = {}
for name, (fn, saved, ev) in exploits.items():
    d = baseline()
    fn(d)
    flawed = contract(d, saved)
    s = EV.conforms(sound, ev)
    f = EV.conforms(flawed, ev)
    res["runtime"][name] = {"event": ev["kind"], "sound_contract": s["outcome"], "sound_classes": s["classes"], "flawed_contract": f["outcome"], "flawed_classes": f["classes"]}
res["not_expressible"] = {"F14 code execution": "ASI05 is 'never applicable' in the seeded rules: the design vocabulary has no code-execution tool, so the flaw cannot be written"}
json.dump(res, open("/data/seeded.json", "w"), indent=1)
print("written")
