"""Seeded-flaw test, round 2, after the fixes (see SEEDED_PROTOCOL_ROUND2.md). Platform code on a scratch database. Writes /data/seeded2.json."""
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
EV1 = {f"astra:{k}": None for k in KINDS}
EV2 = dict(EV1, **{"astra:auth": None})


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


def delegate_doc():
    return {"nodes": [node("b1", "agent", DELEGATE, {"owner": "Sam", "auto": "approval"}, True), node("bt", "tool", "pay lookup", {}), node("bd", "data", "Payroll", {"purpose": "answer payroll queries"})],
            "edges": [{"from": "b1", "to": "bt", "label": "uses"}, {"from": "b1", "to": "bd", "label": "reads"}]}


def ctx(others=None):
    c = AE.Ctx(dept_names={"D-FIN": "Finance", "D-HR": "HR"}, tolerance={"D-FIN": 2, "D-HR": 1},
               tiers={"DS-LEDGER": 3, "DS-PAYROLL": 4, "DS-TREASURY": 3, "DS-ARCHIVE": 2})
    for k, ext, dept in (("ledger", "DS-LEDGER", "D-FIN"), ("payroll", "DS-PAYROLL", "D-HR"), ("treasury", "DS-TREASURY", "D-FIN"), ("archive", "DS-ARCHIVE", "D-FIN")):
        c.stores[k] = {"ext": ext, "department": dept}
    c.dept_of_agent[AE._norm(NAME)] = "D-FIN"
    c.dept_of_agent[AE._norm(DELEGATE)] = "D-HR"
    for name, (d, ev) in (others or {}).items():
        with SessionLocal() as s:
            c.others[AE._norm(name)] = AE.Source(d, _rows(s, d), dict(ev))
    return c


def assess(doc, delegate=None, evidence=None):
    with SessionLocal() as s:
        rows = _rows(s, doc)
    c = ctx({DELEGATE: (delegate, EV1)} if delegate is not None else None)
    built = AE.build(AE.Source(doc, rows, dict(evidence or EV1)), c)
    return AE.describe(built, c, 0), rows, built


def drop_node(d, nid):
    d["nodes"] = [n for n in d["nodes"] if n["id"] != nid]
    d["edges"] = [e for e in d["edges"] if nid not in (e["from"], e["to"])]


def add_delegation(d, name=DELEGATE, nid="x1"):
    d["nodes"].append(node(nid, "agent", name, {"owner": "Sam"}))
    d["edges"].append({"from": "a1", "to": nid, "label": "delegates"})


def setp(d, nid, **kw):
    for n in d["nodes"]:
        if n["id"] == nid:
            n["p"].update(kw)


def add(d, n, e=None):
    d["nodes"].append(n)
    if e:
        d["edges"].append(e)


# ---- primary-design changes (on B1 or B2) ----
PF = {
    "F1": lambda d: drop_node(d, "ap1"), "F2": lambda d: drop_node(d, "g1"), "F3": lambda d: setp(d, "s1", signed=False), "F4": lambda d: drop_node(d, "c1"), "F5": lambda d: setp(d, "a1", owner=""),
    "F6": lambda d: add(d, node("t3", "tool", "wire transfer", {"write": True}), {"from": "a1", "to": "t3", "label": "uses"}),
    "F7": lambda d: [e.update(to="t2") for e in d["edges"] if e["label"] == "gates"],
    "F8": lambda d: setp(d, "g1", kind="rate"),
    "F9": lambda d: add(d, node("d2", "data", "Payroll"), {"from": "a1", "to": "d2", "label": "reads"}),
    "F10": lambda d: add_delegation(d),
    "F11": lambda d: add_delegation(d, "Unknown helper", "x2"),
    "F12": lambda d: drop_node(d, "g2"), "F13": lambda d: drop_node(d, "g3"),
    "F14": lambda d: add(d, node("t5", "tool", "run script", {"code": True}), {"from": "a1", "to": "t5", "label": "uses"}),
    "H1": lambda d: add(d, node("d3", "data", "Treasury"), {"from": "a1", "to": "d3", "label": "reads"}),
    "H2": lambda d: setp(d, "d1", purpose="   "),
    "F12b": lambda d: drop_node(d, "g2"),
}
DF = {"H3": lambda d: add(d, node("bm", "mcp", "unsigned server", {"signed": False}), {"from": "b1", "to": "bm", "label": "connects"}),
      "H4": lambda d: setp(d, "b1", owner=""),
      "H5": lambda d: add(d, node("bw", "tool", "pay update", {"write": True}), {"from": "b1", "to": "bw", "label": "uses"}),
      "H6": lambda d: add(d, node("bc", "tool", "run report", {"code": True}), {"from": "b1", "to": "bc", "label": "uses"})}


def mk(base, pf=None, df=None, saved=False, evidence=None):
    d, dl = baseline(), None
    if base == "B2":
        add_delegation(d)
    if base == "B2" or saved or df:
        dl = delegate_doc()
    if pf:
        PF[pf](d)
    if df:
        DF[df](dl)
    return d, dl, dict(evidence or (EV2 if base == "B2" else EV1))


# (name, group, base, pf, df, saved, evidence, expected verdicts)
BLOCK, REVIEW, APPR = {"BLOCKED"}, {"REQUIRES_REVIEW"}, {"APPROVED"}
FLAWS = [
    ("F1 no approval gate", "round 1", "B1", "F1", None, False, None, BLOCK), ("F2 no injection filter", "round 1", "B1", "F2", None, False, None, BLOCK),
    ("F3 unsigned MCP server", "round 1", "B1", "F3", None, False, None, BLOCK), ("F4 memory without retention", "round 1", "B1", "F4", None, False, None, BLOCK),
    ("F5 no named owner", "round 1", "B1", "F5", None, False, None, BLOCK), ("F6 second write tool, ungated", "round 1", "B1", "F6", None, False, None, BLOCK),
    ("F7 approval beside the route", "round 1", "B1", "F7", None, False, None, BLOCK), ("F8 wrong kind of filter", "round 1", "B1", "F8", None, False, None, BLOCK),
    ("F10 over-broad delegation", "round 1", "B1", "F10", None, True, None, REVIEW),
    ("F9 over-broad data access", "fixed (G1)", "B1", "F9", None, False, None, REVIEW), ("F11 delegation, reach unknown", "fixed (G3)", "B1", "F11", None, False, None, REVIEW),
    ("F14 code tool, no sandbox", "fixed (G4)", "B1", "F14", None, False, None, BLOCK),
    ("F12b no rate limit, agent delegates", "fixed (G2)", "B2", "F12b", None, False, None, BLOCK),
    ("H1 second store above tolerance, no purpose", "held-out", "B1", "H1", None, False, None, REVIEW), ("H2 purpose is only spaces", "held-out", "B1", "H2", None, False, None, REVIEW),
    ("H3 delegate: unsigned MCP server", "held-out", "B2", None, "H3", False, None, BLOCK), ("H4 delegate: no owner", "held-out", "B2", None, "H4", False, None, BLOCK),
    ("H5 delegate: ungated write tool", "held-out", "B2", None, "H5", False, None, BLOCK), ("H6 delegate: code tool, no sandbox", "held-out", "B2", None, "H6", False, None, BLOCK),
]
ADVISORY = [("F12 no rate limit, single agent", "B1", "F12", "ASI08"), ("F13 no AI disclosure", "B1", "F13", "ASI09")]


def n_rename(d):
    for n in d["nodes"]:
        if n["type"] in ("tool", "data", "guardrail"):
            n["name"] += " (renamed)"


NEUTRAL = [
    ("N1 renamed nodes (B1)", "B1", lambda d: n_rename(d), None), ("N2 added read-only tool", "B1", lambda d: add(d, node("t4", "tool", "search", {}), {"from": "a1", "to": "t4", "label": "uses"}), None),
    ("N3 second injection filter", "B1", lambda d: add(d, node("g4", "guardrail", "second filter", {"kind": "injection"}), {"from": "g4", "to": "a1", "label": "limits"}), None),
    ("N4 second approval", "B1", lambda d: add(d, node("ap2", "approval", "second approval"), {"from": "ap2", "to": "t1", "label": "gates"}), None),
    ("N5 second untrusted input", "B1", lambda d: add(d, node("i2", "input", "web page", {"untrusted": True}), {"from": "i2", "to": "a1", "label": "feeds"}), None),
    ("N6 reordered nodes and edges", "B1", lambda d: (d["nodes"].reverse(), d["edges"].reverse()), None),
    ("N7 second retention constraint", "B1", lambda d: add(d, node("c2", "constraint", "retention 30 days", {"kind": "retention"})), None),
    ("N8 second store above tolerance, with purpose", "B1", lambda d: add(d, node("d3", "data", "Treasury", {"purpose": "hold settlement balances"}), {"from": "a1", "to": "d3", "label": "reads"}), None),
    ("N9 second store within tolerance, no purpose", "B1", lambda d: add(d, node("d4", "data", "Archive"), {"from": "a1", "to": "d4", "label": "reads"}), None),
    ("N10 code tool with a sandbox and attestation", "B1", lambda d: (add(d, node("t5", "tool", "run script", {"code": True}), {"from": "a1", "to": "t5", "label": "uses"}),
                                                                        add(d, node("sb", "constraint", "sandbox", {"kind": "sandbox"}))), dict(EV1, **{"astra:sandbox": None})),
    ("N11 renamed nodes (B2)", "B2", lambda d: n_rename(d), None),
]


def summary(out, rows, base_rows):
    viol = sorted({f"{c['kind']}:{c['agent']}" for p in out["paths"] for c in p["controls"] if c["status"] == "VIO"})
    unv = sorted({f"{c['kind']}:{c['agent']}" for p in out["paths"] if p["verdict"] != "APPROVED" for c in p["controls"] if c["status"] == "UNV"})
    return {"verdict": out["verdict"], "paths": len(out["paths"]), "violated": viol, "unverified_on_open_paths": unv, "advisory": [a["code"] for a in out["advisory"]]}


res = {"baselines": {}, "flaws": {}, "advisory": {}, "neutral": {}, "pairs": [], "runtime": {}}
for b in ("B1", "B2"):
    d, dl, ev = mk(b)
    out, rows, built = assess(d, dl, ev)
    res["baselines"][b] = {"verdict": out["verdict"], "paths": len(out["paths"]), "advisory": [a["code"] for a in out["advisory"]]}
    assert out["verdict"] == "APPROVED", f"baseline {b} is {out['verdict']}: the test is void: {summary(out, rows, rows)}"
base_rows = {}
for name, group, base, pf, df, saved, ev, expected in FLAWS:
    d, dl, e = mk(base, pf, df, saved, ev)
    out, rows, built = assess(d, dl, e)
    r = summary(out, rows, rows)
    r.update(group=group, base=base, expected=sorted(expected), as_predicted=out["verdict"] in expected)
    res["flaws"][name] = r
for name, base, pf, code in ADVISORY:
    d, dl, e = mk(base, pf)
    out, rows, built = assess(d, dl, e)
    r = summary(out, rows, rows)
    r.update(group="advisory by decision", expected=["APPROVED"], as_predicted=out["verdict"] == "APPROVED" and code in r["advisory"])
    res["advisory"][name] = r
for name, base, fn, ev in NEUTRAL:
    d, dl, e = mk(base, None, None, False, ev)
    fn(d)
    out, rows, built = assess(d, dl, e)
    r = summary(out, rows, rows)
    r.update(group="neutral", expected=["APPROVED"], as_predicted=out["verdict"] == "APPROVED")
    res["neutral"][name] = r

# pairs of the gate-affecting flaws on B1 (round-1 flaws and the fixed ones)
singles, pairs_pool = {}, ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F14"]
for k in pairs_pool:
    d, dl, e = mk("B1", k, None, k == "F10")
    singles[k] = RANK[assess(d, dl, e)[0]["verdict"]]
for a, b in itertools.combinations(pairs_pool, 2):
    d, dl, e = mk("B1", a, None, "F10" in (a, b))
    PF[b](d)
    try:
        v = RANK[assess(d, dl, e)[0]["verdict"]]
        res["pairs"].append({"a": a, "b": b, "rank": v, "best_single": max(singles[a], singles[b]), "worst_single": min(singles[a], singles[b]), "monotone": v <= max(singles[a], singles[b])})
    except Exception as exc:
        res["pairs"].append({"a": a, "b": b, "error": str(exc)[:120]})

# runtime link (as in round 1)
sound = assess(*mk("B1")[:2], mk("B1")[2])[2].estate
exploits = {"F1 no approval gate": ("F1", False, {"kind": "tool_call", "agent": NAME, "t": 1, "tool": "refund", "confirmed": False}),
            "F6 second write tool, ungated": ("F6", False, {"kind": "tool_call", "agent": NAME, "t": 1, "tool": "wire transfer"}),
            "F9 over-broad data access": ("F9", False, {"kind": "res_access", "agent": NAME, "t": 1, "resource": "DS-PAYROLL", "mode": "read"}),
            "F10 over-broad delegation": ("F10", True, {"kind": "deleg_out", "agent": NAME, "t": 1, "target": DELEGATE, "mode": "execution", "depth": 1})}
for name, (pf, saved, ev) in exploits.items():
    d, dl, e = mk("B1", pf, None, saved)
    flawed = assess(d, dl, e)[2].estate
    s, f = EV.conforms(sound, ev), EV.conforms(flawed, ev)
    res["runtime"][name] = {"event": ev["kind"], "sound_contract": s["outcome"], "sound_classes": s["classes"], "flawed_contract": f["outcome"], "flawed_classes": f["classes"]}
json.dump(res, open("/data/seeded2.json", "w"), indent=1)
print("written")
