"""
Tests for the estate builder (astra_estate.py): an agent design, the organisation and the risk layer become the formal model, read back as attack paths and a verdict.
Pure functions over plain data, so no database:

    docker compose exec backend python -m tests.test_astra_estate

The designs are written the way the studio saves them (nodes with type, name, p; edges with from, to, label). The check rows are what the OWASP checks return for a design.
"""
import copy
import sys

import astra_estate as AE
from astra_model import gate

NOW = 800000                                         # a day number


def doc(name="payments-agent", write=True, approval=False, mcp=False, data=("Ledger",), delegates=(), untrusted=True, memory=False):
    nodes = [{"id": "a1", "type": "agent", "name": name, "p": {"owner": "Owner", "auto": "approval"}, "primary": True}]
    edges = []

    def add(t, n, p, label, rev=False, to="a1"):
        nid = f"n{len(nodes)}"
        nodes.append({"id": nid, "type": t, "name": n, "p": p})
        edges.append({"from": nid, "to": to, "label": label} if rev else {"from": "a1", "to": nid, "label": label})
        return nid
    if untrusted:
        add("input", "customer email", {"untrusted": True}, "feeds", rev=True)
    tool = add("tool", "refund", {"write": write}, "uses")
    if approval:
        ap = add("approval", "manager approval", {}, "gates", rev=True, to=tool)
        assert ap
    if mcp:
        add("mcp", "docs", {"signed": True}, "connects")
    for d in data:
        add("data", d, {}, "reads")
    if memory:
        add("memory", "notes", {"long": False}, "stores")
    for d in delegates:
        add("agent", d, {"owner": "", "auto": "approval"}, "delegates")
    return {"nodes": nodes, "edges": edges}


def rows(**over):
    base = {f"ASI{i:02d}": ("Covered", "ok") for i in (1, 2, 3, 6, 7, 10)}
    base["ASI04"] = ("Not applicable", "No MCP servers")
    base.update({k.upper(): v for k, v in over.items()})
    return [{"id": k, "status": v[0], "why": v[1]} for k, v in sorted(base.items())]


def ctx(tolerance=1, tier=4):
    return AE.Ctx(dept_of_agent={"payments-agent": "D-FIN"}, dept_names={"D-FIN": "Finance"}, stores={"ledger": {"ext": "DS-L", "department": "D-FIN"}},
                  tiers={"DS-L": tier}, tolerance={"D-FIN": tolerance})


ALL = {f"astra:{k}": None for k in ("iso", "least", "ident", "life", "hitl")}


def result(d, r, c=None, ev=None, now=NOW):
    c = c or ctx()
    b = AE.build(AE.Source(d, r, ev or {}), c)
    return b, AE.describe(b, c, now)


def test_a_missing_control_on_a_severe_path_blocks():
    _b, out = result(doc(), rows(asi01=("Gap", "no injection filter"), asi02=("Gap", "no approval on the write route")))
    assert out["verdict"] == "BLOCKED" and out["runtime_name"] == "DIVERGENT", out["verdict"]
    p = out["paths"][0]
    assert p["input"] == "customer email" and p["chain"] == ["payments-agent"] and p["resource_name"] == "Ledger" and p["mode"] == "write" and p["tier"] == 4 and p["tier_declared"]
    st = {c["kind"]: c["status"] for c in p["controls"]}
    assert st["iso"] == "VIO" and st["hitl"] == "VIO" and st["supply"] == "NA" and st["least"] == "UNV", st
    assert out["departments"] == [{"department_ext": "D-FIN", "department": "Finance", "highest_open_tier": 4, "tolerance": 1, "tolerance_declared": True, "verdict": "BLOCKED"}]


def test_declared_but_unevidenced_controls_need_review():
    _b, out = result(doc(approval=True), rows())
    assert out["verdict"] == "REQUIRES_REVIEW", out["verdict"]
    assert {c["status"] for c in out["paths"][0]["controls"]} == {"UNV", "NA"}
    assert any("no attested evidence" in c["why"] for c in out["paths"][0]["controls"])


def test_attested_evidence_makes_the_controls_satisfied_and_the_path_approved():
    _b, out = result(doc(approval=True), rows(), ev=ALL)
    assert out["verdict"] == "APPROVED" and out["departments"][0]["highest_open_tier"] == 0, out
    assert {c["status"] for c in out["paths"][0]["controls"]} == {"SAT", "NA"}


def test_evidence_lapses_with_its_expiry():
    ev = dict(ALL, **{"astra:hitl": NOW + 5})
    _b, ok = result(doc(approval=True), rows(), ev=ev, now=NOW + 5)
    assert ok["verdict"] == "APPROVED"
    _b, late = result(doc(approval=True), rows(), ev=ev, now=NOW + 6)
    assert late["verdict"] == "REQUIRES_REVIEW" and any(c["kind"] == "hitl" and c["status"] == "UNV" for c in late["paths"][0]["controls"])


def test_a_gap_in_the_design_is_not_rescued_by_evidence():
    _b, out = result(doc(), rows(asi02=("Gap", "no approval")), ev=ALL)
    assert out["verdict"] == "BLOCKED" and any(c["kind"] == "hitl" and c["status"] == "VIO" for c in out["paths"][0]["controls"])


def test_an_invalid_check_is_unverified_not_violated():
    _b, out = result(doc(approval=True), rows(asi03=("Partial", "This check is invalid and could not be evaluated: x")), ev=ALL)
    assert any(c["kind"] == "least" and c["status"] == "UNV" for c in out["paths"][0]["controls"]) and out["verdict"] == "REQUIRES_REVIEW"


def test_the_tolerance_decides_what_an_open_path_means():
    _b, strict = result(doc(approval=True), rows(), c=ctx(tolerance=0))
    _b, loose = result(doc(approval=True), rows(), c=ctx(tolerance=4))
    assert strict["verdict"] == "REQUIRES_REVIEW" and loose["verdict"] == "APPROVED", (strict["verdict"], loose["verdict"])
    _b, none = result(doc(approval=True), rows(), c=AE.Ctx(dept_of_agent={"payments-agent": "D-FIN"}, dept_names={"D-FIN": "Finance"}, stores={"ledger": {"ext": "DS-L", "department": "D-FIN"}}))
    assert none["verdict"] == "REQUIRES_REVIEW" and not none["departments"][0]["tolerance_declared"], "no ratified tolerance accepts nothing"


def test_data_that_does_not_match_the_organisation_gets_the_strictest_tier():
    b, out = result(doc(data=("Ledger", "Shadow spreadsheet"), approval=True), rows(), ev=ALL)
    names = {p["resource_name"]: p for p in out["paths"]}
    assert names["Shadow spreadsheet"]["tier"] == 4 and not names["Shadow spreadsheet"]["tier_declared"] and names["Ledger"]["tier_declared"]
    assert [u["node"] for u in out["unmapped"]] == ["Shadow spreadsheet"] and b.estate.res["unmapped:payments-agent:Shadow spreadsheet"][0] == "D-FIN"


def test_an_agent_the_organisation_does_not_know_falls_in_the_unassigned_department():
    c = ctx()
    c.dept_of_agent.clear()
    b = AE.build(AE.Source(doc(data=("Shadow spreadsheet",), approval=True), rows(), {}), c)       # no evidence: the controls are only declared
    out = AE.describe(b, c, NOW)
    assert out["departments"][0]["department_ext"] == AE.UNASSIGNED and out["departments"][0]["tolerance"] == 0 and any("not linked to a department" in n for n in out["notes"])
    assert out["verdict"] == "REQUIRES_REVIEW"


def test_no_declared_untrusted_input_means_no_paths():
    _b, out = result(doc(untrusted=False), rows())
    assert out["paths"] == [] and out["verdict"] == "APPROVED"
    assert any("declares none" in lim for lim in out["limits"]), "the approximation is stated"


def test_a_read_only_agent_does_not_need_a_human_confirmation():
    _b, out = result(doc(write=False), rows(), ev={f"astra:{k}": None for k in ("iso", "least", "ident", "life")})
    assert out["paths"][0]["mode"] == "read" and "hitl" not in {c["kind"] for c in out["paths"][0]["controls"]} and out["verdict"] == "APPROVED"


def test_memory_is_a_resource_and_needs_validated_writes():
    b, out = result(doc(data=(), memory=True, approval=True), rows(asi06=("Covered", "retention")), ev=ALL)
    p = out["paths"][0]
    assert p["resource_name"] == "notes" and "memval" in {c["kind"] for c in p["controls"]} and b.estate.res[p["resource"]][2] == "memory"


def test_a_delegate_with_a_saved_design_brings_its_own_reach():
    other = doc(name="ledger-agent", data=("Ledger",), approval=True)
    c = ctx()
    c.dept_of_agent["ledger-agent"] = "D-FIN"
    c.others["ledger-agent"] = AE.Source(other, rows(), ALL)
    b = AE.build(AE.Source(doc(data=(), delegates=("ledger-agent",), approval=True), rows(), ALL), c)
    out = AE.describe(b, c, NOW)
    chains = {tuple(p["chain"]) for p in out["paths"]}
    assert ("payments-agent", "ledger-agent") in chains, chains
    p = next(x for x in out["paths"] if x["chain"] == ["payments-agent", "ledger-agent"])
    kinds = {(c_["kind"], c_["agent"]) for c_ in p["controls"]}
    assert ("deleg", "payments-agent") in kinds and ("auth", "payments-agent") in kinds and ("least", "ledger-agent") in kinds, kinds
    assert next(c_ for c_ in p["controls"] if c_["kind"] == "auth")["status"] == "UNV" and "authenticated" in next(c_ for c_ in p["controls"] if c_["kind"] == "auth")["why"]
    assert out["verdict"] == "REQUIRES_REVIEW"


def test_a_delegate_with_no_saved_design_is_reported_not_guessed():
    c = ctx()
    b = AE.build(AE.Source(doc(delegates=("mystery-agent",), approval=True), rows(), ALL), c)
    out = AE.describe(b, c, NOW)
    assert any(u["kind"] == "agent" and u["node"] == "mystery-agent" for u in out["unmapped"]) and any("unknown" in n for n in out["notes"])
    assert "mystery-agent" in out["agents"]


def test_removing_a_capability_from_the_design_never_makes_the_verdict_worse():
    big = doc(data=("Ledger", "Shadow spreadsheet"), approval=True)
    small = copy.deepcopy(big)
    gone = next(n["id"] for n in small["nodes"] if n["name"] == "Shadow spreadsheet")
    small["nodes"] = [n for n in small["nodes"] if n["id"] != gone]
    small["edges"] = [e for e in small["edges"] if gone not in (e["from"], e["to"])]
    order = {"INVALID_CONTRACT": 0, "BLOCKED": 1, "REQUIRES_REVIEW": 2, "APPROVED": 3}
    for ev in ({}, ALL):
        assert order[result(small, rows(), ev=ev)[1]["verdict"]] >= order[result(big, rows(), ev=ev)[1]["verdict"]]


def test_the_result_is_deterministic_and_the_gate_agrees_with_the_paths():
    a, b = result(doc(approval=True), rows())[1], result(doc(approval=True), rows())[1]
    assert a == b
    worst = min(gate.VERDICT_NAME.keys(), key=lambda k: k if gate.VERDICT_NAME[k] in {p["verdict"] for p in a["paths"]} else 9)
    assert gate.VERDICT_NAME[worst] == a["verdict"]


def test_suggestions_name_the_controls_that_keep_the_verdict_down_most_severe_first():
    _b, out = result(doc(), rows(asi01=("Gap", "no injection filter"), asi02=("Gap", "no approval")))
    s = out["suggestions"]
    assert [x["state"] for x in s][:2] == ["VIO", "VIO"] and {x["kind"] for x in s[:2]} == {"iso", "hitl"}, s
    fix = {x["kind"]: x for x in s}
    assert fix["iso"]["action"] == "fix" and fix["iso"]["asi"] == "ASI01" and fix["hitl"]["action"] == "fix" and fix["hitl"]["asi"] == "ASI02"
    assert all(x["tier"] == 4 and x["paths"] == 1 for x in s)
    assert {x["kind"] for x in s[2:]} == {"least", "ident", "life"} and all(x["action"] == "manual" and x["control_key"] == f"astra:{x['kind']}" for x in s[2:])
    assert len({x["id"] for x in s}) == len(s), "one suggestion per control and agent"


def test_after_the_fixes_only_evidence_is_left_to_attach_and_then_nothing():
    _b, out = result(doc(approval=True), rows())
    assert out["verdict"] == "REQUIRES_REVIEW" and {x["action"] for x in out["suggestions"]} == {"manual"} and all(x["state"] == "UNV" for x in out["suggestions"])
    assert all("attested evidence" in x["label"] for x in out["suggestions"])
    _b, done = result(doc(approval=True), rows(), ev=ALL)
    assert done["verdict"] == "APPROVED" and done["suggestions"] == []


def test_a_path_the_department_accepts_needs_no_suggestion():
    _b, out = result(doc(approval=True), rows(), c=ctx(tolerance=4))
    assert out["verdict"] == "APPROVED" and out["suggestions"] == []


def test_a_gap_in_a_delegate_is_a_manual_suggestion_about_that_agent():
    other = doc(name="ledger-agent", data=("Ledger",), approval=True)
    c = ctx()
    c.dept_of_agent["ledger-agent"] = "D-FIN"
    c.others["ledger-agent"] = AE.Source(other, rows(asi01=("Gap", "no filter")), {})
    b = AE.build(AE.Source(doc(data=(), delegates=("ledger-agent",), approval=True), rows(), ALL), c)
    s = AE.describe(b, c, NOW)["suggestions"]
    gap = next(x for x in s if x["agent"] == "ledger-agent" and x["kind"] == "iso")
    assert gap["state"] == "VIO" and gap["action"] == "manual" and "ledger-agent" in gap["label"] and gap["asi"] is None


def test_a_design_without_a_primary_agent_is_refused():
    try:
        AE.build(AE.Source({"nodes": [], "edges": []}, []), ctx())
        assert False, "should have been refused"
    except ValueError as exc:
        assert "primary agent" in str(exc)


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
