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


def doc(name="payments-agent", write=True, approval=False, mcp=False, data=("Ledger",), delegates=(), untrusted=True, memory=False, purpose=True, code=False, sandbox=False):
    nodes = [{"id": "a1", "type": "agent", "name": name, "p": {"owner": "Owner", "auto": "approval"}, "primary": True}]
    edges = []

    def add(t, n, p, label, rev=False, to="a1"):
        nid = f"n{len(nodes)}"
        nodes.append({"id": nid, "type": t, "name": n, "p": p})
        edges.append({"from": nid, "to": to, "label": label} if rev else {"from": "a1", "to": nid, "label": label})
        return nid
    if untrusted:
        add("input", "customer email", {"untrusted": True}, "feeds", rev=True)
    tool = add("tool", "refund", {"write": write, "code": code}, "uses")
    if sandbox:
        nodes.append({"id": "sb", "type": "constraint", "name": "code sandbox", "p": {"kind": "sandbox"}})
    if approval:
        ap = add("approval", "manager approval", {}, "gates", rev=True, to=tool)
        assert ap
    if mcp:
        add("mcp", "docs", {"signed": True}, "connects")
    for d in data:
        add("data", d, {"purpose": "settle customer refunds"} if purpose else {}, "reads")
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


def test_a_delegate_with_no_saved_design_is_read_at_its_strictest():
    c = ctx()
    b = AE.build(AE.Source(doc(delegates=("mystery-agent",), approval=True), rows(), ALL), c)
    out = AE.describe(b, c, NOW)
    assert any(u["kind"] == "agent" and u["node"] == "mystery-agent" for u in out["unmapped"]) and any("unknown" in n for n in out["notes"])
    assert "mystery-agent" in out["agents"]
    p = next(x for x in out["paths"] if x["chain"] == ["payments-agent", "mystery-agent"])
    assert p["tier"] == 4 and p["mode"] == "write" and p["department_ext"] == AE.UNASSIGNED and "unknown" in p["resource_name"], p
    assert out["verdict"] == "REQUIRES_REVIEW", "an agent whose reach is unknown is not approved on the strength of the others' evidence"


def test_a_data_store_above_the_tolerance_needs_a_purpose_and_evidence_cannot_stand_in_for_it():
    _b, bare = result(doc(approval=True, purpose=False), rows(), ev=ALL)
    least = next(c for c in bare["paths"][0]["controls"] if c["kind"] == "least")
    assert bare["verdict"] == "REQUIRES_REVIEW" and least["status"] == "UNV" and "gives no purpose" in least["why"], bare["verdict"]
    assert any("add a purpose" in x["label"] for x in bare["suggestions"])
    _b, ok = result(doc(approval=True), rows(), ev=ALL)
    assert ok["verdict"] == "APPROVED"


def test_a_blank_purpose_does_not_count_and_a_store_the_department_accepts_needs_none():
    d = doc(approval=True)
    for n in d["nodes"]:
        if n["type"] == "data":
            n["p"]["purpose"] = "   "
    _b, blank = result(d, rows(), ev=ALL)
    assert blank["verdict"] == "REQUIRES_REVIEW"
    _b, accepted = result(doc(approval=True, purpose=False), rows(), c=ctx(tolerance=4), ev=ALL)
    assert accepted["verdict"] == "APPROVED", "tier 4 is within a tolerance of 4: no purpose is asked for"


def test_a_missing_rate_limit_lowers_the_verdict_only_for_an_agent_that_delegates():
    other = doc(name="ledger-agent", data=("Ledger",), approval=True)
    c = ctx()
    c.dept_of_agent["ledger-agent"] = "D-FIN"
    c.others["ledger-agent"] = AE.Source(other, rows(), ALL)
    b = AE.build(AE.Source(doc(data=(), delegates=("ledger-agent",), approval=True), rows(asi08=("Gap", "No rate limit between agents")), ALL), c)
    out = AE.describe(b, c, NOW)
    assert out["verdict"] == "BLOCKED" and any(x["kind"] == "deleg" and x["status"] == "VIO" and "cascade" in x["why"] for p in out["paths"] for x in p["controls"])
    _b, single = result(doc(approval=True), rows(asi08=("Gap", "No rate limit between agents")), ev=ALL)
    assert single["verdict"] == "APPROVED" and [a["code"] for a in single["advisory"]] == ["ASI08"] and "no one" in single["advisory"][0]["reason"]


def test_a_missing_ai_disclosure_is_advisory_and_never_gates():
    _b, out = result(doc(approval=True), rows(asi09=("Partial", "Customer-facing without AI disclosure")), ev=ALL)
    assert out["verdict"] == "APPROVED" and [a["code"] for a in out["advisory"]] == ["ASI09"], out["advisory"]
    _b, clean = result(doc(approval=True), rows(), ev=ALL)
    assert clean["advisory"] == []


def test_code_execution_needs_a_sandbox_constraint():
    sand = dict(ALL, **{"astra:sandbox": None})
    _b, none = result(doc(approval=True, code=True), rows(), ev=sand)
    ctl = next(x for x in none["paths"][0]["controls"] if x["kind"] == "sandbox")
    assert none["verdict"] == "BLOCKED" and ctl["status"] == "VIO" and "no sandbox" in ctl["why"], none["verdict"]
    _b, declared = result(doc(approval=True, code=True, sandbox=True), rows(), ev=ALL)
    assert next(x for x in declared["paths"][0]["controls"] if x["kind"] == "sandbox")["status"] == "UNV" and declared["verdict"] == "REQUIRES_REVIEW"
    _b, done = result(doc(approval=True, code=True, sandbox=True), rows(), ev=sand)
    assert done["verdict"] == "APPROVED" and next(x for x in done["paths"][0]["controls"] if x["kind"] == "sandbox")["status"] == "SAT"
    _b, plain = result(doc(approval=True), rows(), ev=ALL)
    assert "sandbox" not in {x["kind"] for x in plain["paths"][0]["controls"]}, "an agent that runs no code needs no sandbox"


def test_attested_authentication_of_delegated_messages_lets_a_delegation_be_approved():
    other = doc(name="ledger-agent", data=("Ledger",), approval=True)
    c = ctx()
    c.dept_of_agent["ledger-agent"] = "D-FIN"
    c.others["ledger-agent"] = AE.Source(other, rows(), ALL)
    parent = doc(data=(), delegates=("ledger-agent",), approval=True)
    out = AE.describe(AE.build(AE.Source(parent, rows(), ALL), c), c, NOW)
    assert out["verdict"] == "REQUIRES_REVIEW" and any(x["kind"] == "auth" and x["status"] == "UNV" for p in out["paths"] for x in p["controls"])
    ok = AE.describe(AE.build(AE.Source(parent, rows(), dict(ALL, **{"astra:auth": None, "astra:deleg": None})), c), c, NOW)
    assert ok["verdict"] == "APPROVED" and any(x["kind"] == "auth" and x["status"] == "SAT" for p in ok["paths"] for x in p["controls"]), ok["verdict"]


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


def controls(out):
    return {(c["kind"], c["agent"]): c["status"] for p in out["paths"] for c in p["controls"]}


def test_the_primary_has_to_be_both_flagged_primary_and_an_agent():
    for change in ("flag_on_a_tool", "agent_without_the_flag"):
        d = doc()
        if change == "flag_on_a_tool":
            d["nodes"][0]["type"] = "tool"
        else:
            d["nodes"][0].pop("primary")
        try:
            AE.build(AE.Source(d, rows(), {}), ctx())
            assert False, change
        except ValueError as exc:
            assert "primary agent" in str(exc), change


def test_only_an_approval_with_a_gates_edge_onto_a_tool_counts_as_a_gate():
    def hitl(d):
        return AE.build(AE.Source(d, rows(), ALL), ctx()).estate.agents["payments-agent"].hitl_tools
    assert hitl(doc(approval=True)) == {"refund"}
    d = doc(approval=True)
    next(e for e in d["edges"] if e["label"] == "gates")["label"] = "limits"
    assert hitl(d) == set(), "a limits edge is not a gate"
    d = doc(approval=True)
    e = next(e for e in d["edges"] if e["label"] == "gates")
    next(n for n in d["nodes"] if n["id"] == e["from"])["type"] = "guardrail"
    assert hitl(d) == set(), "only an approval gates"
    d = doc(approval=True)
    e = next(e for e in d["edges"] if e["label"] == "gates")
    e["to"] = next(n["id"] for n in d["nodes"] if n["type"] == "data")
    assert hitl(d) == set(), "a gate onto a data store is not a gate on a tool"


def test_a_path_starts_only_at_an_untrusted_input_that_feeds_the_agent():
    def n_paths(d):
        return len(AE.describe(AE.build(AE.Source(d, rows(), ALL), ctx()), ctx(), NOW)["paths"])
    assert n_paths(doc()) == 1
    d = doc()
    next(n for n in d["nodes"] if n["type"] == "input")["p"]["untrusted"] = False
    assert n_paths(d) == 0, "a trusted input starts no path"
    d = doc()
    d["edges"] = [e for e in d["edges"] if e["label"] != "feeds"]
    assert n_paths(d) == 0, "an input that feeds nothing starts no path"
    d = doc()
    next(n for n in d["nodes"] if n["type"] == "input")["type"] = "external"
    assert n_paths(d) == 1, "an external untrusted source counts"
    d = doc()
    next(n for n in d["nodes"] if n["type"] == "input")["type"] = "tool"
    assert n_paths(d) == 0, "only inputs and external sources are untrusted inputs"
    d = doc()
    next(e for e in d["edges"] if e["label"] == "feeds")["to"] = next(n["id"] for n in d["nodes"] if n["type"] == "data")
    assert n_paths(d) == 0, "an input that feeds something other than the agent starts no path"


def test_one_tool_that_runs_code_and_one_long_term_memory_are_enough():
    d = doc(approval=True, code=True)
    d["nodes"].append({"id": "x9", "type": "tool", "name": "lookup", "p": {"write": False}})
    d["edges"].append({"from": "a1", "to": "x9", "label": "uses"})
    b = AE.build(AE.Source(d, rows(), ALL), ctx())
    assert b.estate.agents["payments-agent"].runs_code is True
    d = doc(approval=True, memory=True)
    d["nodes"].append({"id": "m2", "type": "memory", "name": "scratch", "p": {"long": True}})
    d["edges"].append({"from": "a1", "to": "m2", "label": "stores"})
    assert AE.build(AE.Source(d, rows(asi06=("Covered", "retention")), ALL), ctx()).estate.agents["payments-agent"].long_term_memory is True
    assert AE.build(AE.Source(doc(approval=True, memory=True), rows(asi06=("Covered", "retention")), ALL), ctx()).estate.agents["payments-agent"].long_term_memory is False


def test_a_sandbox_has_to_be_a_constraint_of_kind_sandbox():
    sand = dict(ALL, **{"astra:sandbox": None})
    for ntype, kind in (("constraint", "retention"), ("guardrail", "sandbox")):
        d = doc(approval=True, code=True)
        d["nodes"].append({"id": "z1", "type": ntype, "name": "not a sandbox", "p": {"kind": kind}})
        _b, out = result(d, rows(), ev=sand)
        assert controls(out)[("sandbox", "payments-agent")] == "VIO", (ntype, kind)


def test_a_probe_pass_supports_a_control_until_it_lapses_and_a_miss_never_lifts():
    ev = {k: v for k, v in ALL.items() if k != "astra:iso"}
    _b, unproved = result(doc(approval=True), rows(), ev=ev)
    assert controls(unproved)[("iso", "payments-agent")] == "UNV"
    c = ctx()
    b = AE.build(AE.Source(doc(approval=True), rows(), ev, probe={"iso": (True, NOW + 5)}), c)
    assert controls(AE.describe(b, c, NOW + 5))[("iso", "payments-agent")] == "SAT"
    assert controls(AE.describe(b, c, NOW + 6))[("iso", "payments-agent")] == "UNV", "a Probe pass lapses"
    b = AE.build(AE.Source(doc(approval=True), rows(), ev, probe={"iso": (True, None)}), c)
    assert controls(AE.describe(b, c, NOW + 10 ** 6))[("iso", "payments-agent")] == "SAT", "no expiry means none"
    b = AE.build(AE.Source(doc(approval=True), rows(), ALL, probe={"iso": (False, None)}), c)
    assert controls(AE.describe(b, c, NOW))[("iso", "payments-agent")] == "VIO", "a missed scenario is not rescued by an attestation"
    b = AE.build(AE.Source(doc(approval=True), rows(asi01=("Gap", "no filter")), ev, probe={"iso": (True, None)}), c)
    assert controls(AE.describe(b, c, NOW))[("iso", "payments-agent")] == "VIO", "a pass never rescues a gap the design shows"
    b = AE.build(AE.Source(doc(approval=True), rows(), dict(ALL, **{"astra:iso": NOW + 50}), probe={"iso": (True, NOW + 5)}), c)
    assert controls(AE.describe(b, c, NOW + 20))[("iso", "payments-agent")] == "SAT", "a short Probe pass does not shorten a longer attestation"


def test_the_baseline_control_is_required_for_a_monitored_agent_and_needs_its_own_evidence():
    c = ctx()
    b = AE.build(AE.Source(doc(approval=True), rows(), ALL, monitored=True), c)
    assert controls(AE.describe(b, c, NOW))[("base", "payments-agent")] == "UNV"
    b = AE.build(AE.Source(doc(approval=True), rows(), dict(ALL, **{"astra:base": None}), monitored=True), c)
    assert controls(AE.describe(b, c, NOW + 10 ** 6))[("base", "payments-agent")] == "SAT"
    b = AE.build(AE.Source(doc(approval=True), rows(), dict(ALL, **{"astra:base": NOW + 5}), monitored=True), c)
    assert controls(AE.describe(b, c, NOW + 5))[("base", "payments-agent")] == "SAT" and controls(AE.describe(b, c, NOW + 6))[("base", "payments-agent")] == "UNV"
    b = AE.build(AE.Source(doc(approval=True), rows(), ALL), c)
    assert ("base", "payments-agent") not in controls(AE.describe(b, c, NOW)), "an agent with no calibrated baseline needs none"


def test_a_check_that_is_invalid_is_not_a_failure_and_a_partial_one_is():
    other = doc(name="ledger-agent", data=("Ledger",), approval=True)
    c = ctx()
    c.dept_of_agent["ledger-agent"] = "D-FIN"
    c.others["ledger-agent"] = AE.Source(other, rows(), ALL)
    parent = doc(data=(), delegates=("ledger-agent",), approval=True)
    bad = AE.describe(AE.build(AE.Source(parent, rows(asi08=("Partial", "This check is invalid and could not be evaluated: x")), ALL), c), c, NOW)
    assert bad["advisory"] == [] and controls(bad)[("deleg", "payments-agent")] != "VIO"
    part = AE.describe(AE.build(AE.Source(parent, rows(asi08=("Partial", "a rate limit exists but is too high")), ALL), c), c, NOW)
    assert controls(part)[("deleg", "payments-agent")] == "VIO"
    gap = AE.describe(AE.build(AE.Source(parent, rows(asi08=("Gap", "none")), ALL), c), c, NOW)
    assert controls(gap)[("deleg", "payments-agent")] == "VIO"
    ok = AE.describe(AE.build(AE.Source(parent, rows(asi08=("Covered", "limited")), ALL), c), c, NOW)
    assert controls(ok)[("deleg", "payments-agent")] != "VIO" and ok["advisory"] == []


def test_the_purpose_rule_applies_strictly_above_the_tolerance_and_a_store_without_a_department_takes_the_agents():
    _b, equal = result(doc(approval=True, purpose=False), rows(), c=ctx(tolerance=4, tier=4), ev=ALL)
    assert equal["verdict"] == "APPROVED" and controls(equal)[("least", "payments-agent")] == "SAT", "tier equal to the tolerance is accepted: nothing to explain"
    _b, above = result(doc(approval=True, purpose=False), rows(), c=ctx(tolerance=3, tier=4), ev=ALL)
    assert controls(above)[("least", "payments-agent")] == "UNV"
    c = ctx()
    c.stores["ledger"] = {"ext": "DS-L"}
    b = AE.build(AE.Source(doc(approval=True), rows(), ALL), c)
    assert b.estate.res["DS-L"][0] == "D-FIN", "a store that names no department takes the agent's"
    b2 = AE.build(AE.Source(doc(data=("Ledger", "Shadow")), rows(), ALL), ctx())
    assert b2.resources["DS-L"]["matched"] is True and b2.resources["unmapped:payments-agent:Shadow"]["matched"] is False
    assert b2.estate.agents["payments-agent"].components == {} and AE.build(AE.Source(doc(mcp=True), rows(), ALL), ctx()).estate.agents["payments-agent"].components == {"docs": True}


def test_a_delegation_cycle_terminates_and_the_unknown_reach_is_described_exactly():
    a_doc, b_doc = doc(data=(), delegates=("ledger-agent",), approval=True), doc(name="ledger-agent", data=("Ledger",), delegates=("payments-agent",), approval=True)
    c = ctx()
    c.dept_of_agent["ledger-agent"] = "D-FIN"
    c.others["ledger-agent"] = AE.Source(b_doc, rows(), ALL)
    c.others["payments-agent"] = AE.Source(a_doc, rows(), ALL)
    b = AE.build(AE.Source(a_doc, rows(), ALL), c)
    assert sorted(b.estate.agents) == ["ledger-agent", "payments-agent"]
    b = AE.build(AE.Source(doc(delegates=("mystery-agent",), approval=True), rows(), ALL), ctx())
    r = b.resources["unknown-reach:mystery-agent"]
    assert r["tier"] == 4 and r["declared"] is False and r["matched"] is False and r["department_ext"] == AE.UNASSIGNED
    assert b.estate.res["unknown-reach:mystery-agent"] == (AE.UNASSIGNED, 4, "data") and b.estate.agents["mystery-agent"].resources == {"unknown-reach:mystery-agent": "write"}


def test_the_size_limits_are_exact():
    def build(n):
        return AE.build(AE.Source(doc(data=tuple(f"store {i}" for i in range(n)), approval=True), rows(), ALL), ctx())
    assert not any("attack paths" in note for note in build(AE.WARN_PATHS).notes)
    assert any("attack paths, which is large" in note for note in build(AE.WARN_PATHS + 1).notes)
    build(AE.MAX_PATHS)
    try:
        build(AE.MAX_PATHS + 1)
        assert False, "should have been refused"
    except ValueError as exc:
        assert "more than 5000 attack paths" in str(exc)
    assert (AE.WARN_PATHS, AE.MAX_PATHS) == (500, 5000)


def test_the_suggestions_say_what_to_do_how_many_paths_it_helps_and_in_which_order():
    _b, out = result(doc(), rows(asi01=("Gap", "no injection filter"), asi02=("Gap", "no approval on the write route")))
    by = {x["kind"]: x for x in out["suggestions"]}
    assert by["iso"]["action"] == "fix" and by["iso"]["asi"] == "ASI01" and by["iso"]["label"] == "Add a prompt-injection filter" and by["iso"]["tier"] == 4 and by["iso"]["paths"] == 1
    assert by["hitl"]["asi"] == "ASI02" and by["hitl"]["label"] == "Put a human approval on every write tool"
    assert out["paths"][0]["id"] == "P1"
    states = [x["state"] for x in out["suggestions"]]
    assert states == sorted(states, key=lambda v: v != "VIO"), "violations come before unverified controls"
    d = doc(approval=True)
    d["nodes"][0]["p"]["owner"] = ""
    _b, own = result(d, rows(asi10=("Gap", "no owner")))
    ident = next(x for x in own["suggestions"] if x["kind"] == "ident")
    assert ident["action"] == "manual" and ident["label"] == "Name an accountable owner for the agent" and ident["asi"] is None
    _b, many = result(doc(data=("Ledger", "Other"), approval=True), rows(asi01=("Gap", "no filter")))
    assert next(x for x in many["suggestions"] if x["kind"] == "iso")["paths"] == 2, "one control that holds up two paths helps both"


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
