"""
Tests for rule_checks.py. Plain asserts, no test framework needed:

    docker compose exec backend python -m tests.test_rule_checks
"""
import sys

from rule_checks import (
    CheckConfigError, DesignGraph, GEdge, GNode, evaluate_graph_rule, holds, select, validate_config,
)


def graph(*nodes, edges=()):
    return DesignGraph(list(nodes), [GEdge(*e) for e in edges])


def n(id, type, primary=False, **props):
    return GNode(id, type, props, primary)


def raises(fn, exc=CheckConfigError):
    try:
        fn()
    except exc:
        return True
    return False


# ── selectors ───────────────────────────────────────────────────────────────

def test_select_by_type_primary_and_where():
    g = graph(n("a1", "agent", True, owner="CX eng"), n("a2", "agent"), n("t1", "tool", write=True), n("t2", "tool", write=False))
    assert [x.id for x in select(g, {"type": "agent"})] == ["a1", "a2"]
    assert [x.id for x in select(g, {"primary": True})] == ["a1"]
    assert [x.id for x in select(g, {"type": ["tool", "agent"], "where": {"write": True}})] == ["t1"]
    assert [x.id for x in select(g, {"type": "tool", "where": {"write": False}})] == ["t2"]


def test_where_operators():
    g = graph(n("m1", "mcp", signed=True), n("m2", "mcp"), n("m3", "mcp", signed=False), n("a", "agent", True, owner="  "), n("b", "agent", owner="Platform"))
    assert [x.id for x in select(g, {"type": "mcp", "where": {"signed": {"falsy": True}}})] == ["m2", "m3"]
    assert [x.id for x in select(g, {"type": "mcp", "where": {"signed": {"truthy": True}}})] == ["m1"]
    assert [x.id for x in select(g, {"type": "agent", "where": {"owner": {"nonempty": True}}})] == ["b"]
    assert [x.id for x in select(g, {"type": "agent", "where": {"owner": {"empty": True}}})] == ["a"]
    assert [x.id for x in select(g, {"type": "agent", "where": {"owner": {"in": ["Platform", "CX eng"]}}})] == ["b"]
    assert [x.id for x in select(g, {"type": "agent", "where": {"owner": {"eq": "Platform"}}})] == ["b"]
    assert [x.id for x in select(g, {"type": "agent", "where": {"owner": {"ne": "Platform"}}})] == ["a"]


# ── conditions ──────────────────────────────────────────────────────────────

def test_boolean_combinators_and_counts():
    g = graph(n("t1", "tool", write=True), n("t2", "tool", write=True), n("g1", "guardrail", kind="rate"), edges=[("a", "b", "delegates")])
    write = {"type": "tool", "where": {"write": True}}
    assert holds(g, {"exists": write})
    assert holds(g, {"count": {"select": write, "op": "==", "value": 2}})
    assert not holds(g, {"count": {"select": write, "op": ">", "value": 2}})
    assert holds(g, {"all": [{"exists": write}, {"exists": {"type": "guardrail", "where": {"kind": "rate"}}}]})
    assert not holds(g, {"all": [{"exists": write}, {"exists": {"type": "approval"}}]})
    assert holds(g, {"any": [{"exists": {"type": "approval"}}, {"exists": write}]})
    assert holds(g, {"not": {"exists": {"type": "approval"}}})
    assert holds(g, {"edge_exists": {"label": "delegates"}})
    assert not holds(g, {"edge_exists": {"label": "gates"}})
    assert holds(g, {"edge_count": {"label": "delegates", "op": "==", "value": 1}})
    assert holds(g, {"always": True}) and not holds(g, {"never": True})


# ── whole rules ─────────────────────────────────────────────────────────────

INJECTION = {
    "code": "ASI01",
    "applies_if": {"all": [{"exists": {"type": "input", "where": {"untrusted": True}}}, {"exists": {"type": "tool", "where": {"write": True}}}]},
    "satisfied_if": {"exists": {"type": "guardrail", "where": {"kind": "injection"}}},
    "flag_nodes": [{"primary": True}, {"type": "input", "where": {"untrusted": True}}],
    "messages": {"not_applicable": "No untrusted input with write tools", "satisfied": "Filter present", "unsatisfied": "Untrusted input reaches a write tool"},
}


def test_rule_not_applicable_satisfied_unsatisfied_and_flags():
    safe = graph(n("a1", "agent", True), n("t1", "tool", write=False))
    out = evaluate_graph_rule(safe, INJECTION)
    assert (out.status, out.message, out.flagged) == ("NOT_APPLICABLE", "No untrusted input with write tools", [])

    risky = graph(n("a1", "agent", True), n("i1", "input", untrusted=True), n("t1", "tool", write=True))
    out = evaluate_graph_rule(risky, INJECTION)
    assert (out.status, out.message, out.flagged) == ("RED", "Untrusted input reaches a write tool", ["a1", "i1"])
    assert evaluate_graph_rule(risky, INJECTION, default_unsatisfied="AMBER").status == "AMBER"
    assert evaluate_graph_rule(risky, {**INJECTION, "unsatisfied_status": "AMBER"}).status == "AMBER"

    fixed = graph(*risky.nodes, n("g1", "guardrail", kind="injection"))
    out = evaluate_graph_rule(fixed, INJECTION)
    assert (out.status, out.message, out.flagged) == ("GREEN", "Filter present", [])


def test_variables_in_messages_and_inapplicable_overrides():
    cfg = {
        "applies_if": {"exists": {"type": "mcp"}},
        "satisfied_if": {"count": {"select": {"type": "mcp", "where": {"signed": {"falsy": True}}}, "op": "==", "value": 0}},
        "vars": {"n": {"count": {"type": "mcp", "where": {"signed": {"falsy": True}}}}, "owner": {"prop": {"select": {"primary": True}, "name": "owner"}}},
        "messages": {"unsatisfied": "{n} unsigned MCP server(s), owner {owner}", "not_applicable": "No MCP servers"},
        "inapplicable": [{"when": {"exists": {"type": "memory"}}, "status": "GREEN", "message": "Session memory only"}],
    }
    g = graph(n("a1", "agent", True, owner="Platform"), n("m1", "mcp"), n("m2", "mcp", signed=True))
    assert evaluate_graph_rule(g, cfg).message == "1 unsigned MCP server(s), owner Platform"
    assert evaluate_graph_rule(graph(n("a1", "agent", True)), cfg).status == "NOT_APPLICABLE"
    out = evaluate_graph_rule(graph(n("mem", "memory")), cfg)
    assert (out.status, out.message) == ("GREEN", "Session memory only")


def test_missing_primary_does_not_crash():
    cfg = {"satisfied_if": {"exists": {"type": "agent", "primary": True, "where": {"owner": {"nonempty": True}}}},
           "flag_nodes": [{"primary": True}], "messages": {"unsatisfied": "No owner"}}
    out = evaluate_graph_rule(graph(), cfg)
    assert (out.status, out.message, out.flagged) == ("RED", "No owner", [])


# ── bad and hostile configs ─────────────────────────────────────────────────

def test_malformed_configs_raise_a_config_error():
    g = graph(n("a", "agent"))
    assert raises(lambda: holds(g, {"frobnicate": 1}))
    assert raises(lambda: holds(g, {"all": {"not": "a list"}}))
    assert raises(lambda: holds(g, {"exists": {"type": "tool"}, "extra": 1}))
    assert raises(lambda: holds(g, {"count": {"select": {}, "op": "~=", "value": 1}}))
    assert raises(lambda: holds(g, {"count": {"select": {}, "op": ">=", "value": "1"}}))
    assert raises(lambda: select(g, {"where": {"x": {"bogus": 1}}}))
    assert raises(lambda: evaluate_graph_rule(g, {}))
    assert raises(lambda: evaluate_graph_rule(g, {"satisfied_if": {"never": True}, "unsatisfied_status": "PURPLE"}))
    deep = {"always": True}
    for _ in range(40):
        deep = {"not": deep}
    assert raises(lambda: holds(g, deep))


def test_values_are_data_never_code():
    g = graph(n("a", "agent", owner="__import__('os').system('echo pwned')"))
    assert select(g, {"where": {"owner": "__import__('os').system('echo pwned')"}})  # compared as a string, nothing runs
    # Message templates are substituted token by token, never passed to str.format, so
    # attribute/index tricks cannot reach into objects: unknown names render empty and
    # anything that isn't a plain {name} token stays literal.
    out = evaluate_graph_rule(g, {"satisfied_if": {"never": True}, "messages": {"unsatisfied": "{__class__} {0} {x.y}"}})
    assert out.message == "  {x.y}", repr(out.message)


def test_validate_config_reports_every_problem():
    assert validate_config(INJECTION) == []
    errs = validate_config({"applies_if": {"nope": 1}, "flag_nodes": [{"colour": "red"}], "unsatisfied_status": "PURPLE"})
    assert any("satisfied_if" in e for e in errs)
    assert any("unknown operator" in e for e in errs)
    assert any("unknown selector key" in e for e in errs)
    assert any("unsatisfied_status" in e for e in errs)
    assert validate_config("not an object") == ["check_config must be an object"]


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
