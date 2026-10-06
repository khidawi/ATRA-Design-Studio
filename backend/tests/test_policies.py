"""
Tests for the organisation-policy compiler (policies.py). Plain asserts:

    docker compose exec backend python -m tests.test_policies
"""
import sys

from policies import PolicySpec, describe, spec_to_check_config, validate_spec
from rule_checks import DesignGraph, GEdge, GNode, evaluate_graph_rule, validate_config


def spec(**kw):
    return PolicySpec.model_validate(kw)


def run(subject, s, graph, severity="RED"):
    assert validate_spec(subject, s) == [], validate_spec(subject, s)
    config = spec_to_check_config(s, "Violated", "ORG-TEST")
    assert validate_config(config) == [], validate_config(config)
    return evaluate_graph_rule(graph, config, severity)


def g(nodes, edges=()):
    return DesignGraph([GNode(*n) for n in nodes], [GEdge(*e) for e in edges])


# ── compile + evaluate ──────────────────────────────────────────────────────

def test_agent_when_write_tool_require_approval():
    s = spec(when={"element": "tool", "where": [{"property": "write", "op": "is_true"}]}, rule="REQUIRE", element="approval")
    ro = g([("a", "agent", {}, True), ("t", "tool", {"write": False})])
    assert run("AGENT", s, ro).status == "NOT_APPLICABLE"

    risky = g([("a", "agent", {}, True), ("t1", "tool", {"write": True}), ("t2", "tool", {"write": False})])
    out = run("AGENT", s, risky)
    assert (out.status, out.message, out.flagged) == ("RED", "Violated", ["t1"])  # the offending tool is flagged
    assert run("AGENT", s, risky, "AMBER").status == "AMBER"                       # RECOMMENDED policy

    fixed = g([("a", "agent", {}, True), ("t1", "tool", {"write": True}), ("ap", "approval", {})])
    out = run("AGENT", s, fixed)
    assert (out.status, out.flagged) == ("GREEN", [])


def test_model_forbid_third_party_hosting():
    s = spec(rule="FORBID", element="AI_MODEL", where=[{"property": "hostingEnvironment", "op": "is", "value": "TYPE_3_THIRDPARTY_API"}])
    ok = g([("m1", "AI_MODEL", {"hostingEnvironment": "TYPE_1_INHOUSE"})])
    assert run("MODEL", s, ok).status == "GREEN"
    bad = g([("m1", "AI_MODEL", {"hostingEnvironment": "TYPE_1_INHOUSE"}), ("m2", "AI_MODEL", {"hostingEnvironment": "TYPE_3_THIRDPARTY_API"})])
    out = run("MODEL", s, bad)
    assert (out.status, out.flagged) == ("RED", ["m2"])


def test_enum_one_of_text_set_and_minimum_count():
    s = spec(rule="REQUIRE", element="ACTOR", min=2, where=[
        {"property": "subtype", "op": "is_one_of", "value": ["VALIDATOR", "DEPLOYER"]}, {"property": "identity", "op": "is_set"}])
    one = g([("a1", "ACTOR", {"subtype": "VALIDATOR", "identity": "qa"}), ("a2", "ACTOR", {"subtype": "TRAINER", "identity": "x"})])
    assert run("MODEL", s, one).status == "RED"
    two = g([("a1", "ACTOR", {"subtype": "VALIDATOR", "identity": "qa"}), ("a2", "ACTOR", {"subtype": "DEPLOYER", "identity": "ops"}),
             ("a3", "ACTOR", {"subtype": "DEPLOYER", "identity": ""})])
    assert run("MODEL", s, two).status == "GREEN"          # the nameless deployer doesn't count
    s2 = spec(rule="REQUIRE", element="ACTOR", where=[{"property": "identity", "op": "is_empty"}])
    assert run("MODEL", s2, two).status == "GREEN"


def test_relations():
    need = spec(rule="REQUIRE_RELATION", relation="RUNS_IN")
    assert run("MODEL", need, g([("m", "AI_MODEL", {})])).status == "RED"
    assert run("MODEL", need, g([("m", "AI_MODEL", {}), ("e", "DEPLOYMENT_ENV", {})], [("m", "e", "RUNS_IN")])).status == "GREEN"
    ban = spec(rule="FORBID_RELATION", relation="delegates")
    assert run("AGENT", ban, g([("a", "agent", {}, True)])).status == "GREEN"
    assert run("AGENT", ban, g([("a", "agent", {}, True), ("b", "agent", {})], [("a", "b", "delegates")])).status == "RED"


def test_policy_text_is_data_not_code():
    s = spec(rule="FORBID", element="tool", where=[{"property": "name", "op": "is", "value": "__import__('os').system('x')"}])
    assert run("AGENT", s, g([("t", "tool", {"name": "__import__('os').system('x')"})])).status == "RED"  # compared as text


# ── validation ──────────────────────────────────────────────────────────────

def errs(subject, **kw):
    return validate_spec(subject, spec(**kw))


def test_validation_rejects_things_that_could_never_match():
    assert any("not an element" in e for e in errs("AGENT", rule="REQUIRE", element="AI_MODEL"))        # wrong vocabulary for the subject
    assert any("not an element" in e for e in errs("MODEL", rule="REQUIRE", element="tool"))
    assert any("no property" in e for e in errs("AGENT", rule="FORBID", element="tool", where=[{"property": "colour", "op": "is", "value": "x"}]))
    assert any("cannot use" in e for e in errs("AGENT", rule="FORBID", element="tool", where=[{"property": "write", "op": "is_set"}]))
    assert any("cannot use" in e for e in errs("AGENT", rule="FORBID", element="tool", where=[{"property": "name", "op": "is_true"}]))
    assert any("not one of" in e for e in errs("MODEL", rule="FORBID", element="AI_MODEL", where=[{"property": "modelType", "op": "is", "value": "ROBOT"}]))
    assert any("pick one or more" in e for e in errs("MODEL", rule="FORBID", element="AI_MODEL", where=[{"property": "modelType", "op": "is_one_of", "value": []}]))
    assert any("enter a value" in e for e in errs("AGENT", rule="FORBID", element="tool", where=[{"property": "name", "op": "is", "value": "  "}]))
    assert any("used twice" in e for e in errs("MODEL", rule="FORBID", element="AI_MODEL", where=[
        {"property": "modelType", "op": "is", "value": "LLM"}, {"property": "modelType", "op": "is", "value": "NN"}]))
    assert any("choose an element" in e for e in errs("AGENT", rule="REQUIRE"))
    assert any("choose a relationship" in e for e in errs("AGENT", rule="REQUIRE_RELATION", relation="eats"))
    assert any("When" in e for e in errs("AGENT", when={"element": "nothing"}, rule="REQUIRE", element="tool"))
    assert errs("AGENT", rule="REQUIRE", element="tool") == []


# ── plain English ───────────────────────────────────────────────────────────

def test_describe():
    s = spec(when={"element": "tool", "where": [{"property": "write", "op": "is_true"}]}, rule="REQUIRE", element="approval")
    assert describe("AGENT", s) == "When the design has a tool where write-capable is true, the design must include at least 1 human approval."
    s = spec(rule="FORBID", element="AI_MODEL", where=[{"property": "hostingEnvironment", "op": "is", "value": "TYPE_3_THIRDPARTY_API"}])
    assert describe("MODEL", s) == "The design must not include any ai model where hosting is TYPE_3_THIRDPARTY_API."
    assert describe("MODEL", spec(rule="REQUIRE_RELATION", relation="RUNS_IN")) == "The design must include a relationship where one element runs in another."


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
