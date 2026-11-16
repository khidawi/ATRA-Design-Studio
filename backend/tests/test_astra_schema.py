"""
Tests for the Appendix A behavioural contract schema and its validator (astra_schema.py). Pure: no database.

    python -m tests.test_astra_schema
"""
import copy
import json
import sys
from pathlib import Path

import astra_schema as S

EXAMPLE = json.loads((Path(__file__).parent / "fixtures" / "appendix_b_example.json").read_text(encoding="utf-8"))


def bad(mutate):
    d = copy.deepcopy(EXAMPLE)
    mutate(d)
    return S.validate(d)


def test_the_worked_example_of_appendix_b_is_valid():
    assert S.validate(EXAMPLE) == [], S.validate(EXAMPLE)


def test_required_fields_are_enforced():
    for key in ("schema_version", "agent", "permitted_goals", "permitted_tasks"):
        assert any("missing required" in e for e in bad(lambda d, k=key: d.pop(k))), key
    for key in ("id", "owner", "lifecycle", "model_version"):
        assert any("missing required" in e for e in bad(lambda d, k=key: d["agent"].pop(k))), key


def test_malformed_values_are_rejected():
    assert bad(lambda d: d["agent"].update(id="Bad Id"))
    assert bad(lambda d: d["agent"].update(id="a"))
    assert bad(lambda d: d["agent"].update(owner="not-an-email"))
    assert bad(lambda d: d["agent"].update(model_version="1.0"))
    assert bad(lambda d: d["agent"]["lifecycle"].update(status="live"))
    assert bad(lambda d: d["agent"]["lifecycle"].update(expires="31/12/2030"))
    assert bad(lambda d: d["permitted_goals"][0].update(id="goal1"))
    assert bad(lambda d: d["permitted_tasks"][0].update(id="X1"))
    assert bad(lambda d: d["delegation"].update(mode="anything"))
    assert bad(lambda d: d["resource_scopes"]["memory"].update(writes="sometimes"))


def test_constraints_and_mappings_are_checked():
    assert bad(lambda d: d["constraints"].append({"asi": "ASI11", "control": "x"}))
    assert bad(lambda d: d["constraints"].append({"asi": "ASI00", "control": "x"}))
    assert bad(lambda d: d["constraints"].append({"asi": "ASI05"}))
    assert bad(lambda d: d["regulatory_mappings"].append({"control": "x", "clauses": []}))


def test_stray_fields_and_wrong_types_are_rejected():
    assert any("not allowed" in e for e in bad(lambda d: d.update(extra=1)))
    assert any("not allowed" in e for e in bad(lambda d: d["agent"].update(extra=1)))
    assert any("must be array" in e for e in bad(lambda d: d.update(permitted_goals="G1")))
    assert any("must be object" in e for e in bad(lambda d: d.update(agent="a")))


def test_an_empty_task_list_and_a_malformed_chain_are_rejected():
    assert bad(lambda d: d.update(permitted_tasks=[]))
    chain = [t for t in EXAMPLE["permitted_tasks"] if "prohibited_chains" in t]
    if chain:
        i = EXAMPLE["permitted_tasks"].index(chain[0])
        assert bad(lambda d: d["permitted_tasks"][i].update(prohibited_chains=["no arrow here"]))


def test_a_schema_keyword_the_validator_does_not_know_is_refused_not_ignored():
    try:
        S.validate({"a": 1}, {"type": "object", "oneOf": []})
    except ValueError as exc:
        assert "oneOf" in str(exc)
    else:
        raise AssertionError("an unsupported keyword must raise")
    try:
        S.validate("x", {"type": "string", "format": "uri"})
    except ValueError:
        pass
    else:
        raise AssertionError("an unsupported format must raise")


def test_the_stored_schema_uses_only_supported_keywords():
    S.validate(EXAMPLE)                      # walks every subschema the example touches; raises ValueError on an unsupported keyword
    S.validate({"agent": {"signature": "x"}}, S.load_schema())


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
