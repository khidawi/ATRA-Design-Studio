"""
Tests for the ST-AI v2.5 policy rules (st_ai_policy.py). Plain asserts, no database:

    docker compose exec backend python -m tests.test_st_ai_policy
"""
import sys

import st_ai_policy as P


def tol(scope, name, dim, metric, value, parent=None):
    return {"scope": scope, "name": name, "dimension": dim, "metric": metric, "value": value, **({"parent": parent} if parent else {})}


def test_defaults_are_complete_and_valid():
    p = P.normalise(None)
    assert set(p["independence"]) == set(P.USES) and p["risk"]["basis"] == "legacy_until_intervals" and p["tolerances"] == []
    assert P.validate(None) == []
    assert P.independence_requirement(None, "review") == ("PERSON", "AT_ACT")


def test_partial_policy_takes_defaults_for_the_rest():
    p = P.normalise({"independence": {"review": {"level": "UNIT"}}})
    assert p["independence"]["review"] == {"level": "UNIT", "mode": "AT_ACT"} and p["independence"]["approval"]["level"] == "PERSON"
    assert P.independence_requirement({"independence": {"approval": {"level": "REPORTING_LINE", "mode": "CONTINUING"}}}, "approval") == ("REPORTING_LINE", "CONTINUING")


def test_invalid_parameters_are_named():
    bad = {"independence": {"review": {"level": "COUSIN", "mode": "SOMETIME"}, "unknown_use": {"level": "PERSON"}}, "risk": {"basis": "vibes", "confidence_level": 1.2}}
    problems = "\n".join(P.validate(bad))
    for frag in ("independence for review: the level", "the mode must be", "not a use that needs independence", "the basis must be", "confidence level"):
        assert frag in problems, (frag, problems)


def test_tolerances_are_allocated_down_the_organisation():
    ok = [tol("organisation", "organisation", "Financial", "R", 1000), tol("unit", "Logistics", "Financial", "R", 600, "organisation"), tol("unit", "Finance", "Financial", "R", 300, "organisation"),
          tol("deployment", "d-forecast", "Financial", "R", 400, "Logistics"), tol("deployment", "d-routing", "Financial", "R", 200, "Logistics")]
    assert P.validate({"tolerances": ok}) == []
    assert P.tolerance_for({"tolerances": ok}, "d-forecast", "Financial", "R") == 400
    assert P.tolerance_for({"tolerances": ok}, "d-forecast", "Financial", "Q") is None            # nothing allocated for that metric
    assert P.tolerance_for({"tolerances": ok}, "d-unknown", "Financial", "R") is None
    assert P.tolerance_for({"tolerances": ok}, None, "Financial", "R") is None
    over = ok + [tol("deployment", "d-extra", "Financial", "R", 50, "Logistics")]                  # 400 + 200 + 50 > 600
    assert any("add up to 650" in x for x in P.validate({"tolerances": over})), P.validate({"tolerances": over})
    orphan = [tol("deployment", "d1", "Financial", "R", 10, "Nowhere")]
    assert any("has no allocation" in x for x in P.validate({"tolerances": orphan}))
    top = ok + [tol("unit", "Ops", "Financial", "R", 200, "organisation")]                         # 600 + 300 + 200 > 1000
    assert any("under 'organisation'" in x for x in P.validate({"tolerances": top}))


def test_tolerance_rows_are_checked():
    cases = [(tol("organisation", "organisation", "Financial", "R", 0), "above 0"), (tol("organisation", "organisation", "Safety", "Q", 1.5), "at most 1"),
             (tol("organisation", "organisation", "Financial", "X", 5), "metric"), (tol("planet", "x", "Financial", "R", 5), "scope"),
             (tol("organisation", "Acme", "Financial", "R", 5), "named 'organisation'"), (tol("organisation", "organisation", "", "R", 5), "name and a harm dimension"),
             (tol("organisation", "organisation", "Financial", "R", "lots"), "must be a number")]
    for row, frag in cases:
        assert any(frag in x for x in P.validate({"tolerances": [row]})), (row, P.validate({"tolerances": [row]}))
    dup = [tol("organisation", "organisation", "Financial", "R", 5), tol("organisation", "organisation", "Financial", "R", 6)]
    assert any("already has" in x for x in P.validate({"tolerances": dup}))
    assert any("parent unit" in x for x in P.validate({"tolerances": [tol("organisation", "organisation", "F", "R", 9), tol("unit", "U", "F", "R", 1)]}))


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
