"""
Tests for rcr_engine.py against the worked example in RCR_Algorithm_Step_by_Step.docx.

    docker compose exec backend python -m tests.test_rcr_engine
"""
import sys

from rcr_engine import COVERED, GAP, PARTIAL, UNMAPPED, RcrError, Requirement, score, validate_registry


def example(dpia=(GAP, "", ""), oversight=(PARTIAL, "oversight plan draft", "")):
    def R(key, name, inst, cls, w, phi, d):
        return Requirement(key, name, inst, cls, w, phi, d[0], d[1], d[2])
    return [
        R("dpia", "Art.35 DPIA", "GDPR", "veto", 3, 0.85, dpia),
        R("lawful", "Lawful basis", "GDPR", "ordinary", 2, None, (COVERED, "lawful basis document", "")),
        R("retention", "Retention limit", "GDPR", "ordinary", 1, None, (UNMAPPED, "", "")),
        R("oversight", "Art.14 Human oversight", "EU AI Act", "veto", 3, 0.90, oversight),
        R("asi10", "ASI10 Rogue agent", "OWASP ASI", "veto", 2, 0.80, (COVERED, "ASI10 document", "Compliance lead")),
        R("access", "Staff access control", "Org policy", "ordinary", 1, None, (COVERED, "policy note", "")),
    ]


def near(a, b, tol=1e-9):
    return abs(a - b) < tol


def test_step1_coverage_as_counted_in_the_document():
    r = {x.key: x for x in score(example()).rows}
    assert (r["dpia"].counted, r["dpia"].c) == (GAP, 0)
    assert (r["lawful"].counted, r["lawful"].c) == (COVERED, 1)          # ordinary needs evidence only
    assert (r["retention"].counted, r["retention"].c) == (UNMAPPED, 0)
    assert (r["oversight"].counted, r["oversight"].c) == (PARTIAL, 0.5)  # draft with a document, no sign-off
    assert (r["asi10"].counted, r["asi10"].c) == (COVERED, 1)            # document and sign-off
    assert r["access"].counted == COVERED


def test_step2_breadth_per_instrument():
    res = score(example())
    g = {i.instrument: (i.uncovered, i.total, round(i.g, 3)) for i in res.instruments}
    assert g["GDPR"] == (4, 6, 0.667)
    assert g["EU AI Act"] == (1.5, 3, 0.5)
    assert g["OWASP ASI"] == (0, 2, 0)
    assert g["Org policy"] == (0, 1, 0)
    assert near(res.G, 4 / 6) and res.worst_instrument == "GDPR"


def test_step3_to_6_headline_numbers():
    res = score(example())
    assert near(res.F, 0.85) and res.floor_key == "dpia"
    assert near(res.score, 85)
    assert near(res.blocked_line, 80) and near(res.watch_line, 40)       # phi_min = 0.80 (ASI10)
    assert (res.band, res.gate, res.binding) == ("blocked", "BLOCK", "depth")


def test_same_agent_after_fixes():
    one = score(example(dpia=(COVERED, "DPIA report", "Compliance lead")))
    assert near(one.G, 0.5) and near(one.F, 0.45) and near(one.score, 50)
    assert (one.band, one.gate, one.worst_instrument) == ("watch", "REVIEW", "EU AI Act")   # EU AI Act now the worst
    two = score(example(dpia=(COVERED, "DPIA report", "Compliance lead"), oversight=(COVERED, "oversight plan", "Compliance lead")))
    assert near(two.G, 1 / 6) and near(two.F, 0) and near(two.score, 100 / 6)
    assert (two.band, two.gate) == ("clear", "APPROVE")


def test_evidence_without_signoff_counts_as_partial():
    # The document's 42.5 case: the DPIA document exists but nobody signed it. It only works out to 42.5
    # when human oversight is already signed off; with oversight still a draft, the EU AI Act's
    # breadth (0.5) and oversight's own depth (0.45) would drive the score higher.
    signed_oversight = (COVERED, "oversight plan", "Compliance lead")
    res = score(example(dpia=(COVERED, "DPIA report", ""), oversight=signed_oversight))
    rows = {x.key: x for x in res.rows}
    assert rows["dpia"].counted == PARTIAL and rows["dpia"].awaiting_signoff
    assert near(res.G, 2.5 / 6) and near(res.F, 0.85 * 0.5) and near(res.score, 42.5)
    assert res.band == "watch"
    assert near(score(example(dpia=(COVERED, "DPIA report", ""))).score, 50)   # oversight still a draft: EU AI Act breadth 0.5


def test_claimed_covered_with_no_evidence_is_a_gap():
    res = score(example(dpia=(COVERED, "", "Compliance lead")))              # sign-off alone is not evidence
    assert {x.key: x for x in res.rows}["dpia"].counted == GAP
    assert near(res.score, 85)
    res = score(example(oversight=(PARTIAL, "", "")))
    assert {x.key: x for x in res.rows}["oversight"].counted == GAP


def test_registry_validity_check():
    # (1 - c_p) * phi_max must be below phi_min: 0.5 * 0.90 = 0.45 < 0.80 holds
    validate_registry(example(), 0.5)
    bad = example()
    bad[0].phi = 0.30                                                        # phi_min 0.30 but 0.5 * 0.90 = 0.45 is not below it
    try:
        score(bad)
    except RcrError as exc:
        assert "rejected" in str(exc)
    else:
        raise AssertionError("an invalid registry must be rejected")


def test_changing_a_floor_changes_the_score_but_not_the_decision():
    for phi in (0.60, 0.85, 0.95):
        reqs = example()
        reqs[3].phi = 0.95 if phi == 0.95 else reqs[3].phi
        reqs[0].phi = phi
        res = score(reqs)
        assert res.band == "blocked"                                         # a fully open veto always lands in Blocked


def test_input_validation():
    for mutate in (lambda r: setattr(r[0], "w", 4), lambda r: setattr(r[0], "cls", "x"), lambda r: setattr(r[0], "phi", None),
                   lambda r: setattr(r[0], "declared", "Done"), lambda r: r.append(r[1])):
        reqs = example()
        mutate(reqs)
        try:
            score(reqs)
        except RcrError:
            continue
        raise AssertionError("expected RcrError")


def test_no_veto_uses_the_convention_lines():
    res = score([Requirement("a", "A", "GDPR", "ordinary", 2, None, GAP)])
    assert (res.lines_derived, res.blocked_line, res.watch_line, res.band) == (False, 80.0, 40.0, "blocked")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
            print("PASS ", n)
        except AssertionError as exc:
            failed += 1
            print("FAIL ", n, repr(exc))
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
