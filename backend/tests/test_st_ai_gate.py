"""
Tests for the ST-AI v2.5 gate (st_ai_gate.py). Plain asserts, no database:

    docker compose exec backend python -m tests.test_st_ai_gate

The main test compares the executable gate with the reference gate of the paper's supplementary package (modelcheck_v25.py) over all 13,500 combinations and checks
the published totals: 16 APPROVED, 884 REQUIRES_REVIEW (176 releasable by a review, 708 needing a fact recorded first), 12,600 BLOCKED.
"""
import itertools
import sys
from datetime import date, timedelta

import st_ai_gate as G

# ── the reference gate, as in supplementary/modelcheck_v25.py (kept here as the oracle) ─────────────────────────────────
CS = [("T", "S"), ("T", "V"), ("T", "U"), ("U", None), ("NA", None)]
UNQ = ["none", "noQA_hard", "noQA_review", "ACC", "UNACC_hard", "UNACC_review"]
REF_RESOLVABLE = {"rc", "overlap", "unacc_review"}


def ref_gate(h1, h2, r1, stop, rr, rq, unq):
    if stop or any(c[0] == "T" and c[1] in ("V", "U") for c in (h1, h2)) or "block" in (rr, rq) or unq == "UNACC_hard":
        return "BLOCKED", set()
    trig = set()
    if any(c[0] == "U" for c in (h1, h2, r1)):
        trig.add("appunk")
    if r1[0] == "T" and r1[1] != "S":
        trig.add("rc")
    if "overlap" in (rr, rq):
        trig.add("overlap")
    if unq in ("noQA_hard", "noQA_review"):
        trig.add("unq_noQA")
    if unq == "UNACC_review":
        trig.add("unacc_review")
    return ("REVIEW", trig) if trig else ("APPROVED", set())


def constraint(cid, klass, state):
    app, sat = state
    if app == "T":
        return G.ConstraintInput(cid, klass, G.APP_TRUE, False, {"S": G.SATISFIED, "V": G.VIOLATED, "U": G.UNKNOWN}[sat])
    if app == "U":
        return G.ConstraintInput(cid, klass, G.APP_UNKNOWN)
    return G.ConstraintInput(cid, klass, G.APP_FALSE, True)          # NOT_APPLICABLE with a valid rationale


def ours(h1, h2, r1, stop, rr, rq, unq):
    cons = [constraint("H1", G.HARD, h1), constraint("H2", G.HARD, h2), constraint("R1", G.REVIEW, r1)]
    risks = [G.RiskInput("rr", rr), G.RiskInput("rq", rq)]
    un = []
    if unq in ("noQA_hard", "noQA_review"):
        un.append(G.UnquantifiedInput("d", "noQA", unq == "noQA_hard"))
    elif unq == "ACC":
        un.append(G.UnquantifiedInput("d", "ACC"))
    elif unq in ("UNACC_hard", "UNACC_review"):
        un.append(G.UnquantifiedInput("d", "UNACC", unq == "UNACC_hard"))
    return G.evaluate_gate(cons, risks, ["stop"] if stop else [], un)


CODE = {"appunk": G.T_APP_UNKNOWN, "rc": G.T_REVIEW_CLASS, "overlap": G.T_OVERLAP, "unq_noQA": G.T_NO_ASSESSMENT, "unacc_review": G.T_UNACC_REVIEW}


def test_gate_matches_reference_on_all_13500_combinations():
    cells = list(itertools.product(CS, CS, CS, [False, True], ["pass", "overlap", "block"], ["pass", "overlap", "block"], UNQ))
    assert len(cells) == 13500
    totals = {"APPROVED": 0, "REVIEW": 0, "BLOCKED": 0}
    releasable_n = 0
    for c in cells:
        ref, rtrig = ref_gate(*c)
        mine = ours(*c)
        want = {"REVIEW": G.REQUIRES_REVIEW}.get(ref, ref)
        assert mine.result == want, (c, ref, mine.result)
        assert mine.trigger_codes == {CODE[t] for t in rtrig}, (c, rtrig, mine.trigger_codes)
        totals[ref] += 1
        if ref == "REVIEW" and rtrig <= REF_RESOLVABLE:
            releasable_n += 1
            assert mine.releasable(), c
        elif ref == "REVIEW":
            assert not mine.releasable(), c
    assert totals == {"APPROVED": 16, "REVIEW": 884, "BLOCKED": 12600}, totals
    assert releasable_n == 176, releasable_n          # and 884 - 176 = 708 need a fact recorded first


def test_unknown_never_passes_and_not_applicable_needs_a_rationale():
    assert G.effective_applicability(G.APP_FALSE, False) == (G.APP_UNKNOWN, G.UNKNOWN)
    assert G.effective_applicability(G.APP_FALSE, True) == (G.APP_FALSE, G.NOT_APPLICABLE)
    assert G.effective_applicability(G.APP_UNKNOWN, True)[0] == G.APP_UNKNOWN
    hard_unknown = G.ConstraintInput("X", G.HARD, G.APP_TRUE, False, G.UNKNOWN)
    assert G.evaluate_gate([hard_unknown]).result == G.BLOCKED
    na_without_reason = G.ConstraintInput("X", G.HARD, G.APP_FALSE, False)
    r = G.evaluate_gate([na_without_reason])
    assert r.result == G.REQUIRES_REVIEW and not r.releasable(), r           # a review cannot make an unknown applicability go away
    assert not G.ConstraintInput("X", G.HARD, G.APP_UNKNOWN).passes()


def test_not_applicable_is_not_satisfied_in_status():
    na = G.ConstraintInput("X", G.HARD, G.APP_FALSE, True)
    assert na.status == G.NOT_APPLICABLE and na.status != G.SATISFIED
    assert G.evaluate_gate([na]).result == G.APPROVED


def test_rationale_needs_author_independent_reviewer_and_expiry():
    tomorrow = date.today() + timedelta(days=1)
    yesterday = date.today() - timedelta(days=1)
    assert G.rationale_valid("not personal data", "Ann", "Bo", tomorrow)
    assert not G.rationale_valid("", "Ann", "Bo", tomorrow)
    assert not G.rationale_valid("why", "Ann", "ann", tomorrow)          # same person
    assert not G.rationale_valid("why", "Ann", "", tomorrow)
    assert not G.rationale_valid("why", "Ann", "Bo", None)               # no expiry
    assert not G.rationale_valid("why", "Ann", "Bo", yesterday)          # lapsed


def test_wf_failure_gives_invalid_model_and_computes_nothing_else():
    bad = G.well_formed_graph({"nodes": [{"id": "a"}, {"id": "a"}], "edges": [{"id": "e1", "type": "X", "source": "a", "target": "zz"}]})
    assert len(bad) == 2, bad
    r = G.evaluate_gate([G.ConstraintInput("X", G.HARD, G.APP_TRUE, False, G.SATISFIED)], wf_problems=bad)
    assert r.result == G.INVALID_MODEL and not r.releasable() and r.triggers == []
    assert G.well_formed_graph({"nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"id": "e", "type": "X", "source": "a", "target": "b"}]}) == []


def test_interval_rule():
    assert G.interval_state(120, 150, 100) == "block"
    assert G.interval_state(55, 140, 100) == "overlap"
    assert G.interval_state(55, 85, 100) == "pass"
    assert G.interval_state(55, 100, 100) == "pass"           # the upper bound may equal the tolerance
    assert G.interval_state(100, 140, 100) == "overlap"       # the lower bound equal to the tolerance is not blocked
    assert G.interval_state(None, 85, 100) == "unresolved"
    assert G.interval_state(55, 85, None) == "unresolved"
    assert G.evaluate_gate([], [G.RiskInput("r", "unresolved")]).releasable() is False


def test_review_resolves_only_what_a_review_can_resolve():
    rc = G.ConstraintInput("R", G.REVIEW, G.APP_TRUE, False, G.UNKNOWN)
    r = G.evaluate_gate([rc])
    assert r.result == G.REQUIRES_REVIEW and r.releasable()
    both = G.evaluate_gate([rc, G.ConstraintInput("A", G.REVIEW, G.APP_UNKNOWN)])
    assert both.result == G.REQUIRES_REVIEW and not both.releasable() and [t.code for t in both.unresolvable()] == [G.T_APP_UNKNOWN]
    assert not G.releasable(G.BLOCKED, set()) and not G.releasable(G.INVALID_MODEL, set())


def test_worse_takes_the_stricter_gate():
    assert G.worse(G.APPROVED, G.REQUIRES_REVIEW) == G.REQUIRES_REVIEW
    assert G.worse(G.BLOCKED, G.REQUIRES_REVIEW) == G.BLOCKED
    assert G.worse(G.APPROVED, G.INVALID_MODEL) == G.INVALID_MODEL


# ── risk criteria: evidenced and bounded intervals, and the ratchet ─────────────────────────────────────────────────────
def crit(tol=100.0, ev=None, until=None, bd=None):
    return G.CriterionIn("c", tol, ev, until, bd)


def test_evidenced_interval_counts_while_its_evidence_is_valid():
    today = date(2026, 11, 9)
    assert G.criterion_state(crit(ev=(55, 85), until=date(2026, 12, 1)), today).state == "pass"
    assert G.criterion_state(crit(ev=(55, 140), until=date(2026, 12, 1)), today).state == "overlap"
    assert G.criterion_state(crit(ev=(110, 160), until=None), today).state == "block"          # no expiry: it does not lapse


def test_lapsed_evidence_falls_back_to_the_bounded_interval():
    today = date(2026, 11, 9)
    r = G.criterion_state(crit(ev=(55, 85), until=date(2026, 11, 1), bd=(55, 140)), today)
    assert r.state == "overlap" and "bounded" in r.detail                                       # a pass becomes a review when the evidence lapses
    assert G.criterion_state(crit(ev=(55, 85), until=date(2026, 11, 1)), today).state == "unresolved"     # nothing to fall back on


def test_ratchet_losing_evidence_never_improves_a_blocked_criterion():
    today = date(2026, 11, 9)
    lapsed = date(2026, 11, 1)
    r = G.criterion_state(crit(ev=(110, 160), until=lapsed, bd=(70, 160)), today)                # the bounded interval alone would only overlap
    assert r.state == "block" and "ratchet" in r.detail, r
    fresh = G.criterion_state(crit(ev=(110, 160), until=date(2026, 12, 1), bd=(70, 160)), today)
    assert fresh.state == "block"
    reestimated = G.criterion_state(crit(ev=(60, 90), until=date(2027, 1, 1), bd=(70, 160)), today)  # a new estimate releases it
    assert reestimated.state == "pass"
    assert G.criterion_state(crit(ev=None, bd=(70, 160)), today).state == "overlap"              # never evidenced: no ratchet


def test_missing_tolerance_or_interval_is_unresolved_and_a_review_cannot_clear_it():
    today = date(2026, 11, 9)
    assert G.criterion_state(crit(tol=None, ev=(1, 2)), today).state == "unresolved"
    assert G.criterion_state(crit(ev=None, bd=None), today).state == "unresolved"
    r = G.evaluate_gate([], [G.criterion_state(crit(tol=None, ev=(1, 2)), today)])
    assert r.result == G.REQUIRES_REVIEW and not r.releasable() and r.unresolvable()[0].code == G.T_RISK_UNRESOLVED


def test_worked_example_of_the_paper():
    """The paper's worked example (T = 100): approved, review, releasable, blocked, ratchet, lapsed rationale."""
    today = date(2026, 11, 9)
    live = date(2027, 1, 1)
    gate = lambda c: G.evaluate_gate([G.ConstraintInput("H", G.HARD, G.APP_TRUE, False, G.SATISFIED)], [G.criterion_state(c, today)])      # noqa: E731
    assert gate(crit(ev=(55, 85), until=live)).result == G.APPROVED                                         # 1
    s2 = gate(crit(ev=(55, 85), until=date(2026, 11, 1), bd=(55, 140)))                                      # 2 effectiveness record expires
    assert s2.result == G.REQUIRES_REVIEW and s2.releasable()                                                # 3 an independent reviewer can clear it
    assert gate(crit(ev=(110, 160), until=live)).result == G.BLOCKED                                         # 4 re-estimated above tolerance
    assert gate(crit(ev=(110, 160), until=date(2026, 11, 1), bd=(70, 160))).result == G.BLOCKED             # 5 revoked while blocked: ratchet
    lapsed = G.evaluate_gate([G.ConstraintInput("H", G.HARD, G.APP_FALSE, False)], [])                      # 6 the rationale lapses
    assert lapsed.result == G.REQUIRES_REVIEW and not lapsed.releasable()


# ── independence ────────────────────────────────────────────────────────────────────────────────────────────────────────
def org():
    # board > eng > ml ; board > ops
    return G.Structure(parent={"board": None, "eng": "board", "ml": "eng", "ops": "board"},
                       head={"board": "Dana", "eng": "Eli", "ml": "Fay", "ops": "Gus"},
                       unit_of={"Dana": "board", "Eli": "eng", "Fay": "ml", "Gus": "ops", "Hal": "ml", "Ida": "ops"})


def test_independence_levels():
    s = org()
    assert G.independent("Hal", "Hal", G.LEVEL_PERSON) == G.F
    assert G.independent("Hal", "Ida", G.LEVEL_PERSON) == G.T
    assert G.independent("Hal", "Fay", G.LEVEL_REPORTING_LINE, s) == G.F          # Fay heads Hal's unit
    assert G.independent("Hal", "Eli", G.LEVEL_REPORTING_LINE, s) == G.F          # Eli heads a unit above Hal's
    assert G.independent("Hal", "Ida", G.LEVEL_REPORTING_LINE, s) == G.T
    assert G.independent("Hal", "Ida", G.LEVEL_UNIT, s) == G.T
    s2 = org()
    s2.unit_of["Jon"] = "ml"
    assert G.independent("Hal", "Jon", G.LEVEL_REPORTING_LINE, s2) == G.T          # peers in one unit are independent in line...
    assert G.independent("Hal", "Jon", G.LEVEL_UNIT, s2) == G.F                    # ...but not at the unit level


def test_missing_or_contradictory_data_is_unknown_and_never_meets_a_requirement():
    s = org()
    assert G.independent("Hal", None, G.LEVEL_PERSON, s) == G.U
    assert G.independent("Hal", "Zed", G.LEVEL_REPORTING_LINE, s) == G.U           # Zed has no unit
    s.head["ops"] = None
    assert G.independent("Hal", "Ida", G.LEVEL_REPORTING_LINE, s) == G.U           # an unknown head above Ida
    assert not G.meets(G.U)
    bad = org()
    bad.unit_of["Eli"] = "ops"                                                      # Eli heads eng but sits in ops: head rule violated
    assert not bad.head_rule_holds()
    assert G.independent("Hal", "Ida", G.LEVEL_REPORTING_LINE, bad) == G.U


def test_head_rule_prevents_mutual_supervision():
    """Over every assignment of three people to three units, with the head rule no two people supervise each other."""
    units = ["a", "b", "c"]
    people = ["p", "q", "r"]
    parents = [{"a": None, "b": "a", "c": "b"}, {"a": None, "b": "a", "c": "a"}, {"a": None, "b": None, "c": "a"}]
    checked = 0
    for par in parents:
        for heads in itertools.product(people + [None], repeat=3):
            for homes in itertools.product(units, repeat=3):
                s = G.Structure(parent=par, head=dict(zip(units, heads)), unit_of=dict(zip(people, homes)))
                if not s.head_rule_holds():
                    continue
                checked += 1
                for x, y in itertools.permutations(people, 2):
                    assert not (G.supervises(x, y, s) == G.T and G.supervises(y, x, s) == G.T), (par, heads, homes, x, y)
    assert checked > 100, checked


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
