"""
Tests for the learned layer (ASTRA phase 9): the statistical baseline (pure), the calibration state machine, Lemma 3 (a learned detector can only mark the baseline control unverified),
and the whole path through the API on a scratch database:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_learned        # see tests/_guard.py

Normal traffic is synthetic and seeded: an agent that looks something up, refunds, notifies, over and over, a little irregularly. The unusual traffic is the same agent doing things in an
order it never did, in a burst, or something it never did at all.
"""
import copy
import random
import sys
from datetime import datetime, timedelta, timezone

import astra_baseline as B
from astra_model import statuses
from astra_model.statuses import NA, SAT, UNV, VIO, State

W = 60                                                  # window length in seconds for the tests
NORMAL = ["lookup", "refund", "notify"]


def window_events(w, n, seq=None, kind="tool_call", offset=0):
    """n events of a window with index w (seconds from w*W), cycling through seq."""
    seq = seq or NORMAL
    return [(w * W + offset + i * (W / (n + 1)), kind, seq[i % len(seq)]) for i in range(n)]


def normal_traffic(first, windows, seed=1):
    rng = random.Random(seed)
    ev = []
    for w in range(first, first + windows):
        ev += window_events(w, rng.choice([7, 8, 8, 9]))
    return ev


# ── pure: calibration state machine ───────────────────────────────────────────────────────────────────────────

def test_the_calibration_state_machine():
    s = B.calibration_state(10, 2, False)
    assert s["state"] == B.COLLECTING and len(s["missing"]) == 2 and "190 more conforming events" in s["missing"][0] and "22 more windows" in s["missing"][1], s
    s = B.calibration_state(500, 30, False)
    assert s == {"state": B.READY, "missing": []}
    s = B.calibration_state(500, 10, False)
    assert s["state"] == B.COLLECTING and s["missing"] == ["14 more windows with activity"]
    assert B.calibration_state(0, 0, True)["state"] == B.CALIBRATED, "an active model wins over the counts"
    assert B.calibration_state(10, 2, False, retired=True) == {"state": B.RETIRED, "missing": []}, "a retired model is shown as retired until a new one is calibrated"
    assert B.calibration_state(0, 0, False, retired=False, min_events=0, min_windows=0)["state"] == B.READY
    try:
        B.train([], W)
    except ValueError:
        pass
    else:
        raise AssertionError("nothing to calibrate from must be refused")


# ── pure: the baseline ─────────────────────────────────────────────────────────────────────────────────────────

def test_normal_windows_stay_below_the_threshold_and_unusual_ones_reach_it():
    p = B.train(normal_traffic(0, 60), W)
    held_out = [B.score_window(p, window_events(w, n)) for w, n in zip(range(100, 130), [7, 8, 9] * 10)]
    assert max(r["score"] for r in held_out) < p["threshold"], max(r["score"] for r in held_out)
    wrong_order = B.score_window(p, window_events(200, 8, ["notify", "notify", "refund", "lookup", "lookup", "notify", "refund", "refund"]))
    assert wrong_order["score"] >= p["threshold"] and any("order" in x for x in wrong_order["why"]) and wrong_order["unseen_transitions"], wrong_order
    burst = B.score_window(p, window_events(201, 60))
    assert burst["score"] >= p["threshold"] and any("normally about" in x for x in burst["why"]), burst
    never_seen = B.score_window(p, window_events(202, 8) + [(202 * W + 1, "tool_call", "export")] * 6)
    assert never_seen["score"] >= p["threshold"], never_seen
    other_kind = B.score_window(p, window_events(203, 8) + window_events(203, 6, ["x"], kind="exec"))
    assert other_kind["score"] >= p["threshold"], "a kind of event the agent never produced"


def test_silence_inside_the_calibration_period_counts_as_normal_and_scoring_is_per_window():
    ev = normal_traffic(0, 10) + normal_traffic(30, 10, seed=2)             # twenty empty windows between
    p = B.train(ev, W)
    assert p["windows"] == 40 and p["windows_with_events"] == 20
    m, s = p["rates"]["tool_call:lookup"]
    assert 1.0 < m < 2.0 and s > 1.0, (m, s)
    rows = B.score_windows(p, normal_traffic(100, 5, seed=3), after_window=101, before_window=104)
    assert [w for w, _ in rows] == [102, 103], "only the windows between the bounds are scored"


def test_a_baseline_is_deterministic_and_never_reads_anything_but_names_and_times():
    a, b = B.train(normal_traffic(0, 40), W), B.train(normal_traffic(0, 40), W)
    assert a == b
    assert all(isinstance(e[0], float) and isinstance(e[1], str) and isinstance(e[2], str) for e in normal_traffic(0, 3))
    assert B.feature("tool_call", "refund") == "tool_call:refund" and B.feature("exec", "") == "exec"


# ── pure: Lemma 3 ───────────────────────────────────────────────────────────────────────────────────────────────

def test_lemma_3_a_learned_score_can_only_lower_the_baseline_control_to_unverified():
    rng = random.Random(7)
    for _ in range(300):
        S = State()
        for kind in ("iso", "least", "hitl", "base", "supply"):
            c = (kind, "a")
            r = rng.choice([VIO, UNV, SAT, NA, None])
            if r == SAT:
                statuses.support(S, c, "attestation", 0, rng.choice([5, 50, float("inf")]))
            elif r in (VIO, UNV):
                statuses.adverse(S, c, r)
            elif r == NA:
                statuses.mark_not_applicable(S, c, "not used here")
        before = copy.deepcopy(S)
        score, theta = rng.uniform(0, 12), rng.uniform(1, 8)
        statuses.learned_evidence(S, "a", score, theta)
        now = rng.choice([0, 10, 100])
        for kind in ("iso", "least", "hitl", "supply"):
            assert S.st.get((kind, "a")) == before.st.get((kind, "a")) and S.fresh.get((kind, "a")) == before.fresh.get((kind, "a")), "no control but the baseline is touched"
        a, b = before.status(("base", "a"), now), S.status(("base", "a"), now)
        assert b in (a, UNV), (a, b)
        assert b != VIO or a == VIO, "never VIOLATED"
        assert not (b == SAT and a != SAT), "never SATISFIED"
        if score < theta:
            assert S.st.get(("base", "a")) == before.st.get(("base", "a")), "below the threshold nothing changes"
    for source in ("learned", "baseline", "tgn", "gnn", "detector"):
        try:
            statuses.support(State(), ("base", "a"), source, 0)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{source} must not be a source of supportive evidence")
    assert statuses.SUPPORT_SOURCES == frozenset({"probe_pass", "attestation", "human", "new_contract"})


def test_adverse_evidence_on_a_control_declared_not_applicable_makes_it_apply_instead_of_failing():
    S = State()
    statuses.mark_not_applicable(S, ("supply", "A"), "no MCP servers declared")
    statuses.adverse(S, ("supply", "A"), VIO)                                  # an unsigned component was seen at runtime after all
    assert S.status(("supply", "A")) == VIO and ("supply", "A") not in S.rationale
    S = State()
    statuses.mark_not_applicable(S, ("base", "A"), "not monitored")
    statuses.learned_evidence(S, "A", 9.0, 4.0)
    assert S.status(("base", "A")) == UNV, "a learned score still only reaches unverified"


def test_the_verdict_overlay_hands_a_learned_flag_to_learned_evidence_and_nothing_else():
    import astra_verdicts as V
    S = State()
    for kind in ("iso", "least", "base"):
        statuses.support(S, (kind, "A"), "attestation", 0)
    because = V.overlay(S, {"a": "A"}, [], {}, [{"agent_key": "a", "id": "f1", "score": 9.0, "threshold": 4.0}, {"agent_key": "zz", "id": "f2", "score": 9.0, "threshold": 4.0}])
    assert S.status(("base", "A")) == UNV and S.status(("iso", "A")) == SAT and S.status(("least", "A")) == SAT
    assert list(because) == [("base", "A")] and "learned flag" in because[("base", "A")][0]


# ── through the API ───────────────────────────────────────────────────────────────────────────────────────────────

OTHER = "zz-other-agent"


def _db():
    from db.models import LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent
    from db.session import SessionLocal
    return LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent, SessionLocal


def clean():
    LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent, SessionLocal = _db()
    from tests.test_astra_assessment_api import KEY, NAME
    from db.models import ProbeRun
    with SessionLocal() as s:
        s.query(ProbeRun).filter(ProbeRun.design_key == KEY).delete(synchronize_session=False)          # a Probe run of the same design would validate the baseline
        for M in (LearnedFlag, LearnedScore, LearnedModel):
            s.query(M).filter(M.agent_key.in_((NAME, OTHER))).delete(synchronize_session=False)
        s.query(RuntimeEvent).filter(RuntimeEvent.agent_key.in_((NAME, OTHER))).delete(synchronize_session=False)
        s.commit()


def put_events(agent, start, windows, seed=1, seq=None, n=None, verdict="CONFORMING", kind="tool_call"):
    """Runtime events of an agent in `windows` consecutive windows starting at `start` (a datetime on a window boundary)."""
    LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent, SessionLocal = _db()
    from db.bootstrap import DEFAULT_ORG_SLUG
    from db.models import Organisation
    from sqlalchemy import select
    rng = random.Random(seed)
    with SessionLocal() as s:
        org = s.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
        for w in range(windows):
            cnt = n or rng.choice([7, 8, 8, 9])
            for i in range(cnt):
                at = start + timedelta(seconds=w * W + i * (W / (cnt + 1)))
                name = (seq or NORMAL)[i % len(seq or NORMAL)]
                s.add(RuntimeEvent(organisation_id=org.id, agent_key=agent, at=at, type=kind, name=name, attrs={}, verdict=verdict, contract_version="1.0.0", reported_by="zz test"))
        s.commit()


def boundary(hours_ago):
    t = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return t.replace(second=0, microsecond=0)


def world(fn):
    from tests.test_astra_verdicts import with_world

    def run():
        from fastapi.testclient import TestClient
        from main import app
        with TestClient(app):
            pass
        clean()
        try:
            with_world(fn)()
        finally:
            clean()
    run.__name__ = fn.__name__
    return run


CAL = {"window_seconds": W, "min_events": 50, "min_windows": 6}


def _verdict(c):
    from tests.test_astra_verdicts import verdict
    return verdict(c)


def _statuses(c, key):
    a = c.get(f"/api/agents/designs/{key}/assessment").json()
    return a["verdict"], {x["kind"]: x["status"] for x in a["paths"][0]["controls"]}, a


def _setup_calibrated(one, two, eng, attest_base=True):
    """Calibrated on 40 normal windows, tolerance 1 so that an unverified control matters, every other control attested."""
    from tests.test_astra_verdicts import attest_all, lower_tolerance
    from tests.test_astra_assessment_api import attest, NAME
    attest_all()
    lower_tolerance(one, two, 1)
    put_events(NAME, boundary(6), 40)
    r = two.post(f"/api/astra/learned/agents/{NAME}/calibrate", json=CAL)
    assert r.status_code == 201, r.text
    if attest_base:
        attest("astra:base")
    return r.json()


@world
def test_calibration_waits_for_enough_conforming_events_and_a_person_who_may_sign_off(one, two, eng):
    from tests.test_astra_assessment_api import NAME
    r = two.post(f"/api/astra/learned/agents/{NAME}/calibrate", json=CAL)
    assert r.status_code == 409 and "50 more conforming events" in r.json()["detail"], r.text
    put_events(NAME, boundary(6), 5)
    put_events(NAME, boundary(5), 40, verdict="DIVERGENT")                       # events that diverged are never learned as normal
    a = next(x for x in eng.get("/api/astra/learned/agents").json() if x["agent_key"] == NAME)
    assert a["state"] == "COLLECTING" and a["events"] < 50, a
    put_events(NAME, boundary(4), 40)
    a = next(x for x in eng.get("/api/astra/learned/agents").json() if x["agent_key"] == NAME)
    assert a["events"] >= 50, a
    assert eng.post(f"/api/astra/learned/agents/{NAME}/calibrate", json=CAL).status_code == 403, "what counts as normal is for compliance or admin to decide"
    assert two.post(f"/api/astra/learned/agents/{NAME}/calibrate", json={**CAL, "min_events": 10}).status_code == 422, "the floors cannot be lowered"
    m = two.post(f"/api/astra/learned/agents/{NAME}/calibrate", json=CAL)
    assert m.status_code == 201 and m.json()["version"] == 1 and m.json()["status"] == "ACTIVE" and m.json()["trained_on"]["events"] >= 50, m.text
    a = next(x for x in eng.get("/api/astra/learned/agents").json() if x["agent_key"] == NAME)
    assert a["state"] == "CALIBRATED" and a["model"]["version"] == 1
    m2 = two.post(f"/api/astra/learned/agents/{NAME}/calibrate", json=CAL).json()
    assert m2["version"] == 2
    det = {d["id"]: d for d in eng.get("/api/astra/learned/detectors").json()}
    assert det["baseline"]["status"] == "available" and det["baseline"]["models"] >= 1 and det["tgn"]["status"] == "available" and det["tgn"]["models"] == 0 and det["gnn"]["status"] == "available" and det["gnn"]["models"] == 0


@world
def test_a_monitored_baseline_is_required_and_unverified_until_an_attestation_validates_it(one, two, eng):
    from tests.test_astra_assessment_api import KEY
    from tests.test_astra_verdicts import attest_all, lower_tolerance
    attest_all()
    lower_tolerance(one, two, 1)
    v, st, _ = _statuses(eng, KEY)
    assert v == "APPROVED" and "base" not in st, "no baseline, no baseline control"
    from tests.test_astra_assessment_api import NAME, attest
    put_events(NAME, boundary(6), 40)
    assert two.post(f"/api/astra/learned/agents/{NAME}/calibrate", json=CAL).status_code == 201
    v, st, a = _statuses(eng, KEY)
    assert v == "REQUIRES_REVIEW" and st["base"] == "UNV", (v, st)
    assert "stays unverified until" in next(c["why"] for c in a["paths"][0]["controls"] if c["kind"] == "base")
    attest("astra:base")
    v, st, _ = _statuses(eng, KEY)
    assert v == "APPROVED" and st["base"] == "SAT", (v, st)


@world
def test_a_probe_pass_also_validates_the_calibration(one, two, eng):
    from tests.test_astra_assessment_api import KEY, NAME
    from tests.test_astra_verdicts import attest_all, lower_tolerance
    attest_all()
    lower_tolerance(one, two, 1)
    put_events(NAME, boundary(6), 40)
    two.post(f"/api/astra/learned/agents/{NAME}/calibrate", json=CAL)
    assert _statuses(eng, KEY)[1]["base"] == "UNV"
    run = eng.post("/api/astra/probe/run", json={"design_key": KEY}).json()
    assert run["summary"]["scenarios"] == 22 and next(r for r in run["results"] if r["class"] == "DVG-BASE-01")["passed"]
    v, st, _ = _statuses(eng, KEY)
    assert v == "APPROVED" and st["base"] == "SAT", (v, st)


@world
def test_an_unusual_sequence_raises_a_flag_and_the_verdict_moves_to_review_never_to_a_block(one, two, eng):
    from tests.test_astra_assessment_api import NAME
    from tests.test_astra_verdicts import lower_tolerance
    _setup_calibrated(one, two, eng)
    assert _verdict(eng)["verdict"] == "APPROVED"
    put_events(NAME, boundary(2), 6, seed=5)                                          # normal traffic after calibration: no flag
    r = eng.post(f"/api/astra/learned/agents/{NAME}/score").json()
    assert r["scored"] == 6 and r["flagged"] == 0, r
    put_events(NAME, boundary(1), 3, seq=["notify", "notify", "refund", "lookup", "lookup", "notify", "refund", "refund"], n=8)      # the order is unlike anything calibrated
    r = eng.post(f"/api/astra/learned/agents/{NAME}/score").json()
    assert r["scored"] == 3 and r["flagged"] == 3, r
    assert eng.post(f"/api/astra/learned/agents/{NAME}/score").json()["scored"] == 0, "a window is scored once"
    v = _verdict(eng)
    assert v["verdict"] == "REQUIRES_REVIEW" and v["learned"] == {"monitored": True, "flags": 3}, v
    assert [(m["kind"], m["from"], m["to"]) for m in v["controls_moved"]] == [("base", "SAT", "UNV")] and "learned flag" in v["controls_moved"][0]["because"][0]
    assert v["findings"]["total"] == 0, "a learned flag is not a finding"
    lower_tolerance(one, two, 0)                                                        # a department that accepts nothing: still a review, never a block
    v = _verdict(eng)
    assert v["verdict"] == "REQUIRES_REVIEW" and v["posture"]["recommended"] == "observe", v
    scores = eng.get(f"/api/astra/learned/agents/{NAME}/scores").json()
    assert len(scores) == 9 and max(s["score"] for s in scores) >= scores[0]["threshold"] and any(s["why"] for s in scores)


@world
def test_a_burst_and_something_never_done_before_are_flagged_too(one, two, eng):
    from tests.test_astra_assessment_api import NAME
    _setup_calibrated(one, two, eng)
    put_events(NAME, boundary(2), 1, n=70)
    put_events(NAME, boundary(1), 1, seq=["export"], n=8)
    r = eng.post(f"/api/astra/learned/agents/{NAME}/score").json()
    assert r["flagged"] == 2, r


@world
def test_a_flag_is_judged_by_a_person_benign_for_a_while_or_real(one, two, eng):
    from tests.test_astra_assessment_api import NAME
    from tests.test_astra_verdicts import sign_row
    _setup_calibrated(one, two, eng)
    put_events(NAME, boundary(1), 1, n=70)
    eng.post(f"/api/astra/learned/agents/{NAME}/score")
    f = eng.get("/api/astra/learned/flags").json()[0]
    assert f["status"] == "OPEN" and f["effective"] and f["control"] == "base" and f["level"] == "UNV" and _verdict(eng)["verdict"] == "REQUIRES_REVIEW"
    assert eng.post(f"/api/astra/learned/flags/{f['id']}/adjudicate", json={"outcome": "benign", "note": "A planned batch job."}).status_code == 403
    assert one.post(f"/api/astra/learned/flags/{f['id']}/adjudicate", json={"outcome": "benign", "note": "a"}).status_code == 422
    ok = one.post(f"/api/astra/learned/flags/{f['id']}/adjudicate", json={"outcome": "benign", "note": "A planned batch job.", "days": 7})
    assert ok.status_code == 200 and ok.json()["status"] == "BENIGN" and not ok.json()["effective"] and ok.json()["expires_at"]
    assert _verdict(eng)["verdict"] == "APPROVED", "a benign judgement is human adjudication: the flag stops counting"
    assert one.post(f"/api/astra/learned/flags/{f['id']}/adjudicate", json={"outcome": "real", "note": "Changed my mind."}).status_code == 409
    LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent, SessionLocal = _db()
    with SessionLocal() as s:
        row = s.get(LearnedFlag, __import__("uuid").UUID(f["id"]))
        row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)                   # the benign judgement has lapsed
        s.commit()
    assert _verdict(eng)["verdict"] == "REQUIRES_REVIEW", "after its expiry the flag counts again"
    again = two.post(f"/api/astra/learned/flags/{f['id']}/adjudicate", json={"outcome": "real", "note": "It was real: add a control."})
    assert again.status_code == 200 and again.json()["status"] == "REAL" and again.json()["effective"] and again.json()["expires_at"] is None
    assert _verdict(eng)["verdict"] == "REQUIRES_REVIEW"
    sign_row()                                                                          # a new signed contract starts clean
    v = _verdict(eng)
    assert v["verdict"] == "APPROVED" and v["learned"]["flags"] == 0, v


@world
def test_flags_are_ordered_by_the_impact_tier_the_agent_can_reach(one, two, eng):
    from tests.test_astra_assessment_api import NAME
    _setup_calibrated(one, two, eng)
    put_events(OTHER, boundary(6), 40, seed=9)
    assert two.post(f"/api/astra/learned/agents/{OTHER}/calibrate", json=CAL).status_code == 201
    put_events(NAME, boundary(1), 1, n=70)
    put_events(OTHER, boundary(1), 1, n=70)
    out = eng.post("/api/astra/learned/score-all").json()
    assert out["failed"] == 0 and out["flagged"] == 2, out
    fl = eng.get("/api/astra/learned/flags?status=open").json()
    assert [f["agent_key"] for f in fl] == [OTHER, NAME], "an agent with no saved design reaches an unknown set: the most severe tier first"
    assert fl[0]["tier"] == 4 and fl[1]["tier"] == 2, [(f["agent_key"], f["tier"]) for f in fl]


@world
def test_the_lemma_is_in_the_table_nothing_but_baseline_unverified_can_be_stored(one, two, eng):
    from sqlalchemy.exc import IntegrityError
    from tests.test_astra_assessment_api import NAME
    LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent, SessionLocal = _db()
    _setup_calibrated(one, two, eng)
    put_events(NAME, boundary(1), 1, n=70)
    eng.post(f"/api/astra/learned/agents/{NAME}/score")
    with SessionLocal() as s:
        flags = s.query(LearnedFlag).filter(LearnedFlag.agent_key == NAME).all()
        assert flags and all(f.control == "base" and f.level == "UNV" for f in flags)
        f = flags[0]
        for control, level in (("iso", "UNV"), ("base", "VIO"), ("base", "SAT"), ("least", "VIO")):
            s2 = SessionLocal()
            try:
                s2.add(LearnedFlag(organisation_id=f.organisation_id, model_id=f.model_id, score_id=f.score_id, agent_key=NAME, detector="baseline", score=9.0, threshold=4.0, control=control,
                                   level=level, detail={}))
                s2.commit()
            except IntegrityError:
                s2.rollback()
            else:
                raise AssertionError(f"the table accepted a flag on {control} at {level}")
            finally:
                s2.close()


@world
def test_the_classes_screen_counts_the_baseline_class_by_the_windows_it_has_scored(one, two, eng):
    from tests.test_astra_assessment_api import NAME
    before = {c["id"]: c for c in eng.get("/api/astra/classes").json()["classes"]}["DVG-BASE-01"]
    assert before["state"] == "advisory" and before["needs"] and "baseline" in before["needs"]
    _setup_calibrated(one, two, eng)
    put_events(NAME, boundary(2), 3, seed=4)
    eng.post(f"/api/astra/learned/agents/{NAME}/score")
    after = {c["id"]: c for c in eng.get("/api/astra/classes").json()["classes"]}["DVG-BASE-01"]
    assert after["events"] >= 3 and after["needs"] is None


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed_n = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed_n += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"{len(tests) - failed_n}/{len(tests)} passed")
    sys.exit(1 if failed_n else 0)
