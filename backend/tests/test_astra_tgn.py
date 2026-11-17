"""
Tests for the temporal graph network on the platform side (ASTRA phase 10): the adoption gate (pure), and through the API on a scratch database the event stream, the registry of
candidates, adoption, scores from a service, flags that can only tighten, rollback and the detector's own health. The network itself runs in the separate `learned` service and is
tested there; here a stand-in service posts numbers, which is all the platform ever receives from it.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_tgn        # see tests/_guard.py
"""
import copy
import math
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

import astra_tgn as T

GOOD = {
    "simulated": True, "dataset_hash": "a" * 64, "seed": 7, "budget_fpr": 0.05, "margin": 0.05,
    "families": {"dev": ["order_swap", "burst_repeat", "novel_target"], "test": ["metronome", "lateral_chain", "slow_drip", "kind_switch"]},
    "tgn": {"threshold": 2.5, "fpr_test": 0.03, "tpr": {"order_swap": 0.7, "burst_repeat": 0.9, "novel_target": 1.0, "metronome": 0.9, "lateral_chain": 1.0, "slow_drip": 0.6, "kind_switch": 1.0}},
    "baseline": {"threshold": 1.7, "fpr_test": 0.05, "tpr": {"order_swap": 0.0, "burst_repeat": 1.0, "novel_target": 1.0, "metronome": 0.3, "lateral_chain": 0.8, "slow_drip": 0.1, "kind_switch": 1.0}},
    "normalisation": {"zz-pay-agent": [3.0, 0.5]},
}


def metrics(**over):
    m = copy.deepcopy(GOOD)
    for k, v in over.items():
        if k == "tgn_tpr":
            m["tgn"]["tpr"].update(v)
        elif k == "base_tpr":
            m["baseline"]["tpr"].update(v)
        elif k == "tgn_fpr":
            m["tgn"]["fpr_test"] = v
        else:
            m[k] = v
    return m


def test_a_clearly_better_network_with_a_contained_false_positive_rate_passes():
    d = T.decide(GOOD)
    assert d == {"passed": True, "reasons": []}, d


def test_every_way_of_not_earning_adoption_is_refused_with_its_reason():
    cases = [
        (metrics(tgn_tpr={f: 0.3 for f in GOOD["families"]["test"]}), "not clearly better"),
        (metrics(tgn_fpr=0.2), "false-positive rate"),
        (metrics(families={"dev": ["order_swap", "metronome"], "test": GOOD["families"]["test"]}), "overlap"),
        (metrics(families={"dev": GOOD["families"]["dev"], "test": ["metronome"]}), "fewer than 2"),
        (metrics(margin=0.0), "minimum"),
        (metrics(budget_fpr=0.5), "outside"),
        (metrics(budget_fpr=0.0), "outside"),
    ]
    for m, word in cases:
        d = T.decide(m)
        assert not d["passed"] and any(word in r for r in d["reasons"]), (word, d)
    bad = metrics()
    del bad["normalisation"]
    assert not T.decide(bad)["passed"] and "cannot be judged" in T.decide(bad)["reasons"][0]
    nan = metrics(tgn_fpr=float("nan"))
    assert not T.decide(nan)["passed"]
    assert not T.decide({"tgn": {}})["passed"] and not T.decide("x")["passed"]
    skewed = metrics(tgn_tpr={"metronome": None, "lateral_chain": None, "slow_drip": None})
    assert any("fewer than 2" in r for r in T.decide(skewed)["reasons"]), "families that were not measured do not count"


def test_the_rule_is_monotone_a_better_baseline_or_a_worse_network_never_turns_a_refusal_into_a_pass():
    rng = random.Random(3)
    fam = GOOD["families"]["test"]
    for _ in range(400):
        m = metrics(tgn_tpr={f: rng.random() for f in fam}, base_tpr={f: rng.random() for f in fam}, tgn_fpr=rng.random() * 0.2)
        base = T.decide(m)["passed"]
        worse = copy.deepcopy(m)
        f = rng.choice(fam)
        worse["tgn"]["tpr"][f] = max(0.0, worse["tgn"]["tpr"][f] - rng.random())
        better_base = copy.deepcopy(m)
        better_base["baseline"]["tpr"][f] = min(1.0, better_base["baseline"]["tpr"][f] + rng.random())
        higher_fpr = copy.deepcopy(m)
        higher_fpr["tgn"]["fpr_test"] = min(1.0, higher_fpr["tgn"]["fpr_test"] + rng.random() * 0.1)
        for other in (worse, better_base, higher_fpr):
            assert not (T.decide(other)["passed"] and not base), "evidence against the network can never help it"


# ── through the API ───────────────────────────────────────────────────────────────────────────────────────────────

WS = 60


def _keyed(key):
    from fastapi.testclient import TestClient
    from main import app
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {key}"
    return c


def clean_tgn():
    from db.models import ApiKey, LearnedEvaluation, LearnedFlag, LearnedModel, LearnedScore
    from db.session import SessionLocal
    with SessionLocal() as s:
        for M in (LearnedFlag, LearnedScore):
            s.query(M).filter(M.detector == "tgn").delete(synchronize_session=False)
        s.query(LearnedEvaluation).filter(LearnedEvaluation.detector == "tgn").delete(synchronize_session=False)
        s.query(LearnedModel).filter(LearnedModel.detector == "tgn").delete(synchronize_session=False)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test-tgn%")).delete(synchronize_session=False)
        s.commit()


def tgn_world(fn):
    from tests.test_astra_learned import world

    def run():
        from fastapi.testclient import TestClient
        from main import app
        with TestClient(app):
            pass
        clean_tgn()
        try:
            world(fn)()
        finally:
            clean_tgn()
    run.__name__ = fn.__name__
    return run


def service_key(admin):
    k = admin.post("/api/keys", json={"name": "zz-test-tgn service", "role": "collector"})
    assert k.status_code in (200, 201), k.text
    return _keyed(k.json()["key"])


def post_eval(svc, checksum, m):
    return svc.post("/api/astra/learned/tgn/evaluations", json={"checksum": checksum, "metrics": m, "vocab": {"nodes": ["a"], "kinds": ["tool_call"]}, "hyper": {"window_seconds": WS, "seed": 7},
                                                                 "training": {"events": 1000}})


def cs():
    return uuid.uuid4().hex + uuid.uuid4().hex


def backdate(model_id, hours=3):
    """Adoption happened some hours ago, so windows that are complete now are windows the adopted model may score."""
    from db.models import LearnedModel
    from db.session import SessionLocal
    with SessionLocal() as s:
        m = s.get(LearnedModel, uuid.UUID(model_id))
        m.adopted_at = datetime.now(timezone.utc) - timedelta(hours=hours)
        s.commit()


def aligned(hours_ago):
    return int((datetime.now(timezone.utc) - timedelta(hours=hours_ago)).timestamp() // WS * WS)


@tgn_world
def test_the_stream_gives_a_collector_key_names_kinds_times_and_where_the_agent_sits(one, two, eng):
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import NAME
    from tests.test_astra_learned import boundary, put_events
    put_events(NAME, boundary(3), 2, n=5)
    put_events("zz-other-agent", boundary(3), 1, n=4)
    with authed_client("admin", "Alice Admin") as admin, authed_client("auditor", "Alex Auditor") as aud:
        svc = service_key(admin)
        r = svc.get("/api/astra/learned/stream?since=0&limit=1000")
        assert r.status_code == 200, r.text
        ev = r.json()["events"]
        assert {e["agent"] for e in ev} >= {NAME, "zz-other-agent"} and not r.json()["more"]
        assert all(set(e) == {"t", "agent", "kind", "target", "dept", "tier"} for e in ev), "nothing but the schema leaves the platform"
        mine = [e for e in ev if e["agent"] == NAME]
        assert mine and all(e["dept"] == "ZZ Finance" and e["tier"] == 2 for e in mine), mine[:1]
        other = [e for e in ev if e["agent"] == "zz-other-agent"]
        assert other and all(e["dept"] == "(unassigned)" and e["tier"] == 4 for e in other), "an agent with no saved design is read as the most severe tier"
        assert ev == sorted(ev, key=lambda e: e["t"])
        page = svc.get("/api/astra/learned/stream?since=0&limit=3").json()
        assert len(page["events"]) == 3 and page["more"]
        assert aud.get("/api/astra/learned/stream").status_code == 403, "a read-only key cannot read the stream"
        assert svc.post("/api/astra/learned/tgn/models/x/adopt").status_code == 403 and svc.get("/api/agents").status_code == 403, "a collector key can do nothing else"


@tgn_world
def test_an_evaluation_that_did_not_pass_cannot_be_adopted_by_anyone_and_the_platform_judges_for_itself(one, two, eng):
    from tests._auth import authed_client
    with authed_client("admin", "Alice Admin") as admin:
        svc = service_key(admin)
        bad = metrics(tgn_tpr={f: 0.2 for f in GOOD["families"]["test"]})
        bad["decision"] = {"passed": True, "reasons": []}                                 # a service that claims a pass it did not earn
        r = post_eval(svc, cs(), bad)
        assert r.status_code == 201, r.text
        out = r.json()
        assert out["evaluation"]["passed"] is False and out["disagrees"] is True and out["model"]["status"] == "CANDIDATE" and not out["model"]["adopted"]
        assert any("not clearly better" in x for x in out["evaluation"]["reasons"])
        for who in (two, admin):
            a = who.post(f"/api/astra/learned/tgn/models/{out['model']['id']}/adopt")
            assert a.status_code == 409 and "did not pass" in a.json()["detail"], a.text
        assert eng.post(f"/api/astra/learned/tgn/models/{out['model']['id']}/adopt").status_code == 403
        assert svc.get("/api/astra/learned/tgn/active").json() is None, "nothing is switched on"
        assert eng.get("/api/astra/learned/tgn/health").json() == {"adopted": False, "status": "off"}
        m = eng.get("/api/astra/learned/tgn/models").json()
        assert len(m) == 1 and m[0]["evaluation"]["passed"] is False and m[0]["evaluation"]["simulated"] is True and m[0]["status"] == "CANDIDATE"
        assert post_eval(svc, out["model"]["checksum"], GOOD).status_code == 422, "the same weights are recorded once"
        assert post_eval(svc, "short", GOOD).status_code == 422


@tgn_world
def test_a_passing_model_is_adopted_by_a_person_advisory_only_and_can_be_rolled_back(one, two, eng):
    from tests._auth import authed_client
    with authed_client("admin", "Alice Admin") as admin:
        svc = service_key(admin)
        first = post_eval(svc, cs(), GOOD).json()
        assert first["evaluation"]["passed"] and first["model"]["version"] == 1
        assert two.post(f"/api/astra/learned/tgn/models/{first['model']['id']}/adopt").status_code == 200
        act = svc.get("/api/astra/learned/tgn/active").json()
        assert act["id"] == first["model"]["id"] and act["threshold"] == 2.5 and act["normalisation"] == GOOD["normalisation"] and act["window_seconds"] == WS and act["last_window_end"] > 0
        assert two.post(f"/api/astra/learned/tgn/models/{first['model']['id']}/adopt").status_code == 409, "already adopted"
        second = post_eval(svc, cs(), GOOD).json()
        assert second["model"]["version"] == 2
        assert one.post(f"/api/astra/learned/tgn/models/{second['model']['id']}/adopt").status_code == 200
        assert svc.get("/api/astra/learned/tgn/active").json()["id"] == second["model"]["id"], "a new adoption retires the old model"
        models = {m["id"]: m for m in eng.get("/api/astra/learned/tgn/models").json()}
        assert models[first["model"]["id"]]["status"] == "RETIRED" and models[second["model"]["id"]]["adopted"]
        assert eng.post("/api/astra/learned/tgn/rollback").status_code == 403
        rb = two.post("/api/astra/learned/tgn/rollback").json()
        assert rb["adopted"] and rb["restored"]["id"] == first["model"]["id"]
        assert svc.get("/api/astra/learned/tgn/active").json()["id"] == first["model"]["id"]
        off = two.post("/api/astra/learned/tgn/rollback").json()
        assert off == {"restored": None, "adopted": False}, "nothing earlier passed: the detector is off"
        assert svc.get("/api/astra/learned/tgn/active").json() is None
        assert two.post("/api/astra/learned/tgn/rollback").status_code == 409


@tgn_world
def test_scores_are_accepted_only_for_the_adopted_model_and_only_complete_windows_of_known_agents(one, two, eng):
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import NAME
    with authed_client("admin", "Alice Admin") as admin:
        svc = service_key(admin)
        cand = post_eval(svc, cs(), GOOD).json()["model"]
        w = aligned(0.1)
        body = {"model_id": cand["id"], "windows": [{"agent": NAME, "window_start": w - 600, "events": 5, "score": 1.0}]}
        r = svc.post("/api/astra/learned/tgn/scores", json=body)
        assert r.status_code == 409, "a candidate's scores are not accepted"
        assert two.post(f"/api/astra/learned/tgn/models/{cand['id']}/adopt").status_code == 200
        backdate(cand["id"])
        start = aligned(0.0) - WS * 5
        ok = {"agent": NAME, "window_start": start, "events": 6, "score": 1.0}
        high = {"agent": NAME, "window_start": start + WS, "events": 6, "score": 9.0}
        out = svc.post("/api/astra/learned/tgn/scores", json={"model_id": cand["id"], "windows": [
            ok, high, {"agent": "zz-never-seen", "window_start": start, "events": 3, "score": 99.0},                          # an agent the model never saw
            {"agent": NAME, "window_start": aligned(0.0) + WS * 30, "events": 3, "score": 99.0},                              # a window in the future
            {"agent": NAME, "window_start": start + 7, "events": 3, "score": 99.0},                                           # not aligned
            {"agent": NAME, "window_start": start + 2 * WS, "events": 0, "score": 99.0},                                      # no events
            {"agent": NAME, "window_start": aligned(48), "events": 3, "score": 99.0},                                         # before the adoption
        ]}).json()
        assert out == {"scored": 2, "flagged": 1, "skipped": 5}, out
        again = svc.post("/api/astra/learned/tgn/scores", json={"model_id": cand["id"], "windows": [ok]}).json()
        assert again["scored"] == 0 and again["skipped"] == 1, "a window is scored once"
        assert svc.post("/api/astra/learned/tgn/scores", json={"model_id": str(uuid.uuid4()), "windows": [ok]}).status_code == 409
        flags = eng.get("/api/astra/learned/flags").json()
        net = [f for f in flags if f["detector"] == "tgn"]
        assert len(net) == 1 and net[0]["control"] == "base" and net[0]["level"] == "UNV" and net[0]["score"] == 9.0 and net[0]["threshold"] == 2.5 and net[0]["agent_key"] == NAME
        assert svc.get("/api/astra/learned/tgn/active").json()["last_window_end"] >= start + 2 * WS


@tgn_world
def test_a_network_flag_can_only_tighten_the_baseline_control_and_never_blocks(one, two, eng):
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import NAME, attest
    from tests.test_astra_verdicts import attest_all, lower_tolerance, verdict
    with authed_client("admin", "Alice Admin") as admin:
        svc = service_key(admin)
        attest_all()
        lower_tolerance(one, two, 1)
        assert verdict(eng)["learned"] == {"monitored": False, "flags": 0}
        cand = post_eval(svc, cs(), GOOD).json()["model"]
        two.post(f"/api/astra/learned/tgn/models/{cand['id']}/adopt")
        backdate(cand["id"])
        assert verdict(eng)["learned"]["monitored"] is False, "adopted, but it has scored nothing of this agent yet"
        start = aligned(0.0) - WS * 4
        svc.post("/api/astra/learned/tgn/scores", json={"model_id": cand["id"], "windows": [{"agent": NAME, "window_start": start, "events": 6, "score": 1.0}]})
        v = verdict(eng)
        assert v["learned"] == {"monitored": True, "flags": 0}
        assert v["verdict"] == "REQUIRES_REVIEW", "a monitored baseline is required and starts unverified until validated"
        attest("astra:base")
        assert verdict(eng)["verdict"] == "APPROVED"
        svc.post("/api/astra/learned/tgn/scores", json={"model_id": cand["id"], "windows": [{"agent": NAME, "window_start": start + WS, "events": 6, "score": 11.0}]})
        v = verdict(eng)
        assert v["verdict"] == "REQUIRES_REVIEW" and v["learned"]["flags"] == 1 and [(m["kind"], m["from"], m["to"]) for m in v["controls_moved"]] == [("base", "SAT", "UNV")], v
        lower_tolerance(one, two, 0)
        assert verdict(eng)["verdict"] == "REQUIRES_REVIEW", "never a block, whatever the department accepts"
        f = [x for x in eng.get("/api/astra/learned/flags").json() if x["detector"] == "tgn"][0]
        assert one.post(f"/api/astra/learned/flags/{f['id']}/adjudicate", json={"outcome": "benign", "note": "A planned migration.", "days": 3}).status_code == 200
        assert verdict(eng)["verdict"] == "APPROVED", "a person's judgement is the only thing that lifts it"


@tgn_world
def test_the_detectors_own_health_reports_drift_when_it_flags_far_more_than_its_budget(one, two, eng):
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import NAME
    with authed_client("admin", "Alice Admin") as admin:
        svc = service_key(admin)
        cand = post_eval(svc, cs(), GOOD).json()["model"]
        two.post(f"/api/astra/learned/tgn/models/{cand['id']}/adopt")
        backdate(cand["id"])
        base = aligned(0.0) - WS * 60
        def feed(scores, offset):
            wins = [{"agent": NAME, "window_start": base + (offset + i) * WS, "events": 5, "score": s} for i, s in enumerate(scores)]
            r = svc.post("/api/astra/learned/tgn/scores", json={"model_id": cand["id"], "windows": wins}).json()
            assert r["scored"] == len(scores), r
        assert eng.get("/api/astra/learned/tgn/health").json()["status"] == "collecting"
        feed([0.1] * 5, 0)
        h = eng.get("/api/astra/learned/tgn/health").json()
        assert h["status"] == "collecting" and h["windows_24h"] == 5 and any("more live windows" in r for r in h["reasons"])
        feed([0.0, -0.2, 0.3, 0.1, -0.1] * 4, 5)
        h = eng.get("/api/astra/learned/tgn/health").json()
        assert h["status"] == "ok" and h["flag_rate"] == 0.0, h
        feed([5.0] * 12, 25)                                                               # a third of the live windows now flagged
        h = eng.get("/api/astra/learned/tgn/health").json()
        assert h["status"] == "drifting" and any("three times the budget" in r for r in h["reasons"]) and any("mean live score" in r for r in h["reasons"]), h


@tgn_world
def test_only_the_flag_the_table_allows_can_be_stored_for_a_network_too(one, two, eng):
    from sqlalchemy.exc import IntegrityError
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import NAME
    from db.models import LearnedFlag
    from db.session import SessionLocal
    with authed_client("admin", "Alice Admin") as admin:
        svc = service_key(admin)
        cand = post_eval(svc, cs(), GOOD).json()["model"]
        two.post(f"/api/astra/learned/tgn/models/{cand['id']}/adopt")
        backdate(cand["id"])
        svc.post("/api/astra/learned/tgn/scores", json={"model_id": cand["id"], "windows": [{"agent": NAME, "window_start": aligned(0.0) - WS * 3, "events": 4, "score": 8.0}]})
        with SessionLocal() as s:
            f = s.query(LearnedFlag).filter(LearnedFlag.detector == "tgn").one()
            for control, level in (("iso", "UNV"), ("base", "VIO"), ("least", "SAT")):
                s2 = SessionLocal()
                try:
                    s2.add(LearnedFlag(organisation_id=f.organisation_id, model_id=f.model_id, score_id=f.score_id, agent_key=NAME, detector="tgn", score=9.0, threshold=2.5, control=control, level=level, detail={}))
                    s2.commit()
                except IntegrityError:
                    s2.rollback()
                else:
                    raise AssertionError(f"the table accepted a network flag on {control} at {level}")
                finally:
                    s2.close()


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
