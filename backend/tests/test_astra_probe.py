"""
Tests for ASTRA Probe (phase 8): the generator and replay (pure), the mutation test, the evidence it feeds back, incident scenarios and the admission check (through the API).

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_probe        # see tests/_guard.py

The mutation test is the one that matters: each class check is broken in turn, and the Probe has to fail exactly that class's scenario. A Probe that cannot fail would say nothing.
"""
import copy
import json
import os
import sys
from datetime import date, timedelta

from sqlalchemy import select

import astra_probe as AP
import astra_runtime as AR
import astra_schema
from astra_model.classes import CLASSES

RICH = {
    "schema_version": "0.1",
    "agent": {"id": "zz-probe-agent", "owner": "owner.zz@example.test", "lifecycle": {"status": "production", "expires": "2099-12-31"}, "model_version": "1.0.0"},
    "permitted_goals": [{"id": "G1", "statement": "Handle refunds"}],
    "permitted_tasks": [
        {"id": "T1", "tool": "lookup", "scope": {"amount": [0, 100]}},
        {"id": "T2", "tool": "refund", "scope": {"access": "write"}},
        {"id": "T3", "tool": "export", "scope": {}},
        {"id": "T4", "tool": "notify", "scope": {}, "prohibited_chains": ["export -> notify"]},
        {"id": "T5", "tool": "wipe", "scope": {"access": "write"}},
    ],
    "resource_scopes": {"memory": {"writes": "validated", "default_context": "ephemeral"}, "data": [{"resource": "ledger", "access": "read"}]},
    "delegation": {"may_delegate_to": ["zz-peer-agent"], "accepts_delegation_from": ["zz-orchestrator"], "mode": "execution_only"},
    "autonomy": {"unattended_actions": ["T1", "T3", "T4"], "human_in_the_loop": [{"action": "refund over limit", "require": "forced_confirmation"}]},
    "constraints": [], "regulatory_mappings": [],
}
MINIMAL = {
    "schema_version": "0.1",
    "agent": {"id": "zz-min-agent", "owner": "owner.zz@example.test", "lifecycle": {"status": "production", "expires": "2099-12-31"}, "model_version": "1.0.0"},
    "permitted_goals": [{"id": "G1", "statement": "Look things up"}],
    "permitted_tasks": [{"id": "T1", "tool": "lookup", "scope": {}}],
    "autonomy": {"unattended_actions": ["T1"], "human_in_the_loop": []},
    "constraints": [], "regulatory_mappings": [],
}
assert astra_schema.validate(RICH) == [] and astra_schema.validate(MINIMAL) == []


def failed(results):
    return sorted(r["class"] for r in results if r["applicable"] and not r["passed"])


class mutated:
    """Replace the conformity predicate the runtime and the Probe both use, for the length of a block."""
    def __init__(self, wrap):
        self.wrap = wrap

    def __enter__(self):
        self.real = AR.conforms
        AR.conforms = self.wrap(self.real)

    def __exit__(self, *exc):
        AR.conforms = self.real


def drop(cid):
    def wrap(real):
        def fake(E, ev, hist=()):
            r = real(E, ev, hist)
            if cid in r["classes"]:
                cl = [c for c in r["classes"] if c != cid]
                r = dict(r, classes=cl, outcome=r["outcome"] if cl else "CONFORMS")
            return r
        return fake
    return wrap


# ── pure ──────────────────────────────────────────────────────────────────────────────────────────────────────

def test_every_class_gets_a_scenario_and_the_honest_reconciler_passes_them_all():
    sc = AP.generate(RICH)
    assert [s["class"] for s in sc] == AP.CLASS_IDS and len(AP.CLASS_IDS) == 22 and "DVG-BASE-01" in AP.CLASS_IDS
    results = AP.run(RICH)
    assert all(r["applicable"] for r in results), [r["class"] for r in results if not r["applicable"]]
    assert failed(results) == [] and AP.summary(results)["passed"] == 22 and AP.summary(results)["caught"] == 22
    assert AP.generate(RICH) == AP.generate(RICH), "scenarios are reproducible"


def test_the_expected_outcome_comes_from_the_class_table_not_from_the_reconciler():
    for cid in AP.CLASS_IDS:
        e = AP.expected(cid)
        assert e["classes"] == [cid]
        assert e["outcome"] == {"semantic": "PENDING", "baseline": "ADVISORY"}.get(CLASSES[cid].basis, "DIVERGES"), cid
    assert AP.expected("DVG-GOAL-01")["outcome"] == "PENDING" and AP.expected("DVG-COMM-01")["outcome"] == "DIVERGES"
    src = open(AP.__file__, encoding="utf-8").read()
    assert "AR.conforms(" in src and src.count("AR.conforms(") == 1, "the reconciler is called in one place only, to observe, never to decide what is expected"


def test_mutation_each_broken_class_check_fails_exactly_its_own_scenario():
    for cid in AP.CLASS_IDS:
        with mutated(drop(cid)):
            results = AP.run(RICH)
        assert failed(results) == [cid], (cid, failed(results))
        r = next(x for x in results if x["class"] == cid)
        assert r["bad_ok"] is False and r["bad"]["outcome"] == "CONFORMS", (cid, r["bad"])


def test_mutation_a_check_that_raises_a_false_alarm_at_the_boundary_is_caught_too():
    def wrap(real):
        def fake(E, ev, hist=()):
            if ev["kind"] == "tool_call" and (ev.get("params") or {}).get("amount") == 100:
                return {"outcome": "DIVERGES", "classes": ["DVG-TOOL-02"], "missing": []}        # an off-by-one at the upper bound
            return real(E, ev, hist)
        return fake
    with mutated(wrap):
        results = AP.run(RICH)
    assert failed(results) == ["DVG-TOOL-02"]
    r = next(x for x in results if x["class"] == "DVG-TOOL-02")
    assert r["bad_ok"] is True and r["good_ok"] is False and r["passed"] is False


def test_a_class_the_contract_gives_nothing_to_test_is_not_applicable_never_a_pass():
    results = AP.run(MINIMAL)
    na = {r["class"]: r["reason"] for r in results if not r["applicable"]}
    assert set(na) == {"DVG-TOOL-02", "DVG-TOOL-03", "DVG-AUT-01", "DVG-AUT-02", "DVG-AUT-03", "DVG-DEL-03", "DVG-MEM-02"}, na
    assert all(na.values()) and failed(results) == []
    s = AP.summary(results)
    assert s["not_applicable"] == len(na) and s["passed"] + s["not_applicable"] == s["scenarios"]
    assert next(r for r in results if r["class"] == "DVG-DEL-01")["good_event"] is None, "no delegate to spell a boundary with: only the defect is tested"


def test_a_message_defect_is_caught_by_a_real_signature_check():
    r = next(x for x in AP.run(RICH) if x["class"] == "DVG-COMM-01")
    assert r["bad_ok"] and r["good_ok"] and r["bad"]["classes"] == ["DVG-COMM-01"]
    with mutated(lambda real: (lambda E, ev, hist=(): dict(real(E, dict(ev, verified=True), hist)))):         # a reconciler that believes every message
        r = next(x for x in AP.run(RICH) if x["class"] == "DVG-COMM-01")
    assert r["bad_ok"] is False


def test_replay_changes_nothing_it_is_given():
    before = copy.deepcopy(RICH)
    AP.run(RICH)
    assert RICH == before


def test_the_fold_turns_results_into_evidence_by_the_rules_of_the_model():
    ev = AP.fold(AP.run(RICH))
    assert ev["least"]["ok"] and ev["least"]["supports"] and ev["hitl"]["supports"] and ev["ident"]["supports"]
    assert ev["iso"]["ok"] and not ev["iso"]["supports"], "a semantic class is a person's judgement: a replay cannot vouch for it"
    with mutated(drop("DVG-TOOL-01")):
        ev = AP.fold(AP.run(RICH))
    assert ev["least"]["ok"] is False and ev["least"]["missed"] == ["DVG-TOOL-01"] and ev["hitl"]["ok"]
    with mutated(drop("DVG-GOAL-01")):
        ev = AP.fold(AP.run(RICH))
    assert ev["iso"]["ok"] is False, "a miss counts for a semantic class too"
    assert AP.fold(AP.run(RICH))["base"]["supports"], "a replayed score at the threshold is advisory and one below it is left alone: that validates the advisory path"


# ── through the API ───────────────────────────────────────────────────────────────────────────────────────────────

def _world():
    from tests.test_astra_verdicts import with_world
    return with_world


def probed(fn):
    from db.models import ProbeRun, ProbeScenario
    from db.session import SessionLocal
    from tests.test_astra_assessment_api import KEY, NAME

    def clean():
        with SessionLocal() as s:
            s.query(ProbeRun).filter(ProbeRun.design_key == KEY).delete(synchronize_session=False)
            s.query(ProbeScenario).filter(ProbeScenario.agent_key == NAME).delete(synchronize_session=False)
            s.commit()
    inner = _world()(fn)

    def run():
        from fastapi.testclient import TestClient
        from main import app
        with TestClient(app):                                           # the application brings the scratch database up to date when it starts
            pass
        clean()
        try:
            inner()
        finally:
            clean()
    run.__name__ = fn.__name__
    return run


def _statuses(c, key):
    a = c.get(f"/api/agents/designs/{key}/assessment").json()
    return a["verdict"], {x["kind"]: x["status"] for x in a["paths"][0]["controls"]}, a


def test_a_run_through_the_api_records_results_and_changes_no_runtime_state():
    from db.models import Finding, RuntimeEvent
    from db.session import SessionLocal
    from tests.test_astra_assessment_api import KEY, NAME

    @probed
    def body(one, two, eng):
        with SessionLocal() as s:
            before = (s.query(Finding).count(), s.query(RuntimeEvent).count())
        r = eng.post("/api/astra/probe/run", json={"design_key": KEY})
        assert r.status_code == 201, r.text
        run = r.json()
        assert run["summary"]["scenarios"] == 22 and run["trigger"] == "manual" and run["current"] and run["agent_key"] == NAME
        assert all(x["passed"] for x in run["results"] if x["applicable"])
        with SessionLocal() as s:
            assert (s.query(Finding).count(), s.query(RuntimeEvent).count()) == before, "the Probe writes nothing to the findings or the runtime events"
        latest = eng.get(f"/api/astra/probe/latest?design_key={KEY}").json()
        assert latest["run"]["id"] == run["id"] and latest["run"]["current"] and len(latest["results"]) == 22
        assert eng.get(f"/api/astra/probe/runs/{run['id']}").json()["results"][0]["class"] in AP.CLASS_IDS
        assert len(eng.get(f"/api/astra/probe/runs?design_key={KEY}").json()) == 1
        cr = eng.get("/api/astra/probe/catch-rate").json()
        e = {x["class"]: x for x in cr["classes"]}
        assert cr["runs"] == 1 and e["DVG-TOOL-01"]["catch_rate"] == 1.0 and e["DVG-TOOL-01"]["boundary_ok"] == 1 and cr["catch_rate"] == 1.0
        assert e["DVG-TOOL-02"]["tested"] == 0 and e["DVG-TOOL-02"]["not_applicable"] == 1 and e["DVG-TOOL-02"]["catch_rate"] is None
    body()


def test_a_passing_run_is_supportive_evidence_with_a_lifetime_and_a_changed_design_loses_it():
    from tests.test_astra_assessment_api import KEY, attest, guarded_doc, ratify, set_doc, DEPT

    @probed
    def body(one, two, eng):
        ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 1, "rationale": "Finance now accepts up to tier 1 for this test."})
        attest("astra:iso")                                                     # the injection guard: a person's evidence; a replay cannot vouch for it
        v, st, _ = _statuses(eng, KEY)
        assert v == "REQUIRES_REVIEW" and st["least"] == "UNV" and st["ident"] == "UNV", st
        eng.post("/api/astra/probe/run", json={"design_key": KEY})
        v, st, a = _statuses(eng, KEY)
        assert v == "APPROVED" and st["least"] == "SAT" and st["ident"] == "SAT" and st["life"] == "SAT", (v, st)
        why = {c["kind"]: c["why"] for c in a["paths"][0]["controls"]}
        assert "Verified by an ASTRA Probe run" in why["least"]
        d = guarded_doc()
        d["nodes"].append({"id": "t9", "type": "tool", "name": "lookup", "p": {}})
        d["edges"].append({"from": "a1", "to": "t9", "label": "uses"})
        set_doc(d)                                                              # a new version of the design: the old run says nothing about it
        assert eng.get(f"/api/astra/probe/latest?design_key={KEY}").json()["run"]["current"] is False
        v, st, _ = _statuses(eng, KEY)
        assert v == "REQUIRES_REVIEW" and st["least"] == "UNV"
    body()


def test_a_missed_scenario_sets_the_control_violated_and_admission_refuses():
    from tests.test_astra_assessment_api import KEY

    @probed
    def body(one, two, eng):
        assert eng.get(f"/api/astra/probe/admission?design_key={KEY}").json()["admit"] is False
        with mutated(drop("DVG-TOOL-01")):
            run = eng.post("/api/astra/probe/run", json={"design_key": KEY}).json()
        assert run["summary"]["missed"] == 1
        v, st, a = _statuses(eng, KEY)
        assert st["least"] == "VIO" and "not caught" in next(c["why"] for c in a["paths"][0]["controls"] if c["kind"] == "least")
        adm = eng.get(f"/api/astra/probe/admission?design_key={KEY}").json()
        assert adm["admit"] is False and any("DVG-TOOL-01" in r and "not caught" in r for r in adm["reasons"]), adm
        run = eng.post("/api/astra/probe/run", json={"design_key": KEY, "trigger": "admission"}).json()
        assert run["summary"]["missed"] == 0 and run["trigger"] == "admission"
        adm = eng.get(f"/api/astra/probe/admission?design_key={KEY}").json()
        assert adm["admit"] is True and adm["reasons"] == [], adm
        from tests.test_astra_assessment_api import guarded_doc, set_doc
        d = guarded_doc()
        d["nodes"].append({"id": "t9", "type": "tool", "name": "lookup", "p": {}})
        d["edges"].append({"from": "a1", "to": "t9", "label": "uses"})
        set_doc(d)
        adm = eng.get(f"/api/astra/probe/admission?design_key={KEY}").json()
        assert adm["admit"] is False and any("earlier version" in r for r in adm["reasons"]), adm
    body()


def test_a_finding_becomes_a_scenario_only_when_a_different_person_approves_it_and_it_then_guards_against_regression():
    from tests.test_astra_assessment_api import KEY, NAME, guarded_doc, set_doc
    from tests.test_astra_verdicts import send

    @probed
    def body(one, two, eng):
        r = send(eng, "tool_call", name="shell")
        assert r["verdict"] == "DIVERGENT"
        legacy = eng.post("/api/astra/probe/scenarios/from-finding/F-999999")
        assert legacy.status_code == 404
        made = one.post(f"/api/astra/probe/scenarios/from-finding/{r['finding_key']}")
        assert made.status_code == 201, made.text
        sid = made.json()["id"]
        assert made.json()["status"] == "PROPOSED" and made.json()["class_code"] == "DVG-TOOL-01" and made.json()["proposed_by"] == "Rhea One"
        assert one.post(f"/api/astra/probe/scenarios/from-finding/{r['finding_key']}").status_code == 409, "one scenario per finding"
        run = eng.post("/api/astra/probe/run", json={"design_key": KEY}).json()
        assert run["summary"]["incidents"] == 0, "a proposed scenario is not part of the suite"
        assert eng.post(f"/api/astra/probe/scenarios/{sid}/approve", json={}).status_code == 403, "an engineer cannot approve"
        assert one.post(f"/api/astra/probe/scenarios/{sid}/approve", json={}).status_code == 403, "nor can the person who proposed it"
        ok = two.post(f"/api/astra/probe/scenarios/{sid}/approve", json={"note": "A real incident."})
        assert ok.status_code == 200 and ok.json()["status"] == "STANDING" and ok.json()["decided_by"] == "Rhea Two"
        adm = eng.get(f"/api/astra/probe/admission?design_key={KEY}").json()
        assert adm["admit"] is False and any("approved after the newest run" in x for x in adm["reasons"]), adm
        run = eng.post("/api/astra/probe/run", json={"design_key": KEY}).json()
        inc = [x for x in run["results"] if x["source"] == "incident"]
        assert run["summary"]["incidents"] == 1 and inc[0]["passed"] and inc[0]["good_event"] is None
        assert eng.get(f"/api/astra/probe/admission?design_key={KEY}").json()["admit"] is True
        d = guarded_doc()                                                       # the design now allows the tool the incident used: the suite catches the regression
        d["nodes"].append({"id": "t9", "type": "tool", "name": "shell", "p": {}})
        d["edges"].append({"from": "a1", "to": "t9", "label": "uses"})
        set_doc(d)
        run = eng.post("/api/astra/probe/run", json={"design_key": KEY}).json()
        inc = [x for x in run["results"] if x["source"] == "incident"]
        assert inc and inc[0]["passed"] is False and inc[0]["bad_ok"] is False
        adm = eng.get(f"/api/astra/probe/admission?design_key={KEY}").json()
        assert adm["admit"] is False and any("Standing scenario" in x and "DVG-TOOL-01" in x for x in adm["reasons"]), adm
        assert two.post(f"/api/astra/probe/scenarios/{sid}/retire", json={"note": "The tool is allowed now."}).json()["status"] == "RETIRED"
        assert two.post(f"/api/astra/probe/scenarios/{sid}/retire", json={}).status_code == 409
        assert len(eng.get(f"/api/astra/probe/scenarios?agent={NAME}").json()) == 1
    body()


def test_a_finding_that_cannot_be_replayed_is_refused_with_a_reason():
    from tests.test_astra_verdicts import send

    @probed
    def body(one, two, eng):
        r = send(eng, "tool_call", name="shell")
        two.post(f"/api/findings/{r['finding_key']}/acknowledge", json={"acknowledged": True})
        with __import__("db.session", fromlist=["SessionLocal"]).SessionLocal() as s:
            from db.models import Finding
            f = s.scalar(select(Finding).where(Finding.seq == int(r["finding_key"].removeprefix("F-"))))
            f.class_code = "DVG-COMM-01"
            s.commit()
        x = one.post(f"/api/astra/probe/scenarios/from-finding/{r['finding_key']}")
        assert x.status_code == 422 and "cannot be replayed" in x.json()["detail"], x.text
        with __import__("db.session", fromlist=["SessionLocal"]).SessionLocal() as s:
            f = s.scalar(select(Finding).where(Finding.seq == int(r["finding_key"].removeprefix("F-"))))
            f.class_code = "DVG-TOOL"                                           # raised by the earlier check of an unsigned contract
            s.commit()
        x = one.post(f"/api/astra/probe/scenarios/from-finding/{r['finding_key']}")
        assert x.status_code == 422 and "earlier check" in x.json()["detail"], x.text
    body()


def test_the_nightly_run_probes_every_agent_design_and_only_a_writer_can_run_the_probe():
    from tests._auth import authed_client
    from tests.test_astra_assessment_api import KEY

    @probed
    def body(one, two, eng):
        out = eng.post("/api/astra/probe/run-all").json()
        assert out["failed"] == 0 and any(r["design_key"] == KEY for r in out["runs"]), out
        assert eng.get(f"/api/astra/probe/runs?design_key={KEY}").json()[0]["trigger"] == "nightly"
        with authed_client("auditor", "Alex Auditor") as aud:
            assert aud.get(f"/api/astra/probe/latest?design_key={KEY}").status_code == 200
            assert aud.post("/api/astra/probe/run", json={"design_key": KEY}).status_code == 403
        assert eng.post("/api/astra/probe/run", json={"design_key": "zz-nope"}).status_code == 404
    body()


def test_a_collector_event_with_a_timestamp_is_stored_on_the_finding_without_it():
    from db.session import SessionLocal
    from tests.test_astra_verdicts import NAME

    @probed
    def body(one, two, eng):
        r = eng.post("/api/runtime/events", json={"agent": NAME, "events": [{"type": "tool_call", "name": "shell", "at": "2026-11-16T10:00:00Z"}]})
        assert r.status_code == 202 and r.json()["results"][0]["verdict"] == "DIVERGENT" and r.json()["results"][0]["finding_key"], r.text
        with SessionLocal() as s:
            from db.models import Finding
            f = s.scalar(select(Finding).where(Finding.agent_key == NAME).order_by(Finding.seq.desc()))
            assert "at" not in (f.event or {}) and f.event["name"] == "shell"
    body()


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
