"""
Tests for the Probe told as attack stories for the Design studio (astra_probe_view.py and GET /api/astra/probe/explain), phase 14:

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_probe_view        # see tests/_guard.py

The pure part needs no database. The endpoint part runs the real Probe on the guarded agent of the assessment tests and reads the run back.
"""
import astra_probe as AP
import astra_probe_view as PV
from astra_model.classes import CLASSES
from db.models import ProbeRun
from db.session import SessionLocal
from sqlalchemy import func, select
from tests._auth import authed_client
from tests.test_astra_contract_api import KEY, doc, probe, reset
from tests.test_astra_assessment_api import DEPT, STORE, ratify, seed

ASSESSMENT = {"verdict": "APPROVED", "departments": [{"department_ext": "D-1", "department": "Finance", "tolerance": 4}],
              "paths": [{"resource_name": "Invoices", "department": "Finance", "department_ext": "D-1", "tier": 2}]}


def res(cid, **kw):
    c = CLASSES[cid]
    base = {"class": cid, "control": c.control, "basis": c.basis, "source": "template", "applicable": True, "passed": True, "reason": None,
            "expected": {"outcome": AP.EXPECTED_BY_BASIS[c.basis], "classes": [cid]}, "bad_event": {"type": "x", "_hidden": 1}, "good_event": None,
            "bad": {"outcome": "DIVERGES", "classes": [cid], "missing": []}, "good": None, "bad_ok": True, "good_ok": None}
    base.update(kw)
    return base


def test_the_state_of_a_result_follows_the_class_table():
    assert PV.state_of(res("DVG-TOOL-01")) == "caught"
    assert PV.state_of(res("DVG-GOAL-01")) == "pending", "a semantic class waits for a person"
    assert PV.state_of(res("DVG-BASE-01")) == "advisory"
    assert PV.state_of(res("DVG-TOOL-01", passed=False, bad_ok=False)) == "missed"
    assert PV.state_of(res("DVG-AUT-02", applicable=False, passed=None, bad_event=None, reason="no write tool needs a person's confirmation")) == "open"


def test_a_class_the_contract_gives_nothing_to_test_is_open_not_passed_and_says_what_to_add():
    r = PV.row_of(res("DVG-AUT-02", applicable=False, passed=None, bad_event=None, reason="no write tool needs a person's confirmation"), ASSESSMENT)
    assert r["state"] == "open" and "Approval" in r["fix"] and r["expected"] is None and r["observed"] is None
    r = PV.row_of(res("DVG-TOOL-02", applicable=False, passed=None, bad_event=None, reason="the contract declares no parameter bounds"), ASSESSMENT)
    assert r["state"] == "open" and r["fix"] == PV.NOT_YET, "where the design format cannot say it, the view says so instead of inventing a fix"


def test_a_missed_attack_is_said_to_be_a_defect_of_the_check():
    r = PV.row_of(res("DVG-TOOL-01", passed=False, bad_ok=False, bad={"outcome": "CONFORMS", "classes": [], "missing": []}), ASSESSMENT)
    assert r["state"] == "missed" and "defect in the check" in r["fix"] and r["observed"] == "CONFORMS"


def test_private_keys_of_an_event_are_not_shown_and_the_impact_names_the_department():
    r = PV.row_of(res("DVG-RES-01"), ASSESSMENT)
    assert r["planted"] is not None and "_hidden" not in r["planted"]
    assert "Invoices" in r["impact"] and "Finance" in r["impact"] and "tolerance 4" in r["impact"]
    assert "stopped" in PV.row_of(res("DVG-RES-01"), ASSESSMENT)["impact"]
    assert "got through" in PV.row_of(res("DVG-RES-01", passed=False, bad_ok=False), ASSESSMENT)["impact"]
    assert "no untrusted input" in PV.row_of(res("DVG-RES-01"), {"paths": [], "departments": []})["impact"]
    undeclared = {"departments": [{"department_ext": "D-1", "department": "Finance", "tolerance": 0, "tolerance_declared": False}],
                  "paths": [{"resource_name": "Invoices", "department": "Finance", "department_ext": "D-1", "tier": 4, "tier_declared": False}]}
    imp = PV.row_of(res("DVG-RES-01"), undeclared)["impact"]
    assert "not declared: read as the most severe" in imp and "accepts nothing" in imp, "an undeclared tier and tolerance are said to be read at their strictest"


def test_every_class_has_a_story_and_clauses_come_from_the_specification_table():
    assert set(PV.STORY) == set(CLASSES) and all(PV.STORY[c][0] for c in CLASSES)
    assert {c["clause"] for c in PV.clauses_of("DVG-COMM-01")} == {"EU-AI-Act:Art.15"}, "ASI07 maps to Art. 15"
    assert PV.clauses_of("DVG-AUT-02") == [], "ASI09 has no clause in the specification table; the view does not invent one"
    assert all(c["label"] for cid in CLASSES for c in PV.clauses_of(cid))


def test_a_regulation_clause_takes_the_worst_state_of_the_classes_that_touch_it():
    rows = [PV.row_of(res("DVG-COMM-01"), ASSESSMENT), PV.row_of(res("DVG-GOAL-01"), ASSESSMENT)]
    by = {r["clause"]: r["state"] for r in PV.regulations(rows)}
    assert by["EU-AI-Act:Art.15"] == "person", "a caught class and a class waiting for a person: the clause waits for a person"
    rows.append(PV.row_of(res("DVG-TOOL-01", passed=False, bad_ok=False), ASSESSMENT))
    assert {r["clause"]: r["state"] for r in PV.regulations(rows)}["EU-AI-Act:Art.15"] == "risk"
    rows = [PV.row_of(res("DVG-TOOL-02", applicable=False, passed=None, bad_event=None), ASSESSMENT)]
    assert {r["clause"]: r["state"] for r in PV.regulations(rows)}["EU-AI-Act:Art.15"] == "untested"


# ── the endpoint, on the real Probe ────────────────────────────────────────────────────────────────────────

def prepared(one, two):
    seed(doc())
    ratify(one, two, "tolerance", {"department_ext": DEPT, "tolerance": 4, "rationale": "Finance accepts everything for this test."})
    ratify(one, two, "asset", {"asset_ext": STORE, "tier": 2, "rationale": "A low-impact store for this test."})


def runs():
    with SessionLocal() as s:
        return s.scalar(select(func.count()).select_from(ProbeRun).where(ProbeRun.design_key == KEY))


def test_explain_before_any_run_says_so_and_does_not_admit():
    reset()
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        prepared(one, two)
        out = one.get(f"/api/astra/probe/explain?design_key={KEY}").json()
        assert out["run"] is None and out["rows"] == [] and out["admission"]["admit"] is False and out["counts"]["caught"] == 0, out
    reset()


def test_explain_after_a_run_tells_all_22_classes_and_changes_nothing():
    reset()
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two, authed_client("auditor", "Alex Auditor") as aud:
        prepared(one, two)
        probe(one)
        before = runs()
        out = aud.get(f"/api/astra/probe/explain?design_key={KEY}").json()
        assert runs() == before, "explaining a run is a read: it never runs the Probe"
        assert out["current"] is True and len(out["rows"]) == 22 and sum(out["counts"].values()) == 22, out["counts"]
        assert [r["class"] for r in out["rows"]] == AP.CLASS_IDS
        assert out["counts"]["missed"] == 0 and out["admission"]["admit"] is True
        by = {r["class"]: r for r in out["rows"]}
        assert by["DVG-GOAL-01"]["state"] == "pending" and by["DVG-BASE-01"]["state"] == "advisory"
        assert by["DVG-TOOL-01"]["state"] == "caught" and by["DVG-TOOL-01"]["expected"] == "DIVERGES with DVG-TOOL-01" and by["DVG-TOOL-01"]["observed"] == "DIVERGES with DVG-TOOL-01"
        assert by["DVG-TOOL-01"]["impact"] and by["DVG-TOOL-01"]["kinds"] == ["tool"]
        opens = [r for r in out["rows"] if r["state"] == "open"]
        assert opens and all(r["reason"] and r["fix"] for r in opens), "every class that is not tested says why, and what to add where that can be said"
        assert {r["clause"] for r in out["regulations"]} <= set(PV.CLAUSE_LABELS)
        assert out["verdict"] in ("APPROVED", "REQUIRES_REVIEW", "BLOCKED")
    reset()


def test_explain_marks_a_run_of_an_earlier_version_as_not_current():
    reset()
    with authed_client("compliance", "Rhea One") as one, authed_client("compliance", "Rhea Two") as two:
        prepared(one, two)
        probe(one)
        from db.models import Design
        with SessionLocal() as s:
            d = s.scalar(select(Design).where(Design.design_key == KEY))
            nd = doc()
            nd["nodes"].append({"id": "t2", "type": "tool", "name": "lookup", "p": {}})
            nd["edges"].append({"from": "a1", "to": "t2", "label": "uses"})
            d.document, d.version = nd, d.version + 1
            s.commit()
        out = one.get(f"/api/astra/probe/explain?design_key={KEY}").json()
        assert out["current"] is False and out["admission"]["admit"] is False and any("earlier version" in x for x in out["admission"]["reasons"]), out["admission"]
    reset()


def test_explain_refuses_a_design_that_is_not_an_agent_design():
    with authed_client("compliance", "Rhea One") as one:
        assert one.get("/api/astra/probe/explain?design_key=d-nothere").status_code == 404


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
        except Exception as exc:
            failed += 1
            print(f"FAIL  {name}  {type(exc).__name__}: {exc}")
    print(f"done f={failed}")
    raise SystemExit(1 if failed else 0)
