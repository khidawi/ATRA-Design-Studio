"""
Tests for coverage_scorecard.py (Task 7d): statuses are computed from real contracts, never stored.

    docker compose exec backend python -m tests.test_coverage
"""
import sys
from datetime import date, timedelta

from fastapi.testclient import TestClient

import coverage_scorecard as cs
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc

KEY = "zz-test-patient-agent"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}


def rows(api):
    out = api.get("/api/coverage").json()
    return out, {r["code"]: r for r in out["rows"]}


def clean_assignments():
    from db.models import CoverageAssignment
    from db.session import SessionLocal
    with SessionLocal() as s:
        for x in s.query(CoverageAssignment).all():
            s.delete(x)
        s.commit()


def test_worst_case_aggregation_and_labels():
    assert cs.worst(["Covered", "Covered"]) == "Covered"
    assert cs.worst(["Covered", "Partial"]) == "Partial"
    assert cs.worst(["Covered", "Partial", "Gap"]) == "Gap"
    assert cs.worst(["Not applicable", "Not applicable"]) == "No data" and cs.worst([]) == "No data"
    assert cs.worst(["Not applicable", "Covered"]) == "Covered"
    today = date(2026, 10, 6)
    assert cs.due_label("Covered", None, today) == "Met"
    assert cs.due_label("Gap", None, today) == "No date set"
    assert cs.due_label("Gap", today - timedelta(days=3), today) == "Overdue by 3 days"
    assert cs.due_label("Gap", today - timedelta(days=1), today) == "Overdue by 1 day"
    assert cs.due_label("Partial", today, today) == "Due today"
    assert cs.due_label("Partial", date(2026, 11, 30), today) == "30 Nov 2026"


def test_empty_inventory_has_no_data_everywhere():
    with authed_client() as api:
        out, by = rows(api)
        assert out["agents_in_scope"] == 0 and out["gap"] == 0 and out["covered"] == 0
        assert [r["code"] for r in out["rows"] if r["group"] == "OWASP"] == [f"ASI{i:02d}" for i in range(1, 11)]
        assert all(r["status"] == "No data" for r in out["rows"]) and out["no_data"] == 10


def test_statuses_follow_the_active_contracts_and_the_inventory():
    with authed_client() as api:
        d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
        c = api.post("/api/agents/ratify", json={"design_key": d["design_key"], "reviewer": "Compliance lead"}).json()["contract"]
        try:
            out, by = rows(api)
            assert out["agents_in_scope"] == 1
            # The scorecard must agree with the analysis stored in the contract it was computed from.
            stored = {r["id"]: r["status"] for r in c["design_snapshot"]["analysis"]["rows"]}
            for code, status in stored.items():
                expected = "No data" if status == "Not applicable" else status
                assert by[code]["status"] == expected, (code, by[code]["status"], status)
            gaps = [code for code, s in stored.items() if s == "Gap"]
            assert out["gap"] == len([c_ for c_ in gaps if c_.startswith("ASI")])
            applicable = [r for r in out["rows"] if r["status"] != "No data"]
            assert applicable and all(r["breakdown"][0]["agent"] == "zz-test-patient-agent" and r["breakdown"][0]["version"] == "1.0.0" for r in applicable if r["code"] != "ASI10")

            # An unowned agent in the inventory counts against ASI10, as the inventory screen says it does.
            assert api.post("/api/agents/register", json={"name": "zz-test-rogue"}).status_code == 201
            out2, by2 = rows(api)
            assert by2["ASI10"]["status"] == "Gap" and any(b["agent"] == "zz-test-rogue" for b in by2["ASI10"]["breakdown"])
            assert out2["agents_without_contract"] == 1
            api.patch("/api/agents/zz-test-rogue", json={"owner": "Platform"})
            assert rows(api)[1]["ASI10"]["status"] == stored["ASI10"] or rows(api)[1]["ASI10"]["status"] == "No data"

            # Revoking the only contract leaves nothing to compute from.
            api.post(f"/api/contracts/{c['contract_id']}/revoke", json={"reviewer": "x", "reason": "testing coverage"})
            assert rows(api)[0]["agents_in_scope"] == 0
        finally:
            cleanup(KEY, "zz-test-rogue")


def test_assignments_and_demo_exclusion():
    with authed_client() as api:
        try:
            r = api.put("/api/coverage/ASI08", json={"owner": " Platform lead ", "due": (date.today() - timedelta(days=3)).isoformat(), "note": "circuit breakers"})
            assert r.status_code == 200, r.text
            row = r.json()
            assert row["owner"] == "Platform lead" and row["note"] == "circuit breakers" and row["status"] == "No data"
            assert row["due_label"] == "Overdue by 3 days"
            assert api.put("/api/coverage/ASI99", json={"owner": "x"}).status_code == 404
            cleared = api.put("/api/coverage/ASI08", json={"owner": "  ", "due": None}).json()
            assert cleared["owner"] is None and cleared["due"] is None
            api.post("/api/agents/demo")
            out, _ = rows(api)
            assert out["agents_in_scope"] == 0 and out["demo_agents_excluded"] >= 12 and out["gap"] == 0                      # demo data never counts
        finally:
            api.delete("/api/agents/demo")
            clean_assignments()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
            print("PASS ", n)
        except Exception as exc:
            failed += 1
            print("FAIL ", n, repr(exc))
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
