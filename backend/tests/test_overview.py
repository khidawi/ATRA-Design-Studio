"""
Tests for overview.py (Task 7f): the overview and workspace are computed from what the other screens keep.

    docker compose exec backend python -m tests.test_overview
"""
import sys

from fastapi.testclient import TestClient

from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc

KEY = "zz-test-patient-agent"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}


def clean_all():
    from db.models import DriftItem, EvidencePack, Finding
    from db.session import SessionLocal
    with SessionLocal() as s:
        for model in (EvidencePack, DriftItem, Finding):
            for x in s.query(model).all():
                s.delete(x)
        s.commit()


def test_empty_platform_has_nothing_to_report():
    with authed_client() as api:
        o = api.get("/api/overview").json()
        assert o["agents_total"] == 0 and o["findings"]["open"] == 0 and o["drift"]["open"] == 0 and o["attention"] == []
        assert o["coverage"] == {"covered": 0, "partial": 0, "gap": 0, "no_data": 10, "total": 10}
        w = api.get("/api/workspace").json()
        assert w["compliance"]["queue"] == [] and w["engineering"]["waiting"] == [] and w["auditor"]["packs"] == []


def test_overview_and_workspace_follow_real_activity_and_ignore_demo():
    with authed_client() as api:
        d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
        api.post("/api/designs", json={"name": "zz-test unratified", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc("zz-test-other", REQ)})
        api.post("/api/agents/ratify", json={"design_key": d["design_key"], "reviewer": "Compliance lead"})
        api.post("/api/agents/register", json={"name": "zz-test-sandbox"})
        try:
            api.post("/api/agents/demo")                                                                                    # must not be counted
            api.post("/api/findings/simulate", json={"agent": KEY, "scenario": "write_tool_outside"})
            api.post("/api/drift/simulate", json={"agent": KEY, "scenario": "add_unsigned_mcp"})
            pack = api.post("/api/packs", json={"template": "ASSURANCE", "period": "30d", "generated_by": "Compliance lead"}).json()

            o = api.get("/api/overview").json()
            assert o["demo_agents"] >= 12 and o["agents_total"] == 2 and o["agents_with_contract"] == 1 and o["agents_unowned"] == 1
            assert o["findings"] == {"open": 1, "high": 1, "medium": 0, "low": 0}
            assert o["drift"] == {"open": 1, "from_design": 0, "simulated": 1}
            labels = [a["label"] for a in o["attention"]]
            assert "Drift" in labels and "High" in labels and "Unowned" in labels and "Gap" in labels
            assert all("invoice-agent" not in a["title"] and "sandbox-agent" not in a["title"] for a in o["attention"])        # no demo rows
            texts = " | ".join(a["text"] for a in o["activity"])
            assert "Agent contract issued for zz-test-patient-agent v1.0.0" in texts and "Finding raised" in texts and "Change proposed" in texts and pack["pack_key"] in texts
            assert [a["at"] for a in o["activity"]] == sorted((a["at"] for a in o["activity"]), reverse=True)

            w = api.get("/api/workspace").json()
            assert [q["agent"] for q in w["compliance"]["queue"]] == [KEY] and w["compliance"]["queue"][0]["source"] == "Simulated"
            assert w["compliance"]["policies"] == [{"policy": "block", "agents": [KEY]}]
            assert any(g["code"] == "ASI08" and g["owner"] is None for g in w["compliance"]["gap_owners"])
            waiting = {x["type"]: x for x in w["engineering"]["waiting"]}
            assert {"drift", "owner", "design"} <= set(waiting) and waiting["design"]["title"] == "zz-test unratified"
            assert w["engineering"]["tests"][0]["drafted"] is False
            assert w["auditor"]["packs"][0]["ok"] and w["auditor"]["packs"][0]["contracts_checked"] == 1

            item = api.get("/api/drift").json()
            real = [x for x in item if x["source"] == "SIMULATED"][0]
            api.post(f"/api/drift/{real['id']}/decide", json={"decision": "decline", "reviewer": "Compliance lead"})
            w2 = api.get("/api/workspace").json()
            assert w2["compliance"]["queue"] == [] and w2["auditor"]["approvers"] == ["Compliance lead"] and w2["auditor"]["decisions"][0]["status"] == "DECLINED"
        finally:
            api.delete("/api/agents/demo")
            clean_all()
            cleanup(KEY, "zz-test-sandbox", "zz-test-other")


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
