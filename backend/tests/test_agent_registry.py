"""
Tests for agent_registry.py through the real API and database.

    docker compose exec backend python -m tests.test_agent_registry
"""
import sys

from fastapi.testclient import TestClient

from db.models import Agent, Contract, Design
from db.session import SessionLocal
from main import app
from tests._auth import authed_client

NAME = "zz-test-patient-agent"


def doc(name=NAME, req=None):
    return {
        "nodes": [
            {"id": "h1", "type": "human", "name": "Clinician", "p": {}},
            {"id": "g1", "type": "goal", "name": "Summarise records", "p": {}},
            {"id": "a1", "type": "agent", "name": name, "p": {"owner": "Compliance lead", "auto": "approval"}, "primary": True},
            {"id": "t1", "type": "tool", "name": "ehr.records.read", "p": {"write": False}},
            {"id": "t2", "type": "tool", "name": "email.send.external", "p": {"write": True}},
        ],
        "edges": [{"from": "h1", "to": "a1", "label": "requests"}, {"from": "a1", "to": "g1", "label": "pursues"},
                  {"from": "a1", "to": "t1", "label": "uses"}, {"from": "a1", "to": "t2", "label": "uses"}],
        "n": 100, "profile": "healthcare", "req": req or {}, "policy": "block",
    }


def cleanup(*keys):
    with SessionLocal() as s:
        for k in keys:
            for c in s.query(Contract).filter(Contract.deployment_id == k).all():
                s.delete(c)
            for a in s.query(Agent).filter(Agent.agent_key == k).all():
                s.delete(a)
        for d in s.query(Design).filter(Design.name.like("zz-test%")).all():
            s.delete(d)
        s.commit()


def test_register_owner_and_duplicates():
    with authed_client() as api:
        try:
            r = api.post("/api/agents/register", json={"name": "  ZZ Test Registered  ", "framework": "LangGraph", "tools_count": 2})
            assert r.status_code == 201, r.text
            a = r.json()
            assert a["agent_key"] == "zz-test-registered" and a["status"] == "UNOWNED" and a["owner"] is None and a["origin"] == "REGISTERED"
            assert api.post("/api/agents/register", json={"name": "zz test registered"}).status_code == 409
            assert api.post("/api/agents/register", json={"name": "x"}).status_code == 422
            owned = api.patch("/api/agents/zz-test-registered", json={"owner": "Platform"}).json()
            assert owned["status"] == "TO_RATIFY" and owned["owner"] == "Platform"
            assert api.patch("/api/agents/zz-test-registered", json={"owner": "  "}).status_code == 422
            assert api.patch("/api/agents/nope", json={"owner": "x"}).status_code == 404
        finally:
            cleanup("zz-test-registered")


def test_ratify_refuses_blocked_then_issues_a_verifiable_contract():
    with authed_client() as api:
        d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc()})
        assert d.status_code == 201, d.text
        key = d.json()["design_key"]
        key_agent = "zz-test-patient-agent"
        try:
            assert d.json()["document"]["profile"] == "healthcare"                                # extra fields survive
            blocked = api.post("/api/agents/ratify", json={"design_key": key, "reviewer": "Compliance lead"})
            assert blocked.status_code == 422 and "Blocked" in blocked.json()["detail"], blocked.text
            assert key_agent not in [a["agent_key"] for a in api.get("/api/agents").json()]

            req = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}
            full = api.get(f"/api/designs/{key}").json()
            saved = api.put(f"/api/designs/{key}", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT",
                                                         "document": doc(req=req), "version": full["version"]})
            assert saved.status_code == 200, saved.text
            ok = api.post("/api/agents/ratify", json={"design_key": key, "reviewer": "Compliance lead"})
            assert ok.status_code == 200, ok.text
            body = ok.json()
            assert body["agent"]["status"] == "DESIGNED" and body["agent"]["tools_count"] == 2 and body["agent"]["origin"] == "DESIGNED"
            c = body["contract"]
            assert c["object_type"] == "AGENT" and c["version"] == "1.0.0" and c["deployment_id"] == key_agent
            assert c["design_snapshot"]["rcr"]["gate"] in ("REVIEW", "APPROVE") and c["design_snapshot"]["analysis"]["rows"]
            assert api.get(f"/api/contracts/{c['contract_id']}/verify").json()["ok"]
            assert all(x["object_type"] == "AGENT" for x in api.get("/api/contracts?object_type=AGENT").json())
            assert c["contract_id"] not in [x["contract_id"] for x in api.get("/api/contracts").json()]   # model list stays model-only
            again = api.post("/api/agents/ratify", json={"design_key": key, "reviewer": "Compliance lead"}).json()
            assert again["contract"]["version"] == "2.0.0" and again["agent"]["contract_count"] == 2
            assert len([a for a in api.get("/api/agents").json() if a["agent_key"] == key_agent]) == 1  # one agent, two contracts
        finally:
            cleanup(key_agent)


def test_ratify_needs_a_primary_agent_and_an_agent_design():
    with authed_client() as api:
        m = api.post("/api/designs", json={"name": "zz-test model", "domain": "GENERAL", "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1}}).json()
        d = api.post("/api/designs", json={"name": "zz-test empty", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": {"nodes": [], "edges": [], "n": 1}}).json()
        try:
            assert api.post("/api/agents/ratify", json={"design_key": m["design_key"], "reviewer": "x"}).status_code == 404
            r = api.post("/api/agents/ratify", json={"design_key": d["design_key"], "reviewer": "x"})
            assert r.status_code == 422 and "primary agent" in r.json()["detail"]
        finally:
            cleanup()


def test_demo_agents_load_once_and_remove_cleanly():
    with authed_client() as api:
        before = len(api.get("/api/agents").json())
        try:
            first = api.post("/api/agents/demo").json()
            assert len(api.post("/api/agents/demo").json()) == len(first)                       # loading twice adds nothing
            assert sum(1 for a in first if a["origin"] == "DEMO") >= 12
            assert any(a["status"] == "UNOWNED" and a["owner"] is None for a in first)
        finally:
            assert api.delete("/api/agents/demo").status_code == 204
        assert len(api.get("/api/agents").json()) == before


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
