"""
Tests for runtime.py (Task 12): events from the SDK are recorded, checked against the active contract, and turned into findings and runtime drift.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_runtime     # a scratch database: see tests/_guard.py
"""
import sys
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import runtime
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc

KEY = "zz-test-patient-agent"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}


def keyed(token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def wipe():
    from db.models import Agent, ApiKey, DriftItem, Finding, RuntimeEvent
    from db.session import SessionLocal
    with SessionLocal() as s:
        for model in (RuntimeEvent, DriftItem, Finding):
            for x in s.query(model).all():
                s.delete(x)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        for a in s.query(Agent).filter(Agent.agent_key.like("zz-test%")).all():
            s.delete(a)
        s.commit()
    cleanup(KEY)


def ratified(api):
    d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
    r = api.post("/api/agents/ratify", json={"design_key": d["design_key"]})
    assert r.status_code == 200, r.text
    return r.json()["contract"]


def send(client, agent, events, **extra):
    return client.post("/api/runtime/events", json={"agent": agent, "events": events, **extra})


def test_a_collector_key_can_report_and_nothing_else():
    with authed_client("admin", "Alice Admin") as admin:
        k = admin.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"})
        assert k.status_code == 201, k.text
        try:
            c = keyed(k.json()["key"])
            me = c.get("/api/auth/me").json()
            assert me["user"]["role"] == "collector" and me["permissions"] == ["ingest"]
            r = send(c, "zz-test-newcomer", [{"type": "heartbeat"}])
            assert r.status_code == 202, r.text
            assert c.get("/api/runtime/contract/zz-test-newcomer").status_code == 200
            for method, path in (("get", "/api/agents"), ("get", "/api/runtime/overview"), ("get", "/api/audit"), ("get", "/api/findings"), ("get", "/api/users")):
                assert getattr(c, method)(path).status_code == 403, path
            assert c.post("/api/agents/register", json={"name": "zz-test-x"}).status_code == 403
            assert c.post("/api/findings/ingest", json={"agent": "zz-test-newcomer", "event": {"type": "tool_call", "name": "x"}}).status_code == 403
            assert c.post("/api/agents/ratify", json={"design_key": "x"}).status_code == 403
            assert keyed("astra_deadbeef_x").post("/api/runtime/events", json={"agent": "zz-test-newcomer", "events": [{"type": "heartbeat"}]}).status_code == 401
        finally:
            wipe()


def test_an_unknown_agent_is_discovered_unowned_and_counts_against_asi10():
    with authed_client("admin", "Alice Admin") as admin:
        k = admin.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()
        try:
            c = keyed(k["key"])
            assert send(c, "zz-test-ghost", [{"type": "tool_call", "name": "shell.exec"}], discover=False).status_code == 404
            r = send(c, "zz-test-ghost", [{"type": "tool_call", "name": "shell.exec", "write": True}], framework="LangGraph").json()
            assert r["discovered"] is True and r["accepted"] == 1 and r["results"][0]["verdict"] == "UNKNOWN_AGENT" and r["findings"] == []     # no contract, so nothing to diverge from
            a = [x for x in admin.get("/api/agents").json() if x["agent_key"] == "zz-test-ghost"][0]
            assert a["origin"] == "DISCOVERED" and a["status"] == "UNOWNED" and a["owner"] is None and a["framework"] == "LangGraph" and a["last_seen_at"]
            assert send(c, "zz-test-ghost", [{"type": "heartbeat"}]).json()["discovered"] is False
            cov = {x["code"]: x for x in admin.get("/api/coverage").json()["rows"]}
            assert any(b["agent"] == "zz-test-ghost" for b in cov["ASI10"]["breakdown"]) and cov["ASI10"]["status"] == "Gap"
            admin.post("/api/agents/register", json={"name": "zz-test-registered"})
            nc = send(c, "zz-test-registered", [{"type": "tool_call", "name": "x"}]).json()
            assert nc["results"][0]["verdict"] == "NO_CONTRACT"
            demo = admin.post("/api/agents/demo")
            assert send(c, "invoice-agent", [{"type": "heartbeat"}]).status_code == 409
        finally:
            admin.delete("/api/agents/demo")
            wipe()


def test_divergence_becomes_one_finding_and_one_runtime_drift_item():
    with authed_client("admin", "Alice Admin") as admin, authed_client("compliance", "Compliance lead") as comp:
        contract = ratified(comp)
        k = admin.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()
        try:
            c = keyed(k["key"])
            ok = send(c, KEY, [{"type": "tool_call", "name": "ehr.records.read"}, {"type": "heartbeat"}]).json()
            assert [r["verdict"] for r in ok["results"]] == ["CONFORMING", "CONFORMING"] and ok["contract_version"] == "1.0.0" and ok["divergent"] == 0 and ok["drift_item"] is None

            r = send(c, KEY, [{"type": "tool_call", "name": "payments.transfer.create", "write": True}]).json()
            assert r["divergent"] == 1 and len(r["findings"]) == 1 and r["drift_item"]
            fkey = r["findings"][0]
            f = [x for x in admin.get("/api/findings").json() if x["finding_key"] == fkey][0]
            assert f["severity"] == "High" and f["class_code"] == "DVG-TOOL" and f["source"] == "COLLECTED"
            item = [x for x in admin.get("/api/drift").json() if x["id"] == r["drift_item"]][0]
            assert item["source"] == "RUNTIME" and item["kind"] == "Widening" and item["status"] == "OPEN" and "runtime" in item["source_label"].lower()
            assert any("payments.transfer.create" in ch["text"] for ch in item["changes"])

            again = send(c, KEY, [{"type": "tool_call", "name": "payments.transfer.create", "write": True}] * 3).json()
            assert again["divergent"] == 3 and again["findings"] == [] and {x["finding_key"] for x in again["results"]} == {fkey}                    # the same open finding, not three new ones
            assert again["drift_item"] == r["drift_item"]                                                                                              # nor a new drift item
            assert len([x for x in admin.get("/api/drift").json() if x["source"] == "RUNTIME"]) == 1

            second = send(c, KEY, [{"type": "mcp_connect", "name": "mcp://web-search", "signed": False}]).json()
            assert second["drift_item"] and second["drift_item"] != r["drift_item"]
            items = {x["id"]: x for x in admin.get("/api/drift").json() if x["source"] == "RUNTIME"}
            assert items[r["drift_item"]]["status"] == "SUPERSEDED" and items[second["drift_item"]]["status"] == "OPEN"
            texts = " ".join(ch["text"] for ch in items[second["drift_item"]]["changes"])
            assert "payments.transfer.create" in texts and "mcp://web-search" in texts                                                                # accumulated, not replaced

            declined = comp.post(f"/api/drift/{second['drift_item']}/decide", json={"decision": "decline", "note": "stop it"}).json()
            assert declined["status"] == "DECLINED"
            after = send(c, KEY, [{"type": "tool_call", "name": "payments.transfer.create", "write": True}]).json()
            assert after["divergent"] == 1 and after["drift_item"] is None                                                                            # a declined observation opens nothing new
            assert [x["status"] for x in admin.get("/api/drift").json() if x["source"] == "RUNTIME" and x["status"] == "OPEN"] == []
        finally:
            wipe()


def test_approving_runtime_drift_legitimises_the_behaviour():
    with authed_client("admin", "Alice Admin") as admin, authed_client("compliance", "Compliance lead") as comp:
        contract = ratified(comp)
        k = admin.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()
        try:
            c = keyed(k["key"])
            r = send(c, KEY, [{"type": "tool_call", "name": "ehr.records.write", "write": True}]).json()
            assert r["divergent"] == 1 and r["drift_item"]
            ok = comp.post(f"/api/drift/{r['drift_item']}/decide", json={"decision": "approve"})
            assert ok.status_code == 200 and ok.json()["new_contract_id"], ok.text
            nxt = send(c, KEY, [{"type": "tool_call", "name": "ehr.records.write", "write": True}]).json()
            assert nxt["contract_version"] == "2.0.0" and nxt["divergent"] == 0 and nxt["results"][0]["verdict"] == "CONFORMING"
            recs = [x for x in admin.get(f"/api/contract-records?object_type=AGENT&deployment={KEY}").json()]
            assert sorted(x["status"] for x in recs) == ["ACTIVE", "SUPERSEDED"]
        finally:
            wipe()


def test_overview_status_unused_permissions_and_the_feed():
    with authed_client("admin", "Alice Admin") as admin, authed_client("compliance", "Compliance lead") as comp:
        ratified(comp)
        k = admin.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()
        try:
            c = keyed(k["key"])
            before = {a["agent_key"]: a for a in admin.get("/api/runtime/overview").json()["agents"]}
            assert before[KEY]["status"] == "never" and before[KEY]["unused_tools"] == []                       # nothing observed yet: no claim about unused tools
            send(c, KEY, [{"type": "tool_call", "name": "ehr.records.read"}, {"type": "heartbeat"},
                          {"type": "tool_call", "name": "shell.exec"}, {"type": "tool_call", "name": "x", "at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()}])
            ov = admin.get("/api/runtime/overview").json()
            a = {x["agent_key"]: x for x in ov["agents"]}[KEY]
            assert a["status"] == "live" and a["contract_version"] == "1.0.0" and a["events_1h"] == 4 and a["divergent_1h"] == 2 and a["open_findings"] >= 1
            assert a["unused_tools"] == ["email.send.external"]                                                  # allowed by the contract, never used: a least-privilege hint
            assert ov["events_24h"] == 4 and ov["divergent_24h"] == 2 and ov["max_seq"] >= 4
            feed = ov["events"]
            assert feed[0]["seq"] > feed[-1]["seq"] and {e["verdict"] for e in feed} == {"CONFORMING", "DIVERGENT"} and all(e["reported_by"] == "API key: zz-test-collector" for e in feed)
            far = [e for e in feed if e["name"] == "x"][0]
            assert abs((datetime.fromisoformat(far["at"].replace("Z", "+00:00")) - datetime.now(timezone.utc)).total_seconds()) < 60              # a clock a month ahead is not believed
            assert admin.get(f"/api/runtime/overview?agent={KEY}&limit=1").json()["events"][0]["agent_key"] == KEY
            s = admin.get(f"/api/runtime/contract/{KEY}").json()
            assert s["state"] == "contract" and s["version"] == "1.0.0" and {t["name"] for t in s["allowed"]["tools"]} == {"ehr.records.read", "email.send.external"}
            assert "nodes" not in str(s) and "snapshot" not in str(s)                                              # only what the contract allows
        finally:
            wipe()


def test_limits_throttle_batch_size_and_validation():
    with authed_client("admin", "Alice Admin") as admin:
        k = admin.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()
        old = runtime.RATE_PER_MINUTE
        try:
            c = keyed(k["key"])
            assert send(c, "zz-test-lim", [{"type": "heartbeat"}] * 201).status_code == 422
            assert send(c, "zz-test-lim", []).status_code == 422 and send(c, "zz-test-lim", [{"type": "teleport"}]).status_code == 422
            assert send(c, "!", [{"type": "heartbeat"}]).status_code == 422
            runtime._window.clear()
            runtime.RATE_PER_MINUTE = 5
            assert send(c, "zz-test-lim", [{"type": "heartbeat"}] * 4).status_code == 202
            r = send(c, "zz-test-lim", [{"type": "heartbeat"}] * 3)
            assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1 and "slow down" in r.json()["detail"]
        finally:
            runtime.RATE_PER_MINUTE = old
            runtime._window.clear()
            wipe()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
            print("PASS ", n)
        except Exception as exc:
            failed += 1
            print("FAIL ", n, repr(exc)[:600])
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
