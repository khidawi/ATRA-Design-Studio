"""
Tests for findings (divergence.py, findings.py) and drift (drift_engine.py, drift.py), Task 7c.

    docker compose exec backend python -m tests.test_findings_drift
"""
import sys

from fastapi.testclient import TestClient

import agent_contract
import divergence
import drift_engine
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc

KEY = "zz-test-patient-agent"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}


def view(tools=(("crm.read", False),), delegates=(), mcp=(), memory=(), data=()):
    nodes = [{"id": "a1", "type": "agent", "name": "x", "p": {"owner": "o"}, "primary": True}]
    nodes += [{"id": f"t{i}", "type": "tool", "name": n, "p": {"write": w}} for i, (n, w) in enumerate(tools)]
    nodes += [{"id": f"m{i}", "type": "mcp", "name": n, "p": {"signed": s}} for i, (n, s) in enumerate(mcp)]
    nodes += [{"id": f"y{i}", "type": "memory", "name": n, "p": {"long": l}} for i, (n, l) in enumerate(memory)]
    nodes += [{"id": f"d{i}", "type": "data", "name": n, "p": {}} for i, n in enumerate(data)]
    v = agent_contract.view({"name": "x", "nodes": nodes, "edges": []})
    v["delegates_to"] = list(delegates)
    return v


def test_conforming_events_produce_no_finding():
    v = view(tools=(("crm.read", False),), delegates=("notify",), mcp=(("mcp://kb", True),), data=("store",))
    assert divergence.check_event(v, {"type": "tool_call", "name": "crm.read"}) is None
    assert divergence.check_event(v, {"type": "delegation", "name": "notify"}) is None
    assert divergence.check_event(v, {"type": "mcp_connect", "name": "mcp://kb", "signed": True}) is None
    assert divergence.check_event(v, {"type": "memory_write", "scope": "session"}) is None
    assert divergence.check_event(v, {"type": "data_access", "name": "store"}) is None
    assert divergence.check_event(view(memory=(("notes", True),)), {"type": "memory_write", "scope": "long_term"}) is None   # the contract allows it


def test_each_divergence_class_and_severity():
    v = view()
    f = divergence.check_event(v, {"type": "tool_call", "name": "shell.exec", "write": True})
    assert (f["class_code"], f["severity"], f["threat"].split()[0]) == ("DVG-TOOL", "High", "ASI02") and "crm.read" in f["permitted"]
    assert divergence.check_event(v, {"type": "tool_call", "name": "shell.exec"})["severity"] == "Medium"
    assert divergence.check_event(v, {"type": "delegation", "name": "other"})["class_code"] == "DVG-DEL"
    unlisted = divergence.check_event(v, {"type": "mcp_connect", "name": "mcp://new", "signed": True})
    assert unlisted["class_code"] == "DVG-SUP" and "not in the contract" in unlisted["title"]
    unsigned = divergence.check_event(view(mcp=(("mcp://kb", True),)), {"type": "mcp_connect", "name": "mcp://kb", "signed": False})
    assert unsigned["class_code"] == "DVG-SUP" and "no valid signature" in unsigned["title"]
    assert divergence.check_event(v, {"type": "memory_write", "scope": "long_term"})["severity"] == "Low"
    assert divergence.check_event(v, {"type": "data_access", "name": "customer-documents"})["class_code"] == "DVG-DATA"
    try:
        divergence.check_event(v, {"type": "teleport"})
    except ValueError:
        pass
    else:
        raise AssertionError("an unknown event type must be rejected")


def test_every_simulator_scenario_matches_what_the_checks_say():
    v = view()
    expected = {"tool_outside": "DVG-TOOL", "write_tool_outside": "DVG-TOOL", "delegation_outside": "DVG-DEL", "unsigned_mcp": "DVG-SUP",
                "memory_long_term": "DVG-MEM", "data_outside": "DVG-DATA", "conforming_call": None}
    for sid, _, _ in divergence.SCENARIOS:
        found = divergence.check_event(v, divergence.scenario_event(sid, v))
        assert (found["class_code"] if found else None) == expected[sid], sid


def test_detailed_changes():
    base = {"nodes": [{"id": "a1", "type": "agent", "name": "x", "p": {"owner": "o", "auto": "approval"}, "primary": True},
                      {"id": "t1", "type": "tool", "name": "crm.read", "p": {"write": False}},
                      {"id": "m1", "type": "mcp", "name": "mcp://kb", "p": {"signed": True}},
                      {"id": "ap", "type": "approval", "name": "review", "p": {}}], "edges": []}
    assert drift_engine.detailed_changes(base, base) == []
    new = drift_engine.apply_scenario("add_write_tool", base | {"n": 1})
    ch = drift_engine.detailed_changes(base, new)
    assert [(c["op"], c["class"], c["text"]) for c in ch] == [("add", "Widening", "tool: payments.transfer.create (write)")]
    assert drift_engine.kind_of(ch) == "Widening"
    flipped = {"nodes": [dict(n, p=dict(n["p"], signed=False)) if n["type"] == "mcp" else dict(n) for n in base["nodes"]], "edges": []}
    assert [(c["op"], c["class"]) for c in drift_engine.detailed_changes(base, flipped)] == [("mod", "Widening")]            # signing removed
    narrowed = drift_engine.apply_scenario("remove_tool", base | {"n": 1})
    assert drift_engine.kind_of(drift_engine.detailed_changes(base, narrowed)) == "Narrowing"
    assert drift_engine.kind_of(drift_engine.detailed_changes(base, drift_engine.apply_scenario("remove_approval", base | {"n": 1}))) == "Widening"
    for bad in ("remove_approval",):
        try:
            drift_engine.apply_scenario(bad, {"nodes": [base["nodes"][0]], "edges": []})
        except ValueError:
            continue
        raise AssertionError("expected a refusal")


def ratified(api):
    d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
    r = api.post("/api/agents/ratify", json={"design_key": d["design_key"], "reviewer": "Compliance lead"})
    assert r.status_code == 200, r.text
    return d["design_key"], r.json()["contract"]


def test_findings_come_from_the_contract_and_can_be_worked():
    with authed_client() as api:
        _, c = ratified(api)
        try:
            assert api.post("/api/findings/ingest", json={"agent": "nobody", "event": {"type": "tool_call", "name": "x"}}).status_code == 404
            ok = api.post("/api/findings/simulate", json={"agent": KEY, "scenario": "conforming_call"}).json()
            assert ok["finding"] is None and ok["checked_against"] == "1.0.0"
            bad = api.post("/api/findings/simulate", json={"agent": KEY, "scenario": "write_tool_outside"}).json()
            f = bad["finding"]
            assert f["severity"] == "High" and f["class_code"] == "DVG-TOOL" and f["source"] == "SIMULATED" and f["finding_key"].startswith("F-")
            assert f["evidence"].startswith("sha256:") and f["contract_version"] == "1.0.0"
            real = api.post("/api/findings/ingest", json={"agent": KEY, "event": {"type": "delegation", "name": "stranger"}}).json()["finding"]
            assert real["source"] == "COLLECTED" and real["class_code"] == "DVG-DEL"
            assert [x["finding_key"] for x in api.get(f"/api/findings?agent={KEY}").json()][0] == real["finding_key"]       # newest first

            k = f["finding_key"]
            ack = api.post(f"/api/findings/{k}/acknowledge", json={"by": "Compliance lead"}).json()
            assert ack["status"] == "ACKNOWLEDGED" and ack["acknowledged_by"] == "Compliance lead"
            assert api.post(f"/api/findings/{k}/acknowledge", json={"by": "x", "acknowledged": False}).json()["status"] == "OPEN"
            t = api.post(f"/api/findings/{k}/test").json()
            assert "DVG-TOOL must not recur" in t["test_spec"] and "payments.transfer.create" in t["test_spec"]
            assert api.post(f"/api/findings/{k}/test").json()["test_spec"] == t["test_spec"]                                # idempotent
            h = api.post(f"/api/findings/{k}/halt", json={"by": "Compliance lead"}).json()
            assert h["halt_requested_by"] == "Compliance lead"
            assert api.post("/api/findings/F-9/halt", json={"by": "x"}).status_code == 404
            last = [a for a in api.get("/api/agents").json() if a["agent_key"] == KEY][0]["last_finding"]
            assert last and last.startswith(("High", "Medium"))

            api.post(f"/api/contracts/{c['contract_id']}/revoke", json={"reviewer": "x", "reason": "testing revoke"})
            r = api.post("/api/findings/simulate", json={"agent": KEY, "scenario": "tool_outside"})
            assert r.status_code == 409 and "no active contract" in r.json()["detail"]                                      # nothing to compare with
        finally:
            from db.models import Finding
            from db.session import SessionLocal
            with SessionLocal() as s:
                for x in s.query(Finding).filter(Finding.agent_key == KEY).all():
                    s.delete(x)
                s.commit()
            cleanup(KEY)


def clean_drift():
    from db.models import DriftItem
    from db.session import SessionLocal
    with SessionLocal() as s:
        for x in s.query(DriftItem).filter(DriftItem.agent_key == KEY).all():
            s.delete(x)
        s.commit()


def test_simulated_drift_approval_issues_a_new_contract_and_decline_does_not():
    with authed_client() as api:
        _, c = ratified(api)
        try:
            assert api.post("/api/drift/simulate", json={"agent": KEY, "scenario": "nope"}).status_code == 422
            assert api.post("/api/drift/simulate", json={"agent": KEY, "scenario": "remove_approval"}).status_code == 422   # no approval step in this design
            d1 = api.post("/api/drift/simulate", json={"agent": KEY, "scenario": "add_unsigned_mcp"}).json()
            assert d1["kind"] == "Widening" and d1["status"] == "OPEN" and d1["source"] == "SIMULATED" and d1["from_version"] == "1.0.0"
            assert any("mcp://web-search" in x["text"] and x["class"] == "Widening" for x in d1["changes"])
            assert any("Design-time risk score" in i for i in d1["impact"]) and d1["rcr_after"] is not None

            declined = api.post(f"/api/drift/{d1['id']}/decide", json={"decision": "decline", "reviewer": "Compliance lead", "note": "not needed"}).json()
            assert declined["status"] == "DECLINED" and declined["decision_note"] == "not needed"
            assert api.post(f"/api/drift/{d1['id']}/decide", json={"decision": "approve", "reviewer": "x"}).status_code == 409
            recs = api.get(f"/api/contract-records?object_type=AGENT&deployment={KEY}").json()
            assert [r["status"] for r in recs] == ["ACTIVE"]                                                                  # decline changed nothing

            d2 = api.post("/api/drift/simulate", json={"agent": KEY, "scenario": "add_untrusted_input"}).json()
            ok = api.post(f"/api/drift/{d2['id']}/decide", json={"decision": "approve", "reviewer": "Compliance lead"}).json()
            assert ok["status"] == "APPROVED" and ok["new_contract_id"]
            recs = {r["contract"]["contract_id"]: r for r in api.get(f"/api/contract-records?object_type=AGENT&deployment={KEY}").json()}
            assert recs[c["contract_id"]]["status"] == "SUPERSEDED" and recs[ok["new_contract_id"]]["status"] == "ACTIVE"
            assert recs[ok["new_contract_id"]]["contract"]["version"] == "2.0.0"
            assert any(i["name"] == "public-web-content" for i in recs[ok["new_contract_id"]]["contract"]["design_snapshot"]["nodes"])
            f = api.post("/api/findings/simulate", json={"agent": KEY, "scenario": "tool_outside"}).json()["finding"]
            assert f["contract_version"] == "2.0.0"                                                                           # findings follow the newest contract
        finally:
            from db.models import Finding
            from db.session import SessionLocal
            with SessionLocal() as s:
                for x in s.query(Finding).filter(Finding.agent_key == KEY).all():
                    s.delete(x)
                s.commit()
            clean_drift()
            cleanup(KEY)


def test_design_edit_becomes_drift_and_a_blocked_approval_stays_open():
    with authed_client() as api:
        key, c = ratified(api)
        try:
            assert api.post("/api/drift/propose", json={"design_key": key}).status_code == 409                                  # nothing differs yet
            wider = doc(req=REQ)
            wider["nodes"].append({"id": "t9", "type": "tool", "name": "ehr.records.write", "p": {"write": True}})
            wider["edges"].append({"from": "a1", "to": "t9", "label": "uses"})
            cur = api.get(f"/api/designs/{key}").json()
            api.put(f"/api/designs/{key}", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": wider, "version": cur["version"]})
            d = api.post("/api/drift/propose", json={"design_key": key}).json()
            assert d["source"] == "DESIGN" and d["kind"] == "Widening" and d["design_key"] == key
            again = api.post("/api/drift/propose", json={"design_key": key}).json()
            items = {x["id"]: x for x in api.get("/api/drift").json()}
            assert items[d["id"]]["status"] == "SUPERSEDED" and items[again["id"]]["status"] == "OPEN"                           # resubmitting replaces

            # A change that takes the declarations away would be Blocked: the approval is refused and the item stays open.
            blocked = doc(req={})
            blocked["nodes"].append({"id": "t9", "type": "tool", "name": "ehr.records.write", "p": {"write": True}})
            blocked["edges"].append({"from": "a1", "to": "t9", "label": "uses"})
            cur = api.get(f"/api/designs/{key}").json()
            api.put(f"/api/designs/{key}", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": blocked, "version": cur["version"]})
            b = api.post("/api/drift/propose", json={"design_key": key}).json()
            r = api.post(f"/api/drift/{b['id']}/decide", json={"decision": "approve", "reviewer": "Compliance lead"})
            assert r.status_code == 422 and "Blocked" in r.json()["detail"], r.text
            assert [x for x in api.get("/api/drift").json() if x["id"] == b["id"]][0]["status"] == "OPEN"
            assert [r["status"] for r in api.get(f"/api/contract-records?object_type=AGENT&deployment={KEY}").json()] == ["ACTIVE"]
        finally:
            clean_drift()
            cleanup(KEY)


def test_demo_data_loads_and_removes_with_the_demo_agents():
    with authed_client() as api:
        before = (len(api.get("/api/findings").json()), len(api.get("/api/drift").json()))
        try:
            api.post("/api/agents/demo")
            api.post("/api/agents/demo")
            f, d = api.get("/api/findings").json(), api.get("/api/drift").json()
            assert len([x for x in f if x["source"] == "DEMO"]) == 4 and len([x for x in d if x["source"] == "DEMO"]) == 3      # not doubled
            demo = [x for x in d if x["source"] == "DEMO"][0]
            assert api.post(f"/api/drift/{demo['id']}/decide", json={"decision": "approve", "reviewer": "x"}).json()["new_contract_id"] is None   # nothing real behind it
        finally:
            api.delete("/api/agents/demo")
        assert (len(api.get("/api/findings").json()), len(api.get("/api/drift").json())) == before


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
