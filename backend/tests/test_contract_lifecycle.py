"""
Tests for contract status (supersede, revoke) and the version-to-version change record (Task 7b).

    docker compose exec backend python -m tests.test_contract_lifecycle
"""
import sys

from fastapi.testclient import TestClient

import agent_contract
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc

KEY = "zz-test-patient-agent"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}


def snap(*extra, autonomy="approval"):
    nodes = [{"id": "a1", "type": "agent", "name": "x", "p": {"owner": "o", "auto": autonomy}, "primary": True},
             {"id": "t1", "type": "tool", "name": "crm.read", "p": {"write": False}}] + list(extra)
    return {"nodes": nodes, "edges": []}


def test_change_between_widens_and_narrows():
    base = snap()
    same = agent_contract.change_between(base, snap(), "1.0.0")
    assert not same["widens"] and not same["widened"] and not same["narrowed"]

    wider = agent_contract.change_between(base, snap({"id": "t2", "type": "tool", "name": "stripe.refund", "p": {"write": True}}), "1.0.0")
    assert wider["widens"] and wider["widened"] == ["added tool stripe.refund (write)"]

    narrower = agent_contract.change_between(snap({"id": "t2", "type": "tool", "name": "stripe.refund", "p": {"write": True}}), base, "1.0.0")
    assert not narrower["widens"] and narrower["narrowed"] == ["removed tool stripe.refund (write)"]

    assert agent_contract.change_between(base, snap(autonomy="autonomous"), "1.0.0")["widens"]                    # autonomy raised
    assert not agent_contract.change_between(snap(autonomy="autonomous"), base, "1.0.0")["widens"]                # autonomy lowered
    guard = {"id": "g1", "type": "guardrail", "name": "pii-filter", "p": {}}
    assert not agent_contract.change_between(base, snap(guard), "1.0.0")["widens"]                               # a safeguard added narrows
    removed = agent_contract.change_between(snap(guard), base, "1.0.0")
    assert removed["widens"] and removed["widened"] == ["removed safeguard guardrail pii-filter"]                 # a safeguard removed widens


def test_view_lists_what_the_contract_allows():
    v = agent_contract.view({"name": "x", "nodes": snap({"id": "t2", "type": "tool", "name": "mail.send", "p": {"write": True}},
                                                         {"id": "ap", "type": "approval", "name": "review", "p": {}})["nodes"], "edges": []})
    assert [t["name"] for t in v["tools"]] == ["crm.read", "mail.send"] and v["approvals"] == ["review"]
    assert "agent: x" in v["yaml"] and "mail.send  # write, approval required" in v["yaml"] and "autonomy: acts_with_approval" in v["yaml"]


def test_ratify_supersedes_records_change_and_revoke_keeps_the_hash_valid():
    with authed_client() as api:
        d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
        try:
            v1 = api.post("/api/agents/ratify", json={"design_key": d["design_key"], "reviewer": "Compliance lead"}).json()["contract"]
            assert v1["design_snapshot"]["change"] == {"previous_version": None, "widens": False, "widened": [], "narrowed": []}

            wider = doc(req=REQ)
            wider["nodes"].append({"id": "t3", "type": "tool", "name": "ehr.records.write", "p": {"write": True}})
            wider["edges"].append({"from": "a1", "to": "t3", "label": "uses"})
            cur = api.get(f"/api/designs/{d['design_key']}").json()
            assert api.put(f"/api/designs/{d['design_key']}", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT",
                                                                    "document": wider, "version": cur["version"]}).status_code == 200
            v2 = api.post("/api/agents/ratify", json={"design_key": d["design_key"], "reviewer": "Compliance lead"}).json()["contract"]
            ch = v2["design_snapshot"]["change"]
            assert v2["version"] == "2.0.0" and ch["previous_version"] == "1.0.0" and ch["widens"] and ch["widened"] == ["added tool ehr.records.write (write)"]

            recs = {r["contract"]["contract_id"]: r for r in api.get(f"/api/contract-records?object_type=AGENT&deployment={KEY}").json()}
            r1, r2 = recs[v1["contract_id"]], recs[v2["contract_id"]]
            assert (r1["status"], r2["status"]) == ("SUPERSEDED", "ACTIVE") and r1["superseded_by"] == v2["contract_id"]
            assert any(t["name"] == "ehr.records.write" and t["write"] for t in r2["view"]["tools"])

            assert api.post(f"/api/contracts/{v1['contract_id']}/revoke", json={"reviewer": "x", "reason": "no longer needed"}).status_code == 409
            assert api.post(f"/api/contracts/{v2['contract_id']}/revoke", json={"reviewer": "Compliance lead", "reason": "x"}).status_code == 422   # a reason is needed
            rv = api.post(f"/api/contracts/{v2['contract_id']}/revoke", json={"reviewer": "Compliance lead", "reason": "Write tool not approved"})
            assert rv.status_code == 200 and rv.json()["status"] == "REVOKED" and rv.json()["status_reason"] == "Write tool not approved"
            assert api.get(f"/api/contracts/{v2['contract_id']}/verify").json()["ok"]                                        # status changed, hash did not
            agent = [a for a in api.get("/api/agents").json() if a["agent_key"] == KEY][0]
            assert agent["status"] == "TO_RATIFY"                                                                            # nothing in force any more
            assert api.post(f"/api/contracts/{v2['contract_id']}/revoke", json={"reviewer": "x", "reason": "again"}).status_code == 409
            assert api.post("/api/contracts/nope/revoke", json={"reviewer": "x", "reason": "abc"}).status_code == 404
        finally:
            cleanup(KEY)


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
