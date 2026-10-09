"""
Tests for removal.py and the agents the organisation creates (Task 15): the organisation, Agent assurance and the Model studio are one platform,
so an agent or a model removed in one place is removed in all of them.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_removal     # a scratch database: see tests/_guard.py
"""
import json
import sys

from fastapi.testclient import TestClient

from main import app
from tests._auth import authed_client
from tests.test_agent_registry import NAME, cleanup, doc
from tests.test_company import body, wipe

REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}
ORG = {"departments": [{"id": "D-A", "name": "Alpha"}], "people": [{"id": "EMP-1", "name": "Pat Lee", "department": "D-A"}],
       "ai_systems": [{"id": "AG-1", "type": "agent", "name": NAME, "department": "D-A", "owner": "EMP-1", "hands_tasks_to": [{"agent": "AG-2", "task": "Pass it on"}]},
                      {"id": "AG-2", "type": "agent", "name": "zz-test-second-agent", "department": "D-A"},
                      {"id": "MD-1", "type": "model", "name": "zz-test-model", "department": "D-A", "owner": "EMP-1"}]}


def keyed(token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def inventory(api):
    return {a["agent_key"]: a for a in api.get("/api/agents").json()}


def wipe_all():
    from db.models import Agent, ApiKey, DriftItem, Finding, RemovedContract, RuntimeEvent
    from db.session import SessionLocal
    wipe()
    with SessionLocal() as s:
        for model in (RuntimeEvent, DriftItem, Finding, RemovedContract):
            for x in s.query(model).all():
                s.delete(x)
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.query(Agent).filter(Agent.agent_key.like("zz-test%")).delete(synchronize_session=False)
        s.commit()
    cleanup(NAME, "zz-test-second-agent")


def test_describing_the_company_creates_its_agents_in_agent_assurance():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe_all()
            r = api.post("/api/company/import", json=body(ORG)).json()
            assert r["agents_created"] == [NAME, "zz-test-second-agent"]                                    # agents first; the model is not an agent
            inv = inventory(api)
            a, b = inv[NAME], inv["zz-test-second-agent"]
            assert a["origin"] == "ORG" and a["owner"] == "Pat Lee" and a["status"] == "TO_RATIFY" and a["note"] == "From the organisation: Alpha" and a["framework"] == "Not built yet"
            assert b["origin"] == "ORG" and b["owner"] is None and b["status"] == "UNOWNED"
            assert "zz-test-model" not in inv
            assert api.post("/api/company/import", json=body(ORG)).json()["agents_created"] == []         # a second import creates nothing
            assert api.post("/api/company/sync-agents").json() == {"created": []}
            live = api.get("/api/company").json()["live"]["agents"]
            assert live["AG-1"]["registered"] and live["AG-2"]["registered"]
            assert not any(c["key"] == "not_registered" for c in api.get("/api/company").json()["checks"])

            api.post("/api/agents/register", json={"name": "zz-test-by-hand", "owner": "Someone"})            # an agent that already exists is never overwritten
            api.post("/api/company/import", json=body({"ai_systems": [{"id": "AG-3", "type": "agent", "name": "zz-test-by-hand", "owner": "EMP-1"}], "people": [{"id": "EMP-1", "name": "Pat Lee"}]}))
            assert inventory(api)["zz-test-by-hand"]["origin"] == "REGISTERED" and inventory(api)["zz-test-by-hand"]["owner"] == "Someone"

            n = api.post("/api/company/nodes", json={"type": "agent", "name": "zz-test-added", "props": {"owner": "EMP-1"}}).json()["id"]      # added by hand: also created
            assert inventory(api)["zz-test-added"]["owner"] == "Pat Lee"
            api.patch("/api/company/nodes/AG-2", json={"props": {"owner": "EMP-1"}})                         # a new owner reaches the entry while it is still the organisation's
            assert inventory(api)["zz-test-second-agent"]["owner"] == "Pat Lee" and inventory(api)["zz-test-second-agent"]["status"] == "TO_RATIFY"
            api.patch("/api/company/nodes/AG-2", json={"props": {"owner": ""}})
            assert inventory(api)["zz-test-second-agent"]["owner"] is None and inventory(api)["zz-test-second-agent"]["status"] == "UNOWNED"
        finally:
            wipe_all()


def test_removing_an_agent_removes_it_everywhere_and_packs_stay_verifiable():
    with authed_client("admin", "Alice Admin") as admin, authed_client("compliance", "Compliance lead") as comp, authed_client("engineer", "Eve Engineer") as eng:
        try:
            wipe_all()
            admin.post("/api/company/import", json=body(ORG))
            d = comp.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
            assert comp.post("/api/agents/ratify", json={"design_key": d["design_key"]}).status_code == 200
            k = admin.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()
            ev = keyed(k["key"]).post("/api/runtime/events", json={"agent": NAME, "events": [{"type": "tool_call", "name": "payments.transfer.create", "write": True}]})
            assert ev.status_code == 202 and ev.json()["divergent"] == 1
            pack = comp.post("/api/packs", json={"template": "ASSURANCE", "period": "30d", "generated_by": "Compliance lead"}).json()
            before = comp.get(f"/api/packs/{pack['pack_key']}/verify").json()
            assert before["ok"] and before["contracts_checked"] == 1 and before["contracts_ok"] == 1

            impact = admin.get(f"/api/agents/{NAME}/removal-impact").json()
            assert impact["in_inventory"] and impact["in_organisation"] and impact["designs"] == 1 and impact["contracts"] == 1 and impact["findings"] == 1 and impact["drift_items"] == 1
            assert impact["runtime_events"] == 1 and impact["organisation_connections"] == 1
            assert admin.get("/api/company/nodes/AG-1/removal-impact").json()["contracts"] == 1
            for c in (comp, eng):
                assert c.delete(f"/api/agents/{NAME}").status_code == 403                                 # not even compliance
                assert c.delete("/api/company/nodes/AG-1").status_code == 403
            assert NAME in inventory(admin)

            r = admin.delete(f"/api/agents/{NAME}")
            assert r.status_code == 200 and r.json() == {**impact}
            assert NAME not in inventory(admin) and "zz-test-second-agent" in inventory(admin)                # only that agent went
            assert not [x for x in admin.get("/api/findings").json() if x["agent_key"] == NAME] and not [x for x in admin.get("/api/drift").json() if x["agent_key"] == NAME]
            assert not [x for x in admin.get("/api/designs?subject=AGENT").json() if x["design_key"] == d["design_key"]]
            assert not [c for c in admin.get("/api/contract-records?object_type=AGENT").json() if c["contract"]["deployment_id"] == NAME]
            org = admin.get("/api/company").json()
            assert "AG-1" not in {n["id"] for n in org["nodes"]} and not [e for e in org["edges"] if "AG-1" in (e["from"], e["to"])] and "AG-2" in {n["id"] for n in org["nodes"]}
            assert admin.delete(f"/api/agents/{NAME}").status_code == 404

            after = comp.get(f"/api/packs/{pack['pack_key']}/verify").json()                                 # the pack is still intact, and says what happened
            assert after["ok"] is True and after["contracts_checked"] == 0 and any("was removed on" in n and "Alice Admin" in n for n in after["notes"]) and after["problems"] == []
            events = admin.get("/api/audit?limit=40").json()
            assert any(e["action"] == "agent.removed" and e["actor"] == "Alice Admin" for e in events)
        finally:
            wipe_all()
            from db.models import EvidencePack
            from db.session import SessionLocal
            with SessionLocal() as s:
                for p in s.query(EvidencePack).filter(EvidencePack.generated_by == "Compliance lead").all():
                    s.delete(p)
                s.commit()


def test_removing_an_agent_from_the_organisation_removes_it_from_the_platform_and_a_model_takes_its_designs():
    with authed_client("admin", "Alice Admin") as admin, authed_client("engineer", "Eve Engineer") as eng:
        try:
            wipe_all()
            admin.post("/api/company/import", json=body(ORG))
            assert eng.delete("/api/company/nodes/MD-1").status_code == 403                                   # a model is removed everywhere too: an administrator's decision
            assert eng.delete("/api/company/nodes/EMP-1").status_code == 200                                  # an ordinary item is the editor's
            d = admin.post("/api/designs", json={"name": "zz-test model design", "domain": admin.get("/api/domains").json()[0]["domain_id"], "subject": "MODEL",
                                                 "document": {"nodes": [], "edges": [], "n": 1, "org": {"id": "MD-1", "name": "zz-test-model"}}}).json()
            other = admin.post("/api/designs", json={"name": "zz-test unrelated design", "domain": admin.get("/api/domains").json()[0]["domain_id"], "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1}}).json()
            impact = admin.get("/api/company/nodes/MD-1/removal-impact").json()
            assert impact["type"] == "model" and impact["designs"] == 1 and impact["contracts"] == 0
            r = admin.delete("/api/company/nodes/MD-1")
            assert r.status_code == 200 and r.json()["removed"]["designs"] == 1
            keys = {x["design_key"] for x in admin.get("/api/designs?subject=MODEL").json()}
            assert d["design_key"] not in keys and other["design_key"] in keys                              # only the design started from the model
            assert "MD-1" not in {n["id"] for n in admin.get("/api/company").json()["nodes"]}

            r = admin.delete("/api/company/nodes/AG-2")                                                       # an agent: from the organisation to the whole platform
            assert r.status_code == 200 and r.json()["removed"]["in_inventory"] is True
            assert "zz-test-second-agent" not in inventory(admin) and NAME in inventory(admin)
            assert admin.get("/api/company/nodes/EMP-1/removal-impact").status_code == 404                    # that person was deleted above
            admin.delete(f"/api/designs/{other['design_key']}")
        finally:
            wipe_all()
            from db.models import Design
            from db.session import SessionLocal
            with SessionLocal() as s:
                s.query(Design).filter(Design.name.like("zz-test%")).delete(synchronize_session=False)
                s.commit()


def test_clearing_the_organisation_starts_the_whole_platform_from_scratch_unless_told_not_to():
    with authed_client("admin", "Alice Admin") as api, authed_client("compliance", "Compliance lead") as comp:
        original = api.get("/api/organisation").json()["name"]
        try:
            wipe_all()
            api.post("/api/company/import", json=body({**ORG, "company": {"name": "Zed Ltd"}}))
            name = api.get("/api/organisation").json()["name"]
            domain = api.get("/api/domains").json()[0]["domain_id"]
            api.post("/api/designs", json={"name": "zz-test model design", "domain": domain, "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1, "org": {"id": "MD-1", "name": "zz-test-model"}}})
            api.post("/api/designs", json={"name": "zz-test unrelated model", "domain": domain, "subject": "MODEL", "document": {"nodes": [], "edges": [], "n": 1}})        # not linked to the organisation
            api.post("/api/agents/register", json={"name": "zz-test-outside", "owner": "Someone"})                  # an agent that is not in the organisation
            d = comp.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
            assert comp.post("/api/agents/ratify", json={"design_key": d["design_key"]}).status_code == 200
            k = api.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()
            assert keyed(k["key"]).post("/api/runtime/events", json={"agent": NAME, "events": [{"type": "tool_call", "name": "payments.transfer.create", "write": True}]}).status_code == 202
            pack = comp.post("/api/packs", json={"template": "ASSURANCE", "period": "30d", "generated_by": "Compliance lead"})
            assert pack.status_code in (200, 201)

            impact = api.get("/api/company/clear-impact").json()
            assert impact["nodes"] == 5 and impact["agents_in_organisation"] == 2 and impact["models_in_organisation"] == 1
            assert impact["agents"] >= 3 and impact["agent_designs"] >= 1 and impact["model_designs"] >= 2 and impact["contracts"] >= 1 and impact["findings"] >= 1
            assert impact["drift_items"] >= 1 and impact["runtime_events"] >= 1 and impact["evidence_packs"] >= 1

            keep = api.request("DELETE", "/api/company", json={"confirm": name, "remove_everywhere": False})        # only the organisation model
            assert keep.status_code == 200 and keep.json()["platform_cleared"] is False and keep.json()["deleted_nodes"] == 5 and "agents" not in keep.json()
            assert api.get("/api/company").json()["nodes"] == [] and NAME in inventory(api) and "zz-test-outside" in inventory(api)
            assert [x for x in api.get("/api/designs?subject=MODEL").json() if x["name"] == "zz-test model design"]
            api.post("/api/company/import", json=body(ORG))

            gone = api.request("DELETE", "/api/company", json={"confirm": name})                                    # the default: from scratch
            assert gone.status_code == 200 and gone.json()["platform_cleared"] is True and gone.json()["deleted_nodes"] == 5
            assert gone.json()["agents"] >= 3 and gone.json()["model_designs"] >= 2 and gone.json()["contracts"] >= 1 and gone.json()["evidence_packs"] >= 1
            assert api.get("/api/company").json()["nodes"] == [] and inventory(api) == {}                           # no agent in Agent assurance, linked or not
            assert api.get("/api/designs?subject=MODEL").json() == [] and api.get("/api/designs?subject=AGENT").json() == []     # none in the Model studio or the agent studio
            assert api.get("/api/contract-records?object_type=AGENT").json() == [] and api.get("/api/contract-records?object_type=MODEL").json() == []
            assert api.get("/api/findings").json() == [] and api.get("/api/drift").json() == [] and api.get("/api/packs").json() == []
            assert api.get("/api/runtime/overview").json()["events"] == [] and api.get("/api/runtime/overview").json()["agents"] == []
            assert [x for x in api.get("/api/keys").json() if x["name"] == "zz-test-collector"]                      # people and credentials are kept
            assert api.get("/api/policies").status_code == 200 and api.get("/api/regulations").status_code == 200
            ev = [e for e in api.get("/api/audit?limit=40").json() if e["action"] == "platform.cleared"]
            assert ev and ev[0]["actor"] == "Alice Admin"
        finally:
            api.patch("/api/organisation", json={"name": original})
            wipe_all()
            from db.models import Design, EvidencePack
            from db.session import SessionLocal
            with SessionLocal() as s:
                s.query(Design).filter(Design.name.like("zz-test%")).delete(synchronize_session=False)
                s.query(EvidencePack).filter(EvidencePack.generated_by == "Compliance lead").delete(synchronize_session=False)
                s.commit()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
            print("PASS ", n)
        except Exception as exc:
            failed += 1
            import traceback
            print("FAIL ", n, repr(exc))
            traceback.print_exc(limit=-2)
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
