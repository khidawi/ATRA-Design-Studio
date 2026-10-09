"""
Tests for company.py (Task 13): the organisation model, its import, its checks, and its read-only link to agents, contracts and the runtime.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_company     # a scratch database: see tests/_guard.py
"""
import json
import sys

import company
from tests._auth import authed_client
from tests.test_agent_registry import NAME, cleanup, doc

SENDER, RECEIVER = NAME, "zz-test-receiver"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}


def wipe():
    from db.models import Agent, CompanyDraftCache, CompanyEdge, CompanyNode, RemovedContract, RuntimeEvent
    from db.session import SessionLocal
    with SessionLocal() as s:
        s.query(Agent).filter(Agent.origin == "ORG").delete(synchronize_session=False)
        s.query(RemovedContract).delete()
        s.query(CompanyDraftCache).delete()
        s.query(CompanyEdge).delete()
        s.query(CompanyNode).delete()
        s.query(RuntimeEvent).filter(RuntimeEvent.agent_key.like("zz-test%")).delete(synchronize_session=False)
        s.commit()
    cleanup(SENDER, RECEIVER)


def body(d, **extra):
    return {"content": json.dumps(d), "filename": "company.json", **extra}


def load_sample(api):
    r = api.post("/api/company/import", json=body(api.get("/api/company/sample").json()))
    assert r.status_code == 200, r.text
    return r.json()


def checks(api):
    return api.get("/api/company").json()["checks"]


def keys(api, key):
    return [c for c in checks(api) if c["key"] == key]


def test_the_sample_company_imports_once_and_a_second_import_changes_nothing():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            assert api.get("/api/company").json()["nodes"] == []
            first = load_sample(api)
            assert first["created"] == 64 and first["connections"] == 63 and first["plan"]["ok"]
            assert first["company"]["counts"]["agent"] == 4 and first["company"]["counts"]["model"] == 1 and first["company"]["counts"]["department"] == 7
            again = api.post("/api/company/import", json=body(api.get("/api/company/sample").json())).json()
            assert again["created"] == 0 and again["updated"] == 0 and again["connections"] == 0
            n = api.get("/api/company").json()
            exported = api.get("/api/company/export").json()
            assert len(exported["departments"]) == 7 and any(s["id"] == "MD-TRIAGE" for s in exported["ai_systems"])
            wipe()
            assert api.post("/api/company/import", json=body(exported)).status_code == 200      # an export can be imported again
            assert len(api.get("/api/company").json()["nodes"]) == len(n["nodes"]) and len(api.get("/api/company").json()["edges"]) == len(n["edges"])
        finally:
            wipe()


def test_the_checks_find_what_the_mockup_showed():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            load_sample(api)
            s = api.get("/api/company").json()
            rc = keys(api, "role_concentration")
            assert len(rc) == 1 and "Omar Haddad is both validator and deployer" in rc[0]["detail"] and "SC-RCF-1" in rc[0]["detail"]
            assert s["violations"] == {"separate_validator_deployer": "Omar Haddad is both validator and deployer."}
            assert [c["refs"][0] for c in keys(api, "no_owner")] == ["AG-PAYOUT"]
            assert [c["refs"][0] for c in keys(api, "no_head")] == ["D-FIN"]
            assert [c["refs"][0] for c in keys(api, "threat_unprotected")] == ["TH-LEAK"]
            cross = {tuple(c["refs"]) for c in keys(api, "cross_department")}
            assert ("AG-REFUND", "AG-NOTIFY") in cross and ("AG-REFUND", "AG-PAYOUT") in cross and ("AG-REFUND", "AG-KYC") not in cross      # the KYC handoff names a policy
            gaps = keys(api, "breach_no_deputy")
            assert [c["refs"][0] for c in gaps] == ["ST-3"] and "Priya Nair alone" in gaps[0]["detail"]          # ST-4 has a deputy
            assert keys(api, "no_breach_plan") == [] and all(c["level"] in ("bad", "warn", "info") for c in checks(api))
            assert [c["level"] for c in checks(api)] == sorted([c["level"] for c in checks(api)], key={"bad": 0, "warn": 1, "info": 2}.get)
            api.delete("/api/company/edges/" + [e["id"] for e in s["edges"] if e["from"] == "PR-MON"][0])       # remove the only protection of one threat
            assert sorted(c["refs"][0] for c in keys(api, "threat_unprotected")) == ["TH-LEAK", "TH-PAYOUT"]
        finally:
            wipe()


def test_a_bad_file_is_refused_with_reasons_and_writes_nothing():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            base = {"departments": [{"id": "D-A", "name": "A"}], "people": [{"id": "EMP-1", "name": "One", "department": "D-A"}]}
            for bad, needle in (
                ({"departments": [{"id": "D-A", "name": "A"}, {"id": "D-A", "name": "B"}]}, "appears twice"),
                ({"departments": [{"id": "D-A", "name": "A", "head": "EMP-404"}]}, "EMP-404"),
                ({"departments": [{"id": "D-A", "name": "A", "head": "D-A"}]}, "must be a person or role"),
                ({"departments": [{"id": "D bad!", "name": "A"}]}, "may only use letters"),
                ({"departments": [{"name": ""}]}, "needs a name"),
                ({"ai_systems": [{"type": "robot", "name": "x"}]}, "'agent' or 'model'"),
                ({**base, "ai_systems": [{"id": "AG-1", "type": "agent", "name": "a", "hands_tasks_to": [{"agent": "EMP-1"}]}]}, "'task' cannot end at a person"),
                ({**base, "elements": [{"id": "X", "type": "planet", "name": "x"}]}, "type must be one of"),
                ({}, "nothing to import"),
            ):
                r = api.post("/api/company/import/preview", json=body(bad))
                assert r.status_code == 200 and r.json()["ok"] is False and any(needle in e for e in r.json()["errors"]), (bad, r.json()["errors"])
                assert api.post("/api/company/import", json=body(bad)).status_code == 422
            assert api.post("/api/company/import/preview", json={"content": "key: [unclosed"}).status_code == 422
            assert api.post("/api/company/import/preview", json={"content": "   "}).status_code == 422
            assert api.post("/api/company/import/preview", json={"content": "- a list"}).status_code == 422
            assert api.get("/api/company").json()["nodes"] == []
            ok = api.post("/api/company/import", json={"content": "departments:\n  - {id: D-A, name: A}\npeople:\n  - {name: Zed Zero, department: D-A}\n"})        # YAML, and a person without an id
            assert ok.status_code == 200 and any(w for w in ok.json()["plan"]["warnings"] if "no id" in w)
            assert api.get("/api/company").json()["nodes"][1]["id"] == "EMP-ZED-ZERO"
            clash = api.post("/api/company/import", json=body({"departments": [{"id": "EMP-ZED-ZERO", "name": "Clash"}]}))
            assert clash.status_code == 422 and "already a person" in clash.json()["detail"]
        finally:
            wipe()


def test_an_import_adds_and_updates_but_never_deletes_and_items_can_be_skipped():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            d = {"departments": [{"id": "D-A", "name": "A"}, {"id": "D-B", "name": "B"}], "people": [{"id": "EMP-1", "name": "One", "department": "D-A", "title": "Lead"}]}
            assert api.post("/api/company/import", json=body(d)).json()["created"] == 3
            d["people"][0]["title"] = "Head"
            d["departments"] = [{"id": "D-A", "name": "A renamed"}]
            r = api.post("/api/company/import", json=body(d)).json()
            assert r["created"] == 0 and r["updated"] == 2
            nodes = {n["id"]: n for n in api.get("/api/company").json()["nodes"]}
            assert nodes["D-A"]["name"] == "A renamed" and nodes["EMP-1"]["props"]["title"] == "Head" and "D-B" in nodes         # D-B is not in the second file, and stays
            more = {"departments": [{"id": "D-C", "name": "C"}], "people": [{"id": "EMP-2", "name": "Two", "department": "D-C"}]}
            pv = api.post("/api/company/import/preview", json=body(more, skip=["node:EMP-2"])).json()
            assert pv["ok"] and [i["id"] for i in pv["items"]] == ["D-C"]
            assert api.post("/api/company/import", json=body(more, skip=["node:EMP-2"])).json()["created"] == 1
            lone = {"departments": [{"id": "D-E", "name": "E"}], "people": [{"id": "EMP-9", "name": "Nine", "department": "D-E"}]}
            wrong = api.post("/api/company/import/preview", json=body(lone, skip=["node:D-E"])).json()
            assert wrong["ok"] is False and any("D-E" in e for e in wrong["errors"])                                  # skipping the department leaves the person with nowhere to be
        finally:
            wipe()


def test_editing_by_hand_keeps_the_model_consistent():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            d = api.post("/api/company/nodes", json={"type": "department", "name": "Support"})
            assert d.status_code == 201 and d.json()["id"] == "D-SUPPORT"
            assert api.post("/api/company/nodes", json={"type": "department", "name": "Support"}).json()["id"] == "D-SUPPORT-2"
            assert api.post("/api/company/nodes", json={"type": "department", "name": "x", "id": "D-SUPPORT"}).status_code == 409
            assert api.post("/api/company/nodes", json={"type": "department", "name": "x", "id": "bad id"}).status_code == 422
            p = api.post("/api/company/nodes", json={"type": "person", "name": "Pat", "props": {"department": "D-SUPPORT", "title": "Lead"}}).json()["id"]
            assert api.post("/api/company/nodes", json={"type": "person", "name": "Q", "props": {"department": "D-NOPE"}}).status_code == 422
            assert api.post("/api/company/nodes", json={"type": "person", "name": "Q", "props": {"nickname": "q"}}).status_code == 422
            assert api.post("/api/company/nodes", json={"type": "role", "name": "R", "props": {"headcount": "many"}}).status_code == 422
            a = api.post("/api/company/nodes", json={"type": "agent", "name": "helper", "props": {"department": "D-SUPPORT", "owner": p}}).json()["id"]
            b = api.post("/api/company/nodes", json={"type": "agent", "name": "other"}).json()["id"]
            assert api.patch("/api/company/nodes/D-SUPPORT", json={"props": {"head": p}}).status_code == 200
            assert api.patch("/api/company/nodes/D-SUPPORT", json={"props": {"parent": "D-SUPPORT"}}).status_code == 422
            assert api.patch("/api/company/nodes/NOPE", json={"name": "x"}).status_code == 404
            assert api.patch(f"/api/company/nodes/{a}", json={"name": "   "}).status_code == 422

            e = api.post("/api/company/edges", json={"from": a, "to": b, "kind": "task", "label": "Hand over", "props": {"data": ["order id"]}})
            assert e.status_code == 201, e.text
            assert api.post("/api/company/edges", json={"from": a, "to": b, "kind": "task", "label": "Hand over"}).status_code == 409
            assert api.post("/api/company/edges", json={"from": a, "to": a, "kind": "task"}).status_code == 422
            assert api.post("/api/company/edges", json={"from": a, "to": p, "kind": "task"}).status_code == 422          # a task goes between agents
            assert api.post("/api/company/edges", json={"from": a, "to": "NOPE", "kind": "works_with"}).status_code == 422
            assert api.post("/api/company/edges", json={"from": a, "to": b, "kind": "nonsense"}).status_code == 422
            assert api.patch(f"/api/company/edges/{e.json()['id']}", json={"props": {"data": ["order id", "amount"]}}).status_code == 200
            task = [x for x in api.get("/api/company").json()["edges"] if x["kind"] == "task"][0]
            assert task["props"]["data"] == ["order id", "amount"]

            assert api.delete("/api/company/nodes/D-SUPPORT").status_code == 409                                         # still has people in it
            assert api.delete(f"/api/company/nodes/{p}").status_code == 200
            after = {n["id"]: n for n in api.get("/api/company").json()["nodes"]}
            assert "owner" not in after[a]["props"] and "head" not in after["D-SUPPORT"]["props"]                         # a deleted person is nobody's owner or head
            assert api.delete(f"/api/company/nodes/{b}").status_code == 200 and api.get("/api/company").json()["edges"] == []
            assert api.delete("/api/company/edges/00000000-0000-0000-0000-000000000000").status_code == 404
            assert api.delete(f"/api/company/nodes/{b}").status_code == 404
        finally:
            wipe()


def test_roles_may_read_and_only_some_may_edit():
    with authed_client("admin", "Alice Admin") as admin, authed_client("auditor", "Ada Auditor") as aud, authed_client("engineer", "Eve Engineer") as eng:
        try:
            wipe()
            assert aud.get("/api/company").status_code == 200 and aud.get("/api/company/export").status_code == 200
            for method, path, kw in (("post", "/api/company/nodes", {"json": {"type": "department", "name": "x"}}), ("post", "/api/company/import", {"json": body({"departments": [{"name": "x"}]})}),
                                     ("post", "/api/company/import/preview", {"json": body({"departments": [{"name": "x"}]})})):
                assert getattr(aud, method)(path, **kw).status_code == 403, path
            assert eng.post("/api/company/nodes", json={"type": "department", "name": "Eng made"}).status_code == 201
            events = admin.get("/api/audit?limit=20").json()
            assert any(e["actor"] == "Eve Engineer" and e["action"] == "POST /api/company/nodes" and e["outcome"] == "ok" for e in events)
            assert any(e["actor"] == "Ada Auditor" and e["outcome"] == "denied" for e in events)
        finally:
            wipe()


def test_the_link_to_agents_contracts_and_the_runtime_is_read_only():
    with authed_client("admin", "Alice Admin") as admin, authed_client("compliance", "Compliance lead") as comp:
        try:
            wipe()
            d = doc(SENDER, req=REQ)
            d["nodes"].append({"id": "a2", "type": "agent", "name": RECEIVER, "p": {"owner": "Compliance lead", "auto": "approval"}})
            d["edges"].append({"from": "a1", "to": "a2", "label": "delegates"})
            design = comp.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": d}).json()
            assert comp.post("/api/agents/ratify", json={"design_key": design["design_key"]}).status_code == 200
            admin.post("/api/agents/register", json={"name": RECEIVER})
            before = admin.get("/api/agents").json()

            org = {"departments": [{"id": "D-X", "name": "X"}, {"id": "D-Y", "name": "Y"}],
                   "ai_systems": [{"id": "AG-S", "type": "agent", "name": SENDER, "department": "D-X", "hands_tasks_to": [{"agent": "AG-R", "task": "Hand over", "data": ["order id"]}, {"agent": "AG-U", "task": "Escalate"}]},
                                  {"id": "AG-R", "type": "agent", "name": RECEIVER, "department": "D-Y"},
                                  {"id": "AG-U", "type": "agent", "name": "zz-test-never-registered", "department": "D-Y"}]}
            assert admin.post("/api/company/import", json=body(org)).status_code == 200
            s = admin.get("/api/company").json()
            live = s["live"]
            assert live["agents"]["AG-S"]["registered"] and live["agents"]["AG-S"]["contract_version"] == "1.0.0" and live["agents"]["AG-R"]["registered"] and live["agents"]["AG-R"]["contract_version"] is None
            assert live["agents"]["AG-U"]["registered"] is True and live["agents"]["AG-U"]["contract_version"] is None      # the import created its entry in Agent assurance
            t = {e["label"]: live["tasks"][e["id"]] for e in s["edges"] if e["kind"] == "task"}
            assert t["Hand over"]["declared"] is True and t["Hand over"]["contract_version"] == "1.0.0" and t["Escalate"]["declared"] is False      # the contract declares the receiver, not the other agent
            assert any(c["key"] == "not_in_contract" and c["refs"] == ["AG-S", "AG-U"] and c["level"] == "bad" for c in s["checks"])
            assert not any(c["key"] == "not_registered" for c in s["checks"])

            ev = admin.post("/api/runtime/events", json={"agent": SENDER, "events": [{"type": "delegation", "name": RECEIVER}, {"type": "delegation", "name": RECEIVER}, {"type": "delegation", "name": "zz-test-surprise"}]})
            assert ev.status_code == 202, ev.text
            live = admin.get("/api/company").json()["live"]
            hand = [v for e, v in ((e, live["tasks"][e["id"]]) for e in s["edges"] if e["kind"] == "task") if e["label"] == "Hand over"][0]
            assert hand["observed"] == 2 and hand["last_seen"]
            assert [(u["from"], u["to_name"], u["count"], u["declared"]) for u in live["unmodelled"]] == [("AG-S", "zz-test-surprise", 1, False)]          # seen, not drawn, not declared
            assert any(c["key"] == "seen_not_modelled" and c["level"] == "bad" for c in admin.get("/api/company").json()["checks"])
            assert not any(a["agent_key"] == "zz-test-surprise" for a in live["unmapped_agents"])             # a handoff target is not a registered agent, so it is not offered as one
            assert admin.get("/api/agents").json() is not None and len([a for a in admin.get("/api/agents").json() if a["agent_key"] in (SENDER, RECEIVER)]) == len([a for a in before if a["agent_key"] in (SENDER, RECEIVER)])
        finally:
            from db.models import Agent
            from db.session import SessionLocal
            with SessionLocal() as sess:
                for a in sess.query(Agent).filter(Agent.agent_key.like("zz-test%")).all():
                    sess.delete(a)
                sess.commit()
            wipe()


def test_the_assistant_turns_a_proposal_into_a_draft_without_inventing_anything():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            api.post("/api/company/import", json=body({"departments": [{"id": "D-CX", "name": "Customer Experience"}]}))
            from db.models import CompanyNode
            from db.session import SessionLocal
            schema = company.DraftProposal.model_json_schema()
            assert set(schema["required"]) == {"company_name", "departments", "people", "outside_parties", "ai_systems", "roles", "task_links", "data_stores", "data_use"}     # a model may not answer {}
            for sub in ("DraftDept", "DraftPerson", "DraftSystem", "DraftRole", "DraftTask", "DraftStore", "DraftUse", "DraftOutside"):
                assert schema["$defs"][sub]["required"], sub

            P = company
            prop = P.DraftProposal(
                company_name="Acme Payments",
                departments=[P.DraftDept(name="Platform", reports_to="Customer Experience", head="Lena Fischer")],
                people=[P.DraftPerson(name="Lena Fischer", title="Ops lead", department="Platform", is_group=False), P.DraftPerson(name="Support agents", title="", department="Customer Experience", is_group=True)],
                outside_parties=[P.DraftOutside(name="Customers", kind="customer")],
                ai_systems=[P.DraftSystem(name="refund-agent", type="agent", department="Customer Experience", owner="Sam", purpose="Decides refunds")],
                roles=[P.DraftRole(system="refund-agent", person="Customers", role="requests refunds"), P.DraftRole(system="refund-agent", person="Support agents", role="escalate to")],
                task_links=[P.DraftTask(from_agent="refund-agent", to_agent="notify-agent", task="Send confirmation", data=["customer email"])],
                data_stores=[P.DraftStore(name="Order database", department="Customer Experience", sensitivity="personal data")],
                data_use=[P.DraftUse(system="refund-agent", store="Order database", access="read")])
            with SessionLocal() as s:
                d = company.proposal_to_doc(prop, {n.ext_id: n for n in s.query(CompanyNode).all()})
            assert d["company"] == {"name": "Acme Payments"}
            deps = {x["name"]: x for x in d["departments"]}
            assert list(deps) == ["Platform"] and deps["Platform"]["reports_to"] == "D-CX" and deps["Platform"]["head"] == "EMP-LENA-FISCHER"          # an existing department is reused by name
            ppl = {x["name"]: x for x in d["people"]}
            assert ppl["Lena Fischer"]["title"] == "Ops lead" and ppl["Lena Fischer"]["department"] == "D-PLATFORM" and ppl["Support agents"]["kind"] == "role" and ppl["Support agents"]["department"] == "D-CX"
            assert "EMP-SAM" in {x["id"] for x in d["people"]}                                  # a person named only as an owner is added, so nothing dangles
            assert d["external"] == [{"id": "EXT-CUSTOMERS", "name": "Customers", "kind": "customer"}]
            sysd = {x["name"]: x for x in d["ai_systems"]}
            assert set(sysd) == {"refund-agent", "notify-agent"} and "owner" not in sysd["notify-agent"] and "department" not in sysd["notify-agent"]      # an agent only mentioned in a handoff has no owner and no department
            r = sysd["refund-agent"]
            assert r["owner"] == "EMP-SAM" and r["details"] == {"purpose": "Decides refunds"} and r["hands_tasks_to"] == [{"agent": "AG-NOTIFY-AGENT", "task": "Send confirmation", "data": ["customer email"]}]
            assert r["people"] == [{"id": "EXT-CUSTOMERS", "role": "requests refunds"}, {"id": "ROLE-SUPPORT-AGENTS", "role": "escalate to"}] and r["uses_data"] == [{"store": "DS-ORDER-DATABASE", "access": "read"}]
            assert d["data_stores"] == [{"id": "DS-ORDER-DATABASE", "name": "Order database", "department": "D-CX", "sensitivity": "personal data"}]
            pv = api.post("/api/company/import/preview", json=body(d)).json()
            assert pv["ok"] is True, pv["errors"]                                                # the draft is a valid file as it stands
            applied = api.post("/api/company/import", json=body(d))
            assert applied.status_code == 200 and applied.json()["company"]["counts"]["agent"] == 2
            wipe()
            # what a small model really does wrong: a person in a department's "reports to", and a role with nothing in it
            slip = P.DraftProposal(
                company_name="", departments=[P.DraftDept(name="Claims", reports_to="Maria Costa", head="Maria Costa"), P.DraftDept(name="Fraud", reports_to="Claims", head="Ahmed Khan")],
                people=[P.DraftPerson(name="Maria Costa", title="", department="Claims", is_group=False), P.DraftPerson(name="Ahmed Khan", title="", department="Fraud", is_group=False)],
                outside_parties=[P.DraftOutside(name="Customers", kind="customer")], ai_systems=[P.DraftSystem(name="fraud-agent", type="agent", department="Maria Costa", owner="Claims", purpose="")],
                roles=[P.DraftRole(system="fraud-agent", person="Customers", role="")], task_links=[], data_stores=[], data_use=[])
            d2 = company.proposal_to_doc(slip, {})
            assert [x["name"] for x in d2["departments"]] == ["Claims", "Fraud"]                      # no department called after a person
            claims, fraud = d2["departments"]
            assert "reports_to" not in claims and claims["head"] == "EMP-MARIA-COSTA" and fraud["reports_to"] == "D-CLAIMS" and fraud["head"] == "EMP-AHMED-KHAN"
            assert {x["name"] for x in d2["people"]} == {"Maria Costa", "Ahmed Khan"} and {x["id"] for x in d2["people"]} == {"EMP-MARIA-COSTA", "EMP-AHMED-KHAN"}
            fa = d2["ai_systems"][0]
            assert "department" not in fa and "owner" not in fa and "people" not in fa                  # a wrong-type reference and an empty role are dropped
            assert api.post("/api/company/import/preview", json=body(d2)).json()["ok"] is True
            assert api.post("/api/company/draft", json={"description": "short"}).status_code == 422
        finally:
            wipe()


def test_drafting_runs_as_a_background_job_and_returns_a_proposal():
    import time

    import ollama_client
    canned = {"company": "Zed Ltd", "departments": ["Ops | | Pat Lee"], "people": ["Pat Lee | Head of ops | Ops |"], "outside": [],
              "systems": ["ops-agent | agent | Ops | Pat Lee | "], "roles": [], "handoffs": [], "data": [], "uses": []}
    seen = {}

    def fake(messages, schema, **kw):
        seen["user"], seen["kw"] = messages[-1]["content"], kw
        return seen.get("answer", canned)

    def finish(api, job):
        for _ in range(200):
            s = api.get(f"/api/company/draft/{job}").json()
            if s["status"] != "running":
                return s
            time.sleep(0.05)
        raise AssertionError("the draft did not finish")

    real = ollama_client.chat_json
    with authed_client("admin", "Alice Admin") as api, authed_client("engineer", "Eve Engineer") as other:
        try:
            wipe()
            ollama_client.chat_json = fake
            api.post("/api/company/import", json=body({"departments": [{"id": "D-OLD", "name": "Old department"}]}))
            r = api.post("/api/company/draft", json={"description": "Zed Ltd has an Ops department led by Pat Lee.", "history": ["We are a small company."]})
            assert r.status_code == 202, r.text
            job = r.json()["job"]
            s = finish(api, job)
            assert s["status"] == "done" and s["error"] is None and "pieces" in s
            res = s["result"]
            assert res["doc"]["company"] == {"name": "Zed Ltd"} and [d["id"] for d in res["doc"]["departments"]] == ["D-OPS"] and res["plan"]["ok"] and res["plan"]["summary"]["nodes"] == 3
            assert "Earlier in this conversation" in seen["user"] and "We are a small company." in seen["user"] and "Old department" not in seen["user"]       # it sees what was said, not what is stored
            assert seen["kw"]["timeout"] == company.DRAFT_TIMEOUT and seen["kw"]["temperature"] == 0 and seen["kw"]["options"] == company.DRAFT_OPTIONS and company.DRAFT_OPTIONS["seed"] == 42 and api.get("/api/company").json()["nodes"][0]["id"] == "D-OLD" and len(api.get("/api/company").json()["nodes"]) == 1    # nothing is saved
            assert other.get(f"/api/company/draft/{job}").status_code == 404 and api.get("/api/company/draft/nope").status_code == 404                               # a job is its owner's

            seen["answer"] = {"departments": 3}                                                                  # a model that ignores the schema
            bad = finish(api, api.post("/api/company/draft", json={"description": "Something long enough to send."}).json()["job"])
            assert bad["status"] == "error" and bad["error"]["status"] == 502 and "malformed" in bad["error"]["detail"]
            seen["answer"] = {**canned, "departments": [], "people": [], "systems": [], "company": ""}      # nothing in the description
            empty = finish(api, api.post("/api/company/draft", json={"description": "Nothing about a company here."}).json()["job"])
            assert empty["status"] == "done" and empty["result"]["plan"] is None and empty["result"]["doc"] == {}
            assert api.post("/api/company/draft", json={"description": "short"}).status_code == 422
        finally:
            ollama_client.chat_json = real
            wipe()


def test_the_compact_answer_is_parsed_in_code_and_survives_sloppy_lines():
    schema = company.DraftCompact.model_json_schema()
    assert set(schema["required"]) == {"company", "departments", "people", "outside", "systems", "roles", "handoffs", "data", "uses"}              # a model may not answer {}
    c = company.DraftCompact(
        company=" Acme ", departments=["Support | | Dana Cole", "Finance", " | x | y", "Legal|Support|"],
        people=["Dana Cole | leader of Support | Support |", "Support agents | | Support | group", "Omar Ali"], outside=["Customers | customer", "Regulator"],
        systems=["refund-agent | agent | Support | Dana Cole | decides refunds", "triage-llm | LLM model | Clinical | | suggests", "ledger-agent"],
        roles=["refund-agent | Customers | requests refunds", "refund-agent | Customers", "| x | y"], handoffs=["refund-agent | ledger-agent | pay | order id, amount ,", "a"],
        data=["order database | Support | personal data"], uses=["refund-agent | order database | write", "refund-agent | order database", "x"])
    p = company.parse_compact(c)
    assert p.company_name == "Acme" and [(d.name, d.reports_to, d.head) for d in p.departments] == [("Support", "", "Dana Cole"), ("Finance", "", ""), ("Legal", "Support", "")]
    assert [(x.name, x.is_group) for x in p.people] == [("Dana Cole", False), ("Support agents", True), ("Omar Ali", False)] and [(o.name, o.kind) for o in p.outside_parties] == [("Customers", "customer"), ("Regulator", "")]
    assert [(s.name, s.type, s.owner) for s in p.ai_systems] == [("refund-agent", "agent", "Dana Cole"), ("triage-llm", "model", ""), ("ledger-agent", "agent", "")]
    assert [(r.system, r.person, r.role) for r in p.roles] == [("refund-agent", "Customers", "requests refunds")]                       # a role line with a field missing is dropped
    assert [(t.from_agent, t.to_agent, t.task, t.data) for t in p.task_links] == [("refund-agent", "ledger-agent", "pay", ["order id", "amount"])]
    assert [(u.system, u.store, u.access) for u in p.data_use] == [("refund-agent", "order database", "write"), ("refund-agent", "order database", "read")] and p.data_stores[0].sensitivity == "personal data"
    assert company.proposal_to_doc(p, {})["company"] == {"name": "Acme"}


def test_the_model_is_warmed_at_most_once_in_ten_minutes_and_a_failure_is_harmless():
    import time

    import ollama_client
    calls = []
    real = ollama_client.warm
    ollama_client.warm = lambda *a, **k: calls.append(1) or True
    with authed_client("admin", "Alice Admin") as api, authed_client("auditor", "Ada Auditor") as aud:
        try:
            company._warm["at"] = 0.0
            assert api.post("/api/company/assistant/warm").json() == {"warming": True}
            for _ in range(100):
                if calls:
                    break
                time.sleep(0.02)
            assert calls == [1] and api.post("/api/company/assistant/warm").json() == {"warming": False}          # not again within ten minutes
            assert aud.post("/api/company/assistant/warm").status_code == 403                                      # an auditor changes nothing, not even the model's memory
        finally:
            ollama_client.warm = real
            company._warm["at"] = 0.0
    import httpx
    real_post = httpx.post
    httpx.post = lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("down"))
    try:
        assert real() is False                                                                                       # Ollama unreachable: warming just reports it
    finally:
        httpx.post = real_post


def test_only_an_administrator_can_clear_the_organisation_and_must_type_its_name():
    with authed_client("admin", "Alice Admin") as api, authed_client("compliance", "Cora Compliance") as comp, authed_client("engineer", "Eve Engineer") as eng:
        original = api.get("/api/organisation").json()["name"]
        try:
            wipe()
            load_sample(api)
            name = api.get("/api/organisation").json()["name"]                                              # the sample names the company, and an administrator's import applies it
            assert api.get("/api/company").json()["counts"]["agent"] == 4
            for c in (comp, eng):
                assert c.request("DELETE", "/api/company", json={"confirm": name}).status_code == 403          # not even compliance
            assert api.request("DELETE", "/api/company", json={"confirm": "not the name"}).status_code == 422
            assert api.request("DELETE", "/api/company", json={}).status_code == 422
            assert len(api.get("/api/company").json()["nodes"]) == 64                                           # nothing was deleted by a refused call
            r = api.request("DELETE", "/api/company", json={"confirm": f"  {name} "})
            assert r.status_code == 200 and r.json()["deleted_nodes"] == 64 and r.json()["deleted_connections"] == 63 and r.json()["platform_cleared"] is True and r.json()["agents"] >= 4 and r.json()["organisation"] == name
            s = api.get("/api/company").json()
            assert s["nodes"] == [] and s["edges"] == [] and s["checks"] == [] and s["organisation"]["name"] == name
            events = api.get("/api/audit?limit=30").json()
            assert any(e["actor"] == "Alice Admin" and e["action"] == "DELETE /api/company" and e["outcome"] == "ok" for e in events)
            assert any(e["actor"] == "Cora Compliance" and e["action"] == "DELETE /api/company" and e["outcome"] == "denied" for e in events)
            load_sample(api)                                                                                    # a new company can be described straight away
            r = api.request("DELETE", "/api/company", json={"confirm": name, "new_name": "  Fresh Co "})
            assert r.status_code == 200 and r.json()["organisation"] == "Fresh Co" and api.get("/api/organisation").json()["name"] == "Fresh Co"
        finally:
            api.patch("/api/organisation", json={"name": original})
            wipe()


def test_the_fixed_generation_settings_reach_ollama_unchanged():
    import httpx

    import ollama_client
    captured = {}

    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "{}"}}

    real = httpx.post
    httpx.post = lambda url, json=None, timeout=None: captured.update(json or {}) or Reply()
    try:
        ollama_client.chat_json([{"role": "user", "content": "x"}], {"type": "object"}, temperature=0, options=company.DRAFT_OPTIONS)
        a = dict(captured)
        ollama_client.chat_json([{"role": "user", "content": "y"}], {"type": "object"}, temperature=0, options=company.DRAFT_OPTIONS)
    finally:
        httpx.post = real
    assert a["options"] == company.DRAFT_OPTIONS == captured["options"]                                      # the same settings on every call
    assert a["options"]["temperature"] == 0 and a["options"]["top_k"] == 1 and a["options"]["seed"] == 42 and a["options"]["num_ctx"] == 4096
    assert a["stream"] is False and a["keep_alive"] == ollama_client.OLLAMA_KEEP_ALIVE
    assert ollama_client.chat_json.__kwdefaults__["temperature"] == 0.2 and ollama_client.chat_json.__kwdefaults__["options"] is None      # other callers keep their own defaults


def test_the_same_description_always_gives_the_same_draft():
    import time

    import ollama_client
    from db.models import CompanyDraftCache
    from db.session import SessionLocal
    calls = []

    def fake(messages, schema, **kw):
        calls.append(messages[-1]["content"])
        n = len(calls)                                           # a model that is NOT repeatable: a different answer on every call
        return {"company": f"Run {n} Ltd", "departments": [f"Dept {n} | | "], "people": [], "outside": [], "systems": [], "roles": [], "handoffs": [], "data": [], "uses": []}

    def draft(api, text, history=None):
        job = api.post("/api/company/draft", json={"description": text, "history": history or []}).json()["job"]
        for _ in range(200):
            s = api.get(f"/api/company/draft/{job}").json()
            if s["status"] != "running":
                return s["result"]
            time.sleep(0.05)
        raise AssertionError("the draft did not finish")

    real = ollama_client.chat_json
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            with SessionLocal() as s:
                s.query(CompanyDraftCache).delete()
                s.commit()
            ollama_client.chat_json = fake
            first = draft(api, "Zed Ltd has an Ops department led by Pat Lee.")
            again = draft(api, "Zed Ltd has an Ops department led by Pat Lee.")
            assert len(calls) == 1 and first["cached"] is False and again["cached"] is True              # the model was asked once
            assert again["doc"] == first["doc"] and again["plan"] == first["plan"] and first["doc"]["company"] == {"name": "Run 1 Ltd"}
            other = draft(api, "Zed Ltd has an Ops department led by Pat Lee, and Finance.")            # one word more is a different description
            assert len(calls) == 2 and other["cached"] is False and other["doc"]["company"] == {"name": "Run 2 Ltd"}
            withh = draft(api, "Zed Ltd has an Ops department led by Pat Lee.", ["We are small."])        # earlier messages are part of the input
            assert len(calls) == 3 and withh["cached"] is False
            assert draft(api, "Zed Ltd has an Ops department led by Pat Lee.", ["We are small."])["doc"] == withh["doc"] and len(calls) == 3
            old_seed = company.DRAFT_OPTIONS["seed"]
            company.DRAFT_OPTIONS["seed"] = 7                                                              # a changed setting must not reuse a draft made under the old one
            try:
                assert draft(api, "Zed Ltd has an Ops department led by Pat Lee.")["cached"] is False and len(calls) == 4
            finally:
                company.DRAFT_OPTIONS["seed"] = old_seed
            ollama_client.chat_json = lambda *a, **k: {"departments": 3}                                  # an unusable answer is not kept
            bad_text = "A description that makes the model fail."
            job = api.post("/api/company/draft", json={"description": bad_text}).json()["job"]
            for _ in range(200):
                st = api.get(f"/api/company/draft/{job}").json()
                if st["status"] != "running":
                    break
                time.sleep(0.05)
            assert st["status"] == "error"
            with SessionLocal() as s:
                assert s.query(CompanyDraftCache).count() == 4
        finally:
            ollama_client.chat_json = real
            with SessionLocal() as s:
                s.query(CompanyDraftCache).delete()
                s.commit()
            wipe()


def test_templates_and_starting_points_are_valid_files():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            docs = [api.get("/api/company/template").json()] + [api.get(f"/api/company/starters/{s['id']}").json() for s in api.get("/api/company/starters").json()]
            assert len(docs) == 5 and api.get("/api/company/starters/nope").status_code == 404
            for d in docs:
                r = api.post("/api/company/import/preview", json=body(d)).json()
                assert r["ok"] is True, (d["company"], r["errors"])
        finally:
            wipe()


def test_the_studios_can_start_from_what_the_organisation_knows():
    with authed_client("admin", "Alice Admin") as api:
        try:
            wipe()
            load_sample(api)
            seed = api.get("/api/company/systems/AG-REFUND/agent-seed").json()
            assert seed["name"] == "refund-agent" and seed["owner"] == "Sam Okoye" and seed["department"] == "Customer Experience"
            assert [h["name"] for h in seed["humans"]] == ["Customers", "Support agents"]                      # the owner is not listed as a user
            assert [a["name"] for a in seed["approvals"]] == ["Approval: Jonas Weber"] and [x["name"] for x in seed["externals"]] == ["Stripe"]
            d = {x["name"]: x for x in seed["delegates"]}
            assert set(d) == {"notification-agent", "kyc-agent", "payouts-agent"} and d["notification-agent"]["owner"] == "Lena Fischer" and d["notification-agent"]["cross_department"] is True
            assert d["payouts-agent"]["owner"] == "" and d["notification-agent"]["data"] == ["customer email", "order id"]
            assert [x["name"] for x in seed["data"]] == ["Order store", "Customer email addresses", "Customer risk flags", "Payments ledger"] and not any(x["write"] for x in seed["data"])
            assert seed["goals"] == ["Resolve refunds within policy"]
            inbound = api.get("/api/company/systems/AG-NOTIFY/agent-seed").json()["inputs"]
            assert inbound == [{"name": "refund-agent: Send confirmation email", "from": "refund-agent", "department": "Customer Experience", "cross_department": True}]
            assert api.get("/api/company/systems/MD-TRIAGE/agent-seed").status_code == 404 and api.get("/api/company/systems/NOPE/agent-seed").status_code == 404

            r = api.get("/api/company/systems/MD-TRIAGE/deployment-description").json()
            desc = r["description"]
            assert [(a["subtype"], a["identity"]) for a in desc["actors"]] == [("TRAINER", "Aiko Tanaka"), ("VALIDATOR", "Omar Haddad"), ("DEPLOYER", "Omar Haddad"), ("OPERATOR", "Triage nurses"), ("CONSUMER", "Patients")]
            m = desc["ai_models"][0]
            assert m["ai_criticality"] == "CRITICAL" and m["data_sensitivity"] == "SPECIAL_CATEGORY" and m["hosting_environment"] == "TYPE_1_INHOUSE" and desc["deployment_name"] == "clinical-triage-llm"
            assert [e["name"] for e in desc["deployment_environments"]] == ["Platform & Security"]
            assert {x["name"] for x in desc["departments"]} == {"Clinical AI", "Executive"}
            assert len(r["skipped"]) == 2 and any("Priya Nair" in x for x in r["skipped"]) and any("Data protection authority" in x for x in r["skipped"])
            graph = api.post("/api/designs/import", json=desc)                                                 # the Model studio's own importer accepts it as it is
            assert graph.status_code == 200, graph.text
            assert api.get("/api/company/systems/AG-REFUND/deployment-description").status_code == 404
        finally:
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
            import traceback
            print("FAIL ", n, repr(exc))
            traceback.print_exc(limit=-2)
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
