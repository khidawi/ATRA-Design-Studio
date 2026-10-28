"""
Tests for responsibilities and assignments (responsibility.py): the duty kept apart from the employee and from the organisation's structure, handed over for a period or
for good, with one rule for who holds it on a date, and that rule read by the inventory, the organisation checks and the PCS.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_responsibility     # a scratch database: see tests/_guard.py
"""
import json
import sys
from datetime import date, datetime, timedelta, timezone

import responsibility
from db.models import Agent, Assignment, Design, Responsibility
from db.session import SessionLocal
from tests._auth import authed_client
from tests.test_company import body
from tests.test_removal import wipe_all

fails = []
AG, NO, MD = "zz-test-resp-agent", "zz-test-resp-noowner", "MD-1"


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


ORG = {"departments": [{"id": "D-A", "name": "Alpha"}],
       "people": [{"id": "EMP-1", "name": "Pat Lee", "department": "D-A"}, {"id": "EMP-2", "name": "Sam Ray", "department": "D-A"}, {"id": "EMP-3", "name": "Lou Kim", "department": "D-A"},
                  {"id": "EMP-4", "name": "Ana Ito", "department": "D-A"}],
       "ai_systems": [{"id": "AG-1", "type": "agent", "name": AG, "department": "D-A", "owner": "EMP-1"},
                      {"id": "AG-2", "type": "agent", "name": NO, "department": "D-A"},
                      {"id": MD, "type": "model", "name": "zz-test-resp-model", "department": "D-A", "owner": "EMP-1",
                       "people": [{"id": "EMP-1", "role": "trains"}, {"id": "EMP-2", "role": "validates"}, {"id": "EMP-3", "role": "deploys"}]}]}
D = lambda n: (datetime.now(timezone.utc).date() + timedelta(days=n)).isoformat()      # noqa: E731


def tidy():
    wipe_all()
    with SessionLocal() as s:
        for r in s.query(Responsibility).filter(Responsibility.subject_ref.like("zz-test%") | Responsibility.subject_ref.like("MD-%") | Responsibility.subject_ref.like("d:%")).all():
            s.delete(r)
        s.query(Design).filter(Design.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()


def subject(api, kind, ref):
    return api.get(f"/api/responsibilities/subject?kind={kind}&ref={ref}").json()


def duty(snap, name):
    return next(d for d in snap["duties"] if d["duty"] == name)


try:
    with authed_client("compliance", "Carla Compliance") as api:
        tidy()
        r = api.post("/api/company/import", json=body(ORG))
        check("the organisation is imported", r.status_code == 200, r.text)

        # ── the structure answers until someone makes the first handover
        s0 = subject(api, "agent", AG)
        o = duty(s0, "owner")
        check("before any handover the organisation's own owner is the holder", o["holder"]["name"] == "Pat Lee" and o["source"] == "structure" and o["holder"]["ext_id"] == "EMP-1" and not o["had_assignments"], o)
        check("an agent with no owner in the organisation has no holder", duty(subject(api, "agent", NO), "owner")["holder"] is None)
        inv = {a["agent_key"]: a for a in api.get("/api/agents").json()}
        check("the inventory still shows the owner it always did, with no detail", inv[AG]["owner"] == "Pat Lee" and inv[AG]["owner_detail"] is None)
        sm = subject(api, "model", MD)
        check("a model's roles come from the people drawn against it", {d["duty"]: (d["holder"] or {}).get("name") for d in sm["duties"]} == {"owner": "Pat Lee", "trainer": "Pat Lee", "validator": "Sam Ray", "deployer": "Lou Kim", "operator": None}, sm["duties"])
        check("and they are separate, so no conflict", sm["conflicts"] == [])

        # ── a handover for a period: a cover while the owner is on leave
        r = api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-2", "kind": "COVER", "starts_on": D(-1), "ends_on": D(7), "reason": "Annual leave"})
        check("a cover is accepted", r.status_code == 200, r.text)
        cover_id = r.json()["assignment_id"]
        o = duty(subject(api, "agent", AG), "owner")
        check("the cover is the holder now, covering the primary, until the end date", o["holder"]["name"] == "Sam Ray" and o["kind"] == "COVER" and o["covering_for"]["name"] == "Pat Lee" and o["until"] == D(7), o)
        inv = {a["agent_key"]: a for a in api.get("/api/agents").json()}
        check("the inventory's owner follows, with who is being covered", inv[AG]["owner"] == "Sam Ray" and inv[AG]["owner_detail"]["covering_for"] == "Pat Lee" and inv[AG]["owner_detail"]["until"] == D(7), inv[AG])
        hist = subject(api, "agent", AG)["history"]
        check("the history keeps the structure's owner as the first primary (from the start) and the cover after it", [(h["kind"], h["name"]) for h in hist] == [("COVER", "Sam Ray"), ("PRIMARY", "Pat Lee")] and hist[1]["starts_on"] == "1970-01-01", hist)
        co = api.get("/api/company").json()
        keys = {c["key"] for c in co["checks"]}
        check("the organisation says the agent is covered for now", "owner_covered" in keys and "no_owner" not in {c["key"] for c in co["checks"] if AG in c["detail"]}, keys)
        check("the organisation's own structure is untouched", next(n for n in co["nodes"] if n["name"] == AG)["props"]["owner"] == "EMP-1")
        check("the live view carries the holders for the map", co["live"]["holders"]["AG-1"]["owner"]["holder"]["name"] == "Sam Ray")

        # ── the cover ends early: the duty goes back by itself
        r = api.post(f"/api/responsibilities/assignments/{cover_id}/end", json={"on": D(-1), "reason": "Back early"})
        check("a cover can be ended", r.status_code == 200, r.text)
        o = duty(subject(api, "agent", AG), "owner")
        check("the primary holds the duty again", o["holder"]["name"] == "Pat Lee" and o["kind"] == "PRIMARY" and o["covering_for"] is None, o)
        check("and the inventory follows", {a["agent_key"]: a for a in api.get("/api/agents").json()}[AG]["owner"] == "Pat Lee")
        check("ending it twice is refused", api.post(f"/api/responsibilities/assignments/{cover_id}/end", json={"on": D(-1)}).status_code == 409)

        # ── a cover in the future is upcoming, and can be cancelled
        r = api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-4", "kind": "COVER", "starts_on": D(10), "ends_on": D(12), "reason": "Training week"})
        later = r.json()["assignment_id"]
        o = duty(subject(api, "agent", AG), "owner")
        check("a future cover changes nothing now but is shown as next", o["holder"]["name"] == "Pat Lee" and o["next"]["name"] == "Ana Ito" and o["next"]["starts_on"] == D(10), o)
        pj = api.get("/api/responsibilities/person/EMP-4").json()
        check("the person's page lists it as upcoming", len(pj["upcoming"]) == 1 and pj["upcoming"][0]["subject"] == AG and pj["upcoming"][0]["duty"] == "owner", pj)
        check("one that has not started can be cancelled", api.post(f"/api/responsibilities/assignments/{later}/cancel").status_code == 200)
        check("it no longer shows", duty(subject(api, "agent", AG), "owner")["next"] is None)
        check("one that has started cannot be cancelled, only ended", api.post(f"/api/responsibilities/assignments/{cover_id}/cancel").status_code == 409)

        # ── a new primary: a leaver, or a reorganisation
        r = api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-3", "kind": "PRIMARY", "starts_on": D(-1), "reason": "Pat moved teams"})
        check("a new primary is accepted", r.status_code == 200, r.text)
        prim = r.json()["assignment_id"]
        o = duty(subject(api, "agent", AG), "owner")
        check("the new primary holds the duty", o["holder"]["name"] == "Lou Kim" and o["kind"] == "PRIMARY", o)
        pat = api.get("/api/responsibilities/person/EMP-1").json()
        check("the old one is in their past, with their name kept", any(p["subject"] == AG and p["duty"] == "owner" for p in pat["past"]), pat)
        check("the organisation's structure still says Pat: the structure was never edited", next(n for n in api.get("/api/company").json()["nodes"] if n["name"] == AG)["props"]["owner"] == "EMP-1")

        # ── a lapse: the holder leaves and nobody is assigned
        api.post(f"/api/responsibilities/assignments/{prim}/end", json={"on": D(-1), "reason": "Left the company"})
        o = duty(subject(api, "agent", AG), "owner")
        check("a duty with no active assignment has lapsed: no holder, not the structure", o["holder"] is None and o["source"] == "lapsed", o)
        inv = {a["agent_key"]: a for a in api.get("/api/agents").json()}
        check("the agent counts as unowned everywhere that reads the inventory", inv[AG]["owner"] is None and inv[AG]["status"] == "UNOWNED", inv[AG])
        co = api.get("/api/company").json()
        check("and the organisation says the owner has lapsed", any(c["key"] == "owner_lapsed" and AG in c["detail"] for c in co["checks"]), [c["key"] for c in co["checks"]])
        api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_name": "Ola Freelance (contractor)", "kind": "PRIMARY", "starts_on": D(0)})
        o = duty(subject(api, "agent", AG), "owner")
        check("a duty can be handed to someone outside the organisation by name", o["holder"]["name"] == "Ola Freelance (contractor)" and o["holder"]["in_organisation"] is False, o)
        check("and the agent is owned again", {a["agent_key"]: a for a in api.get("/api/agents").json()}[AG]["status"] == "TO_RATIFY")

        # ── role separation of a model, with a cover
        r = api.post("/api/responsibilities/handover", json={"subject_kind": "model", "subject_ref": MD, "duty": "validator", "holder_ext_id": "EMP-1", "kind": "COVER", "starts_on": D(0), "ends_on": D(5), "reason": "Sam is ill"})
        check("a cover that would create a conflict is allowed, with a warning", r.status_code == 200 and len(r.json()["conflicts"]) == 1, r.text)
        cf = r.json()["conflicts"][0]
        check("it names who holds both, and that it is a cover", cf["holder"] == "Pat Lee" and cf["duties"] == ["trainer", "validator"] and cf["covering"], cf)
        co = api.get("/api/company").json()
        check("the organisation's role-concentration check reads the cover", any(c["key"] == "role_concentration" and "while covering" in c["detail"] for c in co["checks"]), [c["detail"] for c in co["checks"] if c["key"] == "role_concentration"])
        ids = {d["duty"]: d["holder"]["name"] for d in subject(api, "model", MD)["duties"] if d["holder"] and d["duty"] != "owner"}
        check("the identities the scoring reads are the effective holders", ids == {"trainer": "Pat Lee", "validator": "Pat Lee", "deployer": "Lou Kim"} and responsibility.identities, ids)
        reg = lambda t, v, d: {"deployment_context": {"model_type": "HYBRID", "ai_criticality": "OPERATIONAL", "data_sensitivity": "INTERNAL", "domain": "x"}, "system_type": "TYPE_1_INHOUSE",   # noqa: E731
                               "actors": {"trainer": {"identity": t}, "validator": {"identity": v}, "deployer": {"identity": d}}}
        apart = api.post("/score", json={"registry": reg("Pat Lee", "Sam Ray", "Lou Kim")}).json()["pcs_result"]
        covered = api.post("/score", json={"registry": reg(ids["trainer"], ids["validator"], ids["deployer"])}).json()["pcs_result"]
        check("the PCS reads the effective holders: a conflict through a cover raises the role concentration factor", covered["raw_breakdown"]["rcf_adj"] > apart["raw_breakdown"]["rcf_adj"], (apart["raw_breakdown"]["rcf_adj"], covered["raw_breakdown"]["rcf_adj"]))
        check("the same identity in two roles is concentration whether it came from a form or a cover", api.post("/score", json={"registry": reg("pat lee", "PAT LEE", "Lou Kim")}).json()["pcs_result"]["raw_breakdown"]["rcf_adj"] == covered["raw_breakdown"]["rcf_adj"])
        end_id = [h["id"] for h in subject(api, "model", MD)["history"] if h["kind"] == "COVER"][0]
        api.post(f"/api/responsibilities/assignments/{end_id}/end", json={"on": D(0)})
        r2 = api.get(f"/api/responsibilities/subject?kind=model&ref={MD}&on={D(1)}").json()
        check("asked as of a later date, the cover is over and the validator is Sam", duty(r2, "validator")["holder"]["name"] == "Sam Ray" and r2["conflicts"] == [], r2["conflicts"])
        r3 = api.get(f"/api/responsibilities/subject?kind=model&ref={MD}&on={D(2)}").json()
        check("the validator on any date is answered from the history", duty(r3, "validator")["holder"]["name"] == "Sam Ray")

        # ── the model inventory and a model that is not in the organisation yet
        minv = {m["name"]: m for m in api.get("/api/model-screening/inventory").json()}
        mm = minv["zz-test-resp-model"]
        check("the model inventory shows the owner now, and which organisation element it is", mm["owner"] == "Pat Lee" and mm["org_id"] == MD and mm["owner_covering_for"] is None, mm)
        api.post("/api/responsibilities/handover", json={"subject_kind": "model", "subject_ref": MD, "duty": "owner", "holder_ext_id": "EMP-4", "kind": "COVER", "starts_on": D(0), "ends_on": D(3), "reason": "Leave"})
        mm = {m["name"]: m for m in api.get("/api/model-screening/inventory").json()}["zz-test-resp-model"]
        check("a cover on a model shows in its inventory row", mm["owner"] == "Ana Ito" and mm["owner_covering_for"] == "Pat Lee", mm)
        dom = api.get("/api/domains").json()[0]["domain_id"]
        node = lambda i, sub, ident: {"id": i, "kind": "ACTOR", "x": 1, "y": 1, "data": {"subtype": sub, "identity": ident, "departmentId": ""}}   # noqa: E731
        mk = api.post("/api/designs", json={"name": "zz-test unplaced model", "domain": dom, "subject": "MODEL", "document": {"n": 3, "edges": [], "nodes": [
            {"id": "n1", "kind": "AI_MODEL", "x": 1, "y": 1, "data": {"name": "zz-test unplaced model", "modelType": "NN", "aiCriticality": "ADVISORY", "domain": "", "dataSensitivity": "INTERNAL", "hostingEnvironment": "TYPE_1_INHOUSE"}},
            node("n2", "TRAINER", "Zed Trainer")]}}).json()
        ref = "d:" + mk["design_key"]
        check("a model design outside the organisation answers from its designer's own roles", duty(subject(api, "model", ref), "trainer")["holder"]["name"] == "Zed Trainer")
        api.post("/api/responsibilities/handover", json={"subject_kind": "model", "subject_ref": ref, "duty": "trainer", "holder_ext_id": "EMP-2", "kind": "COVER", "starts_on": D(0), "ends_on": D(2), "reason": "Cover"})
        check("and can be handed over before it is placed", duty(subject(api, "model", ref), "trainer")["holder"]["name"] == "Sam Ray")
        placed = api.post("/api/model-screening/place", json={"design_key": mk["design_key"]}).json()
        t = duty(subject(api, "model", placed["id"]), "trainer")
        check("placing it in the organisation takes its duties with it", t["holder"]["name"] == "Sam Ray" and t["covering_for"]["name"] == "Zed Trainer", t)
        with SessionLocal() as s2:
            left = s2.query(Responsibility).filter(Responsibility.subject_ref == ref).count()
        check("nothing is left against the old reference", left == 0, left)

        # ── validation
        bad = lambda **kw: api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-2", **kw}).status_code   # noqa: E731
        check("a cover needs an end date", bad(kind="COVER") == 422)
        check("an end before the start is refused", bad(kind="COVER", starts_on=D(3), ends_on=D(1)) == 422)
        check("an agent has no trainer duty", api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "trainer", "holder_ext_id": "EMP-2", "kind": "PRIMARY"}).status_code == 422)
        check("a holder who is not in the organisation must be named", api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-999", "kind": "PRIMARY"}).status_code == 422)
        check("no holder at all is refused", api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "kind": "PRIMARY"}).status_code == 422)
        check("an unknown agent is a 404", api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": "no-such", "duty": "owner", "holder_ext_id": "EMP-2", "kind": "PRIMARY"}).status_code == 404)
        check("a primary on or before an existing later primary is refused", api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-2", "kind": "PRIMARY", "starts_on": D(-30)}).status_code == 409)
        check("the people a duty can be handed to are listed", {p["name"] for p in api.get("/api/responsibilities/people").json()} >= {"Pat Lee", "Sam Ray", "Lou Kim", "Ana Ito"})

        # ── the person leaves the organisation: what they held ends with them
        api.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": NO, "duty": "owner", "holder_ext_id": "EMP-4", "kind": "PRIMARY", "starts_on": D(-2)})
        check("a person holds a duty", duty(subject(api, "agent", NO), "owner")["holder"]["name"] == "Ana Ito")

        # ── the audit trail (read here: a test client removes the events it wrote when it closes)
        events = api.get("/api/audit?limit=200").json()
        acts = [e for e in events if e["action"] == "responsibility.handover"]
        check("every handover is in the audit log, with who, what and why", acts and any(e["detail"].get("reason") == "Annual leave" and e["detail"].get("to") == "Sam Ray" and e["actor"] == "Carla Compliance" for e in acts), acts[:1])
        check("ending one is in the audit log too", any(e["action"] == "responsibility.end" for e in events))
    with authed_client("admin", "Alice Admin") as adm:
        r = adm.delete("/api/company/nodes/EMP-4")
        check("removing the person from the organisation works", r.status_code == 200, r.text)
        o = duty(subject(adm, "agent", NO), "owner")
        check("what they held has ended: the agent is unowned, and the history still has their name", o["holder"] is None and o["source"] == "lapsed" and subject(adm, "agent", NO)["history"][0]["name"] == "Ana Ito" and subject(adm, "agent", NO)["history"][0]["in_organisation"] is False, o)

        # ── the stored owner is brought up to date on a new day
        with SessionLocal() as s:
            s.query(Agent).filter(Agent.agent_key == AG).update({"owner": "Stale Name", "status": "UNOWNED"})
            s.commit()
        responsibility._refreshed_on = None
        inv = {a["agent_key"]: a for a in adm.get("/api/agents").json()}
        check("the first request of a new day corrects an owner that went out of date", inv[AG]["owner"] == "Ola Freelance (contractor)" and inv[AG]["status"] == "TO_RATIFY", inv[AG])

        # ── who may hand over
    with authed_client("engineer", "Eve Engineer") as eng:
        check("an engineer can read who holds a duty", eng.get(f"/api/responsibilities/subject?kind=agent&ref={AG}").status_code == 200)
        check("but cannot hand a duty over: that is a sign-off decision", eng.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-2", "kind": "PRIMARY"}).status_code == 403)
    with authed_client("auditor", "Read Only") as ro:
        check("an auditor can read the holders and the history", ro.get(f"/api/responsibilities/subject?kind=agent&ref={AG}").status_code == 200)
        check("and cannot change them", ro.post("/api/responsibilities/handover", json={"subject_kind": "agent", "subject_ref": AG, "duty": "owner", "holder_ext_id": "EMP-2", "kind": "PRIMARY"}).status_code == 403)
finally:
    try:
        tidy()
    except Exception as exc:
        print("cleanup failed", exc)
sys.exit(1 if fails else 0)
