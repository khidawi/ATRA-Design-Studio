"""
Tests for the first-pass screening of agents from their descriptions (agent_triage.py), using the fictional list in examples/agent-list-sample.csv.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_agent_triage     # a scratch database: see tests/_guard.py
"""
import pathlib
import sys

from agent_triage import kappa, screen
from db.models import Agent, Design
from db.session import SessionLocal
from tests._auth import authed_client

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


def sample_csv():
    for base in (pathlib.Path("/app/examples"), pathlib.Path(__file__).resolve().parents[2] / "examples"):
        f = base / "agent-list-sample.csv"
        if f.exists():
            return f.read_text(encoding="utf-8")
    raise FileNotFoundError("examples/agent-list-sample.csv")


def tidy():
    """The agents this file imports (origin SCREENED), the designs made for them, and the agent it registers by hand."""
    with SessionLocal() as s:
        for a in s.query(Agent).filter((Agent.origin == "SCREENED") | (Agent.agent_key.like("zz-test%"))).all():
            s.delete(a)
        s.flush()
        for d in s.query(Design).filter(Design.subject == "AGENT", Design.document["source"].astext == "screening").all():
            s.delete(d)
        s.query(Design).filter(Design.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()


# ── the screen itself, with no server ──
care = screen("Drafts a care plan for an adult from a social worker's case notes using generative AI.", "Adult Social Care")
check("a care-plan drafter is High", care["tier"] == "High" and care["needs_investigation"], care)
check("each signal names the phrases that triggered it", all(h["phrases"] for h in care["signals"]))
check("it says what the description does not tell us", care["not_stated"] and any("person review" in q for q in care["not_stated"]), care["not_stated"])
check("a meeting-notes summariser is Low", screen("Summarises internal team meetings into notes for staff.")["tier"] == "Low")
anon = screen("Produces anonymised aggregate forecasts of housing demand for planners. No personal data is used.")
check("a description that says anonymised and aggregate scores low", anon["tier"] == "Low" and anon["score"] == 0, anon)
claim = screen("Assesses eligibility for children's services and decides the outcome. Reviewed by a person, anonymised, internal use only.")
check("mitigations are capped: a claim in a description cannot cancel a high-risk purpose", claim["tier"] != "Low", claim)
check("no description is Unknown and still needs a look", screen("")["tier"] == "Unknown" and screen("")["needs_investigation"])
check("the lines can be moved", screen("Drafts letters for residents.", high_at=2, moderate_at=1)["tier"] == "High")
check("environmental health is not read as health data", screen("Routes noise complaints to officers.", "Environmental Health")["tier"] == "Low")
check("kappa: perfect agreement is 1 and chance level is 0", kappa(5, 0, 0, 5) == 1.0 and kappa(25, 25, 25, 25) == 0.0)

# ── the API ──
text = sample_csv()
with authed_client("admin", "Compliance lead") as api:
    r = api.post("/api/agents/triage", json={"csv": text})
    check("a csv is screened", r.status_code == 200, r.text)
    t = r.json()
    check("every row is returned", t["count"] == 36 and len(t["results"]) == 36, t["count"])
    check("columns were recognised from their headers", t["columns"].get("description") == "description" and "their_flag" in t["columns"], t["columns"])
    check("the tiers add up", sum(t["tiers"].values()) == t["count"])
    by = {x["name"]: x for x in t["results"]}
    check("the care-plan drafter, the referral triage and the homelessness predictor are High", all(by[n]["tier"] == "High" for n in ("Care plan drafting assistant", "Children's referral triage", "Homelessness risk predictor")))
    check("the bin chatbot and the policy search are Low", by["Bin collection chatbot"]["tier"] == "Low" and by["Policy document search"]["tier"] == "Low")
    check("the grant scorer is picked up as a decision about people", by["Grant application scorer"]["needs_investigation"])
    check("the note says it is not a risk assessment", "not a risk assessment" in t["note"])

    a = t["agreement"]
    check("agreement counts add up to the rows compared", a["both_flag"] + a["only_we_flag"] + a["only_they_flag"] + a["neither_flag"] == a["compared"] == 36, a)
    check("their flags are read as a count", a["their_flagged"] == sum(1 for ln in text.splitlines()[1:] if ln.endswith(",yes")), a)
    check("we flag nearly all of the ones they flag", a["both_flag"] >= 15 and a["agreement"] >= 0.8, a)
    check("a kappa is reported and is a sensible number", a["kappa"] is not None and 0.5 < a["kappa"] <= 1, a)
    check("the disagreements can be listed from the rows", any(x["their_flag"] is False and x["needs_investigation"] for x in t["results"]))

    s1 = api.post("/api/agents/triage", json={"csv": text, "sample": {"size": 10, "flagged_share": 0.7, "seed": 3}}).json()["sample"]
    s2 = api.post("/api/agents/triage", json={"csv": text, "sample": {"size": 10, "flagged_share": 0.7, "seed": 3}}).json()["sample"]
    s3 = api.post("/api/agents/triage", json={"csv": text, "sample": {"size": 10, "flagged_share": 0.7, "seed": 4}}).json()["sample"]
    check("the sample is 7 flagged and 3 not flagged", (s1["size"], s1["from_flagged"], s1["from_not_flagged"]) == (10, 7, 3), s1)
    check("the same seed gives the same sample", s1["ids"] == s2["ids"] and len(set(s1["ids"])) == 10)
    check("a different seed gives a different one", s1["ids"] != s3["ids"])
    flagged_ids = {x["id"] for x in t["results"] if x["their_flag"]}
    check("the sample's flagged share really comes from their flagged agents", len(flagged_ids & set(s1["ids"])) == 7)
    big = api.post("/api/agents/triage", json={"csv": text, "sample": {"size": 500}}).json()["sample"]
    check("asking for more than exist returns what there is", big["size"] == 36)

    rows = api.post("/api/agents/triage", json={"rows": [{"name": "x", "description": "Triage of referrals about children."}]}).json()
    check("rows can be sent as json too, with no comparison column", rows["count"] == 1 and "agreement" not in rows and rows["results"][0]["tier"] == "High", rows)
    semi = "name;description\nA;Drafts letters\nB;Checks eligibility of children for support\n"
    check("a semicolon-separated file is read", api.post("/api/agents/triage", json={"csv": semi}).json()["count"] == 2)

    check("a file with no description column is refused with the headers it found", api.post("/api/agents/triage", json={"csv": "name,notes\nA,b\n"}).status_code == 422)
    check("nothing to screen is refused", api.post("/api/agents/triage", json={}).status_code == 422)
    check("a moderate line above the high line is refused", api.post("/api/agents/triage", json={"csv": text, "high_at": 3, "moderate_at": 5}).status_code == 422)
    check("a header with no agents is refused", api.post("/api/agents/triage", json={"csv": "name,description\n"}).status_code == 422)
    many = "name,description\n" + "\n".join(f"a{i},Drafts letters" for i in range(5001))
    check("more than 5,000 agents is refused", api.post("/api/agents/triage", json={"csv": many}).status_code == 422)
    inventory = len(api.get("/api/agents").json())
    api.post("/api/agents/triage", json={"csv": text})
    check("screening stores nothing", len(api.get("/api/agents").json()) == inventory)

    # ── importing a chosen set into the inventory ──
    tidy()
    high = [x["id"] for x in t["results"] if x["tier"] == "High"]
    r = api.post("/api/agents/triage/import", json={"csv": text, "ids": high})
    check("importing the High agents answers", r.status_code == 200, r.text)
    imp = r.json()
    check("every one is created, each with a draft design", imp["created"] == len(high) and imp["designs_created"] == len(high) and imp["updated"] == 0 and imp["skipped"] == 0, {k: imp[k] for k in ("created", "updated", "skipped", "designs_created")})
    check("the social-care profile is used by default", imp["profile"] == "social_care")
    inv = {a["name"]: a for a in api.get("/api/agents").json()}
    care = inv["Care plan drafting assistant"]
    check("they appear in the inventory, marked as screened, with the tier", care["origin"] == "SCREENED" and care["screening"]["tier"] == "High" and care["status"] == "UNOWNED", care)
    check("the inventory entry carries the description and what was not stated", "care plan" in care["screening"]["description"].lower() and care["screening"]["not_stated"])
    check("it has a design key to open in the Design studio", bool(care["design_key"]))
    d = api.get(f"/api/designs/{care['design_key']}").json()
    nodes = {n["type"]: n for n in d["document"]["nodes"]}
    check("the draft design is a real agent design with the agent as primary", d["subject"] == "AGENT" and nodes["agent"]["primary"] and nodes["agent"]["name"] == "Care plan drafting assistant")
    check("it shows who is affected and what data, as the description says", "human" in nodes and "data" in nodes and "Sensitive" in nodes["data"]["name"], list(nodes))
    check("it never credits a control the description only claims", not any(n["type"] in ("approval", "guardrail", "constraint") for n in d["document"]["nodes"]))
    check("the design is judged by the profile and starts blocked, with nothing evidenced",
          api.post("/api/rcr/score", json={"profile": d["document"]["profile"], "graph": {"nodes": [{"id": n["id"], "type": n["type"], "props": {"name": n["name"], **n["p"]}, "primary": bool(n.get("primary"))} for n in d["document"]["nodes"]], "edges": [{"from": e["from"], "to": e["to"], "label": e["label"]} for e in d["document"]["edges"]]}}).json()["gate"] == "BLOCK")
    check("ratifying a draft that has not been completed is refused", api.post("/api/agents/ratify", json={"design_key": care["design_key"]}).status_code == 422)

    again = api.post("/api/agents/triage/import", json={"csv": text, "ids": high}).json()
    check("importing again changes nothing: updated, no new designs, same designs", again["created"] == 0 and again["updated"] == len(high) and again["designs_created"] == 0)
    check("the same design is kept", {a["name"]: a for a in api.get("/api/agents").json()}["Care plan drafting assistant"]["design_key"] == care["design_key"])
    check("the inventory has no duplicates", len([a for a in api.get("/api/agents").json() if a["origin"] == "SCREENED"]) == len(high))

    low = next(x["id"] for x in t["results"] if x["tier"] == "Low")
    nod = api.post("/api/agents/triage/import", json={"csv": text, "ids": [low], "create_designs": False}).json()
    check("designs are optional", nod["created"] == 1 and nod["designs_created"] == 0 and nod["items"][0]["design_key"] is None, nod)
    check("an unknown profile is refused", api.post("/api/agents/triage/import", json={"csv": text, "ids": [low], "profile": "nope"}).status_code == 422)
    check("no matching ids is refused", api.post("/api/agents/triage/import", json={"csv": text, "ids": ["no-such-id"]}).status_code == 422)
    api.post("/api/agents/triage/import", json={"csv": text, "ids": [low], "profile": "payments"})
    check("an agent that was imported without a design gets one later", {a["name"]: a for a in api.get("/api/agents").json()}[next(x["name"] for x in t["results"] if x["id"] == low)]["design_key"] is not None)

    api.post("/api/agents/register", json={"name": "zz-test registered agent", "owner": "Someone"})
    both = "name,description\nzz-test registered agent,Decides eligibility for children's services.\nzz-test twin,Drafts letters.\nzz-test twin,Drafts letters.\n"
    r = api.post("/api/agents/triage/import", json={"csv": both, "create_designs": False}).json()
    by = {i["agent_key"]: i for i in r["items"]}
    check("an agent already in the inventory keeps its place and gets the screening", by["zz-test-registered-agent"]["action"] == "updated" and {a["agent_key"]: a for a in api.get("/api/agents").json()}["zz-test-registered-agent"]["owner"] == "Someone")
    check("its origin is not changed", {a["agent_key"]: a for a in api.get("/api/agents").json()}["zz-test-registered-agent"]["origin"] == "REGISTERED")
    check("two agents with the same name in one list both get an entry", "zz-test-twin" in by and "zz-test-twin-2" in by, list(by))

    # ── linked with the runtime: events for a screened agent go to the same inventory entry, not a new discovered one
    ev = api.post("/api/runtime/events", json={"agent": "Care plan drafting assistant", "events": [{"type": "tool_call", "name": "case.record.save", "write": True}]})
    check("runtime events for a screened agent are accepted", ev.status_code == 202, ev.text)
    check("they are judged as having no contract yet, not as a new unknown agent", ev.json()["results"][0]["verdict"] == "NO_CONTRACT", ev.json())
    after = {a["agent_key"]: a for a in api.get("/api/agents").json()}
    check("it is the same inventory entry (still screened), now seen by the runtime", after["care-plan-drafting-assistant"]["origin"] == "SCREENED" and after["care-plan-drafting-assistant"]["last_seen_at"])
    check("no duplicate was discovered", len([a for a in after.values() if a["name"].lower().startswith("care plan drafting")]) == 1)

with authed_client("auditor", "Read only") as ro:
    check("a read-only role can screen a list", ro.post("/api/agents/triage", json={"csv": text}).status_code == 200)
    check("but cannot import into the inventory", ro.post("/api/agents/triage/import", json={"csv": text}).status_code == 403)
with authed_client("engineer", "An engineer") as eng:
    check("an engineer can import (it needs write, not sign-off)", eng.post("/api/agents/triage/import", json={"csv": text, "ids": ["1"], "create_designs": False}).status_code == 200)
tidy()
sys.exit(1 if fails else 0)
