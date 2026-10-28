"""
Tests for the side-by-side comparison of agent designs and the social-care profile, using the two care-plan designs in examples/care-plan-designs.json.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_agent_compare     # a scratch database: see tests/_guard.py
"""
import json
import pathlib
import sys

from db.models import Design
from db.session import SessionLocal
from tests._auth import authed_client

fails = []
SIGNER = "Compliance lead"


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


def load_examples():
    for base in (pathlib.Path("/app/examples"), pathlib.Path(__file__).resolve().parents[2] / "examples"):
        f = base / "care-plan-designs.json"
        if f.exists():
            raw = f.read_text(encoding="utf-8").replace("SIGNER", SIGNER)
            return json.loads(raw)["designs"]
    raise FileNotFoundError("examples/care-plan-designs.json")


def tidy():
    with SessionLocal() as s:
        s.query(Design).filter(Design.name.like("zz-test care%")).delete(synchronize_session=False)
        s.commit()


try:
    examples = load_examples()
    with authed_client("admin", SIGNER) as api:
        tidy()
        profs = {p["key"]: p for p in api.get("/api/rcr/profiles").json()}
        check("the social-care profile is available and valid", "social_care" in profs and profs["social_care"]["valid"], profs.get("social_care"))
        check("it has critical requirements, so its band lines are derived", profs["social_care"]["blocked_line"] is not None)

        keys = []
        for e in examples:
            r = api.post("/api/designs", json={"name": "zz-test " + e["name"].lower().replace(":", ""), "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": e["document"]})
            assert r.status_code == 201, r.text
            keys.append(r.json()["design_key"])

        inventory = len(api.get("/api/agents").json())
        r = api.post("/api/agents/compare", json={"design_keys": keys})
        check("compare answers", r.status_code == 200, r.text)
        c = r.json()
        basic, bespoke = c["options"]
        check("both are judged against the first design's profile", c["profile"] == "social_care" and all(o["profile"] == "social_care" for o in c["options"]))
        check("the basic assistant is a no-go", basic["gate"] == "BLOCK" and basic["verdict"] == "No-go", (basic["gate"], basic["score"]))
        check("the bespoke service is not blocked", bespoke["gate"] in ("APPROVE", "REVIEW") and bespoke["score"] < basic["score"], (bespoke["gate"], bespoke["score"]))
        check("the score says why: the floor is human oversight", basic["floor"] and "person decides" in basic["floor"].lower(), basic["floor"])
        check("the headline names both and says how many items differ", "No-go" in c["headline"] and "differ" in c["headline"], c["headline"])
        diff_keys = {d["key"] for d in c["requirement_differences"]}
        check("oversight and owner are among the differences", {"oversight", "owner"} <= diff_keys, diff_keys)
        check("each difference carries one value per option", all(len(d["values"]) == 2 for d in c["requirement_differences"]))
        ow = {d["key"]: d for d in c["owasp_differences"]}
        check("the OWASP checks also differ (tool misuse needs an approval step)", "ASI02" in ow and ow["ASI02"]["values"][0]["status"] != ow["ASI02"]["values"][1]["status"], list(ow))
        check("the bespoke design counts its sign-offs", {r["key"]: r["counted"] for r in bespoke["requirements"]}["dpia"] == "Covered")

        r = api.post("/api/agents/compare", json={"design_keys": keys, "profile": "payments"})
        check("a profile can be named so both are judged by the same rules", r.status_code == 200 and r.json()["profile"] == "payments", r.text)
        check("the order of the options follows the request", api.post("/api/agents/compare", json={"design_keys": keys[::-1]}).json()["options"][0]["gate"] != "BLOCK")

        check("one design is refused", api.post("/api/agents/compare", json={"design_keys": [keys[0]]}).status_code == 422)
        check("an unknown design is a 404", api.post("/api/agents/compare", json={"design_keys": [keys[0], "d-nope"]}).status_code == 404)
        check("nothing was stored by comparing: the inventory is unchanged", len(api.get("/api/agents").json()) == inventory)

    with authed_client("auditor", "Read only") as ro:
        r = ro.post("/api/agents/compare", json={"design_keys": keys})
        check("a read-only role can compare (it changes nothing)", r.status_code == 200, r.text)
finally:
    try:
        tidy()
    except Exception as exc:
        print("cleanup failed", exc)
sys.exit(1 if fails else 0)
