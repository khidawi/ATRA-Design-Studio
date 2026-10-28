"""
Tests for screening a list of AI models from their descriptions and importing a chosen set into AI Models (model_triage.py), using the fictional list in
examples/model-list-sample.csv.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_model_triage     # a scratch database: see tests/_guard.py
"""
import pathlib
import sys

from db.models import CompanyNode, Design
from db.session import SessionLocal
from model_triage import infer, screen_model
from tests._auth import authed_client

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


def sample_csv():
    for base in (pathlib.Path("/app/examples"), pathlib.Path(__file__).resolve().parents[2] / "examples"):
        f = base / "model-list-sample.csv"
        if f.exists():
            return f.read_text(encoding="utf-8")
    raise FileNotFoundError("examples/model-list-sample.csv")


def tidy():
    with SessionLocal() as s:
        for d in s.query(Design).filter(Design.subject == "MODEL").all():
            if (d.document or {}).get("source") == "screening" or d.name.startswith("zz-test"):
                s.delete(d)
        s.query(CompanyNode).filter(CompanyNode.ext_id.like("MD-%")).filter(CompanyNode.name.in_(["Loan default predictor"])).delete(synchronize_session=False)
        s.commit()


# ── the screen itself ──
loan = screen_model("Predicts the likelihood of default for loan applicants from their credit history and income. A credit officer makes the final decision.", "Lending")
check("a loan default predictor is High", loan["tier"] == "High" and loan["needs_investigation"], loan)
check("a demand forecaster on aggregate data is Low", screen_model("Forecasts weekly product demand from aggregate sales data for stock planning.")["tier"] == "Low")
check("emotion detection in interviews is picked up as biometric", any(h["key"] == "biometric" for h in screen_model("Detects candidates' emotions from video in interviews to score engagement.")["signals"]))
check("scoring student essays is a decision about people", any(h["key"] == "decision" for h in screen_model("Scores student essays and recommends grades for teachers to confirm.")["signals"]))
check("it lists what a model description rarely says", any("validated" in q or "trained on" in q for q in loan["not_stated"]), loan["not_stated"])
check("no description is Unknown", screen_model("")["tier"] == "Unknown")
check("a model that says it uses only anonymised, aggregate data for internal use is Low", screen_model("Uses anonymised, aggregate data for internal use.")["tier"] == "Low")

# the computation is the ST-AI PCS, run on the draft the description gives: its numbers are the engine's own
check("the loan model's PCS is computed: critical tier, blocked, with the critical constraints still unmet", loan["pcs"]["tier"] == "CRITICAL" and loan["pcs"]["gate"] == "BLOCKED" and loan["pcs"]["score"] == 95.0 and "SC-HITL-1" in loan["pcs"]["vetoes"], loan["pcs"])
check("the result carries the blockers in the engine's words and the six pillars", loan["pcs"]["blockers"] and len(loan["pcs"]["pillars"]) == 6, loan["pcs"])
low = screen_model("Forecasts weekly product demand from aggregate sales data for stock planning.")
check("an advisory, internal-data model scores low on the PCS", low["pcs"]["tier"] == "LOW" and low["pcs"]["score"] < 10 and low["score"] == low["pcs"]["score"], low["pcs"])
check("the tier shown is the PCS tier grouped, not a count of keywords", loan["tier"] == "High" and low["tier"] == "Low")
pinn = screen_model("A physics-informed neural network that simulates heat flow in turbines for design checks.", "Engineering")
check("a physics-informed model with no domain rule cannot be scored: it says so and is ranked first", pinn["pcs"] and not pinn["pcs"]["computable"] and pinn["pcs"]["score"] is None and pinn["tier"] == "Unknown" and pinn["score"] == 100, pinn["pcs"])
check("the guessed deployment context is returned with the result", loan["guess"]["aiCriticality"] == "CRITICAL" and loan["guess"]["dataSensitivity"] == "SENSITIVE_PERSONAL")

g = infer("A convolutional neural network that flags suspected pneumonia on chest x-rays of patients.", "Radiology", "", screen_model("A convolutional neural network that flags suspected pneumonia on chest x-rays of patients.", "Radiology"))
check("the type is guessed from the description (images mean a CNN)", g["modelType"] == "CNN", g)
check("health data is special category", g["dataSensitivity"] == "SPECIAL_CATEGORY", g)
llm = screen_model("A language model chatbot that answers customers' questions.", "", "OpenAI API")
gl = infer("A language model chatbot that answers customers' questions.", "", "OpenAI API", llm)
check("a chatbot is an LLM reached through a third-party API", gl["modelType"] == "LLM" and gl["hostingEnvironment"] == "TYPE_3_THIRDPARTY_API", gl)
anon = screen_model("Detects anomalies in sensor data from machines. Uses no personal data.")
check("a description that says it uses no personal data is internal", infer("Detects anomalies in sensor data from machines. Uses no personal data.", "", "", anon)["dataSensitivity"] == "INTERNAL")
check("an unspecified type is the neutral one, not an invented one", infer("Predicts things.", "", "", screen_model("Predicts things."))["modelType"] == "HYBRID")

# ── the API ──
text = sample_csv()
with authed_client("admin", "Compliance lead") as api:
    tidy()
    r = api.post("/api/model-screening/triage", json={"csv": text})
    check("a list of models is screened", r.status_code == 200, r.text)
    t = r.json()
    by = {x["name"]: x for x in t["results"]}
    check("every row is returned and the tiers add up", t["count"] == 30 and sum(t["tiers"].values()) == 30 and t["tiers"]["Unknown"] == 0, t["tiers"])
    check("the loan, claims and safeguarding models are High", all(by[n]["tier"] == "High" for n in ("Loan default predictor", "Claims fraud scorer", "Child safeguarding risk model")))
    check("the demand forecaster and the weather model are Low", by["Demand forecaster"]["tier"] == "Low" and by["Weather forecast model"]["tier"] == "Low")
    check("the note speaks of models and says it is not a risk assessment", "models" in t["note"] and "not a risk assessment" in t["note"], t["note"])
    loan_r = by["Loan default predictor"]
    check("each result carries its PCS", loan_r["pcs"]["tier"] == "CRITICAL" and loan_r["pcs"]["gate"] == "BLOCKED" and loan_r["score"] == loan_r["pcs"]["score"], loan_r["pcs"])
    reg = {"deployment_context": {"model_type": loan_r["guess"]["modelType"], "ai_criticality": loan_r["guess"]["aiCriticality"], "data_sensitivity": loan_r["guess"]["dataSensitivity"], "domain": "Lending"},
           "system_type": loan_r["guess"]["hostingEnvironment"], "departments": [{"id": "n1", "name": "Lending"}]}
    sc = api.post("/score", json={"registry": reg}).json()["pcs_result"]
    check("it is the same number the platform's own scoring gives for that draft", sc["pcs_final"] == loan_r["pcs"]["score"] and sc["tier"] == loan_r["pcs"]["tier"] and sc["gate"] == loan_r["pcs"]["gate"], (sc["pcs_final"], loan_r["pcs"]))
    check("a route optimiser that merely mentions simulation is not taken for a physics-informed model", by["Warehouse route optimiser"]["guess"]["modelType"] != "PINN" and by["Warehouse route optimiser"]["pcs"]["computable"], by["Warehouse route optimiser"]["guess"])
    a = t["agreement"]
    check("agreement against the other screening is reported", a["compared"] == 30 and a["kappa"] is not None and a["both_flag"] + a["only_we_flag"] + a["only_they_flag"] + a["neither_flag"] == 30, a)
    s1 = api.post("/api/model-screening/triage", json={"csv": text, "sample": {"size": 10, "flagged_share": 0.7, "seed": 3}}).json()["sample"]
    check("the sample works for models too", (s1["size"], s1["from_flagged"], s1["from_not_flagged"]) == (10, 7, 3), s1)
    check("screening stores nothing", api.get("/api/model-screening/inventory").json() == [] or all(i["origin"] != "SCREENED" for i in api.get("/api/model-screening/inventory").json()))

    # ── import
    before = len(api.get("/api/designs?subject=MODEL").json())
    high = [x["id"] for x in t["results"] if x["tier"] == "High"]
    r = api.post("/api/model-screening/import", json={"csv": text, "ids": high})
    check("importing the High models answers", r.status_code == 200, r.text)
    imp = r.json()
    check("each becomes a design in AI Models", imp["created"] == len(high) and imp["updated"] == 0 and len(api.get("/api/designs?subject=MODEL").json()) == before + len(high), imp)
    inv = {i["name"]: i for i in api.get("/api/model-screening/inventory").json()}
    loan_i = inv["Loan default predictor"]
    check("they are in the model inventory as screened, with the tier", loan_i["origin"] == "SCREENED" and loan_i["tier"] == "High" and not loan_i["in_organisation"], loan_i)
    check("with the guessed fields filled in", loan_i["criticality"] == "CRITICAL" and loan_i["data_sensitivity"] == "SENSITIVE_PERSONAL" and loan_i["model_type"], loan_i)
    check("and the PCS it had when it was screened", loan_i["pcs"]["score"] == 95.0 and loan_i["pcs"]["gate"] == "BLOCKED" and "SC-HITL-1" in loan_i["pcs"]["vetoes"], loan_i["pcs"])
    d = api.get(f"/api/designs/{loan_i['design_key']}").json()
    kinds = [n["kind"] for n in d["document"]["nodes"]]
    mdl = next(n for n in d["document"]["nodes"] if n["kind"] == "AI_MODEL")
    check("the design is a real model design: a model node in the designer's own format", d["subject"] == "MODEL" and "AI_MODEL" in kinds and mdl["data"]["name"] == "Loan default predictor", kinds)
    check("the department from the list is there", "DEPARTMENT" in kinds)
    check("it credits no validation, bias check or reviewer", not [k for k in kinds if k not in ("AI_MODEL", "DEPARTMENT")] and d["document"]["edges"] == [])
    check("the guessed fields are named as guesses", set(d["document"]["screening"]["guessed"]) == {"modelType", "aiCriticality", "dataSensitivity", "hostingEnvironment"})

    again = api.post("/api/model-screening/import", json={"csv": text, "ids": high}).json()
    check("importing again creates nothing new", again["created"] == 0 and again["updated"] == len(high) and len(api.get("/api/designs?subject=MODEL").json()) == before + len(high))

    # the designer saves only the keys it knows: the screening must survive its saves
    doc = {k: v for k, v in d["document"].items() if k not in ("source", "screening")}
    doc["nodes"][1]["data"]["domain"] = "lending"
    saved = api.put(f"/api/designs/{loan_i['design_key']}", json={"name": d["name"], "domain": d["domain"], "subject": "MODEL", "document": doc, "version": d["version"]})
    check("the designer can save the design", saved.status_code == 200, saved.text)
    d2 = api.get(f"/api/designs/{loan_i['design_key']}").json()
    check("what the screening found survives the designer's save", d2["document"].get("source") == "screening" and d2["document"]["screening"]["tier"] == "High", list(d2["document"]))

    # a design that already has the name keeps its nodes and gains the screening
    mk = api.post("/api/designs", json={"name": "zz-test existing model", "domain": d["domain"], "subject": "MODEL", "document": {"nodes": [{"id": "n1", "kind": "AI_MODEL", "x": 1, "y": 1, "data": {"name": "zz-test existing model", "modelType": "NN", "aiCriticality": "ADVISORY", "domain": "", "dataSensitivity": "INTERNAL", "hostingEnvironment": "TYPE_1_INHOUSE"}}], "edges": [], "n": 2}}).json()
    r = api.post("/api/model-screening/import", json={"csv": "name,description\nzz-test existing model,Scores applicants for loans.\nzz-test twin,Drafts letters.\nzz-test twin,Drafts letters.\n", "create_designs": False}).json()
    by2 = {i["name"]: i for i in r["items"]}
    check("an existing model design keeps its place and gains the screening", by2["zz-test existing model"]["action"] == "updated" and by2["zz-test existing model"]["design_key"] == mk["design_key"], r)
    ex = api.get(f"/api/designs/{mk['design_key']}").json()
    check("its own nodes are untouched", ex["document"]["nodes"][0]["data"]["modelType"] == "NN" and ex["document"]["screening"]["tier"] in ("High", "Moderate", "Low"))
    check("two models with the same name in one list both get a design", "zz-test twin" in by2 and "zz-test twin (2)" in by2, list(by2))

    # ── the organisation page: outside the structure, then placed
    live = api.get("/api/company").json()["live"]
    out = {x["name"]: x for x in live["unplaced_models"]}
    check("the screened models are listed as outside the organisation", "Loan default predictor" in out and out["Loan default predictor"]["origin"] == "SCREENED" and out["Loan default predictor"]["tier"] == "High", list(out)[:3])
    check("the department and criticality are carried", out["Loan default predictor"]["department"] == "Lending" and out["Loan default predictor"]["criticality"] == "CRITICAL")
    nodes_before = api.get("/api/company").json()["counts"].get("model", 0)
    pl = api.post("/api/model-screening/place", json={"design_key": loan_i["design_key"]})
    check("placing it in the organisation answers", pl.status_code == 200, pl.text)
    c2 = api.get("/api/company").json()
    check("one new model element, nothing else", c2["counts"].get("model", 0) == nodes_before + 1)
    check("it is no longer outside, and the design remembers the organisation", "Loan default predictor" not in {x["name"] for x in c2["live"]["unplaced_models"]} and api.get(f"/api/designs/{loan_i['design_key']}").json()["document"]["org"]["id"] == pl.json()["id"])
    check("the organisation did not start a second design for it", len([x for x in api.get("/api/designs?subject=MODEL").json() if x["name"] == "Loan default predictor"]) == 1)
    check("placing it twice is refused", api.post("/api/model-screening/place", json={"design_key": loan_i["design_key"]}).status_code == 409)
    check("an unknown design is a 404", api.post("/api/model-screening/place", json={"design_key": "d-nope"}).status_code == 404)

    check("a file with no description column is refused", api.post("/api/model-screening/triage", json={"csv": "name,notes\nA,b\n"}).status_code == 422)
    check("no matching ids is refused", api.post("/api/model-screening/import", json={"csv": text, "ids": ["nope"]}).status_code == 422)

with authed_client("auditor", "Read only") as ro:
    check("a read-only role can screen a list of models", ro.post("/api/model-screening/triage", json={"csv": text}).status_code == 200)
    check("and read the inventory", ro.get("/api/model-screening/inventory").status_code == 200)
    check("but cannot import", ro.post("/api/model-screening/import", json={"csv": text}).status_code == 403)
    check("or place a model in the organisation", ro.post("/api/model-screening/place", json={"design_key": "d-x"}).status_code == 403)
tidy()
sys.exit(1 if fails else 0)
