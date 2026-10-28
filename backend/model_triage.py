"""
First-pass screening of a list of AI models from their descriptions, and importing a chosen set into AI Models (Essex demo, Phase 1).

An agent is screened by reading its description for risk signals (agent_triage.py). A model is not: models are assessed by the ST-AI pre-deployment compliance
score, the PCS, so the screen computes that. What a description can honestly give the PCS is the model's deployment context: what kind of model it seems to be,
how critical its output is (advisory, operational, critical, safety critical), how sensitive its data is, and how it is hosted. Those are read from the description
(and named as guesses), then the real PCS engine is run on that draft with nothing yet evidenced, exactly as the model designer would score it on opening. The result
is the engine's own: the PCS (0 to 100, higher is riskier), its tier, its gate, the critical constraints still unmet and the blockers in its words. What moves it is
evidence in the model designer: it is not a verdict on the model, it is where the model stands before anyone has shown anything. The description is read only to set
the inputs, and what it cannot tell you (how it was trained, validated and checked for bias, who reviews it) is listed for each model.

Importing is a separate, explicit step. Each chosen model becomes a design in the model designer (subject MODEL) with a first draft: the model's type, criticality,
data sensitivity and hosting, each guessed from the description and marked as a guess. It never credits a control (a validation, a bias check, a reviewer) that the
description only claims. The screening is kept on the design, so the model inventory and the organisation map can show it. Nothing is stored by the screen itself.

  POST /api/model-screening/triage        screen a list (nothing stored)
  POST /api/model-screening/import        add a chosen set to AI Models, a draft design each
  GET  /api/model-screening/inventory     every model design, with its origin and screening
  POST /api/model-screening/place         put a model that is outside the organisation into it
"""
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_triage import MAX_IMPORT, TriageRequest, _screened, apply_rules, summarise
from schema import RegistryBlock
from scoring_bridge import score_registry
from auth import AuthUser, current_user
from db.models import CompanyNode, Design, Domain, ModelMonitor
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/model-screening", tags=["models"])

HIGH_AT, MODERATE_AT = 6, 3

SIGNALS = [
    ("decision", 3, "Scores, ranks or decides about people (credit, eligibility, hiring, triage, prediction of an outcome)",
     r"\b(credit scor\w*|scor(?:e|es|ing|er)s? (?:\w+ )?(?:applicants?|applications?|customers?|candidates?|claims?|patients?|residents?|people|borrowers?|cases?|students?|essays?|submissions?|pupils?)|rank\w* (?:\w+ )?(?:candidates?|applicants?|cases?|patients?)|shortlist\w*|eligib\w*|underwrit\w*|loan (?:approval|decision)\w*|approv\w+ or (?:refus|reject|den)\w*|triag\w*|prioriti[sz]\w*|risk scor\w*|predict\w* (?:\w+ )?(?:default|churn|risk|likelihood|readmission|re-?offend\w*|recidivism|attrition|outcomes?|need)|risk of|likelihood of)"),
    ("consequential", 2, "Used in a domain where outputs can have legal or similarly significant effects (lending, insurance, employment, education, benefits, policing, health, housing)",
     r"\b(credit|lending|loans?|mortgage\w*|insurance|insurer|underwrit\w*|recruit\w*|hiring|employment|admissions?|exam\w*|grading|benefits?|welfare|policing|police|immigration|asylum|housing|tenan\w+|clinical|diagnos\w*|patients?|care plan\w*|social care|safeguard\w*)"),
    ("vulnerable", 3, "Concerns children, vulnerable adults or people in care",
     r"\b(child\w*|young people|pupils?|vulnerab\w*|older (?:people|adults)|disabilit\w*|disabled|special educational|mental health|homeless\w*|looked[- ]after|foster\w*|care leavers?)"),
    ("biometric", 3, "Identifies or infers things about people from their face, voice, body or behaviour (biometrics, emotion, surveillance)",
     r"\b(facial\w*|face (?:recognition|matching|detection)|biometric\w*|fingerprint\w*|voice (?:recognition|print|identif\w*)|emotion (?:recognition|detection)|detect\w* (?:[\w']+ )?emotion\w*|gait|surveillance|cctv|lip[- ]read\w*)"),
    ("sensitive", 2, "Uses sensitive or special category data (health, genetic, ethnic, religious, criminal)",
     r"\b((?<!environmental )health\w*|medical\w*|clinical\w*|genetic\w*|genom\w*|ethnic\w*|racial\w*|religio\w*|criminal\w*|offend\w*|sexual\w*|trade union|x-?rays?|scans?\b|radiolog\w*|pathology)"),
    ("personal", 1, "Learns from or is applied to personal data about customers, residents, patients, staff or applicants",
     r"\b(personal data|customers?|residents?|citizens?|service users?|patients?|clients?|applicants?|employees?|staff|candidates?|pupils?|students?|claimants?|borrowers?|policyholders?|households?|individuals?)"),
    ("automated", 2, "Used automatically, in real time or without a person in the loop",
     r"\b(automatic\w*|automated|real[- ]time|straight[- ]through|without (?:human|manual|staff|a person)|auto-?(?:approv|decid|reject|block)\w*|instant decision\w*)"),
    ("generative", 1, "A generative or language model (free text out)",
     r"\b(generat\w*|llm|large language|language model|gpt|chatbot|copilot|summari[sz]\w*|assistant\w*|embedding\w*|rag\b)"),
    ("third_party", 1, "Provided by an outside supplier or reached through an API, so its internals cannot be inspected",
     r"\b(supplier|vendor|third[- ]party|api|saas|openai|anthropic|google|microsoft|amazon|aws|azure|hosted by|external provider|off[- ]the[- ]shelf)"),
]
MITIGATIONS = [
    ("human_review", -2, "Says a person reviews, can override or makes the final decision",
     r"\b(human (?:review|in the loop|oversight|check)\w*|reviewed by|approved by|checked by|signed off|oversight|final decision (?:is )?(?:made )?by|can override|overridden by|advisory only|decision support)"),
    ("no_personal", -3, "Says it uses no personal data or only anonymised or aggregate data",
     r"\b(no personal data|anonymi[sz]ed|aggregate\w*|synthetic data|non-personal|open data|public data|statistical|sensor data|machine data)"),
    ("internal_only", -1, "Says it is for internal use, forecasting or analytics",
     r"\b(internal (?:use|only|tool)|staff only|analytics only|dashboard|forecast\w*|demand planning|route optimi[sz]\w*|predictive maintenance|anomaly detection on (?:machines|equipment|servers)|spell|translation|transcription)"),
]
QUESTIONS = [
    ("training", "What was it trained on, and does that data include personal or special category data?", r"\b(train\w*|dataset\w*|data set\w*|learn\w* from|fine-?tun\w*)"),
    ("validation", "How was it validated, and for which groups was accuracy and bias checked?", r"\b(validat\w*|tested|testing|bias|fairness|accuracy|evaluat\w*|benchmark\w*)"),
    ("metrics", "Which accuracy and fairness metrics does it report, and what are the thresholds?", r"\b(metric\w*|threshold\w*|auc|f1|precision|recall|error rate|false (?:positive|negative))"),
    ("oversight", "Does a person review its outputs, and can they override it?", r"\b(human|review\w*|override\w*|oversight|checked|signed off|advisory)"),
    ("monitoring", "Is its drift and performance monitored after deployment?", r"\b(monitor\w*|drift|logg\w*|audit\w*|retrain\w*)"),
    ("hosting", "Is it built in-house, fine-tuned or a third-party API?", r"\b(in-house|fine-?tun\w*|api|vendor|supplier|hosted|cloud|open[- ]source|built by)"),
    ("owner", "Who owns it and who can switch it off?", r"\b(owner|owned by|responsible|head of|team)"),
]


GROUP = {"CRITICAL": "High", "HIGH": "High", "MEDIUM": "Moderate", "LOW": "Low"}      # the PCS tier, grouped for the list's summary and its comparison with another screening
NOT_COMPUTABLE = 900.0                                                                  # the engine reports 999 when a score cannot be computed (a physics-informed model with no domain rule)


def pcs_of(guess: Dict[str, str], department: str) -> Optional[Dict[str, Any]]:
    """The ST-AI PCS of a draft design with this deployment context and nothing evidenced, as the model designer would score it. None if the engine refuses it."""
    reg = RegistryBlock(deployment_context={"model_type": guess["modelType"], "ai_criticality": guess["aiCriticality"], "data_sensitivity": guess["dataSensitivity"], "domain": department or ""},
                        system_type=guess["hostingEnvironment"], departments=([{"id": "n1", "name": department}] if department else []))
    try:
        res, _ = score_registry(reg)
    except Exception:
        return None
    d = res.model_dump()
    final = float(d["pcs_final"])
    blockers = [b for b in ((d.get("raw_breakdown") or {}).get("blockers") or [])]
    return {"score": None if final >= NOT_COMPUTABLE else round(final, 1), "computable": final < NOT_COMPUTABLE, "tier": d["tier"], "gate": d["gate"],
            "vetoes": list(d.get("unmet_veto_constraints") or []), "blockers": [str(b)[:260] for b in blockers[:5]],
            "pillars": {k: round(float(v), 1) for k, v in (d.get("pillar_vector") or {}).items()}}


def screen_model(description: str, department: str = "", supplier: str = "", high_at: int = HIGH_AT, moderate_at: int = MODERATE_AT) -> Dict[str, Any]:
    """One model: what the description says (the signals that set the deployment context), the PCS of that draft, and what the description leaves out. high_at and
    moderate_at are not used: the tier is the PCS's own."""
    reading = apply_rules(description, department, supplier, high_at, moderate_at, SIGNALS, MITIGATIONS, QUESTIONS)
    if not description.strip():
        return {"score": 0, "tier": "Unknown", "needs_investigation": True, "signals": [], "not_stated": ["There is no description to screen. Add one, or assess the design directly."], "pcs": None, "guess": None}
    guess = infer(description, department, supplier, reading)
    pcs = pcs_of(guess, department)
    if pcs is None:
        group, score = "Unknown", 0
    elif not pcs["computable"]:
        group, score = "Unknown", 100                       # blocked outright: it needs a domain rule before it can be scored; rank it with the highest
    else:
        group, score = GROUP.get(pcs["tier"], "Unknown"), pcs["score"]
    text = " ".join(x for x in (description, department, supplier) if x).lower()
    missing = [q for key, q, pattern in QUESTIONS if not re.search(pattern, text)] if group != "Low" else []
    return {"score": score, "tier": group, "needs_investigation": group in ("High", "Moderate", "Unknown"), "signals": reading["signals"], "not_stated": missing, "pcs": pcs, "guess": guess}


def infer(description: str, department: str, supplier: str, found: Dict[str, Any]) -> Dict[str, str]:
    """The fields of a draft model, guessed from the description. Each is a guess a person must confirm in the designer."""
    text = " ".join(x for x in (description, department, supplier) if x).lower()
    keys = {h["key"] for h in found["signals"]}
    if re.search(r"\b(llm|language model|gpt|chatbot|copilot|generative|summari[sz]\w*|embedding)", text):
        mtype = "LLM"
    elif re.search(r"\b(image|vision|x-?ray|scan|photograph\w*|cnn|facial|face|video|radiolog\w*|pathology|cctv)", text):
        mtype = "CNN"
    elif re.search(r"\breinforcement|\brl\b|bandit", text):
        mtype = "RL"
    elif re.search(r"\b(random forest|gradient boost\w*|xgboost|lightgbm|ensemble|decision tree|scorecard|logistic regression|regression)", text):
        mtype = "ENSEMBLE"
    elif re.search(r"\b(physics[- ]informed|physical laws?|pinn)\b", text):
        mtype = "PINN"
    elif re.search(r"\bneural|deep learning|lstm|transformer", text):
        mtype = "NN"
    else:
        mtype = "HYBRID"                                    # the neutral choice when the description does not say
    if re.search(r"\b(safety[- ]critical|autonomous vehicle|medical device|diagnos\w*|clinical decision|surgical|insulin)", text):
        crit = "SAFETY_CRITICAL"
    elif found["tier"] == "High" or ("decision" in keys and keys & {"vulnerable", "biometric", "consequential"}):
        crit = "CRITICAL"
    elif found["tier"] == "Moderate":
        crit = "OPERATIONAL"
    else:
        crit = "ADVISORY"
    sens = "SPECIAL_CATEGORY" if keys & {"sensitive", "biometric"} else ("SENSITIVE_PERSONAL" if keys & {"personal", "vulnerable"} else "INTERNAL")
    if "no_personal" in keys and not keys & {"sensitive", "biometric"}:
        sens = "INTERNAL"
    host = "TYPE_2_FINETUNED" if re.search(r"fine-?tun", text) else ("TYPE_3_THIRDPARTY_API" if "third_party" in keys else "TYPE_1_INHOUSE")
    return {"modelType": mtype, "aiCriticality": crit, "dataSensitivity": sens, "hostingEnvironment": host}


def skeleton(name: str, description: str, department: str, supplier: str, found: Dict[str, Any]) -> Dict[str, Any]:
    """A first draft of a model design (the model designer's own node format). Only the model and, if the list names one, its department: nothing that credits a
    validation, a bias check or a reviewer, because a description only claims those."""
    guess = found.get("guess") or infer(description, department, supplier, found)
    nodes: List[Dict[str, Any]] = []
    if department:
        nodes.append({"id": "n1", "kind": "DEPARTMENT", "x": 40, "y": 40, "w": 260, "h": 200, "data": {"name": department[:120], "reportsToDepartmentId": ""}})
    nodes.append({"id": "n2", "kind": "AI_MODEL", "x": 340, "y": 60, "data": {"name": name, **guess, "domain": (department or "")[:120]}})
    return {"nodes": nodes, "edges": [], "n": 3, "source": "screening",
            "screening": {"tier": found["tier"], "score": found["score"], "pcs": found.get("pcs"), "basis": "description only", "guessed": sorted(guess)}}


def _domain(session: Session) -> str:
    d = session.scalar(select(Domain.domain_key).where(Domain.subject == "MODEL").order_by(Domain.domain_key != "GENERAL", Domain.position, Domain.domain_key))
    if d is None:
        raise HTTPException(status_code=409, detail="There is no model domain to put the designs in.")
    return d


@router.post("/triage")
def triage(body: TriageRequest) -> Dict[str, Any]:
    results, columns = _screened(body, screen_model)
    return summarise(results, columns, body, "models")


class ImportRequest(TriageRequest):
    ids: Optional[List[str]] = None


def _model_node(doc: Dict[str, Any]) -> Dict[str, Any]:
    return next((n for n in doc.get("nodes", []) if n.get("kind") == "AI_MODEL"), {})


@router.post("/import")
def import_models(body: ImportRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    results, _ = _screened(body, screen_model)
    if body.ids is not None:
        wanted = {str(i) for i in body.ids}
        results = [r for r in results if r["id"] in wanted]
    if not results:
        raise HTTPException(status_code=422, detail="No models selected.")
    if len(results) > MAX_IMPORT:
        raise HTTPException(status_code=422, detail=f"Import at most {MAX_IMPORT} models at a time; choose the ones that need a closer look.")
    org = current_organisation(session)
    domain = _domain(session)
    now = datetime.now(timezone.utc).isoformat()
    existing = {d.name.strip().lower(): d for d in session.scalars(select(Design).where(Design.subject == "MODEL"))}
    seen: Dict[str, int] = {}
    items: List[Dict[str, Any]] = []
    for r in results:
        name = (r["name"] or "").strip()[:190]
        if len(name) < 2:
            items.append({"id": r["id"], "name": r["name"], "action": "skipped", "reason": "The name is too short."})
            continue
        seen[name.lower()] = seen.get(name.lower(), 0) + 1
        if seen[name.lower()] > 1:
            name = f"{name} ({seen[name.lower()]})"
        shown = {"tier": r["tier"], "score": r["score"], "pcs": r["pcs"], "guess": r["guess"], "needs_investigation": r["needs_investigation"], "signals": r["signals"], "not_stated": r["not_stated"],
                 "description": r["description"][:600], "department": r["department"], "supplier": r["supplier"], "their_flag": r["their_flag"],
                 "basis": "description only", "screened_at": now, "screened_by": user.name}
        design = existing.get(name.lower())
        if design is None:
            doc = skeleton(name, r["description"], r["department"], r["supplier"], r)
            doc["screening"].update(shown)
            design = Design(design_key="d-" + secrets.token_hex(5), organisation_id=org.id, subject="MODEL", name=name, domain_key=domain, document=doc)
            session.add(design)
            existing[name.lower()] = design
            action = "created"
        else:
            doc = dict(design.document or {})                        # a new dict, so the change is seen; the design's own nodes are never touched
            doc["screening"] = {**(doc.get("screening") or {}), **shown}
            design.document = doc
            action = "updated"
        items.append({"id": r["id"], "name": name, "design_key": design.design_key, "tier": r["tier"], "action": action})
    session.commit()
    return {"created": sum(1 for i in items if i["action"] == "created"), "updated": sum(1 for i in items if i["action"] == "updated"),
            "skipped": sum(1 for i in items if i["action"] == "skipped"), "items": items}


@router.get("/inventory")
def inventory(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Every model design: where it came from, what it is, how it was screened, whether it is in the organisation and whether production data reaches it."""
    monitors = {m.design_key: m.key for m in session.scalars(select(ModelMonitor)) if m.design_key}
    out = []
    for d in session.scalars(select(Design).where(Design.subject == "MODEL").order_by(Design.created_at.desc())):
        doc = d.document or {}
        sc = doc.get("screening") or {}
        org_id = (doc.get("org") or {}).get("id")
        node = _model_node(doc).get("data", {})
        out.append({"design_key": d.design_key, "name": d.name, "origin": "SCREENED" if doc.get("source") == "screening" else ("ORGANISATION" if org_id else "DESIGNED"),
                    "in_organisation": bool(org_id), "model_type": node.get("modelType"), "criticality": node.get("aiCriticality"), "data_sensitivity": node.get("dataSensitivity"),
                    "hosting": node.get("hostingEnvironment"), "tier": sc.get("tier"), "score": sc.get("score"), "pcs": sc.get("pcs"), "screening": sc or None, "monitor": monitors.get(d.design_key),
                    "nodes": len(doc.get("nodes", [])), "updated_at": d.updated_at.isoformat() if d.updated_at else None})
    return out


class PlaceRequest(BaseModel):
    design_key: str = Field(min_length=3)


@router.post("/place")
def place(body: PlaceRequest, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """Puts a model that is outside the organisation into it: one new element of type model, and the design remembers it, so the organisation does not
    start a second design for it. Nothing else of the organisation changes."""
    import company
    org = current_organisation(session)
    d = session.scalar(select(Design).where(Design.design_key == body.design_key, Design.subject == "MODEL"))
    if d is None:
        raise HTTPException(status_code=404, detail="No such model design.")
    doc = dict(d.document or {})
    if (doc.get("org") or {}).get("id"):
        raise HTTPException(status_code=409, detail="This model is already in the organisation.")
    types = {n.ext_id for n in session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id))}
    base, ext, n = f"MD-{company.slug(d.name)}", None, 2
    ext = base
    while ext in types:
        ext, n = f"{base}-{n}", n + 1
    sc = doc.get("screening") or {}
    risk = {"High": "high", "Moderate": "limited", "Low": "minimal"}.get(sc.get("tier") or "", "")
    props = company.clean_props("model", {"purpose": (sc.get("description") or "")[:300], "risk_class": risk})
    session.add(CompanyNode(organisation_id=org.id, ext_id=ext, type="model", name=d.name[:200], props=props))
    doc["org"] = {"id": ext, "name": d.name}
    d.document = doc
    session.commit()
    return {"id": ext, "design_key": d.design_key}
