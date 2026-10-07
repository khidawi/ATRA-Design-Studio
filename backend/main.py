"""
ST-AI Design Studio — FastAPI backend
======================================
Endpoints:
  GET  /health            → liveness check (includes database status)
  GET/PATCH /api/organisation → the organisation this instance belongs to
  POST /score             → score a registry block, returns PCSResultBlock
  POST /document/validate → validate a full DesignStudioDocument
  GET  /catalogue/constraints → return all 12 constraint IDs with metadata
  POST /api/designs/import → JSON deployment description → proposed canvas nodes/edges
  POST /api/designs/{id}/assess → registry + domain → DesignRiskAssessment
  POST /api/designs/{id}/compile → registry + domain → CompiledContract (422 unless all-green)
  GET/POST/PUT/PATCH/DELETE /api/policies, POST /api/policies/test → organisation policies
  GET /api/rcr/profiles, POST /api/rcr/score → agent design-time RCR score
  POST /api/agents/analyse → agent design -> OWASP Agentic Top 10 rows and flags (rules from PostgreSQL)
  GET  /api/domains        → domain -> approved rule sets (PostgreSQL)
  GET  /api/regulations, GET /api/rules, PATCH /api/rules/{rule_key} → regulations and rules
  POST /chat               → natural-language description → proposed canvas nodes/edges
  POST /api/agents/draft   → plain-English agent description → Agent design studio graph (Ollama)
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List

from dotenv import load_dotenv
load_dotenv()

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from pydantic import ValidationError

from chat import ChatRequest, GeneratedGraph, generate_graph
from agent_chat import AgentDesign, AgentDraftRequest, generate_agent_design
from schema import (
    ScoreRequest, ScoreResponse,
    DesignStudioDocument,
    VETO_CLASS_CONSTRAINTS, MODULATING_CLASS_CONSTRAINTS,
)
from scoring_bridge import score_registry
from compliance_schema import CompiledContract, DeploymentDescription, DesignRiskAssessment
from design_import import json_to_canvas_graph
from db.bootstrap import init_database
from db.session import SessionLocal, engine, get_session
from organisation import router as organisation_router
from regulations import require_domain, router as regulations_router
from compliance_engine import AssessRequest, CompileRequest, assess_design, compile_design, to_design_graph
from agent_analysis import router as agent_analysis_router
from policies import router as policies_router
from rcr import router as rcr_router
from agent_import import router as agent_import_router
from agent_registry import router as agent_registry_router
from coverage_scorecard import router as coverage_router
from drift import router as drift_router
from auth import AuthMiddleware, AuthUser, current_user, keys_router, router as auth_router, users_router
from audit import router as audit_router
from exports import router as exports_router
from overview import router as overview_router
from runtime import router as runtime_router
from packs import router as packs_router
from findings import router as findings_router
from design_store import router as design_store_router, store_contract
from ingestion import fail_interrupted_runs, router as ingestion_router

# Tropos catalogue for constraint metadata
from framework.tropos_catalogue import CANONICAL_CONSTRAINTS

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_database()  # wait for PostgreSQL, apply migrations, ensure the default organisation
    with SessionLocal() as session:
        fail_interrupted_runs(session)
    yield


app = FastAPI(
    title="ST-AI Design Studio API",
    version="1.0.0",
    lifespan=lifespan,
    description=(
        "FastAPI backend wrapping the validated ST-AI PCS engine. "
        "The scoring engine (Algorithms 1-3) is used completely unchanged."
    ),
)

app.include_router(organisation_router)
app.include_router(regulations_router)
app.include_router(agent_analysis_router)
app.include_router(policies_router)
app.include_router(rcr_router)
app.include_router(ingestion_router)
app.include_router(design_store_router)
app.include_router(agent_import_router)
app.include_router(agent_registry_router)
app.include_router(findings_router)
app.include_router(drift_router)
app.include_router(coverage_router)
app.include_router(packs_router)
app.include_router(overview_router)
app.include_router(runtime_router)
app.include_router(exports_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(keys_router)
app.include_router(audit_router)

app.add_middleware(AuthMiddleware)      # added first, so CORS (below) wraps it and answers preflight requests itself
app.add_middleware(
    CORSMiddleware,
    # The session cookie is sent only to these origins; "*" with credentials would let any site act as the signed-in user.
    allow_origins=[o.strip() for o in os.environ.get("ASTRA_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8765,http://127.0.0.1:8765").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> Dict[str, Any]:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        database = "ok"
    except Exception:
        database = "unavailable"
    return {
        "status": "ok" if database == "ok" else "degraded",
        "database": database,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


# ── Scoring ───────────────────────────────────────────────────────────────────

@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest) -> ScoreResponse:
    """
    Score a registry block using the existing ST-AI rule engine.
    The engine is called completely unchanged through scoring_bridge.py.
    """
    try:
        pcs_result, warnings = score_registry(req.registry)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return ScoreResponse(pcs_result=pcs_result, warnings=warnings)


# ── Document validation ────────────────────────────────────────────────────────

@app.post("/document/validate")
def validate_document(doc: DesignStudioDocument) -> Dict[str, Any]:
    """
    Validate a full DesignStudioDocument (schema + veto constraints),
    re-score it, and return whether it matches any embedded ground_truth_gate.
    """
    try:
        pcs_result, warnings = score_registry(doc.registry)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    fixture_match: Dict[str, Any] = {}
    if doc.validation and doc.validation.ground_truth_gate:
        computed = pcs_result.gate
        expected = doc.validation.ground_truth_gate
        fixture_match = {
            "expected_gate": expected,
            "computed_gate": computed,
            "match": computed == expected,
        }

    return {
        "pcs_result": pcs_result.model_dump(),
        "warnings": warnings,
        "fixture_validation": fixture_match,
    }


# ── Constraint catalogue ───────────────────────────────────────────────────────

@app.get("/catalogue/constraints")
def get_constraints() -> List[Dict[str, Any]]:
    """
    Return all 12 security constraints with their class (veto/modulating),
    because text, and standard references.
    Drawn directly from the existing tropos_catalogue — not duplicated here.
    """
    result = []
    for sc in CANONICAL_CONSTRAINTS:
        result.append({
            "constraint_id": sc.constraint_id,
            "name":          sc.name,
            "class":         "veto" if sc.constraint_id in VETO_CLASS_CONSTRAINTS else "modulating",
            "because":       getattr(sc, "because", ""),
            "standard_refs": getattr(sc, "standard_refs", []),
            "actor_role":    sc.actor_role.value if hasattr(sc, "actor_role") and sc.actor_role else None,
        })
    return result


# ── Design import (Task 1.1) ─────────────────────────────────────────────────

@app.post("/api/designs/import", response_model=GeneratedGraph)
def import_design(desc: DeploymentDescription) -> GeneratedGraph:
    """
    Validate an uploaded JSON deployment description against the Phase 0
    schema and map it to a proposed canvas graph. FastAPI validates the
    request body against DeploymentDescription before this function ever
    runs (422 on a malformed document); json_to_canvas_graph() raises
    ValueError for a structurally valid document whose field values the
    canvas node types don't recognise (e.g. an unknown model_type).
    """
    try:
        return json_to_canvas_graph(desc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ── Design-time compliance/risk assessment (Task 1.3) ──────────────────────────

@app.post("/api/designs/{design_id}/assess", response_model=DesignRiskAssessment)
def assess(design_id: str, req: AssessRequest, session: Session = Depends(get_session)) -> DesignRiskAssessment:
    """
    Run compliance_engine.py's rule evaluation for the given domain against
    the posted registry's existing GovernanceState (the same evidence-gate
    /score already reads). There is no server-side design store yet, so
    design_id is carried through to the response as deployment_id rather
    than used to look anything up — the assessment itself is computed
    fresh from the request body every call, same statelessness as /score.
    """
    try:
        assessment = assess_design(
            req.registry, require_domain(session, req.domain), req.constraint_node_ids,
            to_design_graph(req.design_graph),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    assessment.deployment_id = design_id
    return assessment


# ── Compile to contract (Task 1.5) ──────────────────────────────────────────────

@app.post("/api/designs/{design_id}/compile", response_model=CompiledContract)
def compile_design_endpoint(
    design_id: str, req: CompileRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)
) -> CompiledContract:
    """
    Refuses server-side — not just client-side — unless the design is
    all-green. compile_design() always re-runs the assessment itself, so
    this cannot be bypassed by a direct API call that skips /assess or
    sends a falsified overall_status; there is no overall_status field on
    CompileRequest at all for a caller to lie with.
    """
    try:
        contract = compile_design(
            req.registry, require_domain(session, req.domain), req.graph,
            req.constraint_node_ids, design_id, user.name, to_design_graph(req.design_graph),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    store_contract(session, contract, design_id)
    return contract


# ── Chatbot integration point ───────────────────────────────────────────────

@app.post("/chat", response_model=GeneratedGraph)
def chat(req: ChatRequest) -> GeneratedGraph:
    """
    Turn a natural-language message into proposed canvas nodes/edges.
    Additive only — does not see or modify the client's existing canvas
    state, only the conversation history it is given.
    """
    return generate_graph(req)


# ── Agent design studio: draft a design from a plain-English description (Ollama) ──────────────

@app.post("/api/agents/draft", response_model=AgentDesign)
def draft_agent(req: AgentDraftRequest) -> AgentDesign:
    """
    Turn a plain-English description of an agent into a proposed design for the Agent design studio.
    Everything it returns is a proposal until a person ratifies the design; controls the description
    did not mention are left out rather than invented.
    """
    return generate_agent_design(req)
