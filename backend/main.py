"""
ST-AI Design Studio — FastAPI backend
======================================
Endpoints:
  GET  /health            → liveness check
  POST /score             → score a registry block, returns PCSResultBlock
  POST /document/validate → validate a full DesignStudioDocument
  GET  /catalogue/constraints → return all 12 constraint IDs with metadata
  POST /api/designs/import → JSON deployment description → proposed canvas nodes/edges
  GET  /api/domains        → domain -> regulation rule-set registry
  POST /chat               → natural-language description → proposed canvas nodes/edges
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timezone
from typing import Any, Dict, List

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from chat import ChatRequest, GeneratedGraph, generate_graph
from schema import (
    ScoreRequest, ScoreResponse,
    DesignStudioDocument,
    VETO_CLASS_CONSTRAINTS, MODULATING_CLASS_CONSTRAINTS,
)
from scoring_bridge import score_registry
from compliance_schema import ComplianceDomain, DeploymentDescription, list_domains
from design_import import json_to_canvas_graph

# Tropos catalogue for constraint metadata
from framework.tropos_catalogue import CANONICAL_CONSTRAINTS

app = FastAPI(
    title="ST-AI Design Studio API",
    version="1.0.0",
    description=(
        "FastAPI backend wrapping the validated ST-AI PCS engine. "
        "The scoring engine (Algorithms 1-3) is used completely unchanged."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # tightened once frontend origin is known
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "timestamp": datetime.now(tz=timezone.utc).isoformat()}


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


# ── Domain selector (Task 1.2) ────────────────────────────────────────────────

@app.get("/api/domains", response_model=List[ComplianceDomain])
def domains() -> List[ComplianceDomain]:
    """
    The domain -> rule-set mapping from Phase 0. Switching the frontend's
    Assessment Domain dropdown only changes which of these rule sets
    Task 1.3's compliance engine will run against later — it never touches
    the canvas graph itself.
    """
    return list_domains()


# ── Chatbot integration point ───────────────────────────────────────────────

@app.post("/chat", response_model=GeneratedGraph)
def chat(req: ChatRequest) -> GeneratedGraph:
    """
    Turn a natural-language message into proposed canvas nodes/edges.
    Additive only — does not see or modify the client's existing canvas
    state, only the conversation history it is given.
    """
    return generate_graph(req)
