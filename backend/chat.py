"""
ST-AI Design Studio — chatbot integration point
=================================================================
Turns a natural-language description of an organisation/deployment into
canvas elements. The target shape (GeneratedGraph below) mirrors the
frontend's node schema (frontend/src/nodeSchema.tsx) field-for-field, so
the chatbot and the manual properties panel are two front-ends over the
same node contract — exactly the "forms become models, chat becomes an
alternate way to fill the same models" design this was scoped for.

Generation is additive only: each turn proposes new nodes/edges based on
the latest message. It does not reference or edit nodes already on the
canvas — the frontend owns final placement, and the user reviews/edits
everything through the existing properties panel (Inspector.tsx), same
as any manually-added node.

Runs against a locally-hosted model via Ollama (https://ollama.com) —
no per-call API cost, no API key. Requires Ollama running locally with
a model pulled; see backend/.env.example.
"""
import json
import os
from typing import List, Literal, Optional

import httpx
from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")


# ── Target shape — mirrors frontend/src/nodeSchema.tsx field-for-field ───────

class GeneratedDepartment(BaseModel):
    temp_id: str = Field(description="Short local id to reference this department from actors/edges, e.g. 'dept-ds'.")
    name: str
    reports_to_temp_id: Optional[str] = Field(default=None, description="temp_id of the parent department, if any.")


class GeneratedActor(BaseModel):
    temp_id: str
    subtype: Literal["TRAINER", "VALIDATOR", "DEPLOYER", "OPERATOR", "CONSUMER"]
    identity: str = Field(default="", description="Display name, e.g. a team or person, e.g. 'Data Science ML Team'.")
    department_temp_id: Optional[str] = Field(default=None, description="temp_id of the department this actor belongs to, if any.")


class GeneratedAIModel(BaseModel):
    temp_id: str
    name: str = ""
    model_type: Literal["NN", "RL", "ENSEMBLE", "PINN", "LLM", "CNN", "HYBRID"] = "LLM"
    ai_criticality: Literal["ADVISORY", "OPERATIONAL", "CRITICAL", "SAFETY_CRITICAL"] = "OPERATIONAL"
    domain: str = ""
    data_sensitivity: Literal[
        "PUBLIC", "INTERNAL", "CONFIDENTIAL", "SENSITIVE_PERSONAL", "SPECIAL_CATEGORY"
    ] = "INTERNAL"
    hosting_environment: Literal[
        "TYPE_1_INHOUSE", "TYPE_2_FINETUNED", "TYPE_3_THIRDPARTY_API"
    ] = "TYPE_1_INHOUSE"


class GeneratedDeploymentEnv(BaseModel):
    temp_id: str
    name: str = ""
    description: str = ""


class GeneratedConstraint(BaseModel):
    temp_id: str
    constraint_id: Literal[
        "SC-DPIA-1", "SC-HITL-1", "SC-HALLU-1", "SC-MAP-1", "SC-CHALL-1", "SC-LIAB-1",
        "SC-MC-1", "SC-TRAIN-1", "SC-RCF-1", "SC-RCF-2", "SC-DOMAIN-1", "SC-CONSENT-1",
    ]
    status: Literal["NOT_YET_DETERMINED", "UNMET", "SATISFIED"] = "NOT_YET_DETERMINED"
    evidence: str = Field(default="", description="Required if status is SATISFIED, else leave empty.")


class GeneratedEdge(BaseModel):
    from_temp_id: str
    to_temp_id: str


class GeneratedGraph(BaseModel):
    """
    Shared "proposed graph" shape consumed by the frontend's
    applyGeneratedGraph() — produced either by the chatbot (generate_graph
    below) or by JSON deployment-description import (design_import.py).
    `reply` is chat-specific and left empty by the importer.
    """
    reply: str = Field(default="", description="One short sentence acknowledging what was added, shown in the chat.")
    departments: List[GeneratedDepartment] = Field(default_factory=list)
    actors: List[GeneratedActor] = Field(default_factory=list)
    ai_models: List[GeneratedAIModel] = Field(default_factory=list)
    deployment_environments: List[GeneratedDeploymentEnv] = Field(default_factory=list)
    constraints: List[GeneratedConstraint] = Field(default_factory=list)
    edges: List[GeneratedEdge] = Field(default_factory=list)


# ── Request / response ────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = Field(default_factory=list)


SYSTEM_PROMPT = """You are the modelling assistant inside ST-AI Design Studio, a canvas tool \
for mapping AI deployments onto a Secure Tropos-style actor/department/model graph.

Given a user's natural-language description of their organisation, departments, actors, and \
AI deployment, propose the Department, Actor, AI Model, and Constraint nodes (and the edges \
between them) that represent it. Respond with ONLY a single JSON object matching the schema \
you have been given — no prose before or after it, no markdown code fences.

Rules:
- Only propose NEW elements based on the user's latest message. Do not repeat elements from \
earlier in the conversation — the canvas already has those.
- Every actor MUST have subtype one of TRAINER, VALIDATOR, DEPLOYER, OPERATOR, CONSUMER, \
chosen from what the message actually describes (a data scientist who builds the model is a \
TRAINER; whoever signs off on it is a VALIDATOR; whoever puts it into production is a \
DEPLOYER; whoever runs it day-to-day is an OPERATOR; whoever acts on its output is a CONSUMER).
- Only set department_temp_id / reports_to_temp_id when the message actually describes that \
structure — do not invent departments or hierarchy that wasn't mentioned.
- Only propose a Constraint node when the message names a specific compliance/governance \
concern (e.g. "we need a DPIA", "GDPR", "human oversight", "right to an explanation", \
"role separation", "hallucination policy"). Map it to the single closest constraint_id — do \
not propose constraints speculatively.
- edges connect temp_ids of nodes you are proposing in THIS turn.
- If the message is a question or doesn't describe any deployment elements, return empty \
lists for every array and use `reply` to answer or ask a clarifying question instead.
- Keep `reply` to one short sentence.
"""


def _extract_json_object(text: str) -> dict:
    """Best-effort extraction of a JSON object from a local model's raw
    output, which — unlike a provider with native structured-output
    support — may still wrap it in prose or a markdown fence despite
    instructions."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in model output")
    return json.loads(text[start : end + 1])


def generate_graph(req: ChatRequest) -> GeneratedGraph:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages += [{"role": m.role, "content": m.content} for m in req.history]
    messages.append({"role": "user", "content": req.message})

    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "format": GeneratedGraph.model_json_schema(),
        "options": {"temperature": 0.2},
    }

    try:
        resp = httpx.post(
            f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=120.0
        )
        resp.raise_for_status()
    except httpx.ConnectError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not reach Ollama at {OLLAMA_BASE_URL}. "
                    "Is it installed and running? See backend/.env.example.",
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Ollama returned an error: {exc.response.status_code} {exc.response.text}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Ollama: {exc}") from exc

    content = resp.json().get("message", {}).get("content", "")

    try:
        raw = json.loads(content)
    except json.JSONDecodeError:
        try:
            raw = _extract_json_object(content)
        except (ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Model did not return valid JSON: {exc}",
            ) from exc

    try:
        return GeneratedGraph.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Model returned a malformed proposal: {exc}",
        ) from exc
