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
from typing import List, Literal, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError

from ollama_client import chat_json


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


def generate_graph(req: ChatRequest) -> GeneratedGraph:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages += [{"role": m.role, "content": m.content} for m in req.history]
    messages.append({"role": "user", "content": req.message})

    raw = chat_json(messages, GeneratedGraph.model_json_schema())

    try:
        return GeneratedGraph.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Model returned a malformed proposal: {exc}",
        ) from exc
