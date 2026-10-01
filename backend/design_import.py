"""
ST-AI Design Studio — JSON deployment-description import (Task 1.1).

Maps a Phase 0 DeploymentDescription (backend/compliance_schema.py) to the
same GeneratedGraph shape the chatbot already produces (backend/chat.py) —
temp_id-addressed nodes the frontend turns into positioned canvas nodes via
applyGeneratedGraph(). Reusing that shape means import and chat share one
"proposed graph -> canvas" path instead of two.

Only structural fields are mapped (departments, actors, AI models,
deployment environments). No constraint nodes are generated from an
import — DeploymentDescription has no field for them, so there is nothing
to auto-satisfy: every veto-class constraint keeps its GovernanceState
default of NOT_YET_DETERMINED when the user later adds one by hand.
"""
from pydantic import ValidationError

from chat import (
    GeneratedActor,
    GeneratedAIModel,
    GeneratedDepartment,
    GeneratedDeploymentEnv,
    GeneratedEdge,
    GeneratedGraph,
)
from compliance_schema import DeploymentDescription


def json_to_canvas_graph(desc: DeploymentDescription) -> GeneratedGraph:
    try:
        departments = [
            GeneratedDepartment(
                temp_id=d.temp_id,
                name=d.name,
                reports_to_temp_id=d.reports_to_temp_id,
            )
            for d in desc.departments
        ]
        actors = [
            GeneratedActor(
                temp_id=a.temp_id,
                subtype=a.subtype.value,
                identity=a.identity,
                department_temp_id=a.department_temp_id,
            )
            for a in desc.actors
        ]
        ai_models = [
            GeneratedAIModel(
                temp_id=m.temp_id,
                name=m.name,
                model_type=m.model_type,
                ai_criticality=m.ai_criticality,
                domain=m.domain,
                data_sensitivity=m.data_sensitivity,
                hosting_environment=m.hosting_environment,
            )
            for m in desc.ai_models
        ]
        environments = [
            GeneratedDeploymentEnv(temp_id=e.temp_id, name=e.name, description=e.description)
            for e in desc.deployment_environments
        ]
    except ValidationError as exc:
        # A structural field used a value outside what the canvas node
        # understands (e.g. model_type "FOO") — surface it as a clear 422
        # rather than a 500, same as any other malformed-body rejection.
        raise ValueError(str(exc)) from exc

    # Auto-link every AI model to every deployment environment named in the
    # same description. The common case is one of each ("deploy GPT-4 in
    # production"); for a multi-model/multi-env description the user edits
    # or deletes whichever RUNS_IN edges don't apply.
    edges = [
        GeneratedEdge(from_temp_id=m.temp_id, to_temp_id=e.temp_id)
        for m in ai_models
        for e in environments
    ]

    reply = (
        f"Imported {len(departments)} department(s), {len(actors)} actor(s), "
        f"{len(ai_models)} AI model(s), {len(environments)} deployment environment(s)."
    )

    return GeneratedGraph(
        reply=reply,
        departments=departments,
        actors=actors,
        ai_models=ai_models,
        deployment_environments=environments,
        constraints=[],
        edges=edges,
    )
