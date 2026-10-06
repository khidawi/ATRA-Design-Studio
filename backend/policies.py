"""
Organisation policies (Task 4): rules an organisation writes itself, which then
flag designs in both studios exactly like a regulation's rule does.

A policy is authored as a small structured form (PolicySpec): an optional
"when" clause, then one requirement. That form is validated against a
vocabulary of the elements and properties a design really has, compiled into
the data-driven condition language of rule_checks.py, and stored as an ordinary
GRAPH rule under the ORG_POLICY regulation. Nothing here evaluates user input as
code, and a policy that names an element or property that doesn't exist is
rejected up front instead of silently never matching.

There is no sign-in yet (Task 8), so anyone who can reach the API can author
policies; Task 8 adds the roles that gate it.
"""
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from compliance_engine import to_design_graph
from compliance_schema import DesignGraphIn, RuleSeverity
from db.models import Domain, DomainRule, Regulation, Rule
from db.session import get_session
from organisation import current_organisation
from rule_checks import CheckConfigError, evaluate_graph_rule, validate_config

router = APIRouter(prefix="/api/policies", tags=["policies"])

Subject = Literal["MODEL", "AGENT"]
PolicyStatus = Literal["DRAFT", "APPROVED", "RETIRED"]

# ── What a policy can talk about ─────────────────────────────────────────────
# Must match the properties the studios actually send in a design graph: model
# designs send each canvas node's data (camelCase) and its relation type; agent
# designs send each element's name and properties.

def _bool(name, label): return {"name": name, "label": label, "kind": "boolean"}
def _enum(name, label, values): return {"name": name, "label": label, "kind": "enum", "values": values}
def _text(name, label): return {"name": name, "label": label, "kind": "text"}
def _el(type, label, *props): return {"type": type, "label": label, "properties": list(props)}

_CONSTRAINT_IDS = ["SC-DPIA-1", "SC-HITL-1", "SC-HALLU-1", "SC-MAP-1", "SC-CHALL-1", "SC-LIAB-1",
                   "SC-MC-1", "SC-TRAIN-1", "SC-RCF-1", "SC-RCF-2", "SC-DOMAIN-1", "SC-CONSENT-1"]
_STATUS = ["NOT_YET_DETERMINED", "UNMET", "SATISFIED"]

VOCABULARY: Dict[str, Dict[str, Any]] = {
    "MODEL": {
        "label": "AI model deployment",
        "elements": [
            _el("AI_MODEL", "AI model", _text("name", "Name"),
                _enum("modelType", "Model type", ["LLM", "NN", "CNN", "RL", "ENSEMBLE", "HYBRID", "PINN"]),
                _enum("aiCriticality", "Criticality", ["ADVISORY", "OPERATIONAL", "CRITICAL", "SAFETY_CRITICAL"]),
                _text("domain", "Domain"),
                _enum("dataSensitivity", "Data sensitivity", ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SENSITIVE_PERSONAL", "SPECIAL_CATEGORY"]),
                _enum("hostingEnvironment", "Hosting", ["TYPE_1_INHOUSE", "TYPE_2_FINETUNED", "TYPE_3_THIRDPARTY_API"])),
            _el("ACTOR", "Actor", _enum("subtype", "Role", ["TRAINER", "VALIDATOR", "DEPLOYER", "OPERATOR", "CONSUMER"]), _text("identity", "Identity")),
            _el("DEPARTMENT", "Department", _text("name", "Name")),
            _el("TRAINING_DATASET", "Training dataset", _text("name", "Name"), _text("description", "Description")),
            _el("DEPLOYMENT_ENV", "Deployment environment", _text("name", "Name"), _text("description", "Description")),
            _el("CONSTRAINT", "Security constraint", _enum("constraintId", "Constraint", _CONSTRAINT_IDS),
                _enum("status", "Status", _STATUS), _text("evidence", "Evidence")),
            _el("REGULATORY_REQ", "Regulatory requirement", _text("instrument", "Instrument"), _text("clause", "Clause"),
                _text("riskTier", "Risk tier"), _enum("status", "Status", _STATUS), _text("evidence", "Evidence")),
            _el("CONSENT_RECORD", "Consent record", _text("diaprodConsentId", "Consent ID"),
                _enum("validationSource", "Validation source", ["MANUAL", "DIAPROD_API"])),
            _el("LEGAL_BASIS", "Legal basis", _enum("basis", "Basis", ["CONSENT", "CONTRACT", "LEGAL_OBLIGATION", "VITAL_INTERESTS", "PUBLIC_TASK", "LEGITIMATE_INTERESTS"])),
            _el("DATA_CATEGORY", "Data category", _text("name", "Name"), _enum("sensitivity", "Sensitivity", ["NON_PERSONAL", "PERSONAL", "SPECIAL_CATEGORY"])),
        ],
        "relations": [
            {"label": "TRAINS", "text": "trains"}, {"label": "VALIDATES", "text": "validates"}, {"label": "DEPLOYS", "text": "deploys"},
            {"label": "OPERATES", "text": "operates"}, {"label": "CONSUMED_BY", "text": "is consumed by"},
            {"label": "IMPOSED_BY", "text": "is imposed by"}, {"label": "BELONGS_TO", "text": "belongs to"},
            {"label": "REPORTS_TO", "text": "reports to"}, {"label": "TRAINED_ON", "text": "is trained on"},
            {"label": "RUNS_IN", "text": "runs in"}, {"label": "COVERED_BY", "text": "is covered by"},
            {"label": "REQUIRES", "text": "requires"}, {"label": "ON_DEPENDENCY", "text": "depends on"},
        ],
    },
    "AGENT": {
        "label": "AI agent design",
        "elements": [
            _el("agent", "Agent", _text("name", "Name"), _text("owner", "Owner"), _enum("auto", "Autonomy", ["suggests", "approval", "autonomous"])),
            _el("tool", "Tool", _text("name", "Name"), _bool("write", "Write-capable")),
            _el("input", "Input source", _text("name", "Name"), _bool("untrusted", "Untrusted content")),
            _el("mcp", "MCP server", _text("name", "Name"), _bool("signed", "Signed")),
            _el("memory", "Memory", _text("name", "Name"), _bool("long", "Long-term")),
            _el("human", "Human actor", _text("name", "Name")),
            _el("external", "External system", _text("name", "Name")),
            _el("goal", "Goal", _text("name", "Name")),
            _el("data", "Data store", _text("name", "Name")),
            _el("approval", "Human approval", _text("name", "Name")),
            _el("guardrail", "Guardrail", _text("name", "Name"), _enum("kind", "Kind", ["injection", "rate", "disclosure"])),
            _el("constraint", "Constraint", _text("name", "Name"), _enum("kind", "Kind", ["egress", "retention"])),
        ],
        "relations": [
            {"label": "requests", "text": "requests"}, {"label": "feeds", "text": "feeds"}, {"label": "pursues", "text": "pursues"},
            {"label": "delegates", "text": "delegates to"}, {"label": "uses", "text": "uses"}, {"label": "connects", "text": "connects to"},
            {"label": "reads", "text": "reads"}, {"label": "stores", "text": "stores in"}, {"label": "gates", "text": "gates"},
            {"label": "limits", "text": "limits"}, {"label": "restricts", "text": "restricts"}, {"label": "writes", "text": "writes to"},
        ],
    },
}

OPERATORS = {
    "boolean": ["is_true", "is_false"],
    "enum": ["is", "is_not", "is_one_of"],
    "text": ["is", "is_not", "is_set", "is_empty"],
}
OP_TEXT = {"is_true": "is true", "is_false": "is false", "is": "is", "is_not": "is not",
           "is_one_of": "is one of", "is_set": "is set", "is_empty": "is empty"}
RuleKind = Literal["REQUIRE", "FORBID", "REQUIRE_RELATION", "FORBID_RELATION"]


@router.get("/vocabulary")
def vocabulary() -> Dict[str, Any]:
    """What a policy can refer to, for each kind of design: the elements, their properties
    (with the values an enum accepts) and the relations. The policy form is built from this."""
    return {"subjects": VOCABULARY, "operators": OPERATORS, "operator_text": OP_TEXT}


# ── The authored form ────────────────────────────────────────────────────────

class WhereIn(BaseModel):
    property: str
    op: str
    value: Optional[Any] = None


class ElementFilter(BaseModel):
    element: str
    where: List[WhereIn] = Field(default_factory=list)


class PolicySpec(BaseModel):
    # "When the design has ..." (optional): the policy only applies if this matches.
    when: Optional[ElementFilter] = None
    rule: RuleKind
    element: Optional[str] = None
    where: List[WhereIn] = Field(default_factory=list)
    min: int = Field(default=1, ge=1, le=100)
    relation: Optional[str] = None


def _element(subject: str, type_: str) -> Optional[Dict[str, Any]]:
    return next((e for e in VOCABULARY[subject]["elements"] if e["type"] == type_), None)


def _validate_filter(subject: str, element: Optional[str], where: List[WhereIn], where_name: str) -> List[str]:
    if not element:
        return [f"{where_name}: choose an element"]
    el = _element(subject, element)
    if el is None:
        return [f"{where_name}: {element!r} is not an element of a {VOCABULARY[subject]['label']}"]
    errors: List[str] = []
    seen = set()
    for i, w in enumerate(where):
        prop = next((p for p in el["properties"] if p["name"] == w.property), None)
        at = f"{where_name}, condition {i + 1}"
        if prop is None:
            errors.append(f"{at}: {el['label']} has no property {w.property!r}")
            continue
        if w.property in seen:
            errors.append(f"{at}: {prop['label']} is used twice; combine them with 'is one of'")
        seen.add(w.property)
        if w.op not in OPERATORS[prop["kind"]]:
            errors.append(f"{at}: {prop['label']} cannot use {OP_TEXT.get(w.op, w.op)!r}")
            continue
        if w.op in ("is", "is_not"):
            if prop["kind"] == "enum" and w.value not in prop["values"]:
                errors.append(f"{at}: {w.value!r} is not one of {prop['values']}")
            elif prop["kind"] == "text" and not (isinstance(w.value, str) and w.value.strip()):
                errors.append(f"{at}: enter a value")
        elif w.op == "is_one_of":
            if not (isinstance(w.value, list) and w.value and all(v in prop["values"] for v in w.value)):
                errors.append(f"{at}: pick one or more of {prop['values']}")
    return errors


def validate_spec(subject: str, spec: PolicySpec) -> List[str]:
    errors: List[str] = []
    if spec.when is not None:
        errors += _validate_filter(subject, spec.when.element, spec.when.where, "When")
    if spec.rule in ("REQUIRE", "FORBID"):
        errors += _validate_filter(subject, spec.element, spec.where, "Requirement")
    else:
        labels = {r["label"] for r in VOCABULARY[subject]["relations"]}
        if spec.relation not in labels:
            errors.append(f"Requirement: choose a relationship ({', '.join(sorted(labels))})")
    return errors


def _where_dict(where: List[WhereIn]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for w in where:
        out[w.property] = {
            "is_true": True, "is_false": False,
            "is": {"eq": w.value}, "is_not": {"ne": w.value}, "is_one_of": {"in": w.value},
            "is_set": {"nonempty": True}, "is_empty": {"empty": True},
        }[w.op]
    return out


def _selector(element: str, where: List[WhereIn]) -> Dict[str, Any]:
    sel: Dict[str, Any] = {"type": element}
    if where:
        sel["where"] = _where_dict(where)
    return sel


def spec_to_check_config(spec: PolicySpec, message: str, code: str) -> Dict[str, Any]:
    """Compile the authored form into rule_checks.py's condition language."""
    config: Dict[str, Any] = {
        "code": code,
        "messages": {"unsatisfied": message, "satisfied": "Policy satisfied", "not_applicable": "Policy does not apply to this design"},
    }
    when_selector = _selector(spec.when.element, spec.when.where) if spec.when else None
    if when_selector:
        config["applies_if"] = {"exists": when_selector}

    if spec.rule in ("REQUIRE", "FORBID"):
        target = _selector(spec.element or "", spec.where)
        if spec.rule == "REQUIRE":
            config["satisfied_if"] = {"exists": target} if spec.min == 1 else {"count": {"select": target, "op": ">=", "value": spec.min}}
            if when_selector:
                config["flag_nodes"] = [when_selector]
        else:
            config["satisfied_if"] = {"count": {"select": target, "op": "==", "value": 0}}
            config["flag_nodes"] = [target]
    else:
        present = {"edge_exists": {"label": spec.relation}}
        config["satisfied_if"] = present if spec.rule == "REQUIRE_RELATION" else {"not": present}
    return config


# ── Plain English ────────────────────────────────────────────────────────────

def _filter_text(subject: str, element: Optional[str], where: List[WhereIn]) -> str:
    el = _element(subject, element or "")
    text = (el["label"] if el else str(element)).lower()
    parts = []
    for w in where:
        prop = next((p for p in (el["properties"] if el else []) if p["name"] == w.property), None)
        label = (prop["label"] if prop else w.property).lower()
        value = ""
        if w.op in ("is", "is_not"):
            value = f" {w.value}"
        elif w.op == "is_one_of":
            value = " " + " / ".join(str(v) for v in (w.value or []))
        parts.append(f"{label} {OP_TEXT.get(w.op, w.op)}{value}")
    return text + (" where " + " and ".join(parts) if parts else "")


def describe(subject: str, spec: PolicySpec) -> str:
    lead = f"When the design has a {_filter_text(subject, spec.when.element, spec.when.where)}, the" if spec.when else "The"
    if spec.rule == "REQUIRE":
        return f"{lead} design must include at least {spec.min} {_filter_text(subject, spec.element, spec.where)}."
    if spec.rule == "FORBID":
        return f"{lead} design must not include any {_filter_text(subject, spec.element, spec.where)}."
    relation = next((r["text"] for r in VOCABULARY[subject]["relations"] if r["label"] == spec.relation), spec.relation)
    verb = "include" if spec.rule == "REQUIRE_RELATION" else "not include"
    return f"{lead} design must {verb} a relationship where one element {relation} another."


# ── API models ───────────────────────────────────────────────────────────────

class PolicyIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    # What people are told when the policy is violated; defaults to the title.
    message: str = Field(default="", max_length=300)
    severity: RuleSeverity = RuleSeverity.REQUIRED
    subject: Subject = "MODEL"
    applies_to_all: bool = True
    domains: List[str] = Field(default_factory=list)
    status: PolicyStatus = "DRAFT"
    spec: PolicySpec

    # Strip before the length limits apply, so a title of spaces is rejected rather than saved blank.
    @field_validator("title", "message", "description", mode="before")
    @classmethod
    def strip(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v


class PolicyOut(BaseModel):
    policy_key: str
    title: str
    description: str
    message: str
    severity: RuleSeverity
    subject: Subject
    status: PolicyStatus
    applies_to_all: bool
    domains: List[str]
    spec: PolicySpec
    summary: str
    version: int
    created_at: datetime
    updated_at: datetime


def _own_policies(session: Session, org_id: uuid.UUID):
    return select(Rule).where(Rule.organisation_id == org_id, Rule.origin == "ORG")


def _domains_of(session: Session, rule: Rule) -> List[str]:
    return list(session.scalars(
        select(Domain.domain_key).join(DomainRule, DomainRule.domain_id == Domain.id)
        .where(DomainRule.rule_id == rule.id).order_by(Domain.position)
    ))


def _out(session: Session, rule: Rule) -> PolicyOut:
    spec = PolicySpec.model_validate(rule.spec)
    return PolicyOut(
        policy_key=rule.rule_key, title=rule.title, description=rule.description,
        message=(rule.check_config.get("messages") or {}).get("unsatisfied", rule.title),
        severity=RuleSeverity(rule.severity), subject=rule.subject, status=rule.status,
        applies_to_all=rule.applies_to_all, domains=_domains_of(session, rule), spec=spec,
        summary=describe(rule.subject, spec), version=rule.version,
        created_at=rule.created_at, updated_at=rule.updated_at,
    )


def _checked(body: PolicyIn, key: str) -> Dict[str, Any]:
    """Validate the form and compile it. Raises 422 with every problem found."""
    errors = validate_spec(body.subject, body.spec)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    config = spec_to_check_config(body.spec, body.message or body.title, "ORG-" + key.split("-")[-1][:4])
    problems = validate_config(config)
    if problems:  # defensive: the compiler should never produce an invalid config
        raise HTTPException(status_code=500, detail=f"Compiled policy is invalid: {problems}")
    return config


def _resolve_domains(session: Session, body: PolicyIn) -> List[Domain]:
    if body.applies_to_all:
        return []
    if not body.domains:
        raise HTTPException(status_code=422, detail=["Choose at least one domain, or apply the policy to all designs."])
    found = {d.domain_key: d for d in session.scalars(select(Domain).where(Domain.domain_key.in_(body.domains)))}
    errors = []
    for key in body.domains:
        d = found.get(key)
        if d is None:
            errors.append(f"Unknown domain {key!r}.")
        elif d.subject != body.subject:
            errors.append(f"Domain {key!r} assesses {d.subject.lower()} designs, not {body.subject.lower()} designs.")
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    return [found[k] for k in body.domains]


def _set_memberships(session: Session, rule: Rule, domains: List[Domain]) -> None:
    for m in session.scalars(select(DomainRule).where(DomainRule.rule_id == rule.id)):
        session.delete(m)
    session.flush()
    for d in domains:
        last = session.scalar(select(func.max(DomainRule.position)).where(DomainRule.domain_id == d.id))
        session.add(DomainRule(domain_id=d.id, rule_id=rule.id, position=(last if last is not None else -1) + 1))


def _get(session: Session, key: str) -> Rule:
    rule = session.scalar(_own_policies(session, current_organisation(session).id).where(Rule.rule_key == key))
    if rule is None:
        raise HTTPException(status_code=404, detail=f"No policy {key!r}.")
    return rule


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=List[PolicyOut])
def list_policies(session: Session = Depends(get_session)) -> List[PolicyOut]:
    org = current_organisation(session)
    return [_out(session, r) for r in session.scalars(_own_policies(session, org.id).order_by(Rule.created_at))]


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(body: PolicyIn, session: Session = Depends(get_session)) -> PolicyOut:
    org = current_organisation(session)
    key = f"ORGPOL-{uuid.uuid4().hex[:8].upper()}"
    config = _checked(body, key)
    domains = _resolve_domains(session, body)
    regulation = session.scalar(select(Regulation).where(Regulation.instrument == "ORG_POLICY"))
    rule = Rule(
        rule_key=key, regulation_id=regulation.id, organisation_id=org.id, citation=body.title, title=body.title,
        description=body.description, severity=body.severity.value, check_type="GRAPH", check_config=config,
        status=body.status, origin="ORG", subject=body.subject, applies_to_all=body.applies_to_all,
        spec=body.spec.model_dump(),
    )
    session.add(rule)
    session.flush()
    _set_memberships(session, rule, domains)
    session.commit()
    session.refresh(rule)
    return _out(session, rule)


@router.put("/{key}", response_model=PolicyOut)
def update_policy(key: str, body: PolicyIn, session: Session = Depends(get_session)) -> PolicyOut:
    rule = _get(session, key)
    config = _checked(body, key)
    domains = _resolve_domains(session, body)
    rule.citation = rule.title = body.title
    rule.description = body.description
    rule.severity = body.severity.value
    rule.check_config = config
    rule.status = body.status
    rule.subject = body.subject
    rule.applies_to_all = body.applies_to_all
    rule.spec = body.spec.model_dump()
    rule.version += 1
    _set_memberships(session, rule, domains)
    session.commit()
    session.refresh(rule)
    return _out(session, rule)


class StatusUpdate(BaseModel):
    status: PolicyStatus


@router.patch("/{key}", response_model=PolicyOut)
def set_policy_status(key: str, body: StatusUpdate, session: Session = Depends(get_session)) -> PolicyOut:
    """Enforce (APPROVED), pause (DRAFT) or retire a policy without touching its definition."""
    rule = _get(session, key)
    if rule.status != body.status:
        rule.status = body.status
        rule.version += 1
        session.commit()
        session.refresh(rule)
    return _out(session, rule)


@router.delete("/{key}", status_code=204)
def delete_policy(key: str, session: Session = Depends(get_session)) -> None:
    rule = _get(session, key)
    for m in session.scalars(select(DomainRule).where(DomainRule.rule_id == rule.id)):
        session.delete(m)
    session.delete(rule)
    session.commit()


class PolicyTest(BaseModel):
    subject: Subject = "MODEL"
    severity: RuleSeverity = RuleSeverity.REQUIRED
    message: str = ""
    spec: PolicySpec
    design_graph: DesignGraphIn


class PolicyTestResult(BaseModel):
    status: Literal["GREEN", "AMBER", "RED", "NOT_APPLICABLE"]
    message: str
    flagged: List[str]
    summary: str


@router.post("/test", response_model=PolicyTestResult)
def test_policy(body: PolicyTest) -> PolicyTestResult:
    """Run a policy against a design without saving it, so an author can see what it would do."""
    errors = validate_spec(body.subject, body.spec)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    config = spec_to_check_config(body.spec, body.message or "Policy violated", "TEST")
    try:
        outcome = evaluate_graph_rule(
            to_design_graph(body.design_graph), config, "RED" if body.severity == RuleSeverity.REQUIRED else "AMBER"
        )
    except CheckConfigError as exc:
        raise HTTPException(status_code=422, detail=[str(exc)]) from exc
    return PolicyTestResult(status=outcome.status, message=outcome.message, flagged=outcome.flagged,
                            summary=describe(body.subject, body.spec))
