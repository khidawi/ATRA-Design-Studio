"""
Regulations, rules and assessment domains, read from PostgreSQL (Task 2).

compliance_engine.py stays a pure function of (registry, ComplianceDomain);
this module is what turns database rows into that ComplianceDomain, so the
engine never knows where the rules came from. Only APPROVED rules are
evaluated: a DRAFT (for example one an LLM proposed, Task 5) or RETIRED rule
is invisible to assessment and to compiled contracts.

There is no sign-in yet (Task 8), so rule edits are open to anyone who can
reach the API; Task 8 adds the roles that gate them.
"""
import uuid
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from compliance_schema import ComplianceDomain, RegulationRule, RuleSeverity
from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import Domain, DomainRule, Organisation, Regulation, Rule
from db.session import get_session

router = APIRouter(prefix="/api", tags=["regulations"])

RuleStatus = Literal["DRAFT", "APPROVED", "RETIRED"]


# ── Database -> the objects the engine consumes ─────────────────────────────

def _engine_rule(rule: Rule, regulation: Regulation) -> RegulationRule:
    return RegulationRule(
        rule_id=rule.rule_key,
        instrument=regulation.instrument,
        citation=rule.citation,
        title=rule.title,
        description=rule.description,
        severity=RuleSeverity(rule.severity),
        maps_to_constraint_id=rule.maps_to_constraint_id,
        check_type=rule.check_type,
        check_config=rule.check_config or {},
        citation_label=f"ORG_POLICY: {rule.title}" if rule.organisation_id is not None else None,
    )


def _domain_with_rules(session: Session, domain: Domain) -> ComplianceDomain:
    rows = session.execute(
        select(Rule, Regulation)
        .join(DomainRule, DomainRule.rule_id == Rule.id)
        .join(Regulation, Regulation.id == Rule.regulation_id)
        .where(DomainRule.domain_id == domain.id, Rule.status == "APPROVED")
        .order_by(DomainRule.position)
    ).all()
    # Organisation policies that apply to every domain of this kind of design (Task 4) follow
    # the domain's own rules, oldest first. Policies listed in specific domains are already
    # in `rows` through domain_rules.
    org = session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
    seen = {rule.id for rule, _ in rows}
    if org is not None:
        rows += [
            (rule, regulation)
            for rule, regulation in session.execute(
                select(Rule, Regulation)
                .join(Regulation, Regulation.id == Rule.regulation_id)
                .where(
                    Rule.organisation_id == org.id, Rule.applies_to_all.is_(True),
                    Rule.status == "APPROVED", Rule.subject == domain.subject,
                )
                .order_by(Rule.created_at)
            ).all()
            if rule.id not in seen
        ]
    return ComplianceDomain(
        domain_id=domain.domain_key,
        name=domain.name,
        description=domain.description,
        subject=domain.subject,
        rule_set=[_engine_rule(rule, regulation) for rule, regulation in rows],
    )


Subject = Literal["MODEL", "AGENT"]


def list_domains(session: Session, subject: Subject = "MODEL") -> List[ComplianceDomain]:
    domains = session.scalars(
        select(Domain).where(Domain.subject == subject).order_by(Domain.position, Domain.created_at)
    ).all()
    return [_domain_with_rules(session, d) for d in domains]


def load_domain(session: Session, domain_key: str, subject: Subject = "MODEL") -> Optional[ComplianceDomain]:
    """A domain only counts for the kind of design it assesses: a model assessment cannot
    be run against the agent domain, and the other way round."""
    domain = session.scalar(select(Domain).where(Domain.domain_key == domain_key, Domain.subject == subject))
    return _domain_with_rules(session, domain) if domain else None


def require_domain(session: Session, domain_key: str, subject: Subject = "MODEL") -> ComplianceDomain:
    domain = load_domain(session, domain_key, subject)
    if domain is None:
        raise HTTPException(status_code=422, detail=f"Unknown assessment domain: {domain_key!r}")
    return domain


# ── API ─────────────────────────────────────────────────────────────────────

@router.get("/domains", response_model=List[ComplianceDomain])
def domains(subject: Subject = "MODEL", session: Session = Depends(get_session)) -> List[ComplianceDomain]:
    """The domain -> approved-rule-set mapping. Defaults to the model domains the Assessment
    Domain selector lists; ?subject=AGENT returns the agent domains."""
    return list_domains(session, subject)


class RegulationOut(BaseModel):
    instrument: str
    name: str
    kind: str
    description: str
    source_url: Optional[str]
    approved_rules: int
    draft_rules: int


@router.get("/regulations", response_model=List[RegulationOut])
def regulations(session: Session = Depends(get_session)) -> List[RegulationOut]:
    counts: Dict[uuid.UUID, Dict[str, int]] = {}
    for regulation_id, status, n in session.execute(
        select(Rule.regulation_id, Rule.status, func.count()).group_by(Rule.regulation_id, Rule.status)
    ):
        counts.setdefault(regulation_id, {})[status] = n
    out = []
    for reg in session.scalars(select(Regulation).order_by(Regulation.created_at, Regulation.instrument)):
        c = counts.get(reg.id, {})
        out.append(RegulationOut(
            instrument=reg.instrument, name=reg.name, kind=reg.kind, description=reg.description,
            source_url=reg.source_url, approved_rules=c.get("APPROVED", 0), draft_rules=c.get("DRAFT", 0),
        ))
    return out


class RuleOut(BaseModel):
    rule_key: str
    instrument: str
    citation: str
    title: str
    description: str
    severity: RuleSeverity
    maps_to_constraint_id: Optional[str]
    status: RuleStatus
    origin: str
    version: int
    check_type: str
    check_config: Dict[str, Any]
    subject: str
    domains: List[str]
    source_url: Optional[str] = None
    source_quote: Optional[str] = None


def _rule_out(rule: Rule, regulation: Regulation, domain_keys: List[str]) -> RuleOut:
    return RuleOut(
        rule_key=rule.rule_key, instrument=regulation.instrument, citation=rule.citation, title=rule.title,
        description=rule.description, severity=RuleSeverity(rule.severity),
        maps_to_constraint_id=rule.maps_to_constraint_id, status=rule.status, origin=rule.origin,
        version=rule.version, check_type=rule.check_type, check_config=rule.check_config or {},
        subject=rule.subject, domains=domain_keys, source_url=rule.source_url, source_quote=rule.source_quote,
    )


def _domain_keys_by_rule(session: Session) -> Dict[uuid.UUID, List[str]]:
    out: Dict[uuid.UUID, List[str]] = {}
    for rule_id, key in session.execute(
        select(DomainRule.rule_id, Domain.domain_key)
        .join(Domain, Domain.id == DomainRule.domain_id)
        .order_by(Domain.position)
    ):
        out.setdefault(rule_id, []).append(key)
    return out


@router.get("/rules", response_model=List[RuleOut])
def rules(
    status: Optional[RuleStatus] = None,
    instrument: Optional[str] = None,
    domain: Optional[str] = None,
    session: Session = Depends(get_session),
) -> List[RuleOut]:
    query = select(Rule, Regulation).join(Regulation, Regulation.id == Rule.regulation_id)
    if status:
        query = query.where(Rule.status == status)
    if instrument:
        query = query.where(Regulation.instrument == instrument)
    if domain:
        query = (
            query.join(DomainRule, DomainRule.rule_id == Rule.id)
            .join(Domain, Domain.id == DomainRule.domain_id)
            .where(Domain.domain_key == domain)
            .order_by(DomainRule.position)
        )
    else:
        query = query.order_by(Regulation.instrument, Rule.rule_key)
    keys = _domain_keys_by_rule(session)
    return [_rule_out(rule, reg, keys.get(rule.id, [])) for rule, reg in session.execute(query).all()]


class RuleUpdate(BaseModel):
    status: Optional[RuleStatus] = None
    severity: Optional[RuleSeverity] = None


@router.patch("/rules/{rule_key}", response_model=RuleOut)
def update_rule(rule_key: str, body: RuleUpdate, session: Session = Depends(get_session)) -> RuleOut:
    """Approve, retire or re-grade a rule. Each real change bumps the rule's version."""
    row = session.execute(
        select(Rule, Regulation).join(Regulation, Regulation.id == Rule.regulation_id).where(Rule.rule_key == rule_key)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No rule {rule_key!r}.")
    rule, regulation = row
    changed = False
    if body.status is not None and body.status != rule.status:
        rule.status = body.status
        changed = True
    if body.severity is not None and body.severity.value != rule.severity:
        rule.severity = body.severity.value
        changed = True
    if changed:
        rule.version += 1
        session.commit()
        session.refresh(rule)
    return _rule_out(rule, regulation, _domain_keys_by_rule(session).get(rule.id, []))
