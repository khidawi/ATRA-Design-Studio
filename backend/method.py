"""
The method a score was produced under.

A score is the output of a method: the approved rules, the requirement registries, the Secure Tropos catalogue and the scoring code. When any of those change, the same design can
score differently, and a score from last year cannot be reproduced unless it says which method made it. Every score, finding set and signed contract carries a stamp:

  * `number`           the published method it falls under (Method 1, Method 2, ...), advanced only by a person with sign-off permission who says what changed;
  * `fingerprint`      a hash of what was actually in force when the score was made, whether or not anyone has published it;
  * `unpublished`      true when the rules differ from the last published method, so a score is never silently attributed to a method it was not made under.

Editing a rule does not publish a method. Publishing is a deliberate act, recorded under a name, and the history is never edited.
"""
import hashlib
import json
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import Domain, DomainRule, MethodVersion, Organisation, RcrProfile, RcrRequirement, Regulation, Rule

# Bump when the scoring or checking code changes in a way that can change a result (the data is fingerprinted separately).
ENGINE_VERSION = "1"

PARTS = ("engine", "rules", "domains", "requirements", "catalogue")


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def parts_now(session: Session) -> Dict[str, str]:
    """A hash for each thing a score depends on, so a change can be traced to the part that changed."""
    instruments = {r.id: r.instrument for r in session.scalars(select(Regulation))}
    rules = sorted(session.scalars(select(Rule).where(Rule.status == "APPROVED")), key=lambda r: r.rule_key)
    keys = {r.id: r.rule_key for r in rules}
    domains = []
    for d in session.scalars(select(Domain).order_by(Domain.domain_key)):
        members = [keys[m.rule_id] for m in session.scalars(select(DomainRule).where(DomainRule.domain_id == d.id).order_by(DomainRule.position)) if m.rule_id in keys]
        domains.append({"key": d.domain_key, "subject": d.subject, "rules": members})
    profiles = []
    for p in session.scalars(select(RcrProfile).order_by(RcrProfile.profile_key)):
        reqs = session.scalars(select(RcrRequirement).where(RcrRequirement.profile_id == p.id).order_by(RcrRequirement.req_key))
        profiles.append({"key": p.profile_key, "partial_credit": p.partial_credit, "requirements": [
            {"key": q.req_key, "instrument": q.instrument, "cls": q.cls, "weight": q.weight, "phi": q.phi, "check": q.design_check, "unsatisfied": q.unsatisfied_declared,
             "default": q.default_declaration} for q in reqs]})
    try:
        from framework.tropos_catalogue import CANONICAL_CONSTRAINTS
        catalogue = [c.model_dump(mode="json") for c in CANONICAL_CONSTRAINTS]
    except Exception:
        catalogue = []
    return {
        "engine": _digest(ENGINE_VERSION),
        "rules": _digest([{"key": r.rule_key, "instrument": instruments.get(r.regulation_id), "citation": r.citation, "severity": r.severity, "constraint": r.maps_to_constraint_id,
                           "type": r.check_type, "config": r.check_config, "subject": r.subject, "all": r.applies_to_all} for r in rules]),
        "domains": _digest(domains), "requirements": _digest(profiles), "catalogue": _digest(catalogue),
    }


def fingerprint_of(parts: Dict[str, str]) -> str:
    return _digest([parts.get(k) for k in PARTS])


def _org_id(session: Session):
    return session.scalar(select(Organisation.id).where(Organisation.slug == DEFAULT_ORG_SLUG))


def _latest(session: Session, org_id) -> Optional[MethodVersion]:
    return session.scalar(select(MethodVersion).where(MethodVersion.organisation_id == org_id).order_by(MethodVersion.number.desc()).limit(1))


def ensure_baseline(session: Session, org_id=None) -> Optional[MethodVersion]:
    """The first time a method is asked for, the rules as they stand are recorded as Method 1, by the system, so no score is ever unnumbered."""
    org_id = org_id or _org_id(session)
    if org_id is None:
        return None
    row = _latest(session, org_id)
    if row is not None:
        return row
    parts = parts_now(session)
    session.add(MethodVersion(organisation_id=org_id, number=1, fingerprint=fingerprint_of(parts), parts=parts, engine=ENGINE_VERSION, published_by="system",
                              note="Baseline: the rules, requirements and catalogue as they stood when methods were first recorded."))
    try:
        session.commit()
    except IntegrityError:         # another request recorded it first
        session.rollback()
    return _latest(session, org_id)


def stamp(session: Session) -> Optional[Dict[str, Any]]:
    """The stamp carried by a score or a contract. Never raises: a score stands on its own when the stamp cannot be made."""
    try:
        org_id = _org_id(session)
        published = ensure_baseline(session, org_id)
        if published is None:
            return None
        parts = parts_now(session)
        now = fingerprint_of(parts)
        return {"number": published.number, "fingerprint": now, "published_fingerprint": published.fingerprint, "engine": ENGINE_VERSION,
                "unpublished": now != published.fingerprint}
    except Exception:
        session.rollback()
        return None


def changed_parts(old: Dict[str, str], new: Dict[str, str]) -> List[str]:
    return [k for k in PARTS if (old or {}).get(k) != (new or {}).get(k)]


def history(session: Session) -> List[MethodVersion]:
    org_id = _org_id(session)
    return list(session.scalars(select(MethodVersion).where(MethodVersion.organisation_id == org_id).order_by(MethodVersion.number.desc())))


def publish(session: Session, by: str, note: str) -> MethodVersion:
    """Records the method in force as the next numbered method. Refuses when nothing changed since the last one."""
    org_id = _org_id(session)
    last = ensure_baseline(session, org_id)
    parts = parts_now(session)
    fp = fingerprint_of(parts)
    if last is not None and last.fingerprint == fp:
        raise ValueError(f"Nothing has changed since Method {last.number}: the rules, requirements and catalogue are the same, so there is nothing to publish.")
    row = MethodVersion(organisation_id=org_id, number=(last.number if last else 0) + 1, fingerprint=fp, parts=parts, engine=ENGINE_VERSION, published_by=by, note=note.strip())
    session.add(row)
    session.commit()
    return row
