"""
The regulation-change watch (ASTRA phase 12): mappings that need a person's review, instead of drifting.

A signed contract maps its controls to clauses of laws and standards ("EU-AI-Act:Art.14"). Those mappings were right when somebody looked at them. The rules the platform holds for a clause
can change afterwards (a rule is edited, retired or added, a severity moves), and nothing in the contract changes with them. The watch compares what the platform holds for each mapped clause
now with what a person last confirmed:

    CURRENT      a person reviewed the mapping against the rules as they are now
    UNREVIEWED   nobody has reviewed this mapping yet
    CHANGED      the rules for the clause are not the ones a person last reviewed: review it again
    UNRESOLVED   the platform holds no rule for the clause, so there is nothing to compare (the anchors are indicative; this says so rather than pretending)

A review is a person's signed-off statement that the mapping still holds for the rules as they are now; it records the fingerprint of those rules, so any later change makes it CHANGED. Nothing is
stored but the reviews, the rest is computed on request. A review changes no contract: the signed bytes stay what they are.
"""
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import audit
from auth import AuthUser, current_user
from db.models import AstraSignedContract, Regulation, RegulationReview, Rule
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/astra/regwatch", tags=["astra"])


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _pattern(ref: str) -> Optional["re.Pattern[str]"]:
    m = re.match(r"^([A-Za-z]+)\.?\s*([0-9][0-9A-Za-z.\-]*)$", ref.strip())
    if not m:
        return None
    return re.compile(rf"^\s*{re.escape(m.group(1))}[a-z]*\.?\s*{re.escape(m.group(2))}(?![0-9A-Za-z])", re.I)


def resolve(session: Session, clause: str) -> List[Rule]:
    """The rules the platform holds for a clause anchor such as EU-AI-Act:Art.14: the regulation by name, the rule by the article or section its citation names."""
    framework, _, ref = clause.partition(":")
    if not framework or not ref:
        return []
    f = norm(framework)
    regs = [r for r in session.scalars(select(Regulation)) if norm(r.instrument) == f or (len(f) >= 5 and (f in norm(r.instrument) or norm(r.instrument) in f))]
    if not regs:
        return []
    pat = _pattern(ref)
    out = []
    for rule in session.scalars(select(Rule).where(Rule.regulation_id.in_([r.id for r in regs]))):
        if (pat is not None and pat.search(rule.citation or "")) or (pat is None and norm(ref) and norm(ref) in norm((rule.citation or "") + " " + (rule.title or ""))):
            out.append(rule)
    return sorted(out, key=lambda r: r.rule_key)


def fingerprint(rules: List[Rule]) -> str:
    """What the platform holds for a clause, as one hash: any edit, retirement, new rule or moved severity changes it."""
    items = [[r.rule_key, r.citation, r.title, r.description, r.severity, r.status, r.check_type, r.check_config or {}] for r in rules]
    return hashlib.sha256(json.dumps(items, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest() if rules else "none"


def watch(session: Session) -> Dict[str, Any]:
    org = current_organisation(session)
    clauses: Dict[str, Dict[str, Any]] = {}
    for c in session.scalars(select(AstraSignedContract).where(AstraSignedContract.organisation_id == org.id, AstraSignedContract.status == "ACTIVE")):
        for m in (c.document.get("regulatory_mappings") or []):
            for clause in m.get("clauses", []):
                e = clauses.setdefault(clause, {"clause": clause, "controls": set(), "agents": set()})
                e["controls"].add(m["control"])
                e["agents"].add(c.agent_key)
    last: Dict[str, RegulationReview] = {}
    for r in session.scalars(select(RegulationReview).where(RegulationReview.organisation_id == org.id).order_by(RegulationReview.created_at)):
        last[r.clause] = r
    out = []
    for clause, e in sorted(clauses.items()):
        rules = resolve(session, clause)
        fp = fingerprint(rules)
        rv = last.get(clause)
        if rv is not None and rv.fingerprint == fp:
            status, why = "CURRENT", ("reviewed: the platform holds no rule for this clause" if not rules else "reviewed against the rules as they are now")
        elif not rules:
            status, why = "UNRESOLVED", "the platform holds no rule for this clause, so there is nothing to compare: the anchor is indicative"
        elif rv is None:
            status, why = "UNREVIEWED", "nobody has reviewed this mapping against the platform's rules yet"
        else:
            status, why = "CHANGED", "the rules for this clause have changed since the mapping was last reviewed"
        out.append({"clause": clause, "controls": sorted(e["controls"]), "agents": sorted(e["agents"]), "rules": [r.rule_key for r in rules], "fingerprint": fp, "status": status, "why": why,
                    "reviewed_by": rv.reviewed_by if rv else None, "reviewed_at": rv.created_at.isoformat() if rv else None, "note": rv.note if rv else None})
    counts = {s: sum(1 for m in out if m["status"] == s) for s in ("CURRENT", "UNREVIEWED", "CHANGED", "UNRESOLVED")}
    return {"mappings": out, "counts": counts}


@router.get("")
def get_watch(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return watch(session)


class ReviewIn(BaseModel):
    clause: str = Field(min_length=3, max_length=120)
    note: str = Field(..., min_length=3, max_length=500)


@router.post("/review", status_code=201)
def review(body: ReviewIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    m = next((x for x in watch(session)["mappings"] if x["clause"] == body.clause), None)
    if m is None:
        raise HTTPException(status_code=404, detail="No signed contract maps to that clause.")
    row = RegulationReview(organisation_id=org.id, clause=body.clause, fingerprint=m["fingerprint"], rules=m["rules"], reviewed_by=user.name, note=body.note.strip())
    session.add(row)
    session.commit()
    audit.record(user.name, user.role, "astra.regwatch.review", detail={"clause": body.clause, "fingerprint": m["fingerprint"][:16], "rules": m["rules"]})
    return next(x for x in watch(session)["mappings"] if x["clause"] == body.clause)
