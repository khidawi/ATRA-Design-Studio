"""
Human review of an AI agent's design.

An agent is ratified by a person, and the contract says so. Two things are added to that, the same as for a model:

  * when the regulatory compliance gate says REVIEW, a person other than the agent's owner has to record a review of this version of the design before it is ratified;
  * when the person ratifying is the agent's owner, someone else has to have reviewed it: an owner does not ratify their own agent alone.

A review applies to one version of the design, bound to a fingerprint of the nodes, the edges, the profile and the declarations: any change makes it lapse. It is recorded under the
signed-in person's name, by someone with sign-off permission, and never edited. The server reads the design it has saved, so a review cannot be recorded for a design other than the one it
names. The reviews are kept in the same table as the model designer's (design_reviews), keyed by the design.
"""
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_findings import design_fingerprint, formal_findings
from auth import AuthUser, current_user
from compliance_engine import to_design_graph
from compliance_schema import DesignGraphIn, ReviewState
from db.models import Design, DesignReview
from db.session import get_session
from design_review import MAX_SHOWN, _out, _rows
from organisation import current_organisation
from rcr import Declaration, RcrOut, RcrRequest, score_agent

router = APIRouter(prefix="/api/agents/designs", tags=["agent-review"])


def _graph(doc: Dict[str, Any]) -> DesignGraphIn:
    return DesignGraphIn(
        nodes=[{"id": n["id"], "type": n["type"], "props": {"name": n.get("name", ""), **(n.get("p") or {})}, "primary": bool(n.get("primary"))} for n in doc.get("nodes", [])],
        edges=[{"from": e["from"], "to": e["to"], "label": e.get("label", "")} for e in doc.get("edges", [])])


def _primary(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return next((n for n in doc.get("nodes", []) if n.get("primary") and n.get("type") == "agent"), None)


def _norm(text: Any) -> str:
    return " ".join(str(text or "").split()).lower()


def is_owner(primary: Optional[Dict[str, Any]], name: str) -> bool:
    owner = _norm(((primary or {}).get("p") or {}).get("owner"))
    return bool(owner) and owner == _norm(name)


def _score(session: Session, doc: Dict[str, Any]) -> RcrOut:
    declarations = {k: Declaration(**v) for k, v in (doc.get("req") or {}).items()}
    return score_agent(RcrRequest(profile=doc.get("profile") or "payments", graph=_graph(doc), declarations=declarations), session)


def _design(session: Session, key: str) -> Design:
    design = session.scalar(select(Design).where(Design.design_key == key))
    if design is None or design.subject != "AGENT":
        raise HTTPException(status_code=404, detail="No such agent design.")
    return design


def review_state(session: Session, design: Design, viewer: str) -> ReviewState:
    doc = design.document
    rcr = _score(session, doc)
    fp = design_fingerprint(doc)
    conflict = is_owner(_primary(doc), viewer)
    rows = _rows(session, design.design_key)
    latest = next((r for r in rows if r.fingerprint == fp), None)
    return ReviewState(
        required=rcr.gate == "REVIEW" or conflict, reason="gate" if rcr.gate == "REVIEW" else ("issuer" if conflict else ""), issuer_role="owner" if conflict else None,
        gate=rcr.gate, pcs=rcr.score, tier=rcr.band, fingerprint=fp, approved=bool(latest and latest.decision == "APPROVED"), rejected=bool(latest and latest.decision == "REJECTED"),
        reviews=[_out(r, fp) for r in rows[:MAX_SHOWN]])


def current_review(session: Session, design: Design) -> Optional[dict]:
    """The approving review of this very version of the design, as recorded in the contract; None when there is none."""
    fp = design_fingerprint(design.document)
    latest = next((r for r in _rows(session, design.design_key) if r.fingerprint == fp), None)
    if not (latest and latest.decision == "APPROVED"):
        return None
    return {"decision": latest.decision, "reviewer": latest.reviewer_name, "role": latest.reviewer_role, "at": latest.created_at.isoformat(), "note": latest.note,
            "score": latest.pcs_final, "band": latest.tier, "gate": latest.gate, "fingerprint": latest.fingerprint}


def check_ratifiable(rcr: RcrOut, analysis, primary: Dict[str, Any], ratifier: str, review: Optional[dict], decided: bool = False) -> None:
    """Refuse to ratify a design that is not correct, or one that needs a person's review and has none."""
    errors = [f for f in analysis.formal_findings if f.severity == "error" and "ratify" in f.blocks]
    if errors:
        raise HTTPException(status_code=422, detail=(
            f"Cannot ratify: the design is not correct ({len(errors)} open), starting with “{errors[0].title}”. Fix what the Fix tab lists first."))
    if review is not None:
        return
    if rcr.gate == "REVIEW" and not decided:
        raise HTTPException(status_code=422, detail=(
            f"Cannot ratify: the risk score is {rcr.score:g} and the gate says REVIEW. A person with sign-off permission who is not the agent's owner records a review of this "
            f"version of the design on the Fix tab. It lapses if the design changes."))
    if is_owner(primary, ratifier):
        raise HTTPException(status_code=422, detail=(
            f"Cannot ratify: {ratifier} is the agent's owner, so the design needs a recorded review by someone who is not. A person with sign-off permission records it on the Fix tab."))


def assurance(rcr: RcrOut, review: Optional[dict], primary: Dict[str, Any], ratifier: str) -> Dict[str, Any]:
    """What a reader of the contract would otherwise have to recompute: the score and gate at ratification, the review, whether the ratifier owns the agent, and which declared
    requirements rest on evidence that names no record."""
    return {
        "rcr": {"score": rcr.score, "band": rcr.band, "gate": rcr.gate}, "levels": rcr.levels, "review": review, "ratified_by_is_owner": is_owner(primary, ratifier),
        "evidence_without_record": sorted(r.key for r in rcr.rows if not r.derived and r.declared in ("Covered", "Partial") and not r.evidence_names_record),
    }


@router.get("/{design_key}/review", response_model=ReviewState)
def get_review(design_key: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ReviewState:
    return review_state(session, _design(session, design_key), user.name)


class AgentReviewIn(BaseModel):
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    note: str = Field(min_length=5, max_length=2000)


@router.post("/{design_key}/review", response_model=ReviewState, status_code=201)
def record_review(design_key: str, body: AgentReviewIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ReviewState:
    design = _design(session, design_key)
    doc = design.document
    errors = [f for f in formal_findings(to_design_graph(_graph(doc))) if f.severity == "error" and "ratify" in f.blocks]
    if errors:
        raise HTTPException(status_code=422, detail=f"A design is reviewed once it is correct: {len(errors)} thing(s) are wrong with it, starting with “{errors[0].title}”. Fix them first.")
    if is_owner(_primary(doc), user.name):
        raise HTTPException(status_code=403, detail=f"{user.name} is the owner of this agent and cannot also review it. Another person with sign-off permission has to.")
    rcr = _score(session, doc)
    session.add(DesignReview(
        id=uuid.uuid4(), organisation_id=current_organisation(session).id, design_key=design.design_key, fingerprint=design_fingerprint(doc), decision=body.decision,
        note=body.note.strip(), reviewer_name=user.name, reviewer_role=user.role, pcs_final=rcr.score, tier=rcr.band, gate=rcr.gate))
    session.commit()
    return review_state(session, design, user.name)
