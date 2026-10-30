"""
Human review of a model design.

When the PCS gate says REQUIRES_REVIEW, a person has to look at the design before a contract is signed. This module records that review and decides whether it still counts:

  * the reviewer is the signed-in person with sign-off permission (compliance or admin); nobody can record a review for someone else, and the person who trains, validates or
    deploys the model cannot review it (the same independence the model's own role-separation constraints ask for), nor the operator who runs it;
  * a review applies to ONE version of the design: it is bound to a fingerprint of the registry, the assessment domain and the design graph, so any change to the design
    (a constraint, an actor, a box) makes it lapse and a new review is needed;
  * reviews are never edited or deleted: a later review of the same version replaces an earlier one (an approval followed by a rejection is a rejection).
"""
import hashlib
import json
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth import AuthUser, current_user
from compliance_engine import AssessRequest
from compliance_schema import ReviewOut, ReviewState
from db.models import Design, DesignReview
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/designs", tags=["reviews"])

MAX_SHOWN = 6
INDEPENDENT_OF = ("trainer", "validator", "deployer", "operator")


def fingerprint(registry, domain: str, design_graph) -> str:
    """What a review applies to. Production observations (lifecycle, incident register) change all the time and are not part of the design, so they are left out."""
    body = registry.model_dump(mode="json")
    body.pop("lifecycle", None)
    body.pop("incident_register", None)
    graph = design_graph.model_dump(mode="json") if design_graph is not None else None
    canonical = json.dumps({"registry": body, "domain": domain, "graph": graph}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _out(row: DesignReview, fp: str) -> ReviewOut:
    return ReviewOut(decision=row.decision, note=row.note, reviewer=row.reviewer_name, role=row.reviewer_role, at=row.created_at, pcs=row.pcs_final, tier=row.tier,
                     gate=row.gate, current=row.fingerprint == fp)


def _rows(session: Session, design_key: str) -> List[DesignReview]:
    return list(session.scalars(select(DesignReview).where(DesignReview.design_key == design_key).order_by(DesignReview.created_at.desc())))


def review_state(session: Session, design_key: str, registry, domain: str, design_graph, pcs) -> ReviewState:
    fp = fingerprint(registry, domain, design_graph)
    rows = _rows(session, design_key)
    latest = next((r for r in rows if r.fingerprint == fp), None)       # the newest review of this very version decides
    return ReviewState(
        required=pcs.gate == "REQUIRES_REVIEW", gate=pcs.gate, pcs=pcs.pcs_final, tier=pcs.tier, fingerprint=fp,
        approved=bool(latest and latest.decision == "APPROVED"), rejected=bool(latest and latest.decision == "REJECTED"),
        reviews=[_out(r, fp) for r in rows[:MAX_SHOWN]],
    )


def current_review(session: Session, design_key: str, registry, domain: str, design_graph) -> Optional[dict]:
    """The approving review of this very version of the design, as it is recorded in the contract; None when there is none."""
    fp = fingerprint(registry, domain, design_graph)
    latest = next((r for r in _rows(session, design_key) if r.fingerprint == fp), None)
    if not (latest and latest.decision == "APPROVED"):
        return None
    return {"decision": latest.decision, "reviewer": latest.reviewer_name, "role": latest.reviewer_role, "at": latest.created_at.isoformat(), "note": latest.note,
            "pcs": latest.pcs_final, "tier": latest.tier, "gate": latest.gate, "fingerprint": latest.fingerprint}


def review_is_current(session: Session, design_key: str, registry, domain: str, design_graph) -> bool:
    return current_review(session, design_key, registry, domain, design_graph) is not None


class ReviewRequest(AssessRequest):
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    note: str = Field(min_length=5, max_length=2000)


@router.post("/{design_key}/review", response_model=ReviewState, status_code=201)
def record_review(design_key: str, body: ReviewRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ReviewState:
    from scoring_bridge import score_registry
    org = current_organisation(session)
    design = session.scalar(select(Design).where(Design.design_key == design_key, Design.organisation_id == org.id))
    if design is None:
        raise HTTPException(status_code=422, detail="Save the design before it is reviewed: a review belongs to a saved design.")
    from compliance_engine import to_design_graph
    from design_findings import formal_findings
    open_errors = [f for f in formal_findings(body.registry, body.constraint_node_ids, to_design_graph(body.design_graph))
                   if f.severity == "error" and "compile" in f.blocks and f.finding_id != "pcs-gate"]
    if open_errors:
        raise HTTPException(status_code=422, detail=f"A design is reviewed once it is correct: {len(open_errors)} thing(s) are wrong with it against the formal model, starting with \u201c{open_errors[0].title}\u201d. Fix them first.")
    me = " ".join(user.name.split()).lower()
    for role in INDEPENDENT_OF:
        who = " ".join((getattr(body.registry.actors, role).identity or "").split()).lower()
        if who and who == me:
            raise HTTPException(status_code=403, detail=f"{user.name} is named as the {role} of this model and cannot also review it. Another person with sign-off permission has to.")
    pcs, _ = score_registry(body.registry)
    fp = fingerprint(body.registry, body.domain, body.design_graph)
    session.add(DesignReview(
        id=uuid.uuid4(), organisation_id=org.id, design_key=design_key, fingerprint=fp, decision=body.decision, note=body.note.strip(), reviewer_name=user.name,
        reviewer_role=user.role, pcs_final=pcs.pcs_final, tier=pcs.tier, gate=pcs.gate,
    ))
    session.commit()
    return review_state(session, design_key, body.registry, body.domain, body.design_graph, pcs)
