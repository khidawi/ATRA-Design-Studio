"""
Responsibilities and assignments: who is accountable for an AI agent or an AI model, kept apart from the employee record and from the organisation's structure.

Three things, deliberately separate:

  * the employee   a person or role of the organisation (a company node of type person or role). Who they are, and where they work. It says nothing about duties.
  * the duty       the responsibility itself: the owner of customs-agent, the validator of the loan model. It belongs to the agent or model and never changes when staff do.
  * the assignment who holds the duty, from which date to which, as primary or as temporary cover, and why. A change is a new row; nothing is edited away.

One rule decides who is responsible at a date, and every page, check and score asks it (resolve below):

  1. an active COVER (the latest to start) wins over the primary, because that is who is standing in;
  2. otherwise the active PRIMARY;
  3. otherwise, if the duty has never had an assignment, the organisation's own structure (the owner set on the agent in the organisation, the people drawn
     against a model as trainer, validator and deployer): so nothing changes until someone makes the first handover;
  4. otherwise nobody: the duty has lapsed (a leaver, an expired cover) and the agent or model counts as unowned.

The organisation's structure is never edited by a handover. A leave of absence is a COVER with dates; a leaver or a reorganisation is a new PRIMARY from a date.

The duty is not a permission. Who may sign off or administer stays with sign-in accounts and their roles; a sign-off still records the person who signed in.
"""
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

import audit
from auth import AuthUser, current_user
from db.models import Agent, Assignment, CompanyEdge, CompanyNode, Design, Responsibility
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/responsibilities", tags=["responsibilities"])

DUTIES: Dict[str, List[tuple]] = {
    "agent": [("owner", "Owner")],
    "model": [("owner", "Owner"), ("trainer", "Trainer"), ("validator", "Validator"), ("deployer", "Deployer"), ("operator", "Operator")],
}
LABEL = {d: l for ds in DUTIES.values() for d, l in ds}
EDGE_LABEL = {"trainer": "trains", "validator": "validates", "deployer": "deploys", "operator": "operates"}     # how the organisation draws a model's roles
SEPARATE = (("trainer", "validator"), ("validator", "deployer"), ("trainer", "deployer"))                         # the role separation the PCS and the organisation checks look at


BEGINNING = date(1970, 1, 1)           # the structure's own holder is the primary "from the start": the platform does not know when they began


def today() -> date:
    return datetime.now(timezone.utc).date()


# ── Reading ─────────────────────────────────────────────────────────────────

def _people(session: Session, org_id: Any) -> Dict[str, CompanyNode]:
    return {n.ext_id: n for n in session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org_id, CompanyNode.type.in_(("person", "role"))))}


def _holder(a: Assignment, people: Dict[str, CompanyNode]) -> Dict[str, Any]:
    node = people.get(a.holder_ext_id) if a.holder_ext_id else None
    return {"ext_id": a.holder_ext_id if node is not None else None, "name": node.name if node is not None else a.holder_name, "in_organisation": node is not None}


def _structure(session: Session, org_id: Any, kind: str, ref: str, duty: str, people: Dict[str, CompanyNode]) -> List[Dict[str, Any]]:
    """The organisation's own answer, used only while a duty has never had an assignment: who is drawn against the agent or model."""
    if kind == "agent":
        import removal
        node = removal.org_agent_node(session, org_id, ref)
        owner = people.get((node.props or {}).get("owner", "")) if node is not None else None
        if owner is not None:
            return [{"ext_id": owner.ext_id, "name": owner.name, "in_organisation": True}]
        a = session.scalar(select(Agent).where(Agent.agent_key == ref, Agent.organisation_id == org_id))
        return [{"ext_id": None, "name": a.owner, "in_organisation": False}] if a is not None and a.owner else []
    if ref.startswith("d:"):                                              # a model design that is not in the organisation yet: its own designer roles
        d = session.scalar(select(Design).where(Design.design_key == ref[2:], Design.subject == "MODEL"))
        out = []
        for n in ((d.document or {}).get("nodes", []) if d is not None else []):
            if n.get("kind") == "ACTOR" and str((n.get("data") or {}).get("subtype", "")).lower() == duty and (n["data"].get("identity") or "").strip():
                out.append({"ext_id": None, "name": n["data"]["identity"].strip(), "in_organisation": False})
        return out
    node = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org_id, CompanyNode.ext_id == ref, CompanyNode.type == "model"))
    if node is None:
        return []
    if duty == "owner":
        o = people.get((node.props or {}).get("owner", ""))
        return [{"ext_id": o.ext_id, "name": o.name, "in_organisation": True}] if o is not None else []
    label = EDGE_LABEL.get(duty)
    out = []
    for e in session.scalars(select(CompanyEdge).where(CompanyEdge.organisation_id == org_id, CompanyEdge.kind == "works_with", CompanyEdge.from_ext == ref)):
        if (e.label or "").lower() == label and e.to_ext in people:
            out.append({"ext_id": e.to_ext, "name": people[e.to_ext].name, "in_organisation": True})
    return out


def resolve(session: Session, org_id: Any, kind: str, ref: str, duty: str, on: Optional[date] = None, people: Optional[Dict[str, CompanyNode]] = None) -> Dict[str, Any]:
    """Who holds this duty on this date (the one rule above), with who is being covered, until when, and what is coming."""
    on = on or today()
    people = people if people is not None else _people(session, org_id)
    resp = session.scalar(select(Responsibility).where(Responsibility.organisation_id == org_id, Responsibility.subject_kind == kind, Responsibility.subject_ref == ref, Responsibility.duty == duty))
    rows: List[Assignment] = []
    if resp is not None:
        rows = list(session.scalars(select(Assignment).where(Assignment.responsibility_id == resp.id).order_by(Assignment.starts_on.desc(), Assignment.created_at.desc())))
    live = [a for a in rows if not a.revoked and a.starts_on <= on and (a.ends_on is None or a.ends_on >= on)]
    cover = next((a for a in live if a.kind == "COVER"), None)
    primary = next((a for a in live if a.kind == "PRIMARY"), None)
    upcoming = sorted((a for a in rows if not a.revoked and a.starts_on > on), key=lambda a: a.starts_on)
    out: Dict[str, Any] = {"duty": duty, "label": LABEL.get(duty, duty), "on": on.isoformat(), "holder": None, "holders": [], "source": "none", "kind": None, "covering_for": None, "primary": None,
                           "until": None, "since": None, "assignment_id": None, "next": None, "had_assignments": bool(rows)}
    if upcoming:
        n = upcoming[0]
        out["next"] = {"name": _holder(n, people)["name"], "kind": n.kind, "starts_on": n.starts_on.isoformat()}
    chosen = cover or primary
    if chosen is not None:
        h = _holder(chosen, people)
        out.update(holder=h, holders=[h], source="assignment", kind=chosen.kind, until=chosen.ends_on.isoformat() if chosen.ends_on else None, since=chosen.starts_on.isoformat(), assignment_id=str(chosen.id))
        if primary is not None:
            out["primary"] = _holder(primary, people)
            if cover is not None:
                out["covering_for"] = out["primary"]
        return out
    if rows:                                                                  # it has had assignments and none is active: lapsed (a leaver, an expired cover), not the structure
        out["source"] = "lapsed"
        return out
    legacy = _structure(session, org_id, kind, ref, duty, people)
    if legacy:
        out.update(holder=legacy[0], holders=legacy, source="structure", kind="PRIMARY", primary=legacy[0])
    return out


def snapshot(session: Session, org_id: Any, kind: str, ref: str, on: Optional[date] = None) -> Dict[str, Any]:
    on = on or today()
    people = _people(session, org_id)
    duties = [resolve(session, org_id, kind, ref, d, on, people) for d, _ in DUTIES[kind]]
    return {"subject_kind": kind, "subject_ref": ref, "on": on.isoformat(), "duties": duties, "conflicts": conflicts(duties) if kind == "model" else []}


def _identity(h: Dict[str, Any]) -> str:
    return h["ext_id"] or h["name"].strip().lower()


def conflicts(duties: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The role separation the framework asks of a model: whoever holds two of the three build, validate and deploy duties on the same date."""
    by = {d["duty"]: d for d in duties}
    out = []
    for a, b in SEPARATE:
        for ha in (by.get(a) or {}).get("holders", []):
            for hb in (by.get(b) or {}).get("holders", []):
                if _identity(ha) == _identity(hb):
                    out.append({"duties": [a, b], "holder": ha["name"], "covering": (by[a]["kind"] == "COVER") or (by[b]["kind"] == "COVER")})
    return out


def identities(session: Session, org_id: Any, kind: str, ref: str, on: Optional[date] = None) -> Dict[str, str]:
    """The effective holder of each of a model's roles, as the identity the scoring reads (a name), for the duties that have one."""
    out = {}
    for d in snapshot(session, org_id, kind, ref, on)["duties"]:
        if d["holder"] is not None and d["duty"] != "owner":
            out[d["duty"]] = d["holder"]["name"]
    return out


def history(session: Session, org_id: Any, kind: str, ref: str, duty: Optional[str] = None) -> List[Dict[str, Any]]:
    people = _people(session, org_id)
    q = select(Responsibility, Assignment).join(Assignment, Assignment.responsibility_id == Responsibility.id).where(
        Responsibility.organisation_id == org_id, Responsibility.subject_kind == kind, Responsibility.subject_ref == ref)
    if duty:
        q = q.where(Responsibility.duty == duty)
    out = []
    for r, a in session.execute(q.order_by(Assignment.starts_on.desc(), Assignment.created_at.desc())):
        out.append({"id": str(a.id), "duty": r.duty, "label": LABEL.get(r.duty, r.duty), **{k: v for k, v in _holder(a, people).items()}, "kind": a.kind, "starts_on": a.starts_on.isoformat(),
                    "ends_on": a.ends_on.isoformat() if a.ends_on else None, "reason": a.reason, "created_by": a.created_by, "created_at": a.created_at.isoformat() if a.created_at else None,
                    "ended_by": a.ended_by, "revoked": a.revoked})
    return out


# ── Writing ─────────────────────────────────────────────────────────────────

def _check_subject(session: Session, org_id: Any, kind: str, ref: str) -> str:
    if kind == "agent":
        a = session.scalar(select(Agent).where(Agent.agent_key == ref, Agent.organisation_id == org_id))
        if a is None:
            raise HTTPException(status_code=404, detail="No such agent.")
        return a.name
    if ref.startswith("d:"):
        d = session.scalar(select(Design).where(Design.design_key == ref[2:], Design.subject == "MODEL"))
        if d is None:
            raise HTTPException(status_code=404, detail="No such model design.")
        return d.name
    n = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org_id, CompanyNode.ext_id == ref, CompanyNode.type == "model"))
    if n is None:
        raise HTTPException(status_code=404, detail="No such model in the organisation.")
    return n.name


def _responsibility(session: Session, org_id: Any, kind: str, ref: str, duty: str) -> Responsibility:
    r = session.scalar(select(Responsibility).where(Responsibility.organisation_id == org_id, Responsibility.subject_kind == kind, Responsibility.subject_ref == ref, Responsibility.duty == duty))
    if r is None:
        r = Responsibility(organisation_id=org_id, subject_kind=kind, subject_ref=ref, duty=duty)
        session.add(r)
        session.flush()
    return r


def _materialise(session: Session, org_id: Any, resp: Responsibility, kind: str, ref: str, duty: str, by: str) -> None:
    """The first handover on a duty that only has the structure's holder: that holder becomes the primary assignment, so the handover has something to be a handover from."""
    if session.scalar(select(Assignment.id).where(Assignment.responsibility_id == resp.id)) is not None:
        return
    people = _people(session, org_id)
    for h in _structure(session, org_id, kind, ref, duty, people)[:1]:
        session.add(Assignment(responsibility_id=resp.id, holder_ext_id=h["ext_id"], holder_name=h["name"][:160], kind="PRIMARY", starts_on=BEGINNING,
                               reason="From the organisation's structure", created_by=by))


def _holder_ref(session: Session, org_id: Any, ext_id: Optional[str], name: Optional[str]) -> Dict[str, Optional[str]]:
    if ext_id:
        n = _people(session, org_id).get(ext_id)
        if n is None:
            raise HTTPException(status_code=422, detail=f"{ext_id!r} is not a person or role of the organisation.")
        return {"ext_id": ext_id, "name": n.name[:160]}
    if name and name.strip():
        return {"ext_id": None, "name": name.strip()[:160]}
    raise HTTPException(status_code=422, detail="Say who: a person of the organisation, or a name.")


def sync_agent(session: Session, org_id: Any, key: str, on: Optional[date] = None) -> bool:
    """An agent's owner as every other page reads it (the inventory, the overview, packs, exports) follows the effective holder. Returns whether it changed."""
    a = session.scalar(select(Agent).where(Agent.agent_key == key, Agent.organisation_id == org_id))
    resp = session.scalar(select(Responsibility).where(Responsibility.organisation_id == org_id, Responsibility.subject_kind == "agent", Responsibility.subject_ref == key, Responsibility.duty == "owner"))
    if a is None or resp is None:                                           # nobody has handed this duty over: the structure's value is already what is stored
        return False
    r = resolve(session, org_id, "agent", key, "owner", on)
    name = r["holder"]["name"][:120] if r["holder"] else None
    changed = False
    if a.owner != name:
        a.owner, changed = name, True
    if a.status in ("UNOWNED", "TO_RATIFY"):
        status = "TO_RATIFY" if name else "UNOWNED"
        if a.status != status:
            a.status, changed = status, True
    return changed


def refresh_owners(session: Session, org_id: Any) -> None:
    """Brings the stored owner of every agent that has assignments up to date with today: a cover that has ended hands the duty back without anyone editing anything."""
    changed = False
    for key in session.scalars(select(Responsibility.subject_ref).where(Responsibility.organisation_id == org_id, Responsibility.subject_kind == "agent", Responsibility.duty == "owner")).all():
        changed = sync_agent(session, org_id, key) or changed
    if changed:
        session.commit()


_refreshed_on: Optional[date] = None


def refresh_daily(session: Session, org_id: Any) -> None:
    """refresh_owners, once per day per process: the only thing that changes without anyone acting is the date, so that is when the stored owners can be out of date."""
    global _refreshed_on
    if _refreshed_on == today():
        return
    _refreshed_on = today()
    refresh_owners(session, org_id)


class HandoverIn(BaseModel):
    subject_kind: str
    subject_ref: str = Field(min_length=1, max_length=80)
    duty: str
    holder_ext_id: Optional[str] = Field(None, max_length=64)
    holder_name: Optional[str] = Field(None, max_length=160)
    kind: str = "COVER"
    starts_on: Optional[date] = None
    ends_on: Optional[date] = None
    reason: Optional[str] = Field(None, max_length=200)

    @field_validator("kind")
    @classmethod
    def kind_ok(cls, v: str) -> str:
        v = v.upper()
        if v not in ("PRIMARY", "COVER"):
            raise ValueError("kind must be PRIMARY or COVER")
        return v

    @model_validator(mode="after")
    def coherent(self) -> "HandoverIn":
        if self.subject_kind not in DUTIES:
            raise ValueError("subject_kind must be agent or model")
        if self.duty not in dict(DUTIES[self.subject_kind]):
            raise ValueError(f"a {self.subject_kind} has no duty called {self.duty!r} (it has {', '.join(d for d, _ in DUTIES[self.subject_kind])})")
        if self.kind == "COVER" and self.ends_on is None:
            raise ValueError("a cover needs an end date: a handover with no end is a new primary")
        if self.starts_on and self.ends_on and self.ends_on < self.starts_on:
            raise ValueError("the end date is before the start date")
        return self


@router.get("/subject")
def get_subject(kind: str, ref: str, on: Optional[date] = None, session: Session = Depends(get_session)) -> Dict[str, Any]:
    if kind not in DUTIES:
        raise HTTPException(status_code=422, detail="kind must be agent or model")
    org = current_organisation(session)
    name = _check_subject(session, org.id, kind, ref)
    out = snapshot(session, org.id, kind, ref, on)
    out.update(name=name, history=history(session, org.id, kind, ref))
    return out


@router.get("/people")
def people(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """The employees (people and roles of the organisation) a duty can be handed to."""
    org = current_organisation(session)
    depts = {n.ext_id: n.name for n in session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.type == "department"))}
    return sorted(({"ext_id": n.ext_id, "name": n.name, "type": n.type, "title": (n.props or {}).get("title"), "department": depts.get((n.props or {}).get("department", ""))}
                   for n in _people(session, org.id).values()), key=lambda x: x["name"].lower())


@router.get("/person/{ext_id}")
def person(ext_id: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """What a person holds now, what is coming, and what they have held: the employee record's side of the story."""
    org = current_organisation(session)
    people_ = _people(session, org.id)
    if ext_id not in people_:
        raise HTTPException(status_code=404, detail="No such person or role in the organisation.")
    on = today()
    rows = session.execute(select(Responsibility, Assignment).join(Assignment, Assignment.responsibility_id == Responsibility.id).where(
        Responsibility.organisation_id == org.id, Assignment.holder_ext_id == ext_id, Assignment.revoked.is_(False)).order_by(Assignment.starts_on.desc())).all()
    names: Dict[str, str] = {}

    def subject(r: Responsibility) -> str:
        if r.subject_ref not in names:
            try:
                names[r.subject_ref] = _check_subject(session, org.id, r.subject_kind, r.subject_ref)
            except HTTPException:
                names[r.subject_ref] = r.subject_ref
        return names[r.subject_ref]

    out: Dict[str, List[Dict[str, Any]]] = {"now": [], "upcoming": [], "past": []}
    for r, a in rows:
        item = {"subject_kind": r.subject_kind, "subject_ref": r.subject_ref, "subject": subject(r), "duty": r.duty, "label": LABEL.get(r.duty, r.duty), "kind": a.kind,
                "starts_on": a.starts_on.isoformat(), "ends_on": a.ends_on.isoformat() if a.ends_on else None, "reason": a.reason}
        eff = resolve(session, org.id, r.subject_kind, r.subject_ref, r.duty, on, people_)
        if a.starts_on > on:
            out["upcoming"].append(item)
        elif a.ends_on is not None and a.ends_on < on:
            out["past"].append(item)
        elif eff["assignment_id"] == str(a.id):
            out["now"].append(item)
        else:
            out["now"].append({**item, "standing_by": True})                    # the primary while someone else is covering
    return {"ext_id": ext_id, "name": people_[ext_id].name, **out}


@router.post("/handover")
def handover(body: HandoverIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    """Hands a duty over: temporary cover for a period (leave, sickness), or a new primary from a date (a leaver, a reorganisation). The structure is not touched."""
    org = current_organisation(session)
    subject_name = _check_subject(session, org.id, body.subject_kind, body.subject_ref)
    who = _holder_ref(session, org.id, body.holder_ext_id, body.holder_name)
    start = body.starts_on or today()
    resp = _responsibility(session, org.id, body.subject_kind, body.subject_ref, body.duty)
    _materialise(session, org.id, resp, body.subject_kind, body.subject_ref, body.duty, user.name)
    rows = list(session.scalars(select(Assignment).where(Assignment.responsibility_id == resp.id, Assignment.revoked.is_(False))))
    if body.kind == "PRIMARY":
        for a in rows:
            if a.kind != "PRIMARY" or (a.ends_on is not None and a.ends_on < start):
                continue
            if a.starts_on >= start:
                raise HTTPException(status_code=409, detail=f"A primary assignment already starts on {a.starts_on.isoformat()}, on or after that date. End or cancel it first.")
            a.ends_on, a.ended_by, a.ended_at = start - timedelta(days=1), user.name, datetime.now(timezone.utc)
    a = Assignment(responsibility_id=resp.id, holder_ext_id=who["ext_id"], holder_name=who["name"], kind=body.kind, starts_on=start, ends_on=body.ends_on, reason=body.reason, created_by=user.name)
    session.add(a)
    session.flush()
    if body.subject_kind == "agent":
        sync_agent(session, org.id, body.subject_ref, start if start <= today() else None)
    session.commit()
    snap = snapshot(session, org.id, body.subject_kind, body.subject_ref, start)
    audit.record(user.name, user.role, "responsibility.handover", "ok", {"subject": f"{body.subject_kind}:{body.subject_ref}", "name": subject_name, "duty": body.duty, "to": who["name"], "kind": body.kind,
                                                                   "from": start.isoformat(), "until": body.ends_on.isoformat() if body.ends_on else None, "reason": body.reason or "", "conflicts": len(snap["conflicts"])})
    return {"assignment_id": str(a.id), "snapshot": snap, "conflicts": snap["conflicts"]}


class EndIn(BaseModel):
    on: Optional[date] = None
    reason: Optional[str] = Field(None, max_length=200)


def _assignment(session: Session, org_id: Any, aid: str) -> tuple:
    try:
        import uuid
        a = session.get(Assignment, uuid.UUID(aid))
    except ValueError:
        a = None
    r = session.get(Responsibility, a.responsibility_id) if a is not None else None
    if a is None or r is None or r.organisation_id != org_id:
        raise HTTPException(status_code=404, detail="No such assignment.")
    return a, r


@router.post("/assignments/{aid}/end")
def end_assignment(aid: str, body: EndIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    """Ends an assignment on a date (today by default): the cover returns early, the person leaves. Nothing is deleted."""
    org = current_organisation(session)
    a, r = _assignment(session, org.id, aid)
    on = body.on or today()
    if a.revoked:
        raise HTTPException(status_code=409, detail="That assignment was cancelled.")
    if on < a.starts_on:
        raise HTTPException(status_code=422, detail="It cannot end before it starts: cancel it instead.")
    if a.ends_on is not None and a.ends_on <= on:
        raise HTTPException(status_code=409, detail="It already ends on or before that date.")
    a.ends_on, a.ended_by, a.ended_at = on, user.name, datetime.now(timezone.utc)
    if body.reason:
        a.reason = ((a.reason + " · ") if a.reason else "") + body.reason[:120]
    if r.subject_kind == "agent":
        sync_agent(session, org.id, r.subject_ref)
    session.commit()
    audit.record(user.name, user.role, "responsibility.end", "ok", {"subject": f"{r.subject_kind}:{r.subject_ref}", "duty": r.duty, "holder": a.holder_name, "on": on.isoformat(), "reason": body.reason or ""})
    return {"snapshot": snapshot(session, org.id, r.subject_kind, r.subject_ref)}


@router.post("/assignments/{aid}/cancel")
def cancel_assignment(aid: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    """Cancels an assignment that has not started yet (a handover made in error). One that has started is ended, not cancelled, so the history stays true."""
    org = current_organisation(session)
    a, r = _assignment(session, org.id, aid)
    if a.starts_on <= today():
        raise HTTPException(status_code=409, detail="It has already started: end it instead, so the history stays true.")
    a.revoked, a.ended_by, a.ended_at = True, user.name, datetime.now(timezone.utc)
    session.commit()
    audit.record(user.name, user.role, "responsibility.cancel", "ok", {"subject": f"{r.subject_kind}:{r.subject_ref}", "duty": r.duty, "holder": a.holder_name})
    return {"snapshot": snapshot(session, org.id, r.subject_kind, r.subject_ref)}


def end_holder(session: Session, org_id: Any, ext_id: str, by: str) -> int:
    """A person or role is removed from the organisation: what they hold stops being theirs as of now, so it ended yesterday (an assignment that only starts today or later is
    cancelled instead). They keep their name in the history. Does not commit."""
    n = 0
    yesterday = today() - timedelta(days=1)
    for a, r in session.execute(select(Assignment, Responsibility).join(Responsibility, Responsibility.id == Assignment.responsibility_id).where(
            Responsibility.organisation_id == org_id, Assignment.holder_ext_id == ext_id, Assignment.revoked.is_(False))).all():
        if a.ends_on is not None and a.ends_on <= yesterday:
            continue
        if a.starts_on > yesterday:
            a.revoked = True
        else:
            a.ends_on = yesterday
        a.ended_by, a.ended_at = by, datetime.now(timezone.utc)
        n += 1
        if r.subject_kind == "agent":
            sync_agent(session, org_id, r.subject_ref)
    return n
