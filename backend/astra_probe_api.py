"""
ASTRA Probe through the API (phase 8): running it, its results, incident scenarios and the admission check.

  POST /api/astra/probe/run                       {design_key, trigger?}   replay the scenarios against the design's contract and record the run (write)
  POST /api/astra/probe/run-all                   run every agent design: what a nightly schedule calls (write)
  GET  /api/astra/probe/latest?design_key=        the newest run of the design, and whether it is of the design as it is now
  GET  /api/astra/probe/runs?design_key=          recent runs;  GET /runs/{id}  one run in full
  GET  /api/astra/probe/catch-rate                per class: how often the planted defect was caught and the boundary case left alone, over the last 30 days
  POST /api/astra/probe/scenarios/from-finding/{key}   turn a finding into a proposed scenario (write)
  GET  /api/astra/probe/scenarios?agent=          incident scenarios
  POST /api/astra/probe/scenarios/{id}/approve|retire   a person other than the proposer approves it into the standing suite (signoff)
  GET  /api/astra/probe/admission?design_key=     admit or refuse a change to the design (what astra-check calls)

What a run tests is the draft behavioural contract of the design as saved (the document that is, or would be, signed), replayed in memory (astra_probe.py): nothing is written to the
findings or to the runtime events, and no collector is reached.
"""
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import astra_assessment_api as AA
import astra_contract_api as CA
import astra_contract_export as EX
import astra_estate as AE
import astra_probe as AP
import astra_signing as SG
import audit
from astra_model.classes import CLASSES
from auth import AuthUser, current_user
from db.models import Design, Finding, ProbeResult, ProbeRun, ProbeScenario
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/astra/probe", tags=["astra"])
WINDOW_DAYS = 30
NOT_REPLAYABLE = {"DVG-COMM-01": "its signature and payload are never stored, so it cannot be replayed", "DVG-LIFE-01": "it depends on the date it happened, which a replay cannot reproduce"}


def _scenario(s: ProbeScenario) -> Dict[str, Any]:
    return {"id": str(s.id), "agent_key": s.agent_key, "finding_key": s.finding_key, "class_code": s.class_code, "class_name": CLASSES[s.class_code].name, "bad_event": s.bad_event, "status": s.status,
            "proposed_by": s.proposed_by, "decided_by": s.decided_by, "decided_at": s.decided_at.isoformat() if s.decided_at else None, "note": s.note, "created_at": s.created_at.isoformat()}


def _agent_design(session: Session, design_key: str) -> Design:
    return AA._agent_design(session, design_key)


def _incidents(session: Session, org_id: uuid.UUID, agent_key: str) -> List[Dict[str, Any]]:
    return [{"id": s.id, "class": s.class_code, "bad": s.bad_event}
            for s in session.scalars(select(ProbeScenario).where(ProbeScenario.organisation_id == org_id, ProbeScenario.agent_key == agent_key, ProbeScenario.status == "STANDING"))]


def _result_row(r: ProbeResult) -> Dict[str, Any]:
    return {"id": str(r.id), "class": r.class_code, "class_name": CLASSES[r.class_code].name, "control": r.control, "basis": r.basis, "source": r.source, "applicable": r.applicable,
            "reason": r.reason, "expected": r.expected, "bad_event": r.bad_event, "good_event": r.good_event, "bad": r.bad, "good": r.good, "bad_ok": r.bad_ok, "good_ok": r.good_ok, "passed": r.passed}


def _run_row(r: ProbeRun, design_hash: Optional[str] = None) -> Dict[str, Any]:
    return {"id": str(r.id), "design_key": r.design_key, "agent_key": r.agent_key, "trigger": r.trigger, "summary": r.summary, "created_by": r.created_by, "created_at": r.created_at.isoformat(),
            "contract_hash": r.contract_hash, "current": None if design_hash is None else r.design_hash == design_hash}


def execute_run(session: Session, design: Design, user_name: str, trigger: str) -> Dict[str, Any]:
    org = current_organisation(session)
    (document, _problems), _assessment = CA._draft(session, design)
    agent_id = EX.contract_agent_id(AE._primary(design.document)["name"])
    results = AP.run(document, _incidents(session, org.id, agent_id))
    run = ProbeRun(organisation_id=org.id, design_key=design.design_key, agent_key=agent_id, design_hash=AA._hash(design.document), contract_hash=SG.digest(document), trigger=trigger,
                   summary=AP.summary(results), created_by=user_name)
    session.add(run)
    session.flush()
    for r in results:
        session.add(ProbeResult(run_id=run.id, class_code=r["class"], control=r["control"], basis=r["basis"], source=r["source"], scenario_id=r["scenario_id"], applicable=r["applicable"],
                                reason=r["reason"], expected=r["expected"], bad_event=r["bad_event"], good_event=r["good_event"], bad=r["bad"], good=r["good"], bad_ok=r["bad_ok"],
                                good_ok=r["good_ok"], passed=r["passed"]))
    session.commit()
    audit.record(user_name, "system" if trigger in ("nightly", "sign") else "user", "astra.probe", detail={"design_key": design.design_key, "run": str(run.id), "trigger": trigger, **run.summary})
    return {**_run_row(run, run.design_hash), "results": results}


class RunIn(BaseModel):
    design_key: str = Field(min_length=1, max_length=40)
    trigger: Literal["manual", "nightly", "admission"] = "manual"


@router.post("/run", status_code=201)
def run_probe(body: RunIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    return execute_run(session, _agent_design(session, body.design_key), user.name, body.trigger)


@router.post("/run-all")
def run_all(session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    out: List[Dict[str, Any]] = []
    for d in session.scalars(select(Design).where(Design.subject == "AGENT").order_by(Design.design_key)).all():
        try:
            r = execute_run(session, d, user.name, "nightly")
            out.append({"design_key": d.design_key, "run": r["id"], **r["summary"]})
        except HTTPException as exc:
            session.rollback()
            out.append({"design_key": d.design_key, "error": str(exc.detail)})
        except Exception as exc:                                                    # one design that cannot be probed must not stop the rest
            session.rollback()
            out.append({"design_key": d.design_key, "error": f"{type(exc).__name__}: {exc}"})
    return {"runs": out, "failed": sum(1 for r in out if "error" in r)}


def _latest(session: Session, design: Design) -> Optional[ProbeRun]:
    return session.scalar(select(ProbeRun).where(ProbeRun.organisation_id == current_organisation(session).id, ProbeRun.design_key == design.design_key)
                          .order_by(ProbeRun.created_at.desc()).limit(1))


@router.get("/latest")
def latest(design_key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    design = _agent_design(session, design_key)
    run = _latest(session, design)
    if run is None:
        return {"run": None}
    rows = session.scalars(select(ProbeResult).where(ProbeResult.run_id == run.id).order_by(ProbeResult.source.desc(), ProbeResult.class_code))
    return {"run": _run_row(run, AA._hash(design.document)), "results": sorted([_result_row(r) for r in rows], key=lambda r: (r["source"] != "template", r["class"])),
            "evidence_days": AP.PROBE_TTL_DAYS}


@router.get("/runs")
def runs(design_key: str, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    design = _agent_design(session, design_key)
    h = AA._hash(design.document)
    return [_run_row(r, h) for r in session.scalars(select(ProbeRun).where(ProbeRun.organisation_id == current_organisation(session).id, ProbeRun.design_key == design_key)
                                                    .order_by(ProbeRun.created_at.desc()).limit(30))]


@router.get("/runs/{run_id}")
def get_run(run_id: uuid.UUID, session: Session = Depends(get_session)) -> Dict[str, Any]:
    run = session.get(ProbeRun, run_id)
    if run is None or run.organisation_id != current_organisation(session).id:
        raise HTTPException(status_code=404, detail="No such Probe run.")
    rows = session.scalars(select(ProbeResult).where(ProbeResult.run_id == run.id))
    return {**_run_row(run), "results": sorted([_result_row(r) for r in rows], key=lambda r: (r["source"] != "template", r["class"]))}


@router.get("/catch-rate")
def catch_rate(session: Session = Depends(get_session)) -> Dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    org = current_organisation(session)
    rows = session.execute(select(ProbeResult.class_code, ProbeResult.source, ProbeResult.applicable, ProbeResult.bad_ok, ProbeResult.good_ok, ProbeResult.run_id)
                           .join(ProbeRun, ProbeRun.id == ProbeResult.run_id).where(ProbeRun.organisation_id == org.id, ProbeRun.created_at >= since)).all()
    by: Dict[str, Dict[str, Any]] = {c: {"class": c, "name": CLASSES[c].name, "basis": CLASSES[c].basis, "asi": list(CLASSES[c].asi), "tested": 0, "caught": 0, "boundary_ok": 0, "boundary_tested": 0,
                                         "not_applicable": 0} for c in AP.CLASS_IDS}
    for c, src, app, bad_ok, good_ok, _ in rows:
        if src != "template" or c not in by:
            continue
        e = by[c]
        if not app:
            e["not_applicable"] += 1
            continue
        e["tested"] += 1
        e["caught"] += 1 if bad_ok else 0
        if good_ok is not None:
            e["boundary_tested"] += 1
            e["boundary_ok"] += 1 if good_ok else 0
    for e in by.values():
        e["catch_rate"] = round(e["caught"] / e["tested"], 4) if e["tested"] else None
    tested = sum(e["tested"] for e in by.values())
    return {"window_days": WINDOW_DAYS, "classes": list(by.values()), "runs": len({r[5] for r in rows}), "tested": tested, "caught": sum(e["caught"] for e in by.values()),
            "catch_rate": round(sum(e["caught"] for e in by.values()) / tested, 4) if tested else None}


# ── incident to test ─────────────────────────────────────────────────────────────────────────────────────────────

@router.post("/scenarios/from-finding/{finding_key}", status_code=201)
def from_finding(finding_key: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    try:
        seq = int(finding_key.removeprefix("F-"))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such finding.")
    org = current_organisation(session)
    f = session.scalar(select(Finding).where(Finding.organisation_id == org.id, Finding.seq == seq))
    if f is None:
        raise HTTPException(status_code=404, detail="No such finding.")
    if f.class_code not in CLASSES or CLASSES[f.class_code].basis == "baseline":
        raise HTTPException(status_code=422, detail="This finding was raised by the earlier check of the unsigned contract; scenarios are made from findings of the typed classes.")
    if f.class_code in NOT_REPLAYABLE:
        raise HTTPException(status_code=422, detail=f"{f.class_code} cannot become a scenario: {NOT_REPLAYABLE[f.class_code]}.")
    if not f.event or "type" not in f.event:
        raise HTTPException(status_code=422, detail="This finding has no recorded event to replay.")
    if session.scalar(select(ProbeScenario.id).where(ProbeScenario.organisation_id == org.id, ProbeScenario.finding_key == finding_key, ProbeScenario.status != "RETIRED")):
        raise HTTPException(status_code=409, detail="This finding already has a scenario.")
    bad = {k: v for k, v in f.event.items() if k not in ("at", "trace_id", "payload", "signature", "key_id")}
    design = None
    for d in session.scalars(select(Design).where(Design.organisation_id == org.id, Design.subject == "AGENT")):          # the design of the agent that raised it
        try:
            if EX.contract_agent_id(AE._primary(d.document)["name"]) == f.agent_key:
                design = d
                break
        except ValueError:
            continue
    if design is None:
        raise HTTPException(status_code=409, detail="No saved design belongs to this finding's agent, so there is no contract to replay the event against.")
    (document, _p), _a = CA._draft(session, design)
    seen = AP.run_scenario(document, {"class": f.class_code, "bad": bad, "good": None, "na": None})
    if not seen["bad_ok"]:
        raise HTTPException(status_code=409, detail=f"Replayed against the current contract this event no longer gives {f.class_code} (it gives {seen['bad']['outcome']} {seen['bad']['classes']}), "
                                                    "so it would not be a useful scenario.")
    s = ProbeScenario(organisation_id=org.id, agent_key=f.agent_key, finding_key=finding_key, class_code=f.class_code, bad_event=bad, proposed_by=user.name)
    session.add(s)
    session.commit()
    audit.record(user.name, user.role, "astra.probe.propose", detail={"finding": finding_key, "class": f.class_code, "id": str(s.id)})
    return _scenario(s)


@router.get("/scenarios")
def list_scenarios(agent: Optional[str] = None, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    q = select(ProbeScenario).where(ProbeScenario.organisation_id == current_organisation(session).id)
    if agent:
        q = q.where(ProbeScenario.agent_key == agent)
    return [_scenario(s) for s in session.scalars(q.order_by(ProbeScenario.created_at.desc()))]


class DecisionIn(BaseModel):
    note: Optional[str] = Field(None, max_length=500)


def _decide(session: Session, user: AuthUser, scenario_id: uuid.UUID, status: str, note: Optional[str]) -> Dict[str, Any]:
    s = session.get(ProbeScenario, scenario_id)
    if s is None or s.organisation_id != current_organisation(session).id:
        raise HTTPException(status_code=404, detail="No such scenario.")
    if status == "STANDING":
        if s.status != "PROPOSED":
            raise HTTPException(status_code=409, detail=f"This scenario is {s.status.lower()}, not waiting for approval.")
        if s.proposed_by == user.name:
            raise HTTPException(status_code=403, detail="A different person from the one who proposed the scenario has to approve it.")
    elif s.status == "RETIRED":
        raise HTTPException(status_code=409, detail="It is already retired.")
    s.status, s.decided_by, s.decided_at, s.note = status, user.name, datetime.now(timezone.utc), (note or "").strip() or None
    session.commit()
    audit.record(user.name, user.role, "astra.probe." + ("approve" if status == "STANDING" else "retire"), detail={"id": str(s.id), "class": s.class_code, "finding": s.finding_key})
    return _scenario(s)


@router.post("/scenarios/{scenario_id}/approve")
def approve(scenario_id: uuid.UUID, body: DecisionIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    return _decide(session, user, scenario_id, "STANDING", body.note)


@router.post("/scenarios/{scenario_id}/retire")
def retire(scenario_id: uuid.UUID, body: DecisionIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    return _decide(session, user, scenario_id, "RETIRED", body.note)


# ── admission ────────────────────────────────────────────────────────────────────────────────────────────────────

@router.get("/admission")
def admission(design_key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """Admit the design only if the newest Probe run is of this exact version, is not older than the lifetime of its evidence, every applicable scenario passed and every standing
    incident scenario was part of that run. The reasons say what to do."""
    design = _agent_design(session, design_key)
    org = current_organisation(session)
    run = _latest(session, design)
    reasons: List[str] = []
    out: Dict[str, Any] = {"design_key": design_key, "run": None}
    if run is None:
        reasons.append("No Probe run exists for this design. Run the Probe on it.")
    else:
        out["run"] = _run_row(run, AA._hash(design.document))
        if run.design_hash != AA._hash(design.document):
            reasons.append("The newest Probe run is of an earlier version of the design. Run the Probe again.")
        if run.created_at < datetime.now(timezone.utc) - timedelta(days=AP.PROBE_TTL_DAYS):
            reasons.append(f"The newest Probe run is more than {AP.PROBE_TTL_DAYS} days old, the lifetime of its evidence. Run the Probe again.")
        rows = list(session.scalars(select(ProbeResult).where(ProbeResult.run_id == run.id)))
        for r in rows:
            if r.applicable and not r.passed:
                why = "the planted defect was not caught" if not r.bad_ok else "the boundary case raised a false alarm"
                reasons.append(f"{'Standing scenario' if r.source == 'incident' else 'Scenario'} {r.class_code} ({CLASSES[r.class_code].name}) failed: {why}.")
        ran = {r.scenario_id for r in rows if r.scenario_id}
        for inc in _incidents(session, org.id, run.agent_key):
            if inc["id"] not in ran:
                reasons.append(f"The standing scenario for {inc['class']} (from {inc['id']}) was approved after the newest run. Run the Probe again.")
        if not any(r.applicable for r in rows):
            reasons.append("The Probe found nothing to test in this design's contract.")
    out.update(admit=not reasons, reasons=reasons, checked_at=datetime.now(timezone.utc).isoformat())
    return out
