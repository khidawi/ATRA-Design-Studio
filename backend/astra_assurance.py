"""
Class-level coverage, the per-agent assurance dossier and the security view (ASTRA phase 12).

Coverage here is not a checklist the design ticks. For each OWASP agentic row (ASI01 to ASI10) and each agent with a signed contract, three facts are read from records that already exist:

    constraint   the signed contract declares a constraint for the row
    probe        the newest ASTRA Probe run of this version of the design passed every scenario of the classes that signal the row (and missed none)
    monitored    at least one divergence class that signals the row is monitored AND events of its kind have actually been received from this agent in the last 30 days

    Covered   all three hold
    Partial   some hold
    Gap       none hold, or a Probe scenario for the row was missed (a miss is a gap whatever else is true)

A row no divergence class signals (there are rows like that) can never be monitored, so it can be at most Partial: the dossier says so instead of rounding it up. Across agents the row takes the
worst verdict, as the older scorecard does: a coverage figure that averages away a gap would hide it. Every row has a named owner and a due date (the same assignments the scorecard keeps), and a
row without an owner is listed as a gap in ownership.

The dossier of one agent resolves every claim to a record (the signed contract, the Probe run, the recorded assessments, the evaluation of a learned model) and to the clauses the contract maps
the row to, and states its gaps and the limits of what it proves. Nothing here is stored: it is computed on request from the records.
"""
import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

import astra_assessment_api as AA
import astra_contract_export as EX
import astra_learned as L
import astra_conformity as AR
import astra_verdicts as V
from astra_model.classes import CLASSES
from db.models import (AstraAssessment, AstraBaseline, AstraSignedContract, CoverageAssignment, Design, Finding, LearnedEvaluation, LearnedFlag, LearnedModel, ProbeResult, ProbeRun,
                       RuntimeEvent)
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/astra", tags=["astra"])
ROWS = [f"ASI{i:02d}" for i in range(1, 11)]
WINDOW_DAYS = 30
EXPIRING_DAYS = 14
LIMITS = [
    "Coverage counts a row as monitored only when events of a class that signals it have really been received from the agent in the last 30 days and the check could judge them (an event with a missing attribute is unverified and does not count); a class that is implemented but receives nothing is not coverage.",
    "A Probe pass shows that the checks catch the scenarios the Probe generated from the contract. It is not a penetration test of the agent.",
    "The clauses are the article-level anchors of the specification, indicative: clause-level mapping is not finished, and a regulation-change watch flags mappings that need a person's review.",
    "Learned detectors are advisory. Their evaluations are measured on simulated traffic and say so.",
]


# ── pure ──────────────────────────────────────────────────────────────────────────────────────────────────────

def row_verdict(constraint: bool, probe: str, monitored: str) -> Dict[str, Any]:
    """The verdict of one row for one agent. probe: pass | fail | none | stale. monitored: receiving | idle | none (no class signals the row)."""
    facts = {"constraint": bool(constraint), "probe": probe == "pass", "monitored": monitored == "receiving"}
    why: List[str] = []
    if not constraint:
        why.append("the signed contract declares no constraint for this row")
    if probe == "fail":
        why.append("a Probe scenario for this row was missed")
    elif probe == "stale":
        why.append("the newest Probe run is of an earlier version of the design")
    elif probe == "none":
        why.append("no Probe scenario has passed for this row" if monitored != "none" else "no Probe scenario exists for this row")
    if monitored == "none":
        why.append("no divergence class signals this row, so it cannot be monitored")
    elif monitored == "idle":
        why.append("the classes that signal this row have received no events from this agent in the last 30 days")
    n = sum(facts.values())
    if probe == "fail" or n == 0:
        verdict = "Gap"
    elif n == 3:
        verdict = "Covered"
    else:
        verdict = "Partial"
    return {"verdict": verdict, "facts": facts, "why": why}


def worst(verdicts: List[str]) -> str:
    if not verdicts:
        return "No data"
    return "Gap" if "Gap" in verdicts else ("Partial" if "Partial" in verdicts else "Covered")


def classes_of(row: str) -> List[str]:
    return [cid for cid, c in CLASSES.items() if row in c.asi]


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


# ── facts from the records ────────────────────────────────────────────────────────────────────────────────────

def signed_agents(session: Session, org_id: Any) -> Dict[str, AstraSignedContract]:
    """The newest signed contract of each agent that has one, and that one is ACTIVE (a revoked or superseded one is not coverage)."""
    out: Dict[str, AstraSignedContract] = {}
    for r in session.scalars(select(AstraSignedContract).where(AstraSignedContract.organisation_id == org_id, AstraSignedContract.status == "ACTIVE").order_by(AstraSignedContract.signed_at)):
        out[r.agent_key] = r
    return out


def event_counts(session: Session, org_id: Any, agent_key: str) -> Dict[str, int]:
    since = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    return {t: n for t, n in session.execute(select(RuntimeEvent.type, func.count()).where(RuntimeEvent.organisation_id == org_id, RuntimeEvent.agent_key == agent_key, RuntimeEvent.at >= since,
                                                                                              RuntimeEvent.verdict != "UNVERIFIED").group_by(RuntimeEvent.type)).all()}


def latest_run(session: Session, org_id: Any, design: Optional[Design]) -> Tuple[Optional[ProbeRun], List[ProbeResult], bool]:
    """(newest Probe run of the design, its results, whether it is of the design as it is now)."""
    if design is None:
        return None, [], False
    run = session.scalar(select(ProbeRun).where(ProbeRun.organisation_id == org_id, ProbeRun.design_key == design.design_key).order_by(ProbeRun.created_at.desc()).limit(1))
    if run is None:
        return None, [], False
    rows = list(session.scalars(select(ProbeResult).where(ProbeResult.run_id == run.id)))
    return run, rows, run.design_hash == AA._hash(design.document)


def agent_rows(session: Session, org_id: Any, row: AstraSignedContract) -> Dict[str, Any]:
    """Every ASI row for one agent, with the three facts and the classes behind them."""
    design = session.scalar(select(Design).where(Design.design_key == row.design_key))
    run, results, current = latest_run(session, org_id, design)
    counts = event_counts(session, org_id, row.agent_key)
    declared = {c["asi"] for c in (row.document.get("constraints") or [])}
    baseline = L.has_active_model(session, org_id, row.agent_key)
    out: List[Dict[str, Any]] = []
    for code in ROWS:
        cls = classes_of(code)
        res = [r for r in results if r.class_code in cls and r.applicable and r.source == "template"]
        if not current:
            probe = "stale" if run is not None else "none"
        elif any(not r.passed for r in res):
            probe = "fail"
        elif any(r.passed for r in res):
            probe = "pass"
        else:
            probe = "none"
        chips = []
        receiving = False
        for cid in cls:
            c = CLASSES[cid]
            n = (1 if baseline else 0) if c.event == "score" else sum(counts.get(w, 0) for w in AR.WIRE.get(c.event, []))      # the baseline class is fed by a calibrated baseline, not by collector events
            receiving = receiving or n > 0
            r = next((x for x in results if x.class_code == cid and x.source == "template"), None)
            chips.append({"id": cid, "name": c.name, "basis": c.basis, "state": AR.class_state(cid), "events_30d": n, "probe": None if r is None else ("n/a" if not r.applicable else ("pass" if r.passed else "fail"))})
        monitored = "none" if not cls else ("receiving" if receiving else "idle")
        v = row_verdict(code in declared, probe, monitored)
        out.append({"code": code, "constraint": code in declared, "probe": probe, "monitored": monitored, "classes": chips, **v})
    return {"agent_key": row.agent_key, "rows": out, "probe_run": None if run is None else {"id": str(run.id), "created_at": run.created_at.isoformat(), "current": current, "summary": run.summary},
            "design_key": row.design_key}


# ── coverage across the estate ───────────────────────────────────────────────────────────────────────────────

def coverage(session: Session) -> Dict[str, Any]:
    org = current_organisation(session)
    agents = signed_agents(session, org.id)
    per = {k: agent_rows(session, org.id, r) for k, r in agents.items()}
    assigned = {a.code: a for a in session.scalars(select(CoverageAssignment).where(CoverageAssignment.organisation_id == org.id))}
    today = datetime.now(timezone.utc).date()
    rows = []
    for code in ROWS:
        by_agent = [{"agent_key": k, **next(x for x in p["rows"] if x["code"] == code)} for k, p in per.items()]
        verdict = worst([b["verdict"] for b in by_agent])
        a = assigned.get(code)
        reasons = sorted({w for b in by_agent if b["verdict"] != "Covered" for w in b["why"]})
        rows.append({"code": code, "name": AR.ASI_NAMES[code], "verdict": verdict, "classes": [{"id": cid, "name": CLASSES[cid].name, "state": AR.class_state(cid)} for cid in classes_of(code)],
                     "agents": by_agent, "reasons": reasons, "owner": a.owner if a else None, "due": a.due_date.isoformat() if a and a.due_date else None,
                     "overdue": bool(a and a.due_date and a.due_date < today and verdict != "Covered"), "unowned": a is None or not a.owner,
                     "agents_covered": sum(1 for b in by_agent if b["verdict"] == "Covered")})
    count = lambda v: sum(1 for r in rows if r["verdict"] == v)       # noqa: E731
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "agents_in_scope": len(agents), "covered": count("Covered"), "partial": count("Partial"), "gap": count("Gap"), "no_data": count("No data"),
            "rows_without_owner": sum(1 for r in rows if r["unowned"] and r["verdict"] != "Covered"), "rows": rows, "limits": LIMITS}


@router.get("/coverage")
def get_coverage(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return coverage(session)


# ── the dossier of one agent ─────────────────────────────────────────────────────────────────────────────────

def dossier(session: Session, agent_key: str) -> Dict[str, Any]:
    org = current_organisation(session)
    row = signed_agents(session, org.id).get(agent_key)
    if row is None:
        raise HTTPException(status_code=404, detail="That agent has no active signed contract, so there is nothing to state about it.")
    judge = AR.Judge.load(session, org.id, agent_key)
    why = list(judge.why) if judge is not None else ["no signed contract"]
    design = session.scalar(select(Design).where(Design.design_key == row.design_key))
    facts = agent_rows(session, org.id, row)
    run, results, current = latest_run(session, org.id, design)
    mappings = {m["control"]: m["clauses"] for m in (row.document.get("regulatory_mappings") or [])}
    constraints = {c["asi"]: c["control"] for c in (row.document.get("constraints") or [])}
    contract_rec = {"kind": "signed contract", "id": str(row.id)}
    claims, gaps = [], []
    for r in facts["rows"]:
        clauses = sorted(set(EX.CLAUSES.get(r["code"], []) + mappings.get(constraints.get(r["code"], ""), [])))
        evidence = []
        if r["constraint"]:
            evidence.append({"fact": "constraint", "record": {**contract_rec, "constraint": constraints[r["code"]]}})
        if r["probe"] in ("pass", "fail") and run is not None:
            evidence.append({"fact": "probe", "record": {"kind": "probe run", "id": str(run.id)}, "result": r["probe"], "scenarios": [c["id"] for c in r["classes"] if c["probe"] in ("pass", "fail")]})
        for c in r["classes"]:
            if c["events_30d"]:
                evidence.append({"fact": "monitored", "record": {"kind": "runtime events", "class": c["id"], "agent": agent_key, "days": WINDOW_DAYS}, "events": c["events_30d"]})
        claims.append({"row": r["code"], "name": AR.ASI_NAMES[r["code"]], "verdict": r["verdict"], "facts": r["facts"], "evidence": evidence, "clauses": clauses, "classes": r["classes"],
                       "why": r["why"] + ([] if clauses else ["no regulatory clause is mapped to this row"])})
        if r["verdict"] != "Covered":
            gaps.append({"row": r["code"], "verdict": r["verdict"], "why": r["why"]})
    if why:
        gaps.insert(0, {"row": None, "verdict": "Gap", "why": ["the signed contract is not valid right now: " + "; ".join(why)]})
    if design is not None and AA._hash(design.document) != row.design_hash:
        gaps.append({"row": None, "verdict": "Partial", "why": ["the design has changed since this contract was signed"]})
    assessments = [{"id": str(a.id), "verdict": a.verdict, "design_version": a.design_version, "created_by": a.created_by, "created_at": a.created_at.isoformat()}
                   for a in session.scalars(select(AstraAssessment).where(AstraAssessment.organisation_id == org.id, AstraAssessment.design_key == row.design_key).order_by(AstraAssessment.created_at.desc()).limit(10))]
    baseline = session.get(AstraBaseline, row.baseline_id)
    learned = []
    for m in session.scalars(select(LearnedModel).where(LearnedModel.organisation_id == org.id, LearnedModel.detector.in_(("baseline", "tgn", "gnn")), LearnedModel.status.in_(("ACTIVE", "CANDIDATE"))
                                                      ).order_by(LearnedModel.created_at.desc())):
        if m.detector == "baseline" and m.agent_key != agent_key:
            continue
        ev = session.scalar(select(LearnedEvaluation).where(LearnedEvaluation.model_id == m.id).order_by(LearnedEvaluation.created_at.desc()).limit(1))
        learned.append({"detector": m.detector, "version": m.version, "status": "adopted" if m.adopted or m.detector == "baseline" and m.status == "ACTIVE" else m.status.lower(), "model": str(m.id),
                        "evaluation": None if ev is None else {"id": str(ev.id), "passed": ev.passed, "simulated": ev.simulated, "reasons": ev.reasons}})
    content = {
        "agent": agent_key, "generated_at": datetime.now(timezone.utc).isoformat(),
        "contract": {"id": str(row.id), "version": row.version, "contract_hash": row.contract_hash, "key_id": row.key_id, "signed_by": row.signed_by, "signed_at": row.signed_at.isoformat(), "not_before": row.not_before,
                     "expires_at": row.expires_at, "valid_now": not why, "reasons": why, "design_key": row.design_key,
                     "baseline": None if baseline is None else {"id": str(baseline.id), "accepted_by": baseline.accepted_by, "at": baseline.created_at.isoformat()}},
        "claims": claims, "gaps": gaps, "unmapped_rows": [c["row"] for c in claims if not c["clauses"]], "assessments": assessments,
        "probe": None if run is None else {"id": str(run.id), "created_at": run.created_at.isoformat(), "current": current, "trigger": run.trigger, "summary": run.summary,
                                           "results": [{"class": r.class_code, "applicable": r.applicable, "passed": r.passed, "reason": r.reason, "source": r.source} for r in results]},
        "monitored_classes": [{"id": cid, "name": c.name, "basis": c.basis, "state": AR.class_state(cid), "asi": list(c.asi)} for cid, c in CLASSES.items()],
        "learned": learned,
        "findings": {"open": session.scalar(select(func.count()).select_from(Finding).where(Finding.organisation_id == org.id, Finding.agent_key == agent_key, Finding.status == "OPEN")) or 0},
        "limits": LIMITS,
        "summary": {v: sum(1 for c in claims if c["verdict"] == v) for v in ("Covered", "Partial", "Gap")},
    }
    content["hash"] = hashlib.sha256(canonical({k: v for k, v in content.items() if k != "generated_at"}).encode("utf-8")).hexdigest()
    return content


@router.get("/assurance/agent/{agent_key}")
def get_dossier(agent_key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    return dossier(session, agent_key)


# ── what an evidence pack carries ────────────────────────────────────────────────────────────────────────────

def pack_section(session: Session, trust: bool) -> Dict[str, Any]:
    """The ASTRA part of an evidence pack: class-level coverage, the signed contracts, the Probe results, the monitored classes and the learned-layer evaluations, and the limits. The short (trust)
    form carries counts only: no agent names, no per-agent results."""
    cov = coverage(session)
    org = current_organisation(session)
    models = [m for m in session.scalars(select(LearnedModel).where(LearnedModel.organisation_id == org.id, LearnedModel.agent_key == "*", LearnedModel.status.in_(("ACTIVE", "CANDIDATE", "RETIRED"))))]
    evals = []
    for m in models:
        ev = session.scalar(select(LearnedEvaluation).where(LearnedEvaluation.model_id == m.id).order_by(LearnedEvaluation.created_at.desc()).limit(1))
        evals.append({"detector": m.detector, "version": m.version, "adopted": m.adopted and m.status == "ACTIVE", "passed": None if ev is None else ev.passed, "simulated": True if ev is None else ev.simulated})
    classes = {"total": len(CLASSES), "monitored": sum(1 for c in CLASSES if AR.class_state(c) == "monitored"), "pending": sum(1 for c in CLASSES if AR.class_state(c) == "pending"),
               "advisory": sum(1 for c in CLASSES if AR.class_state(c) == "advisory")}
    sec: Dict[str, Any] = {"agents_with_signed_contract": cov["agents_in_scope"], "rows": {"covered": cov["covered"], "partial": cov["partial"], "gap": cov["gap"], "no_data": cov["no_data"]},
                           "rows_without_owner": cov["rows_without_owner"], "divergence_classes": classes, "learned_evaluations": [{k: v for k, v in e.items()} for e in evals], "limits": LIMITS}
    if trust:
        return sec
    sec["rows_detail"] = [{k: r[k] for k in ("code", "name", "verdict", "owner", "due", "reasons", "classes", "agents_covered")} for r in cov["rows"]]
    sec["agents"] = []
    for k, r in signed_agents(session, org.id).items():
        run, _res, current = latest_run(session, org.id, session.scalar(select(Design).where(Design.design_key == r.design_key)))
        sec["agents"].append({"agent": k, "contract": {"id": str(r.id), "version": r.version, "hash": r.contract_hash, "key_id": r.key_id, "expires_at": r.expires_at},
                              "probe": None if run is None else {"id": str(run.id), "created_at": run.created_at.isoformat(), "current": current, "summary": run.summary},
                              "assessments": session.scalar(select(func.count()).select_from(AstraAssessment).where(AstraAssessment.organisation_id == org.id, AstraAssessment.design_key == r.design_key)) or 0})
    return sec


# ── the security view ────────────────────────────────────────────────────────────────────────────────────────

def security_view(session: Session) -> Dict[str, Any]:
    """One page for the person responsible for security: what is wrong now, from records. Nothing here changes anything."""
    org = current_organisation(session)
    now = datetime.now(timezone.utc)
    verdicts = V.verdicts(None, session)
    agents = verdicts["agents"]
    signed = signed_agents(session, org.id)
    expiring = []
    for k, r in signed.items():
        exp = datetime.strptime(r.expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if exp - now <= timedelta(days=EXPIRING_DAYS):
            expiring.append({"agent": k, "expires_at": r.expires_at, "version": r.version})
    findings = session.execute(select(Finding.class_code, Finding.class_severity, Finding.severity, func.count()).where(Finding.organisation_id == org.id, Finding.status == "OPEN")
                               .group_by(Finding.class_code, Finding.class_severity, Finding.severity)).all()
    pending = session.scalar(select(func.count()).select_from(Finding).where(Finding.organisation_id == org.id, Finding.adjudication == "PENDING")) or 0
    flags = [f for f in session.scalars(select(LearnedFlag).where(LearnedFlag.organisation_id == org.id)) if L.effective(f, now)]
    misses, stale = [], []
    for d in session.scalars(select(Design).where(Design.organisation_id == org.id, Design.subject == "AGENT")):
        run, results, current = latest_run(session, org.id, d)
        if run is None:
            continue
        if not current:
            stale.append({"design_key": d.design_key, "run_at": run.created_at.isoformat()})
        missed = sorted({r.class_code for r in results if r.applicable and not r.passed})
        if missed:
            misses.append({"design_key": d.design_key, "classes": missed, "run_at": run.created_at.isoformat()})
    cov = coverage(session)
    reviews = regwatch_open(session)
    return {"generated_at": now.isoformat(),
            "contracts": {"signed_agents": len(signed), "invalid": [{"agent": a["agent_key"], "reason": a.get("reason")} for a in agents if a["verdict"] == "INVALID_CONTRACT"], "expiring": expiring,
                          "expiring_within_days": EXPIRING_DAYS},
            "verdicts": {"counts": verdicts["counts"], "worst": [{"agent": a["agent_key"], "verdict": a["verdict"], "posture": (a.get("posture") or {}).get("recommended")} for a in agents if a["verdict"] != "APPROVED"][:10]},
            "findings": {"open": sum(n for *_x, n in findings), "pending_adjudication": pending,
                         "by_class": sorted([{"class": c, "severity": cs or s, "count": n} for c, cs, s, n in findings], key=lambda x: -x["count"])[:10]},
            "learned": {"open_flags": len(flags), "by_detector": {d: sum(1 for f in flags if f.detector == d) for d in ("baseline", "tgn", "gnn")}},
            "probe": {"designs_with_misses": misses, "designs_with_stale_runs": stale},
            "coverage": {"covered": cov["covered"], "partial": cov["partial"], "gap": cov["gap"], "no_data": cov["no_data"], "rows_without_owner": cov["rows_without_owner"],
                         "worst": [{"code": r["code"], "name": r["name"], "verdict": r["verdict"], "owner": r["owner"]} for r in cov["rows"] if r["verdict"] == "Gap"][:10]},
            "regulation_watch": {"needing_review": len(reviews)}}


def regwatch_open(session: Session) -> List[Dict[str, Any]]:
    import astra_regwatch as RW
    return [m for m in RW.watch(session)["mappings"] if m["status"] != "CURRENT"]


@router.get("/security")
def get_security(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return security_view(session)
