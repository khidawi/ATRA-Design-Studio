"""
The runtime verdict of an agent (ASTRA phase 7): what the gate says now that the agent is live.

    GET /api/runtime/verdicts            one entry per agent that has a signed contract: its verdict, why, the department risk vector, the response posture and the evidence behind them
    GET /api/runtime/verdicts?agent=KEY  one agent

The gate is the one of the design-time assessment (astra_model/gate.py). Only the evidence differs. The estate and the starting statuses are rebuilt from the agent's saved design, the
organisation, the ratified risk layer and the attested evidence (astra_estate.py), and then live evidence is laid over them. Live evidence can only lower a status:

    a finding of High or Critical class severity           the control the class protects is VIOLATED
    a finding of Medium class severity                     UNVERIFIED
    an event that could not be judged (last 24 hours)      UNVERIFIED on the control its kind concerns
    a semantic finding waiting for a person                UNVERIFIED; confirmed, its class severity; dismissed, nothing
    a finding of Low severity                              nothing (it is shown, it does not move a status)

Acknowledging a finding does not remove it: a person who has seen a divergence has not shown it was fixed. What takes evidence away is only what the model allows as supportive: a human
adjudication (dismissing a semantic finding), an attestation, a passed Probe scenario (a later phase) or a new contract version. A new signed contract starts clean: only findings raised since it
was signed count. Attestations that have lapsed read as unverified because the clock is read here, on every call.

A contract that is not valid right now (revoked, expired, tampered with, signed by an unknown key) gives INVALID_CONTRACT, which outranks every other verdict. The response posture is the
ratified matrix of the risk layer applied to the highest impact tier the agent reaches and the severity of each open finding; the worst one is recommended. It is a recommendation: a person
or the control plane enacts it, and a recorded halt request is shown beside it, unchanged.
"""
import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

import astra_assessment_api as AA
import astra_estate as AE
import astra_learned
import astra_probe
import astra_conformity as AR
import risk_api
import risk_layer as RL
from agent_registry import agent_key
from astra_model import gate, statuses
from astra_model.classes import CLASSES, EVENT_CONTROL, SEVERITY_LEVEL
from astra_model.statuses import State
from db.models import AstraSignedContract, Design, Finding, RuntimeEvent
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/runtime", tags=["astra"])
log = logging.getLogger(__name__)
UNVERIFIED_HOURS = 24
LEGACY_CONTROL = {"DVG-TOOL": "least", "DVG-DEL": "deleg", "DVG-SUP": "supply", "DVG-MEM": "memval", "DVG-DATA": "least"}
RANK = {"INVALID_CONTRACT": 0, "BLOCKED": 1, "REQUIRES_REVIEW": 2, "APPROVED": 3}


# ── pure ──────────────────────────────────────────────────────────────────────────────────────────────────────

def finding_effect(f: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """(control kind, level) a finding puts on the control it concerns, or None when it moves nothing."""
    code = f["class_code"]
    control = CLASSES[code].control if code in CLASSES else LEGACY_CONTROL.get(code)
    if control is None or f.get("adjudication") == "DISMISSED":
        return None
    if f.get("adjudication") == "PENDING":
        return control, statuses.UNV
    sev = f.get("class_severity") or f.get("severity")
    level = SEVERITY_LEVEL.get(sev)                                  # High and Critical give VIO, Medium gives UNV, Low gives nothing
    return (control, level) if level else None


def overlay(S: State, names: Dict[str, str], findings: List[Dict[str, Any]], unverified: Dict[str, List[str]], learned: Optional[List[Dict[str, Any]]] = None) -> Dict[Tuple[str, str], List[str]]:
    """Lay live evidence over the starting statuses. names: agent key -> the agent's name in the estate. Returns control -> what moved it."""
    because: Dict[Tuple[str, str], List[str]] = {}
    for f in findings:
        eff = finding_effect(f)
        who = names.get(f["agent_key"])
        if eff is None or who is None:
            continue
        statuses.adverse(S, (eff[0], who), eff[1])
        because.setdefault((eff[0], who), []).append(f["key"])
    for fl in learned or []:                         # a learned detector can do one thing: mark the baseline control unverified (statuses.learned_evidence, Lemma 3)
        who = names.get(fl["agent_key"])
        if who is not None:
            statuses.learned_evidence(S, who, fl["score"], fl["threshold"])
            because.setdefault(("base", who), []).append("a learned flag (baseline score " + format(fl["score"], ".1f") + " against " + format(fl["threshold"], ".1f") + ")")
    for key, kinds in unverified.items():
        who = names.get(key)
        for kind in kinds:
            c = EVENT_CONTROL.get(AR.KIND.get(kind, ""), None)
            if c and who:
                statuses.adverse(S, (c, who), statuses.UNV)
                because.setdefault((c, who), []).append(f"events that could not be judged ({kind})")
    return because


def posture_for(matrix: Dict[int, Dict[str, str]], tier: int, severity: str) -> str:
    return matrix[tier][severity] if severity in RL.SEVERITIES else "observe"


# ── database ──────────────────────────────────────────────────────────────────────────────────────────────────

def _finding_dict(f: Finding) -> Dict[str, Any]:
    return {"key": f"F-{f.seq}", "agent_key": f.agent_key, "class_code": f.class_code, "severity": f.severity, "class_severity": f.class_severity, "adjudication": f.adjudication,
            "status": f.status, "created_at": f.created_at, "detection_basis": f.detection_basis, "asi_signal": f.asi_signal, "title": f.title,
            "halt_requested_by": f.halt_requested_by, "halt_requested_at": f.halt_requested_at}


def _reach_tier(E, name: str) -> int:
    tiers = [E.res[r][1] for r in E.agents[name].resources if r in E.res]
    return max(tiers) if tiers else 1


def agent_verdict(session: Session, org, row: AstraSignedContract, eff: Dict[str, Any], now_day: int) -> Dict[str, Any]:
    key = row.agent_key
    judge = AR.Judge.load(session, org.id, key)
    why = list(judge.why) if judge is not None else ["no signed contract"]
    out: Dict[str, Any] = {"agent_key": key, "contract": {"id": str(row.id), "version": row.version, "status": row.status, "signed_at": row.signed_at.isoformat(), "key_id": row.key_id,
                                                             "expires_at": row.expires_at, "valid": not why, "reasons": why, "design_key": row.design_key}}
    design = session.scalar(select(Design).where(Design.design_key == row.design_key))
    if design is None:
        return {**out, "verdict": "INVALID_CONTRACT", "runtime_name": "INVALID_CONTRACT", "reason": "the design the contract was signed for no longer exists", "departments": [], "controls_moved": [],
                "posture": None, "findings": {"open": 0, "pending": 0}, "halt_requests": []}
    out["contract"]["design_changed"] = AA._hash(design.document) != row.design_hash
    try:
        ctx = AA.context(session, design.document)
        built = AE.build(AE.Source(design.document, AA._rows(session, design.document), AA._evidence(session, design.design_key),
                                   astra_probe.latest_evidence(session, org.id, design.design_key, AA._hash(design.document), now_day),
                                   astra_learned.has_active_model(session, org.id, key)), ctx)
    except ValueError as exc:
        log.warning("the estate of %s could not be built: %s", key, exc)
        return {**out, "verdict": "INVALID_CONTRACT", "runtime_name": "INVALID_CONTRACT", "reason": "the design could not be read as an estate; the reason is in the server log", "departments": [], "controls_moved": [], "posture": None,
                "findings": {"open": 0, "pending": 0}, "halt_requests": []}
    before = AE.describe(built, ctx, now_day)
    names = {agent_key(n): n for n in built.estate.agents}
    fs = [_finding_dict(f) for f in session.scalars(select(Finding).where(Finding.organisation_id == org.id, Finding.agent_key.in_(list(names)), Finding.created_at >= row.signed_at)
                                                    .order_by(Finding.created_at.desc()))]
    since = max(row.signed_at, datetime.now(timezone.utc) - timedelta(hours=UNVERIFIED_HOURS))
    unv: Dict[str, List[str]] = {}
    if not why:                                      # with an invalid contract every event is unverified, which the verdict already says
        for k, t in session.execute(select(RuntimeEvent.agent_key, RuntimeEvent.type).where(RuntimeEvent.organisation_id == org.id, RuntimeEvent.agent_key.in_(list(names)),
                                                                                           RuntimeEvent.verdict == "UNVERIFIED", RuntimeEvent.at >= since).distinct()).all():
            unv.setdefault(k, []).append(t)
    start = built.state.copy()
    learned = astra_learned.flags_for_overlay(session, org.id, list(names), row.signed_at)
    because = overlay(built.state, names, fs, unv, learned)
    after = AE.describe(built, ctx, now_day)
    E = built.estate
    moved = []
    for c in sorted(set(because)):
        a, b = start.status(c, now_day), built.state.status(c, now_day)
        if a != b:
            moved.append({"kind": c[0], "agent": c[1], "from": a, "to": b, "because": because[c]})
    verdict = "INVALID_CONTRACT" if why else after["verdict"]
    mine = [f for f in fs if f["agent_key"] in names]
    open_f = [f for f in mine if f["status"] == "OPEN" or f["adjudication"] == "PENDING"]
    basis = []
    for f in mine:
        e = finding_effect(f)
        if e is None:
            continue
        sev = f.get("class_severity") or f["severity"]
        if sev not in RL.SEVERITIES:
            continue
        tier = _reach_tier(E, names[f["agent_key"]])
        basis.append({"finding": f["key"], "class": f["class_code"], "severity": sev, "tier": tier, "posture": posture_for(eff["posture"], tier, sev)})
    worst = max(basis, key=lambda b: RL.POSTURE_RANK[b["posture"]], default=None)
    posture = {"recommended": worst["posture"] if worst else "observe", "basis": sorted(basis, key=lambda b: -RL.POSTURE_RANK[b["posture"]])[:8],
               "note": "A recommendation from the ratified posture matrix: a person or the control plane enacts it."}
    return {**out, "name": built.primary, "verdict": verdict, "runtime_name": gate.RUNTIME_NAME[gate.INVALID_CONTRACT] if why else after["runtime_name"], "design_verdict": before["verdict"],
            "reason": None if not why else "; ".join(why), "departments": after["departments"], "controls_moved": moved, "posture": posture,
            "findings": {"open": len([f for f in open_f if f["adjudication"] != "PENDING"]), "pending": len([f for f in mine if f["adjudication"] == "PENDING"]), "total": len(mine)},
            "unverified_events": sorted({t for ts in unv.values() for t in ts}), "learned": {"monitored": astra_learned.has_active_model(session, org.id, key), "flags": len(learned)},
            "halt_requests": [{"finding": f["key"], "by": f["halt_requested_by"], "at": f["halt_requested_at"].isoformat()} for f in mine if f["halt_requested_at"]]}


@router.get("/verdicts")
def verdicts(agent: Optional[str] = None, session: Session = Depends(get_session)) -> Dict[str, Any]:
    org = current_organisation(session)
    eff = risk_api.effective(session)
    now_day = date.today().toordinal()
    rows = list(session.scalars(select(AstraSignedContract).where(AstraSignedContract.organisation_id == org.id).order_by(AstraSignedContract.signed_at.desc())))
    latest: Dict[str, AstraSignedContract] = {}
    for r in rows:
        latest.setdefault(r.agent_key, r)
    if agent:
        if agent not in latest:
            raise HTTPException(status_code=404, detail="That agent has no signed contract, so it has no runtime verdict.")
        latest = {agent: latest[agent]}
    out = [agent_verdict(session, org, r, eff, now_day) for r in latest.values()]
    out.sort(key=lambda a: (RANK[a["verdict"]], a["agent_key"]))
    counts = {v: sum(1 for a in out if a["verdict"] == v) for v in RANK}
    feed = [{**{k: v for k, v in _finding_dict(f).items() if k not in ("halt_requested_by", "halt_requested_at", "created_at")}, "created_at": f.created_at.isoformat(),
             "class_name": CLASSES[f.class_code].name if f.class_code in CLASSES else f.title, "element": f.contract_element or f.element, "event_agent": f.agent_key}
            for f in session.scalars(select(Finding).where(Finding.organisation_id == org.id, *( [Finding.agent_key == agent] if agent else [])).order_by(Finding.created_at.desc()).limit(25))]
    return {"agents": out, "counts": counts, "feed": feed, "generated_at": datetime.now(timezone.utc).isoformat(), "unverified_window_hours": UNVERIFIED_HOURS}
