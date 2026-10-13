"""
Assurance Packs for AI models: what the platform can evidence about the models in use, from the design to the running model. Built by packs.py, which stores,
hashes and chains it exactly as it does an agent pack (the chain is shared).

For each model with an active compiled contract the pack gives three scores, all recomputed here by the same scoring engine and none supplied by a browser:

  * design time: the contract's own registry snapshot, which the contract hash covers, so anyone can reproduce it;
  * declared: the same design with the facts people have stated about the running model since (the design's lifecycle facts and incident log);
  * observed: the declared position plus what production monitoring shows (drift, a fairness breach, out-of-domain values, human review that is not catching the
    model's mistakes, open monitor incidents). Production can raise a declared risk, never lower it.

The difference between the last two is the assurance gap. The pack lists where production contradicts what was declared, what is declared but not checked by
anything, the state of each model's monitors (data received, version changes, canary checks, what leaves and comes back unsafe, how people use the outputs,
thresholds loosened past a compliance floor), and states what it does not claim.

What is in the pack is statistics and findings. No prompt, reply, record or person's name is in it. The TRUST form drops model names, monitor names and details.
"""
import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

import attestation as att
import llm_safety as lsf
import model_versions as mv
import threshold_policy as tp
from db.models import Contract, Design, ModelMonitor
from model_monitor import decisions_evaluation, design_signals, safety_evaluation
from organisation import current_organisation
from schema import RegistryBlock
from scoring_bridge import score_registry

PERIODS = {"30d": ("Last 30 days", 30), "90d": ("Last 90 days", 90), "all": ("All time", None)}
STALE_DAYS = 3
INC_KEYS = ["occurred_at", "mitigated_at", "resolved_at", "title", "description", "root_cause", "lessons_learned", "owner"]
FRAMEWORKS = ["ST-AI Pre-deployment Compliance Score (design time, declared and observed)", "Production monitoring of model behaviour"]


def _inc(i: Dict[str, Any]) -> Dict[str, Any]:
    o = {"id": i["id"], "type": i["type"], "severity": i["severity"], "status": i.get("status", "OPEN"), "detected_at": i["detected_at"]}
    o.update({k: i[k] for k in INC_KEYS if i.get(k)})
    return o


def _registry(base: Dict[str, Any], life: Optional[Dict[str, Any]], incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The contract's registry with the facts stated now in place of the ones it was compiled with."""
    r = copy.deepcopy(base)
    for k in ("lifecycle", "incident_register", "hallucination_constraint_declared", "confidence_signal"):
        r.pop(k, None)
    if life:
        r["lifecycle"] = dict(life)
        if life.get("hallucination_constraint_declared") is not None:
            r["hallucination_constraint_declared"] = bool(life["hallucination_constraint_declared"])
        if life.get("confidence_signal"):
            r["confidence_signal"] = life["confidence_signal"]
    if incidents:
        r["incident_register"] = [_inc(i) for i in incidents]
    return r


def _score(reg: Dict[str, Any]) -> Dict[str, Any]:
    try:
        res, _ = score_registry(RegistryBlock(**reg))
    except Exception as exc:                                             # a registry the engine refuses is a gap, not a crash
        return {"error": str(exc)[:200]}
    return {"pcs": round(res.pcs_final, 1) if res.pcs_final is not None else None, "tier": res.tier, "gate": res.gate,
            "pillars": {k: round(v, 1) for k, v in res.pillar_vector.model_dump().items() if v is not None}, "unmet_veto": res.unmet_veto_constraints}


def _observed_life(life: Dict[str, Any], sig: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """The declared facts with what production shows added, and the contradictions found. Production can raise a declared risk, never lower it."""
    out, why = dict(life), []
    for k, text in (("drift_detected", "Production shows drift; none was declared."), ("bias_breach_detected", "Production shows a fairness breach; none was declared."),
                    ("domain_violation_occurred", "Values outside the declared domain were seen in production; none was declared.")):
        if sig.get(k):
            if not life.get(k):
                why.append(text)
            out[k] = True
    if sig.get("drift_detected") and sig.get("drift_type"):
        out["drift_type"] = sig["drift_type"]
    if sig.get("hitl_verified_substantive") is False:
        if life.get("hitl_verified_substantive", True):
            why.append("Human review is declared substantive, but staff decisions do not support it.")
        out["hitl_verified_substantive"] = False
    rank = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    b = sig.get("automation_bias_risk")
    if b in rank and rank.index(b) > max(0, rank.index(life["automation_bias_risk"]) if life.get("automation_bias_risk") in rank else 0):
        out["automation_bias_risk"] = b
        why.append(f"Automation-bias risk is {b.lower()} in production" + (f", declared {life['automation_bias_risk'].lower()}." if life.get("automation_bias_risk") else "; the declaration did not assess it."))
    return out, why


def _monitor_block(session: Session, m: ModelMonitor, now: datetime, floors: Dict[str, Any], trust: bool, label: str) -> Dict[str, Any]:
    """What one monitor shows, as statistics. Read-only: it does not re-evaluate or raise incidents."""
    dec = decisions_evaluation(session, m, now)
    saf = safety_evaluation(session, m, now)
    ver = mv.evaluate(m.versions, m.spec["output"]["kind"], m.thresholds, now.isoformat()) if m.versions and m.versions.get("items") else None
    can = lsf.evaluate_canaries(m.canaries, (m.versions or {}).get("current")) if m.canaries and m.canaries.get("items") else None
    waivers = tp.current_waivers("model", m.waivers or [], m.thresholds or {}) + tp.current_waivers("decisions", m.waivers or [], (m.decision_settings or {}).get("thresholds") or {})
    b: Dict[str, Any] = {"monitor": label, "status": m.status, "task": m.task, "records_received": m.records_total, "last_record_at": m.last_record_at.isoformat() if m.last_record_at else None,
                         "baseline": "ready" if m.baseline else "learning", "baseline_source": (m.baseline or {}).get("source"),
                         "findings": [{"level": r["level"], "kind": r["kind"], "text": r["text"]} for r in (m.reasons or [])[:10]],
                         "versions": {"current": ver["current"], "changes": len(ver["events"]), "seen": len(ver["versions"])} if ver else None,
                         "canaries": {"checks": len(can["rows"]), "failing": sum(1 for r in can["reasons"]), "runs": sum(r["n"] for r in can["rows"])} if can else None,
                         "safety": {"checked_requests": saf["n"], "flagged": {r["flag"]: r["count"] for r in saf["rows"] if r["count"]}} if saf.get("enabled") else None,
                         "people": ({"decisions": dec["n"], "accepted": dec.get("accepted"), "median_look_seconds": dec.get("review_p50"), "wrong_outputs": dec.get("wrong"), "wrong_accepted": dec.get("wrong_accepted"),
                                     "coverage": dec.get("coverage"), "roles": len(dec["roles"]), "individuals_counted": bool((m.decision_settings or {}).get("individuals"))} if dec["n"] else None),
                         "thresholds_loosened_past_floor": [{"threshold": w["key"], "value": w["value"], "floor": w["floor"], "signed_off_by": w["by"], "reason": w["reason"]} for w in waivers]}
    if not trust:
        b["name"] = m.name
    return b


def _gaps_from(model: Dict[str, Any], label: str, trust: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    g = lambda text, status="Gap": out.append({"id": "", "check": "MODEL", "text": f"{label}: {text}", "status": status, "owner": None, "due": None})   # noqa: E731
    for t in model["contradictions"]:
        g(t)
    mons = model["monitors"]
    if not mons:
        g("no production monitor is connected, so nothing checks what was declared about the running model.")
    for mb in mons:
        if mb["baseline"] == "learning":
            g("the production monitor is still learning its baseline, so drift and bias are not yet judged.", "Partial")
        last = mb["last_record_at"]
        if mb["records_received"] == 0:
            g("the production monitor has received no data.")
        elif last and (datetime.now(timezone.utc) - datetime.fromisoformat(last)).days >= STALE_DAYS:
            g(f"the production monitor has had no data for {(datetime.now(timezone.utc) - datetime.fromisoformat(last)).days} days, so drift and bias are not being seen.")
        if mb["status"] == "DRIFT":
            g("the production monitor reports drift: " + (mb["findings"][0]["text"] if mb["findings"] else "see its findings."))
        for w in mb["thresholds_loosened_past_floor"]:
            g(f"a threshold ({w['threshold']}) is looser than the compliance floor, signed off by {w['signed_off_by']}: {w['reason']}", "Partial")
    for a in model["attestations"]["attention"]:
        if a["state"] == "lapsed":
            g(f"the claim '{a['claim']}' lapsed {abs(a['days_left'])} days ago" + ("" if trust else f" (last confirmed by {a['confirmed_by']})") + " and has not been confirmed again.")
        elif a["state"] == "never":
            g(f"the claim '{a['claim']}' has never been confirmed by anyone, so nothing says when it was last true.", "Partial")
    if model["open_monitor_incidents"]:
        g(f"{model['open_monitor_incidents']} open incident(s) raised by monitoring.")
    if model["observed"].get("error"):
        g("the observed position could not be scored: " + model["observed"]["error"])
    return out


def build_model_content(session: Session, template: str, period: str, generated_by: str) -> Dict[str, Any]:
    trust = template == "TRUST"
    now = datetime.now(timezone.utc)
    label, days = PERIODS[period]
    start = now - timedelta(days=days) if days else None
    org = current_organisation(session)

    rows = list(session.scalars(select(Contract).where(Contract.organisation_id == org.id, Contract.object_type == "MODEL", Contract.status == "ACTIVE").order_by(Contract.issued_at)))
    latest: Dict[str, Contract] = {}
    for c in rows:
        latest[c.deployment_id] = c                                      # the newest active contract per deployment
    if not latest:
        raise HTTPException(status_code=409, detail="No model has an active compiled contract, so there is nothing to attest. Compile a model design first.")
    designs = list(session.scalars(select(Design).where(Design.organisation_id == org.id, Design.subject == "MODEL")))
    by_design = {d.id: d for d in designs}
    from attestations import design_rows, policy_days
    from model_monitor import _floors
    floors = _floors(session, org.id)
    policy = policy_days(session)

    evidence: List[Dict[str, Any]] = []
    models: List[Dict[str, Any]] = []
    claims: List[Dict[str, Any]] = []
    gaps: List[Dict[str, Any]] = []
    n_monitors = 0
    for i, c in enumerate(latest.values(), 1):
        label_m = f"Model {i}" if trust else (by_design[c.design_id].name if c.design_id in by_design else c.deployment_id)
        doc = c.document
        base = (doc.get("design_snapshot") or {}).get("registry") or {}
        d = by_design.get(c.design_id)
        life = (d.document.get("life") or {}) if d else {}
        incs = (d.document.get("incidents") or []) if d else []
        mons = list(session.scalars(select(ModelMonitor).where(ModelMonitor.organisation_id == org.id, ModelMonitor.design_key == d.design_key))) if d else []
        sig = design_signals(design_key=d.design_key, session=session) if d else {"signals": {}, "incidents": []}
        mon_incs = [x for x in sig["incidents"] if x["status"] in ("OPEN", "INVESTIGATING", "MITIGATED") and (start is None or x["detected_at"] >= start.isoformat())]
        obs_life, contradictions = _observed_life(life, sig["signals"])
        design_time, declared = _score(base), _score(_registry(base, life, incs))
        observed = _score(_registry(base, obs_life, incs + [{"id": x["id"], "type": x["type"], "severity": x["severity"], "status": x["status"], "detected_at": x["detected_at"], "title": x["title"], "owner": "Production monitoring"} for x in mon_incs]))
        moved = []
        if "error" not in declared and "error" not in observed:
            moved = [{"pillar": k, "declared": declared["pillars"].get(k), "observed": v} for k, v in observed["pillars"].items() if abs(v - (declared["pillars"].get(k) or 0)) >= 0.5]
        arows = design_rows(session, d, policy, now) if d else []
        attested = {"summary": att.summary(arows), "attention": [{"claim": r["label"], "state": r["state"], "days_left": r["days_left"], **({} if trust else {"confirmed_by": r["by"], "confirmed_at": r["at"]})}
                                                                   for r in arows if r["state"] in ("lapsed", "never", "due_soon")]}
        blocks = [_monitor_block(session, m, now, floors, trust, f"Monitor {j}") for j, m in enumerate(mons, 1)]
        n_monitors += len(blocks)
        model: Dict[str, Any] = {"model": label_m, "contract": {"version": doc["version"], "issued_at": doc["issued_at"], "hash": c.contract_hash}, "design_time": design_time, "declared": declared, "observed": observed,
                                 "assurance_gap": {"headline": round(observed["pcs"] - declared["pcs"], 1) if "error" not in observed and "error" not in declared else None, "pillars_moved": moved},
                                 "contradictions": contradictions, "attestations": attested, "monitors": blocks, "open_monitor_incidents": len(mon_incs)}
        if not trust:
            model["contract"].update(id=c.contract_id, issued_by=doc.get("issued_by"))
            model["design_key"] = d.design_key if d else None
        models.append(model)
        evidence.append({"type": "contract", "ref": c.contract_id, "hash": c.contract_hash, "agent": label_m})
        evidence.append({"type": "attestation", "ref": f"{label_m} / declared claims", "hash": _sha(attested)})
        for j, mb in enumerate(blocks, 1):
            evidence.append({"type": "monitor", "ref": f"{label_m} / monitor {j}", "hash": _sha(mb)})
        for x in mon_incs:
            evidence.append({"type": "incident", "ref": x["id"], "hash": _sha({k: x[k] for k in ("id", "type", "severity", "status", "title", "detected_at")})})
        cref = [e["ref"] for e in evidence if e["type"] == "contract" and e["agent"] == label_m]
        claims.append({"id": f"C-{len(claims) + 1}", "text": f"{label_m} operates under ratified contract v{doc['version']}", "status": "evidenced", "evidence": cref})
        if "error" not in design_time:
            claims.append({"id": f"C-{len(claims) + 1}", "text": f"{label_m}: design-time score {design_time['pcs']} ({design_time['tier']}, gate {design_time['gate']}), recomputed from the contract's registry", "status": "evidenced", "evidence": cref})
        if "error" not in declared and "error" not in observed:
            claims.append({"id": f"C-{len(claims) + 1}", "status": "evidenced" if not contradictions else "gap_stated", "evidence": cref,
                           "text": f"{label_m}: declared score {declared['pcs']}, observed score {observed['pcs']}" + (f"; production contradicts {len(contradictions)} declaration(s)" if contradictions else "; production has not contradicted the declaration")})
        if attested["summary"]["claims"]:
            sm = attested["summary"]
            claims.append({"id": f"C-{len(claims) + 1}", "status": "evidenced" if not (sm["lapsed"] or sm["never"]) else "gap_stated", "evidence": [f"{label_m} / declared claims"],
                           "text": f"{label_m}: {sm['current'] + sm['due_soon']} of {sm['claims']} declared claims are confirmed and in date" + (f", {sm['lapsed']} have lapsed" if sm["lapsed"] else "") + (f", {sm['never']} were never confirmed" if sm["never"] else "")})
        for j, mb in enumerate(blocks, 1):
            if mb["records_received"]:
                claims.append({"id": f"C-{len(claims) + 1}", "text": f"{label_m}: production monitor {j} has received {mb['records_received']:,} records and reports {mb['status'].lower().replace('_', ' ')}", "status": "evidenced", "evidence": [f"{label_m} / monitor {j}"]})
            if mb["people"] and mb["people"]["decisions"]:
                claims.append({"id": f"C-{len(claims) + 1}", "text": f"{label_m}: what people do with the outputs is measured ({mb['people']['decisions']:,} decisions by {mb['people']['roles']} role(s))", "status": "evidenced", "evidence": [f"{label_m} / monitor {j}"]})
        for g in _gaps_from(model, label_m, trust):
            g["id"] = f"G-{len(gaps) + 1}"
            gaps.append(g)

    without = [d for d in designs if not any(c.design_id == d.id for c in latest.values())]
    if without:
        gaps.append({"id": f"G-{len(gaps) + 1}", "check": "MODEL", "status": "Gap", "owner": None, "due": None,
                     "text": f"{len(without)} model design(s) have no active contract" + ("" if trust else ": " + ", ".join(d.name for d in without))})
    limits = [
        "No prompt, reply, record or person's name is in this pack. Production figures are statistics kept by monitors; a monitor sees only the traffic the application sends it.",
        "The design-time score is recomputed from the registry inside the compiled contract (the contract hash covers it). Later design edits are not in it until the model is compiled again. The facts stated about the running model are as of generation.",
        "Declared facts are what people stated. Production can raise a declared risk, never lower it; 'no contradiction found' means what is watched agrees with what was said, not that the model is safe.",
        "Checks for personal data, keys and prompt injection are pattern matches run in the organisation's own code, not proof; a match can be a false alarm and a miss is possible.",
        "A declared claim that lowers a model's risk lapses after a period set by compliance unless someone confirms it again; a lapse is advice and does not change the score. A claim made before attestation existed shows as never confirmed.",
        "Monitor thresholds are rules of thumb, not calibrated to any one model. Compliance floors and any waivers signed off against them are listed per monitor.",
        "Each approval is recorded against the signed-in person who made it (local accounts with a password); there is no second factor and no second approver.",
        "Risk scores use weights and floors that are judgement values and have not been calibrated. An Approved gate does not certify compliance.",
    ]
    return {"schema": "astra.pack/1", "subject": "MODEL", "template": template, "organisation": org.name, "generated_at": now.isoformat(), "generated_by": generated_by,
            "period": {"label": label, "from": start.isoformat() if start else None, "to": now.isoformat()}, "frameworks": FRAMEWORKS,
            "approval_mode": "Single signed-in reviewer per action; recorded in the audit log", "limits": limits,
            "scope": {"models_in_scope": len(latest), "models_without_contract": len(without), "monitors": n_monitors, "agents_in_scope": 0},
            "models": models, "claims": claims, "gaps": gaps, "evidence": evidence}


def _sha(obj: Any) -> str:
    from packs import sha
    return sha(obj)
