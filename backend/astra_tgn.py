"""
The learned detectors that run in the `learned` service, on the platform side (ASTRA phases 10 and 11): the temporal graph network ("tgn") and the graph model ("gnn"). The adoption gate,
the registry of candidate models, scores and the detector's own health, the same for both.

The network itself runs in the separate `learned` service (learned/, its own image). The platform never imports it and never trusts it with a decision:

    * the service sends an evaluation: the weights' checksum and the numbers (detection of the network and of the phase 9 baseline on held-out attack families, false positives on held-out
      normal traffic). The platform recomputes the adoption decision from those numbers with its own copy of the rule (decide), records both, and a service that claims a pass it did not
      earn is simply recorded as not passed;
    * a model is adopted only by a person (compliance or admin) and only if its recorded evaluation passed; a model that did not pass cannot be adopted, whatever anyone asks;
    * an adopted model is advisory-only: what it scores becomes flags that can only mark the baseline control unverified (astra_learned.py, Lemma 3, the table constraint);
    * the service holds a collector-role key: it may read the event stream and post an evaluation and window scores, nothing else.

Both outcomes of the gate are valid and both are recorded. An evaluation says what it was measured on: simulated traffic, or (phase 16) a company's real normal traffic with attacks injected into held-out windows (simulated=false, with a data summary). Neither is a measurement against real attacks.
"""
import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import LearnedEvaluation, LearnedFlag, LearnedModel, LearnedScore

ORG_WIDE = "*"                           # the network is one model for the whole estate, not one per agent
MIN_MARGIN = 0.05                        # the network has to beat the baseline by at least this, whatever the service asks
MAX_BUDGET = 0.10
MIN_TEST_FAMILIES = 2
DETECTORS = ("tgn", "gnn")
MIN_NOVEL = 0.25                         # the graph model must also catch this share of what neither the reachability check nor the baseline catch, on at least two held-out families
HEALTH_WINDOWS = 20                      # live windows needed before the detector's own drift is judged
WHY = {"tgn": "the temporal network found the order or timing of these events unlike this agent's normal",
       "gnn": "the graph model found what this agent does, and what is around it, unlike its normal and its peers"}
CHECKSUM = re.compile(r"^[0-9a-f]{64}$")


def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def problems(m: Any, det: str = "tgn") -> List[str]:
    """What is wrong with the shape of a reported evaluation (an empty list: it can be judged)."""
    out: List[str] = []
    if not isinstance(m, dict):
        return ["the metrics are not an object"]
    for k in ("budget_fpr", "margin"):
        if not _num(m.get(k)):
            out.append(f"{k} is missing or not a number")
    fam = m.get("families") or {}
    for k in ("dev", "test"):
        if not isinstance(fam.get(k), list) or not all(isinstance(x, str) for x in fam.get(k, [])):
            out.append(f"families.{k} is missing")
    for who in (det, "baseline"):
        d = m.get(who) or {}
        if not _num(d.get("fpr_test")) or not isinstance(d.get("tpr"), dict):
            out.append(f"{who} needs fpr_test and tpr")
            continue
        for f, v in d["tpr"].items():
            if v is not None and not (_num(v) and 0 <= v <= 1):
                out.append(f"{who}.tpr.{f} is not a rate")
        if not 0 <= d["fpr_test"] <= 1:
            out.append(f"{who}.fpr_test is not a rate")
    if not _num(((m.get(det) or {}).get("threshold"))):
        out.append(f"{det}.threshold is missing")
    if det == "gnn":
        nov = (m.get("gnn") or {}).get("novel")
        if not isinstance(nov, dict) or not isinstance((m.get("reachability") or {}).get("tpr"), dict) or not _num(m.get("attack_events_not_permitted")):
            out.append("the graph model's evaluation needs its novel catches, the reachability check's results and the count of attack events the estate did not permit")
    if not isinstance(m.get("normalisation"), dict) or not m["normalisation"]:
        out.append("the per-agent normalisation is missing")
    return out


def decide(m: Dict[str, Any], det: str = "tgn") -> Dict[str, Any]:
    """The adoption rule. The model passes only if, on attack families that were not used to choose its settings, at the same false-positive budget, it detects clearly more than the
    baseline of phase 9, and its false positives on held-out normal traffic stay within twice the budget. Same rule as learned/tgn/evaluate.py, with floors a service cannot lower."""
    bad = problems(m, det)
    if bad:
        return {"passed": False, "reasons": ["the evaluation cannot be judged: " + "; ".join(bad)]}
    reasons: List[str] = []
    if m["budget_fpr"] <= 0 or m["budget_fpr"] > MAX_BUDGET:
        reasons.append(f"the false-positive budget {m['budget_fpr']} is outside (0, {MAX_BUDGET}]")
    if m["margin"] < MIN_MARGIN:
        reasons.append(f"the margin {m['margin']} is below the platform's minimum of {MIN_MARGIN}")
    if set(m["families"]["dev"]) & set(m["families"]["test"]):
        reasons.append("the families used to choose settings and the families used to judge overlap")
    fams = [f for f in m["families"]["test"] if m[det]["tpr"].get(f) is not None and m["baseline"]["tpr"].get(f) is not None]
    if len(fams) < MIN_TEST_FAMILIES:
        reasons.append(f"fewer than {MIN_TEST_FAMILIES} held-out attack families were measured")
    else:
        t = sum(m[det]["tpr"][f] for f in fams) / len(fams)
        b = sum(m["baseline"]["tpr"][f] for f in fams) / len(fams)
        if t - b < max(m["margin"], MIN_MARGIN):
            reasons.append(f"on held-out families the model detects {t:.3f} and the baseline {b:.3f}: the model is not clearly better (it must beat the baseline by {max(m['margin'], MIN_MARGIN)})")
    if m[det]["fpr_test"] > 2 * m["budget_fpr"]:
        reasons.append(f"the false-positive rate on held-out normal traffic is {m[det]['fpr_test']}, above twice the budget of {m['budget_fpr']}")
    if det == "gnn":                          # the second question: does it add anything to what the platform already has (the exact reachability check and the baseline)?
        if m["attack_events_not_permitted"]:
            reasons.append(f"{int(m['attack_events_not_permitted'])} attack events were not permitted by the estate: those are the reachability check's job, not this model's")
        novel = [f for f in m["families"]["test"] if _num(m["gnn"]["novel"].get(f)) and m["gnn"]["novel"][f] >= max(float(m.get("novel_min", MIN_NOVEL)), MIN_NOVEL)]
        if len(novel) < MIN_TEST_FAMILIES:
            reasons.append(f"it catches at least {MIN_NOVEL:.0%} of the attacks that neither the reachability check nor the baseline catch on only {len(novel)} held-out families (needs {MIN_TEST_FAMILIES}): it does not add enough to what the platform already has")
    return {"passed": not reasons, "reasons": reasons}


def _utc(x: datetime) -> datetime:
    return x if x.tzinfo else x.replace(tzinfo=timezone.utc)


MAX_EVALUATION_BYTES = 1_000_000                       # an evaluation is a few thousand numbers; a collector key cannot make the platform store more than this


def register(session: Session, org_id: Any, user_name: str, body: Dict[str, Any], det: str = "tgn") -> Dict[str, Any]:
    """Record a candidate model and its evaluation. The decision stored is the platform's own."""
    if len(json.dumps(body, default=str)) > MAX_EVALUATION_BYTES:
        raise ValueError(f"The evaluation is larger than {MAX_EVALUATION_BYTES // 1000} kB, which no evaluation needs to be.")
    cs = str(body.get("checksum", ""))
    if not CHECKSUM.match(cs):
        raise ValueError("the checksum of the weights is a 64-character hex hash")
    m = body.get("metrics")
    decision = decide(m, det)
    hyper = body.get("hyper") or {}
    ws = hyper.get("window_seconds")
    if not (isinstance(ws, int) and 10 <= ws <= 86400):
        raise ValueError("hyper.window_seconds is missing")
    if session.scalar(select(LearnedModel.id).where(LearnedModel.organisation_id == org_id, LearnedModel.detector == det, LearnedModel.parameters["checksum"].astext == cs)):
        raise ValueError("a model with these weights is already recorded")
    version = (session.scalar(select(func.max(LearnedModel.version)).where(LearnedModel.organisation_id == org_id, LearnedModel.agent_key == ORG_WIDE, LearnedModel.detector == det)) or 0) + 1
    model = LearnedModel(organisation_id=org_id, agent_key=ORG_WIDE, detector=det, version=version, status="CANDIDATE", created_by=user_name,
                         trained_on={"dataset_hash": m.get("dataset_hash"), "simulated": bool(m.get("simulated", True)), **(body.get("training") or {})},
                         parameters={"checksum": cs, "window_seconds": ws, "threshold": m[det]["threshold"], "normalisation": m["normalisation"], "vocab": body.get("vocab"), "hyper": hyper,
                                     "budget_fpr": m["budget_fpr"]})
    session.add(model)
    session.flush()
    ev = LearnedEvaluation(organisation_id=org_id, model_id=model.id, detector=det, dataset_hash=str(m.get("dataset_hash", "")), simulated=bool(m.get("simulated", True)),
                           budget_fpr=float(m["budget_fpr"]), metrics=m, passed=decision["passed"], reasons=decision["reasons"], recorded_by=user_name)
    session.add(ev)
    session.flush()
    claimed = (m.get("decision") or {}).get("passed")
    return {"model": model_row(model), "evaluation": evaluation_row(ev), "service_claimed_pass": claimed, "disagrees": claimed is not None and bool(claimed) != decision["passed"]}


def model_row(m: LearnedModel) -> Dict[str, Any]:
    p = m.parameters
    return {"id": str(m.id), "detector": m.detector, "version": m.version, "status": m.status, "adopted": m.adopted, "adopted_by": m.adopted_by, "adopted_at": m.adopted_at.isoformat() if m.adopted_at else None,
            "checksum": p.get("checksum"), "window_seconds": p.get("window_seconds"), "threshold": p.get("threshold"), "created_by": m.created_by, "created_at": m.created_at.isoformat(),
            "simulated": (m.trained_on or {}).get("simulated", True), "agents": sorted((p.get("normalisation") or {}))}


def evaluation_row(e: LearnedEvaluation) -> Dict[str, Any]:
    m = e.metrics
    return {"id": str(e.id), "model_id": str(e.model_id), "passed": e.passed, "reasons": e.reasons, "simulated": e.simulated, "dataset_hash": e.dataset_hash, "budget_fpr": e.budget_fpr,
            "recorded_by": e.recorded_by, "created_at": e.created_at.isoformat(), "families": m.get("families"), "detector": e.detector, "model_metrics": {k: m[e.detector].get(k) for k in ("threshold", "fpr_test", "tpr", "macro_test", "macro_dev", "novel", "tpr_late")},
            "tgn": {k: m["tgn"].get(k) for k in ("threshold", "fpr_test", "tpr", "macro_test", "macro_dev")} if e.detector == "tgn" else None,
            "baseline": {k: m["baseline"].get(k) for k in ("threshold", "fpr_test", "tpr", "macro_test", "macro_dev", "tpr_late")}, "reachability": m.get("reachability"), "novel_min": m.get("novel_min"),
            "attack_events_not_permitted": m.get("attack_events_not_permitted"), "selection": m.get("selection"),
            "data": m.get("data") if isinstance(m.get("data"), dict) else None}


def latest_evaluation(session: Session, model_id: Any) -> Optional[LearnedEvaluation]:
    return session.scalar(select(LearnedEvaluation).where(LearnedEvaluation.model_id == model_id).order_by(LearnedEvaluation.created_at.desc()).limit(1))


def adopted_model(session: Session, org_id: Any, det: str = "tgn") -> Optional[LearnedModel]:
    return session.scalar(select(LearnedModel).where(LearnedModel.organisation_id == org_id, LearnedModel.agent_key == ORG_WIDE, LearnedModel.detector == det, LearnedModel.status == "ACTIVE",
                                                     LearnedModel.adopted.is_(True)))


def adopt(session: Session, org_id: Any, user_name: str, model: LearnedModel) -> None:
    """Switch a candidate on, advisory-only. Refused unless its recorded evaluation passed."""
    if model.detector not in DETECTORS or model.status != "CANDIDATE":
        raise ValueError(f"this model is {model.status.lower()}, not a candidate")
    ev = latest_evaluation(session, model.id)
    if ev is None or not ev.passed:
        raise PermissionError("The evaluation of this model did not pass, so it cannot be switched on: " + "; ".join(ev.reasons if ev else ["it has no evaluation"]))
    old = adopted_model(session, org_id, model.detector)
    if old is not None:
        old.status = "RETIRED"
        session.flush()
    model.status, model.adopted, model.adopted_by, model.adopted_at = "ACTIVE", True, user_name, datetime.now(timezone.utc)
    session.flush()


def rollback(session: Session, org_id: Any, user_name: str, det: str = "tgn") -> Optional[LearnedModel]:
    """Retire the adopted model and bring back the one adopted before it whose evaluation passed. None when there was none: the detector is then off."""
    cur = adopted_model(session, org_id, det)
    if cur is None:
        raise ValueError("No model is adopted.")
    cur.status = "RETIRED"
    session.flush()
    for prev in session.scalars(select(LearnedModel).where(LearnedModel.organisation_id == org_id, LearnedModel.agent_key == ORG_WIDE, LearnedModel.detector == det, LearnedModel.status == "RETIRED",
                                                          LearnedModel.adopted.is_(True), LearnedModel.adopted_at < cur.adopted_at).order_by(LearnedModel.adopted_at.desc())):
        ev = latest_evaluation(session, prev.id)
        if ev is not None and ev.passed:
            prev.status = "ACTIVE"                        # it keeps the time it was first adopted; the audit log records who brought it back
            session.flush()
            return prev
    return None


def active_info(session: Session, org_id: Any, det: str = "tgn") -> Optional[Dict[str, Any]]:
    m = adopted_model(session, org_id, det)
    if m is None:
        return None
    p = m.parameters
    ws = p["window_seconds"]
    last = session.scalar(select(func.max(LearnedScore.window_end)).where(LearnedScore.model_id == m.id))
    start = _utc(m.adopted_at).timestamp() // ws * ws
    return {"id": str(m.id), "version": m.version, "checksum": p["checksum"], "window_seconds": ws, "threshold": p["threshold"], "normalisation": p["normalisation"],
            "last_window_end": max(start, _utc(last).timestamp() if last is not None else start)}


def accept_scores(session: Session, org_id: Any, model_id: Any, windows: List[Dict[str, Any]], now: Optional[datetime] = None, det: str = "tgn") -> Dict[str, Any]:
    """Store the window scores a service computed with the adopted model. The threshold is the platform's, never the service's; a flag can only be the kind the table allows."""
    now = now or datetime.now(timezone.utc)
    m = adopted_model(session, org_id, det)
    if m is None or str(m.id) != str(model_id):
        raise PermissionError("That model is not the adopted one, so its scores are not accepted.")
    p = m.parameters
    ws, thr, known = p["window_seconds"], p["threshold"], p["normalisation"]
    done, flagged, skipped = 0, 0, 0
    for w in windows:
        agent, start, score, n = str(w.get("agent", "")), w.get("window_start"), w.get("score"), w.get("events", 0)
        if agent not in known or not _num(start) or not _num(score) or not isinstance(n, int) or n < 1 or start % ws != 0 or start + ws > now.timestamp() or start < _utc(m.adopted_at).timestamp() - ws:
            skipped += 1                                  # an agent the model never saw, a window that is not complete or not aligned, one before adoption, or not a number
            continue
        at = datetime.fromtimestamp(start, timezone.utc)
        if session.scalar(select(LearnedScore.id).where(LearnedScore.model_id == m.id, LearnedScore.agent_key == agent, LearnedScore.window_start == at)):
            skipped += 1
            continue
        s = LearnedScore(organisation_id=org_id, model_id=m.id, agent_key=agent, detector=det, window_start=at, window_end=at + timedelta(seconds=ws), events=n, score=float(score), threshold=thr,
                         detail={"score": float(score), "events": n, "why": [WHY[det]]})
        session.add(s)
        session.flush()
        done += 1
        if float(score) >= thr:
            session.add(LearnedFlag(organisation_id=org_id, model_id=m.id, score_id=s.id, agent_key=agent, detector=det, score=float(score), threshold=thr, detail=s.detail))
            flagged += 1
    session.flush()
    return {"scored": done, "flagged": flagged, "skipped": skipped}


def health(session: Session, org_id: Any, now: Optional[datetime] = None, det: str = "tgn") -> Dict[str, Any]:
    """Is the detector itself still behaving like the one that was evaluated? Over the last day of live windows, the share flagged should be near the false-positive budget and the scores
    near zero on average (they are standard deviations above each agent's validation normal). A detector that flags several times its budget, or whose scores have drifted, is reported."""
    now = now or datetime.now(timezone.utc)
    m = adopted_model(session, org_id, det)
    if m is None:
        return {"adopted": False, "status": "off"}
    since = now - timedelta(hours=24)
    rows = session.execute(select(LearnedScore.score, LearnedScore.threshold).where(LearnedScore.model_id == m.id, LearnedScore.window_start >= since)).all()
    n = len(rows)
    budget = float(m.parameters.get("budget_fpr", 0.05))
    out: Dict[str, Any] = {"adopted": True, "model_id": str(m.id), "windows_24h": n, "budget_fpr": budget, "status": "collecting", "flag_rate": None, "mean_score": None, "reasons": []}
    if n == 0:
        return out
    flagged = sum(1 for s, t in rows if s >= t)
    mean = sum(s for s, _ in rows) / n
    out.update(flag_rate=round(flagged / n, 4), mean_score=round(mean, 4))
    if n < HEALTH_WINDOWS:
        out["reasons"].append(f"{HEALTH_WINDOWS - n} more live windows are needed before drift can be judged")
        return out
    if flagged / n > 3 * budget:
        out["reasons"].append(f"{flagged / n:.0%} of live windows are flagged, more than three times the budget of {budget:.0%}")
    if abs(mean) > 1.0:
        out["reasons"].append(f"the mean live score is {mean:.2f} standard deviations from normal: the detector's picture of normal no longer fits")
    out["status"] = "drifting" if out["reasons"] else "ok"
    return out
