"""
The learned layer, database side (ASTRA phase 9): calibrating and scoring the statistical baseline, and reading its flags.

What a learned detector is allowed to do is the point of this phase (Lemma 3 of the model, astra_model/statuses.py), and it is little:

    * a flag can only mark the baseline control ("base") UNVERIFIED. It is never VIOLATED, never SATISFIED, and a detector is not a source of supportive evidence;
    * the table of flags carries control = 'base' and level = 'UNV' under a check constraint, so no code path can store anything stronger;
    * a flag reaches the gate only through statuses.learned_evidence, which has no other effect. A flag therefore never blocks on its own: at worst an agent whose baseline is monitored
      and validated moves to REQUIRES_REVIEW.

A person decides what a flag was: benign (for a number of days, after which the flag counts again) or real (it stays until a new signed contract is issued, and the person adds a control).
A baseline is monitored once a model is active for the agent. The model then requires the baseline control on every path of the agent, and that control stays UNVERIFIED until a Probe pass or
an attestation (record key astra:base) validates the calibration.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

import astra_baseline as B
from db.models import LearnedFlag, LearnedModel, LearnedScore, RuntimeEvent

DETECTORS = [
    {"id": "baseline", "name": "Statistical baseline", "status": "available", "phase": 9,
     "what": "Rates of each kind of event and tool-order transitions per time window, learned from conforming events, in plain Python."},
    {"id": "tgn", "name": "Temporal graph network", "status": "available", "phase": 10, "what": "Order and timing of events across agents and tools, in its own service. Off until its evaluation against the baseline passes and a person adopts it."},
    {"id": "gnn", "name": "Graph neural network", "status": "planned", "phase": 11, "what": "Which paths through the estate are unlike the others."},
]
LOOKBACK_DAYS = 14                      # the retention of runtime events
MAX_WINDOWS_PER_SCORE = 48


def _utc(x: datetime) -> datetime:
    return x if x.tzinfo else x.replace(tzinfo=timezone.utc)


def events_of(session: Session, org_id: uuid.UUID, agent_key: str, since: datetime, conforming_only: bool, until: Optional[datetime] = None) -> List[B.Event]:
    q = select(RuntimeEvent.at, RuntimeEvent.type, RuntimeEvent.name).where(RuntimeEvent.organisation_id == org_id, RuntimeEvent.agent_key == agent_key, RuntimeEvent.at >= since,
                                                                          RuntimeEvent.type != "heartbeat")
    if conforming_only:
        q = q.where(RuntimeEvent.verdict == "CONFORMING")
    if until is not None:
        q = q.where(RuntimeEvent.at < until)
    return [(_utc(a).timestamp(), t, n or "") for a, t, n in session.execute(q).all()]


def active_model(session: Session, org_id: uuid.UUID, agent_key: str, detector: str = "baseline") -> Optional[LearnedModel]:
    return session.scalar(select(LearnedModel).where(LearnedModel.organisation_id == org_id, LearnedModel.agent_key == agent_key, LearnedModel.detector == detector, LearnedModel.status == "ACTIVE"))


def has_active_model(session: Session, org_id: uuid.UUID, agent_key: str) -> bool:
    """Is a behavioural baseline monitored for this agent: its own statistical baseline, or the adopted temporal network once it has scored one of its windows."""
    if active_model(session, org_id, agent_key) is not None:
        return True
    net = session.scalar(select(LearnedModel.id).where(LearnedModel.organisation_id == org_id, LearnedModel.agent_key == "*", LearnedModel.detector == "tgn", LearnedModel.status == "ACTIVE",
                                                       LearnedModel.adopted.is_(True)))
    return net is not None and session.scalar(select(LearnedScore.id).where(LearnedScore.model_id == net, LearnedScore.agent_key == agent_key).limit(1)) is not None


def counts(session: Session, org_id: uuid.UUID, agent_key: str, window: int) -> Tuple[int, int]:
    """(conforming events, windows with activity) in the lookback period: what calibration has to work with."""
    since = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    ev = events_of(session, org_id, agent_key, since, True)
    return len(ev), len({B.bucket(e[0], window) for e in ev})


def calibrate(session: Session, org_id: uuid.UUID, agent_key: str, user_name: str, window_seconds: int = B.DEFAULT_WINDOW_SECONDS, threshold: float = B.DEFAULT_THRESHOLD,
              min_events: int = B.MIN_EVENTS, min_windows: int = B.MIN_WINDOWS, now: Optional[datetime] = None) -> LearnedModel:
    """Train a new version from the agent's conforming events. Refused, with what is missing, until there is enough; the active version is retired."""
    now = now or datetime.now(timezone.utc)
    ev = events_of(session, org_id, agent_key, now - timedelta(days=LOOKBACK_DAYS), True)
    n, nw = len(ev), len({B.bucket(e[0], window_seconds) for e in ev})
    st = B.calibration_state(n, nw, False, False, min_events, min_windows)
    if st["state"] != B.READY:
        raise ValueError("Not enough to calibrate from yet: " + " and ".join(st["missing"]) + ".")
    params = B.train(ev, window_seconds, threshold)
    old = active_model(session, org_id, agent_key)
    version = (session.scalar(select(func.max(LearnedModel.version)).where(LearnedModel.organisation_id == org_id, LearnedModel.agent_key == agent_key, LearnedModel.detector == "baseline")) or 0) + 1
    if old is not None:
        old.status = "RETIRED"
        session.flush()
    last_bucket = max(B.bucket(e[0], window_seconds) for e in ev)
    m = LearnedModel(organisation_id=org_id, agent_key=agent_key, detector="baseline", version=version, status="ACTIVE", parameters=params, created_by=user_name,
                     trained_on={"events": params["events"], "windows": params["windows"], "windows_with_events": params["windows_with_events"], "last_window": last_bucket,
                                 "from": datetime.fromtimestamp(min(e[0] for e in ev), timezone.utc).isoformat(), "to": datetime.fromtimestamp(max(e[0] for e in ev), timezone.utc).isoformat()})
    session.add(m)
    session.flush()
    return m


def score(session: Session, org_id: uuid.UUID, agent_key: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Score the complete windows since the last one scored (or since calibration), with every event, conforming or not. A window at or above the threshold raises a flag."""
    now = now or datetime.now(timezone.utc)
    m = active_model(session, org_id, agent_key)
    if m is None:
        raise ValueError("No baseline is calibrated for this agent.")
    p = m.parameters
    ws = p["window_seconds"]
    last = session.scalar(select(func.max(LearnedScore.window_start)).where(LearnedScore.model_id == m.id))
    after = B.bucket(_utc(last).timestamp(), ws) if last is not None else m.trained_on["last_window"]
    since = datetime.fromtimestamp((after + 1) * ws, timezone.utc)
    now_bucket = B.bucket(now.timestamp(), ws)
    rows = B.score_windows(p, events_of(session, org_id, agent_key, since, False), after, now_bucket)[:MAX_WINDOWS_PER_SCORE]
    flags = []
    for w, r in rows:
        start = datetime.fromtimestamp(w * ws, timezone.utc)
        s = LearnedScore(organisation_id=org_id, model_id=m.id, agent_key=agent_key, detector="baseline", window_start=start, window_end=start + timedelta(seconds=ws), events=r["events"],
                         score=r["score"], threshold=p["threshold"], detail=r)
        session.add(s)
        session.flush()
        if r["score"] >= p["threshold"]:
            f = LearnedFlag(organisation_id=org_id, model_id=m.id, score_id=s.id, agent_key=agent_key, detector="baseline", score=r["score"], threshold=p["threshold"], detail=r)
            session.add(f)
            session.flush()
            flags.append(f)
    return {"agent_key": agent_key, "model_version": m.version, "scored": len(rows), "flagged": len(flags), "flags": [str(f.id) for f in flags]}


def effective(f: LearnedFlag, now: datetime) -> bool:
    """Does the flag still count? Open ones do; a benign one stops counting until its expiry; a real one counts until a new contract is signed."""
    if f.status == "BENIGN":
        return f.expires_at is not None and _utc(f.expires_at) <= now
    return True


def flags_for_overlay(session: Session, org_id: uuid.UUID, agent_keys: List[str], since: datetime, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """The flags that count against these agents since a contract was signed. Only (agent, id, score, threshold): all the gate ever learns from a learned detector."""
    now = now or datetime.now(timezone.utc)
    rows = session.scalars(select(LearnedFlag).where(LearnedFlag.organisation_id == org_id, LearnedFlag.agent_key.in_(agent_keys), LearnedFlag.created_at >= since))
    return [{"agent_key": f.agent_key, "id": str(f.id), "score": f.score, "threshold": f.threshold} for f in rows if effective(f, now)]
