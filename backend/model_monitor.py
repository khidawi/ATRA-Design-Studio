"""
Production monitoring of AI models: plug a model that is running inside the organisation into ASTRA and watch how its inputs and outputs behave.

  GET    /api/model-monitor/capabilities      the kinds of field, the default thresholds, the limits
  POST   /api/model-monitor/infer-schema      suggest a schema from one example record
  POST   /api/model-monitor                   create a monitor for a model (optionally tied to its design in AI Models)
  GET    /api/model-monitor                   the monitors (?design_key= for one model's)
  GET    /api/model-monitor/{key}             a monitor with its fresh evaluation
  PATCH  /api/model-monitor/{key}             rename, re-link to a design, change thresholds
  DELETE /api/model-monitor/{key}
  POST   /api/model-monitor/{key}/records     the serving code sends what the model saw and answered (an API key of role collector)
  POST   /api/model-monitor/{key}/baseline/freeze   take the baseline from the records so far
  PUT    /api/model-monitor/{key}/baseline    supply the baseline (the statistics of the training data) instead
  POST   /api/model-monitor/{key}/baseline/reset    forget the baseline and learn a new one
  GET    /api/model-monitor/{key}/series      the history, for charts
  GET    /api/model-monitor/{key}/incidents   the incidents monitoring raised
  PATCH  /api/model-monitor/incidents/{id}    a person changes an incident's status
  GET    /api/model-monitor/signals           for a model design: what production shows, as the ST-AI score understands it
  GET    /api/model-monitor/{key}/versions    which provider model versions answered, the changes, and whether behaviour moved
  POST   /api/model-monitor/{key}/decisions   what people did with the outputs (an API key of role collector); roles, not people
  GET    /api/model-monitor/{key}/decisions   how review is going: acceptance, review time, wrong outputs accepted
  PUT    /api/model-monitor/{key}/decision-settings   thresholds; counting distinct people (as pseudonyms) needs a compliance sign-off

The point of reading production is that a model is only as safe as it is where it really runs. A design says what was intended; the score is declared by
people. This reads what is happening: an input whose distribution has moved away from what the model was validated on (data drift), a model that
answers differently (prediction drift) or is wrong more often once the truth is known (performance drift), a group that gets the favourable outcome much
less often (bias), a value outside the range the model is declared to work in (domain violation), errors and slow answers. Each becomes a signal the
score understands (the Runtime facts of the model design) and, when it is serious, an incident that feeds the score and waits for a person.

What is kept is statistics, never records: hourly histograms, category counts, text lengths (never text), confidence and latency buckets, counts of
right and wrong answers, rates by group (model_stats.py). Nothing in them identifies a person. An input that is a free identifier is capped at fifty
categories per window, and the rest is counted as "other". Only fields declared in the schema are read; anything else in a record is ignored.

Third-party models change without notice: a record may carry `model_version` (the model id or fingerprint the provider reports) and a new version
becomes a change event, compared with the one before it (model_versions.py). People's use of the outputs is read from decision records, by role
(decision_stats.py). Both only advise: nothing is stopped or rerouted, and a finding is worded as a question for a person, not a verdict.

Protections: ingestion needs a key with the ingest permission (a collector key can do only this); batches are limited to 1,000 records and 2 MB; a key
is rate limited and answered 429 with Retry-After; a record's own timestamp is honoured only within the retention window; and a monitor's aggregates are
deleted after its retention period (30 days by default).
"""
import copy
import math
import random
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

import decision_stats as ds
import llm_safety as lsf
import model_stats as ms
import model_versions as mv
from agent_registry import agent_key
from auth import AuthUser, current_user, has
from db.models import Design, ModelDecisionWindow, ModelIncident, ModelMonitor, ModelWindow
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/model-monitor", tags=["model-monitor"])

MAX_BATCH = 1000
MAX_BODY = 2 * 1024 * 1024
RECORDS_PER_MINUTE = 120_000
EVAL_EVERY_SECONDS = 20
INCIDENT_STATUSES = ("OPEN", "INVESTIGATING", "MITIGATED", "RESOLVED", "POST_MORTEM")
INCIDENT_KIND = {"DATA_DRIFT": "DRIFT_DETECTION", "PREDICTION_DRIFT": "DRIFT_DETECTION", "PERFORMANCE_DRIFT": "DRIFT_DETECTION", "BIAS_BREACH": "BIAS_BREACH",
                 "DOMAIN_VIOLATION": "MODEL_FAILURE", "MODEL_FAILURE": "MODEL_FAILURE", "MODEL_VERSION": "SUPPLY_CHAIN", "HUMAN_REVIEW": "HUMAN_OVERRIDE_FAILED", "DATA_EGRESS": "DATA_BREACH", "OUTPUT_SAFETY": "SECURITY_EVENT", "CANARY": "MODEL_FAILURE"}
DECISION_DAYS = 7
_window: Dict[str, Deque] = defaultdict(deque)
_last_eval: Dict[Any, float] = {}


def _throttle(key: str, n: int) -> Optional[int]:
    now = time.monotonic()
    q = _window[key]
    while q and now - q[0][0] > 60:
        q.popleft()
    if sum(c for _, c in q) + n > RECORDS_PER_MINUTE:
        return max(1, int(60 - (now - q[0][0]))) if q else 60
    q.append((now, n))
    return None


def _hour(t: datetime) -> datetime:
    return t.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


# ── The schema a person declares ────────────────────────────────────────────

class FieldIn(BaseModel):
    name: str = Field(min_length=1, max_length=60, pattern=r"^[A-Za-z0-9_.\- ]+$")
    kind: str
    min: Optional[float] = None
    max: Optional[float] = None
    allowed: Optional[List[str]] = Field(None, max_length=200)

    @field_validator("kind")
    @classmethod
    def kind_ok(cls, v: str) -> str:
        if v not in ms.KINDS:
            raise ValueError("kind must be one of " + ", ".join(ms.KINDS))
        return v


class OutputIn(BaseModel):
    name: str = Field("prediction", min_length=1, max_length=60, pattern=r"^[A-Za-z0-9_.\- ]+$")
    kind: str = "categorical"
    positive: Optional[str] = Field(None, max_length=60)          # the favourable outcome: a category, or a number the output must reach

    @field_validator("kind")
    @classmethod
    def kind_ok(cls, v: str) -> str:
        if v not in ("numeric", "categorical", "boolean", "text"):
            raise ValueError("kind must be numeric, categorical, boolean or text")
        return v


class CreateBody(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    design_key: Optional[str] = Field(None, max_length=40)
    task: str = "classification"
    features: List[FieldIn] = Field(min_length=1, max_length=ms.MAX_FEATURES)
    output: OutputIn = Field(default_factory=OutputIn)
    segments: List[str] = Field(default_factory=list, max_length=5)
    flags: List[str] = Field(default_factory=list, max_length=10)
    baseline_target: int = Field(1000, ge=100, le=100_000)
    retention_days: int = Field(30, ge=7, le=90)
    thresholds: Dict[str, float] = Field(default_factory=dict)

    @field_validator("task")
    @classmethod
    def task_ok(cls, v: str) -> str:
        if v not in ("classification", "regression", "generative"):
            raise ValueError("task must be classification, regression or generative")
        return v


def _spec(body: CreateBody) -> Dict[str, Any]:
    names = [f.name for f in body.features]
    if len(set(names)) != len(names):
        raise HTTPException(status_code=422, detail="Two features have the same name.")
    out = body.output.model_dump()
    if out["positive"] is not None and out["kind"] == "numeric":
        try:
            out["positive"] = float(out["positive"])
        except ValueError:
            raise HTTPException(status_code=422, detail="For a numeric output, the favourable outcome is a number.")
    flags = list(body.flags) + ([f for f in lsf.SAFETY_FLAGS if f not in body.flags] if body.task == "generative" else [])        # a language model is checked for what leaves and what comes back
    return {"task": body.task, "features": [{k: v for k, v in f.model_dump().items() if v is not None} for f in body.features], "output": {k: v for k, v in out.items() if v is not None},
            "segments": body.segments, "flags": flags}


def _thresholds(raw: Dict[str, float]) -> Dict[str, float]:
    bad = [k for k in raw if k not in ms.DEFAULT_THRESHOLDS]
    if bad:
        raise HTTPException(status_code=422, detail="Unknown threshold: " + ", ".join(bad) + ". Known: " + ", ".join(ms.DEFAULT_THRESHOLDS))
    return {k: float(v) for k, v in raw.items()}


# ── Looking things up ───────────────────────────────────────────────────────

def _get(session: Session, key: str, lock: bool = False) -> ModelMonitor:
    q = select(ModelMonitor).where(ModelMonitor.organisation_id == current_organisation(session).id, ModelMonitor.key == key)
    if lock:
        q = q.with_for_update()
    m = session.scalar(q)
    if m is None:
        raise HTTPException(status_code=404, detail="No such monitor.")
    return m


def _windows(session: Session, m: ModelMonitor, since: datetime) -> List[ModelWindow]:
    return list(session.scalars(select(ModelWindow).where(ModelWindow.monitor_id == m.id, ModelWindow.window_start >= _hour(since)).order_by(ModelWindow.window_start)))


def _merged(wins: List[ModelWindow]) -> Optional[Dict[str, Any]]:
    out = None
    for w in wins:
        out = copy.deepcopy(w.acc) if out is None else ms.merge(out, w.acc)
    return out


# ── Evaluating, and what it raises ──────────────────────────────────────────

def evaluate_monitor(session: Session, m: ModelMonitor, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Judges the recent windows against the baseline, stores the status and signals, and opens or notes incidents. Does not commit."""
    now = now or datetime.now(timezone.utc)
    t = {**ms.DEFAULT_THRESHOLDS, **(m.thresholds or {})}
    m.last_eval_at = now
    extra, extra_sig = _people_and_versions(session, m, now)
    if m.baseline is None:
        n = (m.buffer or {}).get("n", 0)
        m.status, m.reasons, m.signals = "LEARNING", extra[:30], extra_sig
        _sync_incidents(session, m, extra, now)
        return {"status": "LEARNING", "n": n, "reasons": extra, "message": f"Learning what normal looks like: {n} of {m.baseline_target} records."}
    merged = _merged(_windows(session, m, now - timedelta(hours=t["eval_hours"])))
    if merged is None or merged["n"] == 0:
        m.status, m.reasons, m.signals = "NO_DATA", extra[:30], extra_sig
        _sync_incidents(session, m, extra, now)
        return {"status": "NO_DATA", "n": 0, "reasons": extra, "message": f"No records in the last {int(t['eval_hours'])} hours."}
    res = ms.evaluate(m.spec, m.baseline, merged, t)
    if res["status"] in ("OK", "WATCH", "DRIFT"):
        res["reasons"] = res["reasons"] + extra
        levels = {r["level"] for r in res["reasons"]}
        res["status"] = "DRIFT" if "drift" in levels else ("WATCH" if "watch" in levels else "OK")
    m.status, m.reasons, m.signals = res["status"], res["reasons"][:30], {**ms.signals(res["reasons"]), **extra_sig}
    _sync_incidents(session, m, res["reasons"], now)
    return res


def _people_and_versions(session: Session, m: ModelMonitor, now: datetime) -> Any:
    """What the version history and the people's decisions add to a monitor: reasons, and the oversight facts the score understands."""
    reasons: List[Dict[str, Any]] = []
    sig: Dict[str, Any] = {}
    if m.versions and m.versions.get("items"):
        reasons += mv.evaluate(m.versions, m.spec["output"]["kind"], m.thresholds, now.isoformat())["reasons"]
    dec = decisions_evaluation(session, m, now)
    if dec["n"]:
        reasons += dec["reasons"]
        sig = dec["signals"]
    reasons += safety_evaluation(session, m, now)["reasons"]
    if m.canaries and m.canaries.get("items"):
        reasons += lsf.evaluate_canaries(m.canaries, (m.versions or {}).get("current"))["reasons"]
    return reasons, sig


def safety_evaluation(session: Session, m: ModelMonitor, now: datetime) -> Dict[str, Any]:
    """The safety flags over the evaluation window (or, while the baseline is still being learned, over what has been seen so far)."""
    if not any(f in lsf.SAFETY_FLAGS for f in (m.spec.get("flags") or [])):
        return {"enabled": False, "rows": [], "reasons": [], "n": 0}
    if m.baseline is None:
        acc = m.buffer or {}
    else:
        acc = _merged(_windows(session, m, now - timedelta(hours=(m.thresholds or {}).get("eval_hours", ms.DEFAULT_THRESHOLDS["eval_hours"])))) or {}
    res = lsf.evaluate_flags(acc.get("flags", {}), acc.get("n", 0))
    return {**res, "enabled": True}


def decisions_evaluation(session: Session, m: ModelMonitor, now: datetime) -> Dict[str, Any]:
    since = _hour(now - timedelta(days=DECISION_DAYS))
    acc = None
    for w in session.scalars(select(ModelDecisionWindow).where(ModelDecisionWindow.monitor_id == m.id, ModelDecisionWindow.window_start >= since).order_by(ModelDecisionWindow.window_start)):
        acc = copy.deepcopy(w.acc) if acc is None else ms.merge(acc, w.acc)
    if acc is None:
        return {"n": 0, "reasons": [], "signals": {}, "roles": []}
    predictions = sum(w.acc.get("n", 0) for w in _windows(session, m, since))
    return ds.evaluate(acc, (m.decision_settings or {}).get("thresholds"), predictions)


def _sync_incidents(session: Session, m: ModelMonitor, reasons: List[Dict[str, Any]], now: datetime) -> None:
    by_kind: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in reasons:
        if r["level"] == "drift":
            by_kind[INCIDENT_KIND.get(r["kind"], "MODEL_FAILURE")].append(r)
    open_ = {i.kind: i for i in session.scalars(select(ModelIncident).where(ModelIncident.monitor_id == m.id, ModelIncident.status.in_(("OPEN", "INVESTIGATING", "MITIGATED"))))}
    for kind, rs in by_kind.items():
        kinds = {r["kind"] for r in rs}
        sev = 4 if (kind in ("BIAS_BREACH", "HUMAN_OVERRIDE_FAILED", "DATA_BREACH", "SECURITY_EVENT") or "PERFORMANCE_DRIFT" in kinds or "DOMAIN_VIOLATION" in kinds or len(rs) >= 3) else 3
        detail = {"reasons": rs[:8], "kinds": sorted(kinds)}
        inc = open_.get(kind)
        if inc is None:
            session.add(ModelIncident(monitor_id=m.id, kind=kind, severity=sev, title=rs[0]["text"][:300], detail=detail, status="OPEN", detected_at=now, last_seen_at=now))
        else:
            inc.last_seen_at, inc.detail, inc.recovered_at = now, detail, None
            inc.severity = max(inc.severity, sev)
    for kind, inc in open_.items():
        if kind not in by_kind and inc.recovered_at is None:
            inc.recovered_at = now                         # the signal has gone; a person decides whether to close it


def _maybe_evaluate(session: Session, m: ModelMonitor, force: bool = False) -> None:
    last = _last_eval.get(m.id, 0.0)
    if force or time.monotonic() - last >= EVAL_EVERY_SECONDS:
        _last_eval[m.id] = time.monotonic()
        evaluate_monitor(session, m)


# ── Ingestion ───────────────────────────────────────────────────────────────

class RecordIn(BaseModel):
    at: Optional[datetime] = None
    inputs: Dict[str, Any] = Field(default_factory=dict)
    output: Any = None
    confidence: Optional[float] = Field(None, ge=0, le=1)
    latency_ms: Optional[float] = Field(None, ge=0, le=3_600_000)
    error: Optional[bool] = None
    label: Any = None                       # the true answer, when it is known
    segments: Dict[str, Any] = Field(default_factory=dict)
    flags: Dict[str, bool] = Field(default_factory=dict)
    model_version: Optional[str] = Field(None, max_length=120)      # the model id or fingerprint the provider reports for this answer


class BatchIn(BaseModel):
    records: List[RecordIn] = Field(min_length=1, max_length=MAX_BATCH)


class IngestOut(BaseModel):
    accepted: int
    rejected: int
    status: str
    learning: Optional[Dict[str, int]] = None
    baseline_frozen: bool = False


def _freeze(m: ModelMonitor, now: datetime) -> None:
    m.baseline = ms.build_baseline(m.spec, m.buffer)
    m.baseline["created_at"] = now.isoformat()
    m.baseline["source"] = "learned"
    m.buffer = None


@router.post("/{key}/records", response_model=IngestOut)
async def ingest_records(key: str, request: Request, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> JSONResponse:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY:
        return JSONResponse({"detail": f"A request is limited to {MAX_BODY // 1024} KB."}, status_code=413)
    raw = await request.body()
    if len(raw) > MAX_BODY:
        return JSONResponse({"detail": f"A request is limited to {MAX_BODY // 1024} KB."}, status_code=413)
    try:
        body = BatchIn.model_validate_json(raw)
    except Exception as exc:
        return JSONResponse({"detail": "The body must be {\"records\": [...]} with at most %d records: %s" % (MAX_BATCH, str(exc)[:200])}, status_code=422)
    wait = _throttle(str(user.id), len(body.records))
    if wait is not None:
        return JSONResponse({"detail": f"Too many records from this key; retry in {wait} s (limit {RECORDS_PER_MINUTE} a minute)."}, status_code=429, headers={"Retry-After": str(wait)})
    from starlette.concurrency import run_in_threadpool
    out = await run_in_threadpool(_ingest, key, body.records)
    return JSONResponse(out.model_dump())


def _ingest(key: str, records: List[RecordIn]) -> IngestOut:
    from db.session import SessionLocal
    now = datetime.now(timezone.utc)
    with SessionLocal() as session:
        m = _get(session, key, lock=True)
        oldest = now - timedelta(days=m.retention_days)
        rng = random.Random()
        accepted = rejected = 0
        frozen = False
        groups: Dict[datetime, List[Dict[str, Any]]] = defaultdict(list)
        seen_versions: List[Any] = []
        for r in records:
            at = r.at if r.at is not None else now
            at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
            if at < oldest or at > now + timedelta(minutes=5):
                rejected += 1
                continue
            groups[_hour(at)].append(r.model_dump(exclude={"at"}))
            version = mv.clean(r.model_version)
            if version:
                seen_versions.append((at.astimezone(timezone.utc).isoformat(), version, r))
        if seen_versions:
            state = copy.deepcopy(m.versions) if m.versions and m.versions.get("items") else mv.new_state()
            for at_iso, version, r in sorted(seen_versions, key=lambda x: x[0]):
                mv.fold(state, version, {"output": r.output, "latency_ms": r.latency_ms, "confidence": r.confidence, "error": r.error}, at_iso, m.spec["output"]["kind"])
            m.versions = state
            flag_modified(m, "versions")
        if m.baseline is None:
            buf = m.buffer or ms.new_acc(m.spec, None)
            for recs in groups.values():
                for rec in recs:
                    ms.fold_record(buf, m.spec, None, rec, rng)
                    accepted += 1
            m.buffer = buf
            flag_modified(m, "buffer")
            if buf["n"] >= m.baseline_target:
                _freeze(m, now)
                frozen = True
        else:
            for start, recs in groups.items():
                w = session.scalar(select(ModelWindow).where(ModelWindow.monitor_id == m.id, ModelWindow.window_start == start).with_for_update())
                if w is None:
                    w = ModelWindow(monitor_id=m.id, window_start=start, acc=ms.new_acc(m.spec, m.baseline))
                    session.add(w)
                acc = copy.deepcopy(w.acc)
                for rec in recs:
                    ms.fold_record(acc, m.spec, m.baseline, rec, rng)
                    accepted += 1
                w.acc = acc
                flag_modified(w, "acc")
        m.records_total += accepted
        m.rejected_total += rejected
        if accepted:
            m.last_record_at = now
        session.flush()
        _maybe_evaluate(session, m, force=frozen)
        if rng.random() < 0.03:                                                    # keep the table bounded without a scheduler
            session.execute(delete(ModelWindow).where(ModelWindow.monitor_id == m.id, ModelWindow.window_start < oldest))
            session.execute(delete(ModelDecisionWindow).where(ModelDecisionWindow.monitor_id == m.id, ModelDecisionWindow.window_start < oldest))
        status = m.status
        learning = {"records": (m.buffer or {}).get("n", 0), "target": m.baseline_target} if m.baseline is None else None
        session.commit()
        return IngestOut(accepted=accepted, rejected=rejected, status=status, learning=learning, baseline_frozen=frozen)


# ── Creating and reading monitors ───────────────────────────────────────────

class Capabilities(BaseModel):
    kinds: List[str]
    thresholds: Dict[str, float]
    limits: Dict[str, int]


@router.get("/capabilities", response_model=Capabilities)
def capabilities() -> Capabilities:
    return Capabilities(kinds=list(ms.KINDS), thresholds=ms.DEFAULT_THRESHOLDS,
                        limits={"batch": MAX_BATCH, "body_kb": MAX_BODY // 1024, "features": ms.MAX_FEATURES, "categories": ms.MAX_CATEGORIES, "records_per_minute": RECORDS_PER_MINUTE})


class SampleIn(BaseModel):
    inputs: Dict[str, Any] = Field(min_length=1, max_length=200)
    output: Any = None
    segments: Dict[str, Any] = Field(default_factory=dict)


def _kind_of(v: Any) -> str:
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "numeric"
    return "text" if isinstance(v, str) and len(v) > 40 else "categorical"


@router.post("/infer-schema")
def infer_schema(body: SampleIn) -> Dict[str, Any]:
    """A starting point from one example record. The person corrects it (an integer code is a category, not a number) before creating the monitor."""
    return {"features": [{"name": k, "kind": _kind_of(v)} for k, v in list(body.inputs.items())[:ms.MAX_FEATURES]], "output": {"name": "prediction", "kind": _kind_of(body.output) if body.output is not None else "categorical"},
            "segments": list(body.segments)[:5]}


def _summary(m: ModelMonitor) -> Dict[str, Any]:
    open_inc = 0
    return {"key": m.key, "name": m.name, "design_key": m.design_key, "task": m.task, "status": m.status, "records_total": m.records_total, "rejected_total": m.rejected_total,
            "last_record_at": m.last_record_at, "baseline_ready": m.baseline is not None, "baseline_target": m.baseline_target,
            "learning_records": (m.buffer or {}).get("n", 0) if m.baseline is None else None, "signals": m.signals or {}, "reasons": (m.reasons or [])[:5], "created_by": m.created_by,
            "current_version": (m.versions or {}).get("current"), "version_changes": len((m.versions or {}).get("events", []))}


@router.get("")
def list_monitors(design_key: Optional[str] = None, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    q = select(ModelMonitor).where(ModelMonitor.organisation_id == current_organisation(session).id).order_by(ModelMonitor.created_at)
    if design_key:
        q = q.where(ModelMonitor.design_key == design_key)
    return [_summary(m) for m in session.scalars(q)]


@router.post("", status_code=201)
def create_monitor(body: CreateBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    key = agent_key(body.name)
    if len(key) < 2:
        raise HTTPException(status_code=422, detail="The name needs letters or digits.")
    if session.scalar(select(ModelMonitor.id).where(ModelMonitor.organisation_id == org.id, ModelMonitor.key == key)):
        raise HTTPException(status_code=409, detail="A monitor with that name already exists.")
    if body.design_key:
        d = session.scalar(select(Design).where(Design.design_key == body.design_key, Design.subject == "MODEL"))
        if d is None:
            raise HTTPException(status_code=422, detail="That model design does not exist.")
    spec = _spec(body)
    m = ModelMonitor(organisation_id=org.id, key=key, name=body.name.strip(), design_key=body.design_key, task=body.task, spec=spec, thresholds=_thresholds(body.thresholds),
                     buffer=ms.new_acc(spec, None), baseline_target=body.baseline_target, retention_days=body.retention_days, created_by=user.name)
    session.add(m)
    session.commit()
    session.refresh(m)
    return {**_summary(m), "ingest_path": f"/api/model-monitor/{m.key}/records"}


def _detail(session: Session, m: ModelMonitor) -> Dict[str, Any]:
    res = evaluate_monitor(session, m)
    session.commit()
    t = {**ms.DEFAULT_THRESHOLDS, **(m.thresholds or {})}
    return {**_summary(m), "spec": m.spec, "thresholds": t, "custom_thresholds": m.thresholds or {}, "retention_days": m.retention_days, "evaluation": res,
            "baseline": ({"n": m.baseline["n"], "created_at": m.baseline.get("created_at"), "source": m.baseline.get("source"), "error_rate": m.baseline.get("error_rate"),
                          "performance": m.baseline.get("performance"), "latency": m.baseline.get("latency")} if m.baseline else None),
            "ingest_path": f"/api/model-monitor/{m.key}/records"}


@router.get("/signals")
def design_signals(design_key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """What production shows for one model design, as the ST-AI score understands it: lifecycle facts, and the incidents monitoring raised."""
    mons = list(session.scalars(select(ModelMonitor).where(ModelMonitor.organisation_id == current_organisation(session).id, ModelMonitor.design_key == design_key)))
    sig = {"drift_detected": False, "drift_type": None, "bias_breach_detected": False, "domain_violation_occurred": False}
    for m in mons:
        s = m.signals or {}
        for k in ("drift_detected", "bias_breach_detected", "domain_violation_occurred"):
            sig[k] = sig[k] or bool(s.get(k))
        if s.get("drift_type") and (sig["drift_type"] is None or s["drift_type"] == "PERFORMANCE_DRIFT"):
            sig["drift_type"] = s["drift_type"]
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for m in mons:
        s = m.signals or {}
        if s.get("hitl_verified_substantive") is False:
            sig["hitl_verified_substantive"] = False
        b = s.get("automation_bias_risk")
        if b in rank and rank[b] > rank.get(sig.get("automation_bias_risk"), -1):
            sig["automation_bias_risk"] = b
    since = datetime.now(timezone.utc) - timedelta(days=30)
    incs = []
    for m in mons:
        for i in session.scalars(select(ModelIncident).where(ModelIncident.monitor_id == m.id, ModelIncident.detected_at >= since).order_by(ModelIncident.detected_at.desc())):
            incs.append({"id": f"MON-{i.seq:03d}", "uuid": str(i.id), "monitor": m.name, "monitor_key": m.key, "type": i.kind, "severity": i.severity, "status": i.status, "title": i.title, "detected_at": i.detected_at.isoformat(),
                         "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None, "recovered_at": i.recovered_at.isoformat() if i.recovered_at else None, "reasons": (i.detail or {}).get("reasons", [])[:4]})
    return {"monitors": [_summary(m) for m in mons], "signals": sig, "incidents": incs}


class IncidentPatch(BaseModel):
    status: str


@router.patch("/incidents/{incident_id}")
def set_incident_status(incident_id: str, body: IncidentPatch, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    if body.status not in INCIDENT_STATUSES:
        raise HTTPException(status_code=422, detail="Status must be one of " + ", ".join(INCIDENT_STATUSES))
    import uuid as _uuid
    try:
        iid = _uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="No such incident.")
    inc = session.scalar(select(ModelIncident).join(ModelMonitor, ModelMonitor.id == ModelIncident.monitor_id).where(ModelIncident.id == iid, ModelMonitor.organisation_id == current_organisation(session).id))
    if inc is None:
        raise HTTPException(status_code=404, detail="No such incident.")
    inc.status = body.status
    if body.status in ("RESOLVED", "POST_MORTEM"):
        inc.resolved_at, inc.resolved_by = inc.resolved_at or datetime.now(timezone.utc), user.name
    else:
        inc.resolved_at = inc.resolved_by = None
    session.commit()
    return {"id": str(inc.id), "status": inc.status}


@router.get("/{key}")
def get_monitor(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    return _detail(session, _get(session, key))


class PatchBody(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=120)
    design_key: Optional[str] = Field(None, max_length=40)
    unlink: bool = False
    thresholds: Optional[Dict[str, float]] = None
    baseline_target: Optional[int] = Field(None, ge=100, le=100_000)
    retention_days: Optional[int] = Field(None, ge=7, le=90)
    safety_checks: Optional[bool] = None                        # add the prompt and reply checks of a language model to an existing monitor


@router.patch("/{key}")
def update_monitor(key: str, body: PatchBody, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key)
    if body.name:
        m.name = body.name.strip()
    if body.unlink:
        m.design_key = None
    elif body.design_key:
        if session.scalar(select(Design).where(Design.design_key == body.design_key, Design.subject == "MODEL")) is None:
            raise HTTPException(status_code=422, detail="That model design does not exist.")
        m.design_key = body.design_key
    if body.thresholds is not None:
        m.thresholds = _thresholds(body.thresholds)
    if body.baseline_target:
        m.baseline_target = body.baseline_target
    if body.retention_days:
        m.retention_days = body.retention_days
    if body.safety_checks:
        spec = copy.deepcopy(m.spec)
        spec["flags"] = list(spec.get("flags") or []) + [f for f in lsf.SAFETY_FLAGS if f not in (spec.get("flags") or [])]
        m.spec = spec
        flag_modified(m, "spec")
    session.commit()
    return _detail(session, m)


@router.delete("/{key}", status_code=204)
def delete_monitor(key: str, session: Session = Depends(get_session)) -> None:
    session.delete(_get(session, key))
    session.commit()


# ── The baseline ────────────────────────────────────────────────────────────

@router.post("/{key}/baseline/freeze")
def freeze_baseline(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key, lock=True)
    if m.baseline is not None:
        raise HTTPException(status_code=409, detail="The baseline is already set. Reset it first to learn a new one.")
    n = (m.buffer or {}).get("n", 0)
    if n < ms.DEFAULT_THRESHOLDS["min_n"]:
        raise HTTPException(status_code=409, detail=f"Only {n} records so far; at least {int(ms.DEFAULT_THRESHOLDS['min_n'])} are needed for a baseline.")
    _freeze(m, datetime.now(timezone.utc))
    evaluate_monitor(session, m)
    session.commit()
    return _detail(session, m)


class ProfileIn(BaseModel):
    profile: Dict[str, Any]


@router.put("/{key}/baseline")
def supply_baseline(key: str, body: ProfileIn, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """The statistics of the training data, in the shape model_stats.build_baseline produces, instead of learning from production."""
    m = _get(session, key, lock=True)
    problem = ms.check_profile(m.spec, body.profile)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    p = copy.deepcopy(body.profile)
    for f in m.spec["features"]:
        p["features"][f["name"]].setdefault("kind", f["kind"])
        p["features"][f["name"]].setdefault("missing_rate", 0.0)
    p.setdefault("n", 0)
    p.setdefault("confidence", {"props": [], "mean": None, "n": 0})
    p.setdefault("latency", {"p50": None, "p95": None, "n": 0})
    p.setdefault("error_rate", 0.0)
    p.setdefault("performance", {})
    p.setdefault("flags", {})
    p.setdefault("segments", {})
    p["created_at"], p["source"] = datetime.now(timezone.utc).isoformat(), "supplied"
    m.baseline, m.buffer = p, None
    session.execute(delete(ModelWindow).where(ModelWindow.monitor_id == m.id))
    evaluate_monitor(session, m)
    session.commit()
    return _detail(session, m)


@router.post("/{key}/baseline/reset")
def reset_baseline(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key, lock=True)
    m.baseline, m.buffer = None, ms.new_acc(m.spec, None)
    m.status, m.reasons, m.signals = "LEARNING", [], {}
    session.execute(delete(ModelWindow).where(ModelWindow.monitor_id == m.id))
    session.commit()
    return _detail(session, m)


# ── History and incidents ───────────────────────────────────────────────────

@router.get("/{key}/series")
def series(key: str, hours: int = 168, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key)
    hours = min(max(hours, 6), 24 * 30)
    step = 1 if hours <= 48 else (6 if hours <= 168 else 24)
    now = datetime.now(timezone.utc)
    start = _hour(now - timedelta(hours=hours))
    wins = _windows(session, m, start)
    if m.baseline is None:
        return {"step_hours": step, "buckets": []}
    buckets: Dict[datetime, List[ModelWindow]] = defaultdict(list)
    for w in wins:
        buckets[start + timedelta(hours=step * int((w.window_start - start).total_seconds() // (3600 * step)))].append(w)
    out = []
    for at in sorted(buckets):
        acc = _merged(buckets[at])
        n = acc["n"]
        item: Dict[str, Any] = {"at": at.isoformat(), "n": n}
        if n >= 20:
            item["error_rate"] = round(acc["errors"] / n, 5)
            item["p95"] = ms.percentile(acc["latency"]["b"], 0.95)
            perf = ms._perf(acc, m.spec["output"]["kind"])
            if perf.get("n", 0) >= 10 and "accuracy" in perf:
                item["accuracy"] = perf["accuracy"]
            item["psi"] = {f["name"]: ms._compare(f["kind"], m.baseline["features"][f["name"]], acc["features"][f["name"]])[0] for f in m.spec["features"]}
            item["output_psi"] = ms._compare(m.spec["output"]["kind"], m.baseline["output"], acc["output"])[0]
            item["positive_rate"] = round(acc["output"]["pos"] / n, 5)
        out.append(item)
    return {"step_hours": step, "buckets": out, "thresholds": {"psi_watch": (m.thresholds or {}).get("psi_watch", ms.DEFAULT_THRESHOLDS["psi_watch"]), "psi_drift": (m.thresholds or {}).get("psi_drift", ms.DEFAULT_THRESHOLDS["psi_drift"])}}


@router.get("/{key}/incidents")
def monitor_incidents(key: str, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    m = _get(session, key)
    return [{"id": f"MON-{i.seq:03d}", "uuid": str(i.id), "type": i.kind, "severity": i.severity, "status": i.status, "title": i.title, "detected_at": i.detected_at, "last_seen_at": i.last_seen_at,
             "recovered_at": i.recovered_at, "resolved_at": i.resolved_at, "resolved_by": i.resolved_by, "reasons": (i.detail or {}).get("reasons", [])}
            for i in session.scalars(select(ModelIncident).where(ModelIncident.monitor_id == m.id).order_by(ModelIncident.detected_at.desc()).limit(100))]


# ── Which version answered ──────────────────────────────────────────────────

@router.get("/{key}/versions")
def versions(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key)
    if not m.versions or not m.versions.get("items"):
        return {"current": None, "events": [], "reasons": [], "versions": [], "tracking": False}
    return {**mv.evaluate(m.versions, m.spec["output"]["kind"], m.thresholds, datetime.now(timezone.utc).isoformat()), "tracking": True}


# ── What people do with the outputs ─────────────────────────────────────────

class DecisionIn(BaseModel):
    at: Optional[datetime] = None
    role: str = Field("unspecified", max_length=60)
    action: str
    review_seconds: Optional[float] = Field(None, ge=0, le=7 * 86400)
    reason: bool = False                         # whether the person recorded why
    confidence_shown: bool = False               # whether the model's confidence was shown to them
    model_correct: Optional[bool] = None         # once the truth is known
    person: Optional[str] = Field(None, max_length=120)

    @field_validator("action")
    @classmethod
    def action_ok(cls, v: str) -> str:
        if v not in ds.ACTIONS:
            raise ValueError("action must be one of " + ", ".join(ds.ACTIONS))
        return v


class DecisionBatch(BaseModel):
    decisions: List[DecisionIn] = Field(min_length=1, max_length=MAX_BATCH)


@router.post("/{key}/decisions")
def ingest_decisions(key: str, body: DecisionBatch, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> JSONResponse:
    wait = _throttle("d" + str(user.id), len(body.decisions))
    if wait is not None:
        return JSONResponse({"detail": f"Too many decisions from this key; retry in {wait} s."}, status_code=429, headers={"Retry-After": str(wait)})
    m = _get(session, key, lock=True)
    now = datetime.now(timezone.utc)
    oldest = now - timedelta(days=m.retention_days)
    cfg = m.decision_settings or {}
    individuals = bool(cfg.get("individuals"))
    groups: Dict[datetime, List[Dict[str, Any]]] = defaultdict(list)
    accepted = rejected = ignored = 0
    for d in body.decisions:
        at = d.at or now
        at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        if at < oldest or at > now + timedelta(minutes=5):
            rejected += 1
            continue
        rec = d.model_dump(exclude={"at"})
        if rec.get("person") and not individuals:
            ignored += 1
        groups[_hour(at)].append(rec)
        accepted += 1
    for start, recs in groups.items():
        w = session.scalar(select(ModelDecisionWindow).where(ModelDecisionWindow.monitor_id == m.id, ModelDecisionWindow.window_start == start).with_for_update())
        if w is None:
            w = ModelDecisionWindow(monitor_id=m.id, window_start=start, acc=ds.new_acc())
            session.add(w)
        acc = copy.deepcopy(w.acc)
        for rec in recs:
            ds.fold(acc, rec, cfg.get("salt", ""), individuals)
        w.acc = acc
        flag_modified(w, "acc")
    session.flush()
    _maybe_evaluate(session, m, force=True)
    session.commit()
    return JSONResponse({"accepted": accepted, "rejected": rejected, "people_ignored": ignored, "individuals": individuals})


@router.get("/{key}/decisions")
def get_decisions(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key)
    cfg = m.decision_settings or {}
    res = decisions_evaluation(session, m, datetime.now(timezone.utc))
    return {**res, "days": DECISION_DAYS, "individuals": bool(cfg.get("individuals")), "signed_off_by": cfg.get("signed_off_by"), "signed_off_at": cfg.get("signed_off_at"),
            "thresholds": {**ds.DEFAULTS, **(cfg.get("thresholds") or {})}, "custom_thresholds": cfg.get("thresholds") or {}, "advice_only": True}


class DecisionSettingsBody(BaseModel):
    individuals: Optional[bool] = None
    thresholds: Optional[Dict[str, float]] = None


@router.put("/{key}/decision-settings")
def set_decision_settings(key: str, body: DecisionSettingsBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    import secrets
    m = _get(session, key, lock=True)
    cfg = dict(m.decision_settings or {})
    if body.thresholds is not None:
        bad = [k for k in body.thresholds if k not in ds.DEFAULTS]
        if bad:
            raise HTTPException(status_code=422, detail="Unknown threshold: " + ", ".join(bad) + ". Known: " + ", ".join(ds.DEFAULTS))
        cfg["thresholds"] = {k: float(v) for k, v in body.thresholds.items()}
    if body.individuals is True and not cfg.get("individuals"):
        if not has(user.role, "signoff"):
            raise HTTPException(status_code=403, detail="Counting distinct people needs a compliance sign-off. By default decisions are counted by role only.")
        cfg.update({"individuals": True, "signed_off_by": user.name, "signed_off_at": datetime.now(timezone.utc).isoformat(), "salt": cfg.get("salt") or secrets.token_hex(16)})
    elif body.individuals is False and cfg.get("individuals"):
        cfg.update({"individuals": False, "signed_off_by": None, "signed_off_at": None})
        for w in session.scalars(select(ModelDecisionWindow).where(ModelDecisionWindow.monitor_id == m.id)):        # what was counted is forgotten
            acc = copy.deepcopy(w.acc)
            acc["people"] = {}
            w.acc = acc
            flag_modified(w, "acc")
    m.decision_settings = cfg
    flag_modified(m, "decision_settings")
    session.commit()
    return get_decisions(key, session)


# ── Safety checks and canaries ──────────────────────────────────────────────

@router.get("/{key}/safety")
def safety(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key)
    return safety_evaluation(session, m, datetime.now(timezone.utc))


class CanaryIn(BaseModel):
    canary: str = Field(min_length=1, max_length=80)
    passed: bool
    at: Optional[datetime] = None
    model_version: Optional[str] = Field(None, max_length=120)


class CanaryBatch(BaseModel):
    results: List[CanaryIn] = Field(min_length=1, max_length=MAX_BATCH)


@router.post("/{key}/canaries")
def ingest_canaries(key: str, body: CanaryBatch, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> JSONResponse:
    wait = _throttle("c" + str(user.id), len(body.results))
    if wait is not None:
        return JSONResponse({"detail": f"Too many results from this key; retry in {wait} s."}, status_code=429, headers={"Retry-After": str(wait)})
    m = _get(session, key, lock=True)
    now = datetime.now(timezone.utc)
    state = copy.deepcopy(m.canaries) if m.canaries and m.canaries.get("items") is not None else lsf.new_canaries()
    accepted = rejected = 0
    for r in sorted(body.results, key=lambda r: (r.at or now)):
        at = r.at or now
        at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        if at < now - timedelta(days=m.retention_days) or at > now + timedelta(minutes=5):
            rejected += 1
            continue
        lsf.fold_canary(state, r.canary.strip(), r.passed, mv.clean(r.model_version), at.astimezone(timezone.utc).isoformat())
        accepted += 1
    m.canaries = state
    flag_modified(m, "canaries")
    session.flush()
    _maybe_evaluate(session, m, force=True)
    session.commit()
    return JSONResponse({"accepted": accepted, "rejected": rejected})


@router.get("/{key}/canaries")
def canaries(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    m = _get(session, key)
    st = m.canaries if m.canaries and m.canaries.get("items") is not None else lsf.new_canaries()
    return {**lsf.evaluate_canaries(st, (m.versions or {}).get("current")), "current_version": (m.versions or {}).get("current")}
