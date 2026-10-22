"""
Runtime observation (Task 12): what an agent actually does, reported by the SDK while it runs, checked against its active contract.

The SDK (sdk/python, package astra_runtime) sends the things an agent does: a tool call, a handoff to another agent, a connection to an
MCP server, a data store access, a memory write. This module records every event, checks each against the agent's active contract with
the same deterministic comparison findings use (divergence.py), and turns a divergence into:

  * a finding (de-duplicated: the same open finding is not raised again within ten minutes);
  * and, for a new capability the contract does not allow (a tool, an MCP server, a delegation, a data store, long-term memory), a RUNTIME
    drift item: the ratified design plus what was observed, for compliance to approve (ratify a contract that includes it) or decline.
    A declined observation never creates another item; it keeps raising findings.

An agent the platform has never heard of is registered, unowned, with origin DISCOVERED: it counts against ASI10 until someone owns it.
An agent with no active contract is recorded but cannot diverge from anything. A key of role "collector" may only send events and read
the contract summary it needs; nothing in this module can sign anything off.
"""
import random
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

import agent_contract
import divergence
import drift_engine
import findings as findings_mod
from agent_registry import agent_key
from auth import AuthUser, current_user
from db.models import Agent, Contract, Design, DriftItem, Finding, RuntimeEvent
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/runtime", tags=["runtime"])

MAX_BATCH = 200
RATE_PER_MINUTE = 1200            # per key
RETENTION_DAYS = 14
DEDUPE_MINUTES = 10
LIVE_SECONDS, RECENT_SECONDS = 120, 3600
CAPABILITY_EVENTS = {"tool_call", "mcp_connect", "delegation", "data_access", "memory_write"}

_window: Dict[str, Deque[float]] = defaultdict(deque)


def _throttle(key: str, n: int) -> Optional[int]:
    """None if the call may go ahead, else the seconds to wait. A sliding one-minute window per key."""
    now = time.monotonic()
    q = _window[key]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) + n > RATE_PER_MINUTE:
        return max(1, int(60 - (now - q[0]))) if q else 60
    q.extend([now] * n)
    return None


class EventIn(BaseModel):
    type: Literal["tool_call", "delegation", "mcp_connect", "memory_write", "data_access", "heartbeat"]
    name: str = Field("", max_length=200)
    write: Optional[bool] = None
    signed: Optional[bool] = None
    scope: Optional[Literal["long_term", "session"]] = None
    at: Optional[datetime] = None
    trace_id: Optional[str] = Field(None, max_length=64)
    # what OpenTelemetry telemetry adds (telemetry.py); never prompts, arguments or results
    error: Optional[bool] = None
    duration_ms: Optional[int] = Field(None, ge=0, le=86_400_000)
    model: Optional[str] = Field(None, max_length=80)
    tokens_in: Optional[int] = Field(None, ge=0)
    tokens_out: Optional[int] = Field(None, ge=0)
    calls: Optional[int] = Field(None, ge=0)
    via: Optional[str] = Field(None, max_length=12)


class BatchIn(BaseModel):
    agent: str = Field(min_length=2, max_length=80)
    events: List[EventIn] = Field(min_length=1, max_length=MAX_BATCH)
    discover: bool = True                      # register an agent the platform has not seen, unowned
    framework: Optional[str] = Field(None, max_length=80)


class ResultOut(BaseModel):
    verdict: str
    finding_key: Optional[str] = None


class BatchOut(BaseModel):
    agent_key: str
    discovered: bool
    contract_version: Optional[str]
    accepted: int
    divergent: int
    findings: List[str]
    drift_item: Optional[str]
    results: List[ResultOut]


def _clamp(at: Optional[datetime], now: datetime) -> datetime:
    """The SDK's clock is only believed within a day either side of the server's."""
    if at is None:
        return now
    at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
    return at if abs((at - now).total_seconds()) < 86400 else now


def _observed(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    t, name = ev["type"], str(ev.get("name", "")).strip()
    if t == "tool_call" and name:
        return {"type": "tool", "name": name, "p": {"write": bool(ev.get("write"))}}
    if t == "mcp_connect" and name:
        return {"type": "mcp", "name": name, "p": {"signed": bool(ev.get("signed"))}}
    if t == "delegation" and name:
        return {"type": "agent", "name": name, "p": {"owner": "", "auto": "approval"}}
    if t == "data_access" and name:
        return {"type": "data", "name": name, "p": {}}
    if t == "memory_write" and ev.get("scope") == "long_term":
        return {"type": "memory", "name": "runtime-long-term-memory", "p": {"long": True}}
    return None


def _runtime_drift(session: Session, agent: Agent, contract: Contract, new: List[Dict[str, Any]], sdk: str) -> Optional[str]:
    """Open or extend the agent's RUNTIME drift item with newly observed capabilities. Returns its id when one changed."""
    from drift import _build            # imported here: drift imports agent_registry, as does this module
    if agent.design_id is None:
        return None
    design = session.get(Design, agent.design_id)
    if design is None:
        return None
    key = lambda o: (o["type"], o["name"])
    items = list(session.scalars(select(DriftItem).where(DriftItem.agent_key == agent.agent_key, DriftItem.source == "RUNTIME").order_by(DriftItem.created_at)))
    declined = {key(o) for i in items if i.status == "DECLINED" for o in (i.proposed or {}).get("observed", [])}
    open_item = next((i for i in items if i.status == "OPEN"), None)
    have = [o for o in ((open_item.proposed or {}).get("observed", []) if open_item else [])]
    fresh = [o for o in new if key(o) not in declined and key(o) not in {key(h) for h in have}]
    if not fresh:
        return str(open_item.id) if open_item else None
    observed = have + fresh
    snap = contract.document["design_snapshot"]
    base = {"nodes": snap["nodes"], "edges": snap["edges"], "n": 300, "profile": snap.get("profile"), "req": snap.get("declarations") or {}, "policy": snap.get("drift_policy")}
    proposed = drift_engine.apply_observed(base, observed)
    proposed["observed"] = observed
    label = f"Observed at runtime by {sdk} · {len(observed)} capabilit{'y' if len(observed) == 1 else 'ies'} the contract does not allow"
    item = _build(session, agent, contract, proposed, "RUNTIME", label, design.design_key)
    item.title = "runtime drift"
    if open_item is not None:
        open_item.status, open_item.decision_note = "SUPERSEDED", "Replaced by an item with more observations."
    session.add(item)
    session.flush()
    return str(item.id)


def _active(session: Session, key: str) -> Optional[Contract]:
    return session.scalar(select(Contract).where(Contract.object_type == "AGENT", Contract.deployment_id == key, Contract.status == "ACTIVE").order_by(Contract.issued_at.desc()))


ATTR_KEYS = ("write", "signed", "scope", "trace_id", "error", "duration_ms", "model", "tokens_in", "tokens_out", "calls", "via")


@router.post("/events", response_model=BatchOut)
def ingest_events(body: BatchIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> JSONResponse:
    wait = _throttle(str(user.id), len(body.events))
    if wait is not None:
        return JSONResponse({"detail": f"Too many events from this key; slow down and retry in {wait} s (limit {RATE_PER_MINUTE} a minute)."}, status_code=429, headers={"Retry-After": str(wait)})
    return JSONResponse(ingest_batch(session, user.name, body).model_dump(mode="json"), status_code=202)


def ingest_batch(session: Session, actor: str, body: BatchIn) -> BatchOut:
    """Records a batch of one agent's events, checks each against its active contract, raises findings and runtime drift. Commits.
    Used by the SDK endpoint above and by the OpenTelemetry receiver (telemetry.py), so both are judged the same way."""
    key = agent_key(body.agent)
    if len(key) < 2:
        raise HTTPException(status_code=422, detail="The agent name needs letters or digits.")
    now = datetime.now(timezone.utc)
    org = current_organisation(session)
    agent = session.scalar(select(Agent).where(Agent.agent_key == key))
    discovered = False
    if agent is None:
        if not body.discover:
            raise HTTPException(status_code=404, detail=f"The platform has no agent called {key!r} and discovery is off for this call.")
        agent = Agent(agent_key=key, organisation_id=org.id, name=body.agent.strip()[:80], framework=body.framework or "Reported by the runtime SDK", status="UNOWNED", mode="OBSERVE",
                      origin="DISCOVERED", note=f"Discovered at runtime by {actor}")
        session.add(agent)
        session.flush()
        discovered = True
    elif agent.origin == "DEMO":
        raise HTTPException(status_code=409, detail=f"{key!r} is a demo agent; events cannot be reported for it.")
    agent.last_seen_at = now
    contract = _active(session, key)
    view = agent_contract.view(contract.document["design_snapshot"]) if contract else None
    version = contract.document["version"] if contract else None
    results: List[ResultOut] = []
    raised: List[str] = []
    newly: List[Dict[str, Any]] = []
    recent = now - timedelta(minutes=DEDUPE_MINUTES)
    for ev in body.events:
        data = ev.model_dump(exclude_none=True)
        verdict, finding_key = "CONFORMING", None
        if ev.type != "heartbeat":
            if contract is None:
                verdict = "UNKNOWN_AGENT" if discovered else "NO_CONTRACT"
            else:
                found = divergence.check_event(view, {k: v for k, v in data.items() if k in ("type", "name", "write", "signed", "scope")})
                if found is not None:
                    verdict = "DIVERGENT"
                    twin = session.scalar(select(Finding).where(Finding.agent_key == key, Finding.class_code == found["class_code"], Finding.observed == found["observed"],
                                                                Finding.status == "OPEN", Finding.created_at > recent).order_by(Finding.created_at.desc()))
                    if twin is not None:
                        finding_key = f"F-{twin.seq}"
                    else:
                        finding_key = findings_mod.ingest(session, key, {k: v for k, v in data.items() if k in ("type", "name", "write", "signed", "scope")}, "COLLECTED").finding.finding_key
                        raised.append(finding_key)
                    obs = _observed(data)
                    if obs is not None:
                        newly.append(obs)
        session.add(RuntimeEvent(organisation_id=org.id, agent_key=key, at=_clamp(ev.at, now), type=ev.type, name=(ev.name or "")[:200],
                                 attrs={k: v for k, v in data.items() if k in ATTR_KEYS}, verdict=verdict, contract_version=version,
                                 finding_key=finding_key, reported_by=actor))
        results.append(ResultOut(verdict=verdict, finding_key=finding_key))
    drift_id = _runtime_drift(session, agent, contract, newly, actor) if (contract is not None and newly) else None
    session.commit()
    if random.random() < 0.02:                                  # keep the table bounded without a scheduler
        session.execute(delete(RuntimeEvent).where(RuntimeEvent.received_at < now - timedelta(days=RETENTION_DAYS)))
        session.commit()
    return BatchOut(agent_key=key, discovered=discovered, contract_version=version, accepted=len(results), divergent=sum(1 for r in results if r.verdict == "DIVERGENT"),
                    findings=raised, drift_item=drift_id, results=results)


class AllowedOut(BaseModel):
    tools: List[Dict[str, Any]]
    mcp_servers: List[Dict[str, Any]]
    delegates_to: List[str]
    data: List[str]
    long_term_memory: bool


class ContractSummary(BaseModel):
    agent_key: str
    state: str                          # contract | no_contract | unknown
    version: Optional[str]
    allowed: Optional[AllowedOut]


@router.get("/contract/{key}", response_model=ContractSummary)
def contract_summary(key: str, session: Session = Depends(get_session)) -> ContractSummary:
    """What an agent's active contract allows, for an SDK that wants to enforce it locally. Nothing else about the contract is returned."""
    k = agent_key(key)
    agent = session.scalar(select(Agent).where(Agent.agent_key == k))
    if agent is None:
        return ContractSummary(agent_key=k, state="unknown", version=None, allowed=None)
    c = _active(session, k)
    if c is None:
        return ContractSummary(agent_key=k, state="no_contract", version=None, allowed=None)
    v = agent_contract.view(c.document["design_snapshot"])
    return ContractSummary(agent_key=k, state="contract", version=c.document["version"], allowed=AllowedOut(
        tools=v["tools"], mcp_servers=v["mcp_servers"], delegates_to=v["delegates_to"], data=v["data"], long_term_memory=any(m["long_term"] for m in v["memory"])))


# ── For the Live runtime screen ─────────────────────────────────────────────

class AgentLive(BaseModel):
    agent_key: str
    name: str
    origin: str
    owner: Optional[str]
    status: str                         # live | recent | silent | never
    last_seen_at: Optional[datetime]
    contract_version: Optional[str]
    events_1h: int
    divergent_1h: int
    open_findings: int
    open_drift: Optional[str]
    unused_tools: List[str]


class EventOut(BaseModel):
    seq: int
    at: datetime
    agent_key: str
    type: str
    name: str
    verdict: str
    finding_key: Optional[str]
    contract_version: Optional[str]
    reported_by: str
    attrs: Dict[str, Any]


class LiveOut(BaseModel):
    generated_at: datetime
    agents: List[AgentLive]
    events: List[EventOut]
    max_seq: int
    events_24h: int
    divergent_24h: int


def _status(seen: Optional[datetime], now: datetime) -> str:
    if seen is None:
        return "never"
    age = (now - seen).total_seconds()
    return "live" if age <= LIVE_SECONDS else ("recent" if age <= RECENT_SECONDS else "silent")


@router.get("/series")
def series(hours: int = 24, agent: Optional[str] = None, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """What the agents did over time, for the charts: events per bucket split into conforming and outside the contract, the mix of kinds of event, each agent's
    trend, the capabilities seen outside a contract for the first time in the window, and the findings and runtime drift items raised in it."""
    hours = min(max(hours, 3), 168)
    step = 1 if hours <= 48 else 6
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    n = int((now - start).total_seconds() // (3600 * step)) + 1
    key = agent_key(agent) if agent else None
    base = [RuntimeEvent.at >= start] + ([RuntimeEvent.agent_key == key] if key else [])
    hour = func.date_trunc("hour", RuntimeEvent.at)
    rows = session.execute(select(hour, RuntimeEvent.agent_key, RuntimeEvent.type, RuntimeEvent.verdict, func.count()).where(*base).group_by(hour, RuntimeEvent.agent_key, RuntimeEvent.type, RuntimeEvent.verdict)).all()
    buckets = [{"at": (start + timedelta(hours=step * i)).isoformat(), "total": 0, "divergent": 0, "types": {}, "divergent_types": {}} for i in range(n)]
    names = {a.agent_key: a.name for a in session.scalars(select(Agent))}
    per: Dict[str, Dict[str, Any]] = {}
    types: Dict[str, Dict[str, int]] = {}
    for h, ak, ty, verdict, c in rows:
        i = min(max(int((h - start).total_seconds() // (3600 * step)), 0), n - 1)
        b, bad = buckets[i], verdict == "DIVERGENT"
        b["total"] += c
        b["types"][ty] = b["types"].get(ty, 0) + c
        if bad:
            b["divergent"] += c
            b["divergent_types"][ty] = b["divergent_types"].get(ty, 0) + c
        a = per.setdefault(ak, {"agent_key": ak, "name": names.get(ak, ak), "total": 0, "divergent": 0, "spark": [0] * n, "spark_divergent": [0] * n})
        a["total"] += c
        a["spark"][i] += c
        t = types.setdefault(ty, {"total": 0, "divergent": 0})
        t["total"] += c
        if bad:
            a["divergent"] += c
            a["spark_divergent"][i] += c
            t["divergent"] += c
    first = session.execute(select(RuntimeEvent.agent_key, RuntimeEvent.type, RuntimeEvent.name, func.min(RuntimeEvent.at)).where(RuntimeEvent.verdict == "DIVERGENT", *([RuntimeEvent.agent_key == key] if key else []))
                            .group_by(RuntimeEvent.agent_key, RuntimeEvent.type, RuntimeEvent.name)).all()
    caps = sorted(({"at": at.isoformat(), "agent_key": ak, "type": ty, "name": nm or ("long-term memory" if ty == "memory_write" else "")} for ak, ty, nm, at in first if at >= start), key=lambda x: x["at"])[:30]
    fq = select(Finding).where(Finding.created_at >= start, Finding.source != "DEMO").order_by(Finding.created_at)
    dq = select(DriftItem).where(DriftItem.created_at >= start, DriftItem.source == "RUNTIME").order_by(DriftItem.created_at)
    if key:
        fq, dq = fq.where(Finding.agent_key == key), dq.where(DriftItem.agent_key == key)
    return {"hours": hours, "step_hours": step, "buckets": buckets, "by_agent": sorted(per.values(), key=lambda a: -a["total"]),
            "types": [{"type": k, **v} for k, v in sorted(types.items(), key=lambda kv: -kv[1]["total"])], "new_capabilities": caps,
            "findings": [{"at": f.created_at.isoformat(), "key": f"F-{f.seq}", "severity": f.severity, "agent_key": f.agent_key} for f in session.scalars(fq.limit(100))],
            "drift_items": [{"at": d.created_at.isoformat(), "agent_key": d.agent_key, "status": d.status} for d in session.scalars(dq.limit(50))]}


@router.get("/overview", response_model=LiveOut)
def overview(agent: Optional[str] = None, limit: int = 60, session: Session = Depends(get_session)) -> LiveOut:
    now = datetime.now(timezone.utc)
    hour, day, month = now - timedelta(hours=1), now - timedelta(hours=24), now - timedelta(days=30)
    agents = list(session.scalars(select(Agent).where(Agent.origin != "DEMO").order_by(Agent.created_at)))
    per = {k: (n, d) for k, n, d in session.execute(select(RuntimeEvent.agent_key, func.count(), func.count().filter(RuntimeEvent.verdict == "DIVERGENT")).where(RuntimeEvent.received_at > hour).group_by(RuntimeEvent.agent_key))}
    used: Dict[str, set] = defaultdict(set)
    for k, n in session.execute(select(RuntimeEvent.agent_key, RuntimeEvent.name).where(RuntimeEvent.type == "tool_call", RuntimeEvent.received_at > month).distinct()):
        used[k].add(n)
    seen_any = {k for (k,) in session.execute(select(RuntimeEvent.agent_key).where(RuntimeEvent.received_at > month).distinct())}
    open_f = dict(session.execute(select(Finding.agent_key, func.count()).where(Finding.status == "OPEN", Finding.source != "DEMO").group_by(Finding.agent_key)).all())
    open_d = {d.agent_key: str(d.id) for d in session.scalars(select(DriftItem).where(DriftItem.status == "OPEN", DriftItem.source == "RUNTIME"))}
    live: List[AgentLive] = []
    for a in agents:
        c = _active(session, a.agent_key)
        unused: List[str] = []
        if c is not None and a.agent_key in seen_any:
            unused = sorted(t["name"] for t in agent_contract.view(c.document["design_snapshot"])["tools"] if t["name"] not in used[a.agent_key])
        n, d = per.get(a.agent_key, (0, 0))
        live.append(AgentLive(agent_key=a.agent_key, name=a.name, origin=a.origin, owner=a.owner, status=_status(a.last_seen_at, now), last_seen_at=a.last_seen_at,
                              contract_version=c.document["version"] if c else None, events_1h=n, divergent_1h=d, open_findings=open_f.get(a.agent_key, 0),
                              open_drift=open_d.get(a.agent_key), unused_tools=unused))
    live.sort(key=lambda x: ({"live": 0, "recent": 1, "silent": 2, "never": 3}[x.status], x.name))
    q = select(RuntimeEvent).order_by(RuntimeEvent.seq.desc()).limit(min(max(limit, 1), 300))
    if agent:
        q = q.where(RuntimeEvent.agent_key == agent_key(agent))
    rows = list(session.scalars(q))
    totals = session.execute(select(func.count(), func.count().filter(RuntimeEvent.verdict == "DIVERGENT")).where(RuntimeEvent.received_at > day)).one()
    return LiveOut(generated_at=now, agents=live, max_seq=session.scalar(select(func.coalesce(func.max(RuntimeEvent.seq), 0))) or 0, events_24h=totals[0], divergent_24h=totals[1],
                   events=[EventOut(seq=e.seq, at=e.at, agent_key=e.agent_key, type=e.type, name=e.name, verdict=e.verdict, finding_key=e.finding_key,
                                    contract_version=e.contract_version, reported_by=e.reported_by, attrs=e.attrs) for e in rows])
