"""
Telemetry discovery: find and watch AI agents from the OpenTelemetry data an organisation already produces.

  POST /api/telemetry/v1/traces         the OTLP/HTTP traces endpoint (point an OpenTelemetry Collector or SDK exporter's endpoint at /api/telemetry)
  GET  /api/telemetry/status            what has arrived (last 24 hours), what could not be understood, the current settings
  PUT  /api/telemetry/settings          how an agent is recognised, and whether an unknown agent is registered
  GET  /api/telemetry/agents            what each agent was seen doing: tools, MCP servers, delegations, data, models, errors
  POST /api/telemetry/agents/{key}/design   a draft design from what the agent was seen doing

Spans are turned into the same runtime events the ASTRA SDK sends (telemetry_otlp.py) and judged the same way (runtime.ingest_batch): an agent the
platform has not seen is registered, unowned, as DISCOVERED (it counts against ASI10 until someone owns it); an agent with an active contract is
checked against it, and a tool, MCP server, delegation or data store the contract does not allow becomes a finding and a runtime drift item for
compliance to decide. An agent with the same name as one imported from a repository or an identity provider is the same agent, so the three
sources describe one inventory entry.

What a design built from telemetry means: it holds what the agent was seen doing in the window, which is evidence, but only of what happened. A tool
it has not used yet is not in it, and whether a tool writes is inferred from its name. When the agent already has a design, the observed elements are
merged into it rather than replacing it; when it has an active contract nothing is changed here (a new capability reaches Drift review by itself).

Protections: the endpoint accepts an API key of role "collector" (or an engineer's key) and nothing else, so a leaked key can only send events; the
request body is size-limited, also after decompression; a request is rate-limited per key and answered 429 with Retry-After, which OTLP exporters
honour; prompts, completions, tool arguments and results are never read or kept (telemetry_otlp.py).
"""
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

import hashlib

from agent_import import MAX_NODES, WRITE_WORDS, ImportOut, _active, _clean, _manifest, apply_converted, finish
from agent_registry import agent_key
from auth import AuthUser, current_user
from db.models import Agent, Contract, RuntimeEvent, TelemetryIngest, TelemetrySettings
from db.session import SessionLocal, get_session
from idp_connect import _merged
from organisation import current_organisation
from runtime import BatchIn, EventIn, MAX_BATCH, _throttle, ingest_batch
from telemetry_otlp import MAX_BODY, PendingPool, SpanCache, TelemetryError, decode, map_spans

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])
RETENTION_DAYS = 14
_CACHE = SpanCache()
_PENDING = PendingPool()
MIN_EVIDENCE = 20


def _settings(session: Session, org_id) -> TelemetrySettings:
    s = session.scalar(select(TelemetrySettings).where(TelemetrySettings.organisation_id == org_id))
    if s is None:
        s = TelemetrySettings(organisation_id=org_id, agent_from_service=False, discover=True)
        session.add(s)
        session.flush()
    return s


# ── The OTLP endpoint ───────────────────────────────────────────────────────

class _Throttled(Exception):
    def __init__(self, wait: int):
        self.wait = wait


def _process(spans: List[Dict[str, Any]], actor: str, key_id: str) -> Dict[str, Any]:
    started = datetime.now(timezone.utc)
    with SessionLocal() as session:
        org = current_organisation(session)
        cfg = _settings(session, org.id)
        discover, from_service = cfg.discover, cfg.agent_from_service
        session.commit()
        mapped = map_spans(spans, from_service, _CACHE, pending=_PENDING)
        total = sum(len(b["events"]) + 1 for b in mapped["agents"].values())
        wait = _throttle(key_id, total) if total else None
        if wait is not None:
            raise _Throttled(wait)
        sent = divergent = invalid = 0
        findings: List[str] = []
        unknown: List[str] = []
        refused: List[str] = []
        drifted: List[str] = []
        for name, b in mapped["agents"].items():
            if len(agent_key(name)) < 2:
                continue
            events: List[EventIn] = []
            for ev in b["events"]:
                try:
                    events.append(EventIn(**{k: v for k, v in ev.items() if v is not None}))
                except ValidationError:
                    invalid += 1
            events.append(EventIn(type="heartbeat", calls=b["calls"] or None, model=(b["models"][0] if b["models"] else None), tokens_in=b["tokens_in"] or None,
                                  tokens_out=b["tokens_out"] or None, error=True if b["errors"] else None, via="otlp", at=b["last"]))
            for i in range(0, len(events), MAX_BATCH):
                try:
                    out = ingest_batch(session, actor, BatchIn(agent=name, events=events[i:i + MAX_BATCH], discover=discover, framework=b["framework"] or "OpenTelemetry"))
                except HTTPException as exc:
                    session.rollback()
                    if exc.status_code == 404:
                        unknown.append(name)
                    else:                                              # for example 409: an agent of that name is a demo agent; say so instead of dropping it silently
                        invalid += len(events)
                        refused.append(f"{name}: {exc.detail}"[:160])
                    break
                sent += out.accepted
                divergent += out.divergent
                findings += out.findings
                if out.drift_item:
                    drifted.append(out.drift_item)
        st = mapped["stats"]
        session.add(TelemetryIngest(organisation_id=org.id, at=started, key_name=actor[:200], spans=st["spans"], mapped=st["mapped"], ignored=st["ignored"], unattributed=st["unattributed"],
                                    agents=len(mapped["agents"]), events=sent, divergent=divergent, invalid=invalid, unknown=len(unknown), waiting=st.get("waiting", 0), samples=(mapped["unattributed_samples"] + refused)[:8],
                                    duration_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000)))
        session.execute(delete(TelemetryIngest).where(TelemetryIngest.at < started - timedelta(days=RETENTION_DAYS)))
        session.commit()
        return {"agents": len(mapped["agents"]), "events": sent, "findings": findings}


@router.post("/v1/traces")
async def otlp_traces(request: Request, user: AuthUser = Depends(current_user)) -> Response:
    """OTLP/HTTP traces. Answers in the format it was sent in, as the protocol asks."""
    ct = request.headers.get("content-type", "")
    proto = ct.split(";")[0].strip().lower() == "application/x-protobuf"
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY:
        return Response(status_code=413, content=json.dumps({"detail": "The request is larger than the limit."}), media_type="application/json")
    raw = await request.body()
    try:
        spans = decode(raw, ct, request.headers.get("content-encoding", ""))
    except TelemetryError as exc:
        return Response(status_code=400, content=json.dumps({"detail": str(exc)}), media_type="application/json")
    try:
        await run_in_threadpool(_process, spans, user.name, str(user.id))
    except _Throttled as t:
        return Response(status_code=429, content=json.dumps({"detail": f"Too many events from this key; retry in {t.wait} s."}), media_type="application/json", headers={"Retry-After": str(t.wait)})
    return Response(status_code=200, content=b"" if proto else b"{}", media_type="application/x-protobuf" if proto else "application/json")


# ── Status and settings ─────────────────────────────────────────────────────

class SettingsIO(BaseModel):
    agent_from_service: bool = False
    discover: bool = True


class IngestOut(BaseModel):
    at: datetime
    key_name: str
    spans: int
    mapped: int
    unattributed: int
    waiting: int
    invalid: int
    agents: int
    events: int
    divergent: int
    duration_ms: int


class StatusOut(BaseModel):
    settings: SettingsIO
    endpoint_path: str
    last_received_at: Optional[datetime]
    requests_24h: int
    spans_24h: int
    mapped_24h: int
    ignored_24h: int
    unattributed_24h: int
    events_24h: int
    divergent_24h: int
    unknown_agents_24h: int
    samples: List[str]
    recent: List[IngestOut]


@router.get("/status", response_model=StatusOut)
def status(session: Session = Depends(get_session)) -> StatusOut:
    org = current_organisation(session)
    cfg = _settings(session, org.id)
    session.commit()
    day = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = list(session.scalars(select(TelemetryIngest).where(TelemetryIngest.organisation_id == org.id, TelemetryIngest.at > day).order_by(TelemetryIngest.at.desc())))
    last = session.scalar(select(func.max(TelemetryIngest.at)).where(TelemetryIngest.organisation_id == org.id))
    samples: List[str] = []
    for r in rows:
        for x in r.samples or []:
            if x not in samples and len(samples) < 8:
                samples.append(x)
    s = lambda f: sum(getattr(r, f) for r in rows)
    return StatusOut(settings=SettingsIO(agent_from_service=cfg.agent_from_service, discover=cfg.discover), endpoint_path="/api/telemetry", last_received_at=last, requests_24h=len(rows), spans_24h=s("spans"),
                     mapped_24h=s("mapped"), ignored_24h=s("ignored"), unattributed_24h=s("unattributed"), events_24h=s("events"), divergent_24h=s("divergent"), unknown_agents_24h=s("unknown"), samples=samples,
                     recent=[IngestOut(at=r.at, key_name=r.key_name, spans=r.spans, mapped=r.mapped, unattributed=r.unattributed, waiting=r.waiting, invalid=r.invalid, agents=r.agents, events=r.events, divergent=r.divergent, duration_ms=r.duration_ms) for r in rows[:15]])


@router.put("/settings", response_model=SettingsIO)
def update_settings(body: SettingsIO, session: Session = Depends(get_session)) -> SettingsIO:
    cfg = _settings(session, current_organisation(session).id)
    cfg.agent_from_service, cfg.discover = body.agent_from_service, body.discover
    session.commit()
    return body


# ── What each agent was seen doing ──────────────────────────────────────────

class ObservedAgent(BaseModel):
    agent_key: str
    name: str
    origin: str
    owner: Optional[str]
    framework: str
    has_design: bool
    has_contract: bool
    events: int
    first_at: datetime
    last_at: datetime
    divergent: int
    errors: int
    tools: List[Dict[str, Any]]
    mcp_servers: List[Dict[str, Any]]
    delegations: List[Dict[str, Any]]
    data: List[Dict[str, Any]]
    models: List[str]
    calls: int
    tokens_in: int
    tokens_out: int


def observed_profiles(session: Session, days: int, only: Optional[str] = None) -> List[ObservedAgent]:
    org = current_organisation(session)
    since = datetime.now(timezone.utc) - timedelta(days=min(max(days, 1), RETENTION_DAYS))
    q = select(RuntimeEvent).where(RuntimeEvent.organisation_id == org.id, RuntimeEvent.at > since, RuntimeEvent.attrs["via"].as_string() == "otlp").order_by(RuntimeEvent.seq.desc()).limit(100_000)
    if only:
        q = q.where(RuntimeEvent.agent_key == only)
    per: Dict[str, Dict[str, Any]] = {}
    for e in session.scalars(q):
        p = per.setdefault(e.agent_key, {"events": 0, "first": e.at, "last": e.at, "div": 0, "err": 0, "calls": 0, "ti": 0, "to": 0, "models": Counter(),
                                         "kinds": {"tool_call": defaultdict(lambda: [0, False]), "mcp_connect": defaultdict(lambda: [0, False]), "delegation": defaultdict(lambda: [0, False]), "data_access": defaultdict(lambda: [0, False])}})
        p["first"], p["last"] = min(p["first"], e.at), max(p["last"], e.at)
        a = e.attrs or {}
        if e.type == "heartbeat":
            p["calls"] += int(a.get("calls") or 0)
            p["ti"] += int(a.get("tokens_in") or 0)
            p["to"] += int(a.get("tokens_out") or 0)
            if a.get("model"):
                p["models"][a["model"]] += 1
            continue
        p["events"] += 1
        p["div"] += 1 if e.verdict == "DIVERGENT" else 0
        p["err"] += 1 if a.get("error") else 0
        c = p["kinds"][e.type][e.name]
        c[0] += 1
        c[1] = c[1] or bool(a.get("write"))
    agents = {a.agent_key: a for a in session.scalars(select(Agent).where(Agent.agent_key.in_(list(per)))) } if per else {}
    out: List[ObservedAgent] = []
    for key, p in per.items():
        a = agents.get(key)
        if a is None:
            continue
        top = lambda kind: [{"name": n, "count": c[0], "write": c[1]} for n, c in sorted(p["kinds"][kind].items(), key=lambda kv: -kv[1][0])][:60]
        out.append(ObservedAgent(agent_key=key, name=a.name, origin=a.origin, owner=a.owner, framework=a.framework, has_design=a.design_id is not None, has_contract=_active(session, key) is not None,
                                 events=p["events"], first_at=p["first"], last_at=p["last"], divergent=p["div"], errors=p["err"], tools=top("tool_call"), mcp_servers=top("mcp_connect"),
                                 delegations=top("delegation"), data=top("data_access"), models=[m for m, _ in p["models"].most_common(5)], calls=p["calls"], tokens_in=p["ti"], tokens_out=p["to"]))
    out.sort(key=lambda x: x.last_at, reverse=True)
    return out


@router.get("/agents", response_model=List[ObservedAgent])
def observed_agents(days: int = 7, session: Session = Depends(get_session)) -> List[ObservedAgent]:
    return observed_profiles(session, days)


class DesignBody(BaseModel):
    days: int = Field(7, ge=1, le=RETENTION_DAYS)
    profile: Optional[str] = Field(None, max_length=64)


@router.post("/agents/{key}/design")
def design_from_telemetry(key: str, body: DesignBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    prof = next(iter(observed_profiles(session, body.days, agent_key(key))), None)
    if prof is None:
        raise HTTPException(status_code=404, detail="No telemetry was received for that agent in this window.")
    if prof.has_contract:
        raise HTTPException(status_code=409, detail=f"{prof.name} has an active contract. Anything it does that the contract does not allow already reaches Drift review as runtime drift; nothing is changed here.")
    m = _manifest(prof.name)
    m["framework"] = prof.framework if prof.framework and prof.framework != "Reported by the runtime SDK" else "OpenTelemetry"
    m["owner"] = prof.owner
    m["tools"] = [{"name": t["name"], "write": bool(t["write"] or WRITE_WORDS.search(t["name"]))} for t in prof.tools]
    m["mcp"] = [{"name": s["name"], "signed": False} for s in prof.mcp_servers]
    m["delegates"] = [d["name"] for d in prof.delegations]
    m["data"] = [d["name"] for d in prof.data]
    m["recognised"].append(f"{prof.events} observed events in the last {body.days} days, from {prof.first_at.date()} to {prof.last_at.date()}")
    if prof.models:
        m["recognised"].append("models seen: " + ", ".join(prof.models) + " (not part of the agent model)")
    m["inferred"].append("tools, servers, delegations and data stores are those the agent was seen using in the window: one it has not used yet is not here")
    m["inferred"].append("whether a tool writes is taken from its name unless a write was observed; confirm it")
    m["inferred"].append("goal, inputs, approvals and guardrails are not visible in telemetry; add them in the design")
    m["inferred"].append("autonomy: telemetry does not say how much a person supervises the agent; acts_with_approval was assumed")
    if prof.events < MIN_EVIDENCE:
        m["warnings"].append(f"Only {prof.events} events were observed; this is thin evidence of what the agent does. Let it run longer before relying on the model.")
    if prof.errors:
        m["warnings"].append(f"{prof.errors} of the observed events ended in an error.")
    sha = hashlib.sha256(json.dumps({"t": m["tools"], "m": m["mcp"], "d": m["delegates"], "x": m["data"]}, sort_keys=True).encode()).hexdigest()
    conv, merged = _merged(session, prof.agent_key, finish(m, "telemetry", [prof.name], sha), ("tool", "mcp", "data", "agent"))
    prov = {"source": "telemetry", "format": "telemetry", "window_days": body.days, "events": prof.events, "from": prof.first_at.isoformat(), "to": prof.last_at.isoformat(), "sha256": sha,
            "imported_by": user.name, "imported_at": datetime.now(timezone.utc).isoformat(), "merged": merged, "note": "Generated from what OpenTelemetry showed the agent doing; it is evidence of behaviour, not of intent.",
            "label": f"Built from {prof.events} observed events over {body.days} days (OpenTelemetry), not verified against code"}
    out: ImportOut = apply_converted(session, user.name, conv, prov, body.profile)
    return {"outcome": out.outcome, "summary": out.summary, "design_key": out.design_key, "merged": merged, "drift_id": out.drift_id}
