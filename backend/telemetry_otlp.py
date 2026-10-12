"""
OpenTelemetry traces in, runtime events out.

An organisation's agents are usually already instrumented: an OpenTelemetry SDK or the OpenInference, OpenLLMetry or OpenAI Agents SDK
instrumentations emit a span for every agent run, tool call and model call. This module reads those spans (OTLP over HTTP, as JSON or as
protobuf, optionally gzip) and turns them into the same runtime events the ASTRA SDK sends, so an agent can be discovered and checked against its
contract without the SDK.

What it reads, by convention:
  * OpenTelemetry GenAI semantic conventions: gen_ai.operation.name (invoke_agent, execute_tool, chat), gen_ai.agent.name, gen_ai.tool.name,
    gen_ai.tool.type, gen_ai.request.model, gen_ai.usage.*
  * OpenInference (Arize Phoenix, the OpenAI Agents SDK, LangChain, LlamaIndex, CrewAI instrumentations): openinference.span.kind (AGENT, TOOL, LLM, ...)
  * OpenLLMetry (Traceloop): traceloop.span.kind and traceloop.entity.name
  * MCP: mcp.method.name, mcp.server.name; database spans: db.system with db.namespace or db.name
  * the OpenAI Agents SDK's handoff spans (to_agent)

What it never reads or keeps: prompts, completions, tool arguments or results, message content, span events. Only the names, the kinds, the
timings, the model name and token counts. An attribute that carries content is simply never looked at.

Which agent a span belongs to: its own gen_ai.agent.name, else the nearest ancestor span that is an agent span (so a tool call inside an agent run
belongs to that agent, even if the batch arrives in pieces); else, if the organisation allows it, the service name. A span that cannot be placed is
counted and a few names are kept for the person setting this up, but it creates nothing.

Pure functions: no database, no network.
"""
import gzip
import json
import re
import zlib
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from agent_import import WRITE_WORDS, _clean

MAX_BODY = 16 * 1024 * 1024
MAX_SPANS = 20_000
MAX_ATTRS = 128
MAX_STR = 500
WRITE_SQL = re.compile(r"^\s*(insert|update|delete|drop|alter|create|truncate|merge|replace)", re.I)
FRAMEWORKS = [("langgraph", "LangGraph"), ("langchain", "LangGraph"), ("openai_agents", "OpenAI Agents SDK"), ("openai-agents", "OpenAI Agents SDK"), ("agents", "OpenAI Agents SDK"),
              ("crewai", "CrewAI"), ("autogen", "AutoGen"), ("llama_index", "LlamaIndex"), ("llamaindex", "LlamaIndex"), ("semantic_kernel", "Semantic Kernel"), ("pydantic_ai", "Pydantic AI"),
              ("haystack", "Haystack"), ("smolagents", "smolagents"), ("strands", "Strands Agents")]


class TelemetryError(ValueError):
    """The request could not be read as OTLP; the message says why."""


# ── Reading the request ─────────────────────────────────────────────────────

def _value(v: Dict[str, Any]) -> Any:
    for k in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if k in v:
            x = v[k]
            return int(x) if k == "intValue" else (str(x)[:MAX_STR] if k == "stringValue" else x)
    return None                                                      # arrays and maps are not used by any mapping rule


def _attrs(items: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for kv in (items or [])[:MAX_ATTRS]:
        if isinstance(kv, dict) and isinstance(kv.get("key"), str):
            val = _value(kv.get("value") or {})
            if val is not None:
                out[kv["key"]] = val
    return out


def _span(raw: Dict[str, Any], resource: Dict[str, Any], scope: str) -> Dict[str, Any]:
    st = raw.get("status") or {}
    return {"trace": str(raw.get("traceId") or ""), "span": str(raw.get("spanId") or ""), "parent": str(raw.get("parentSpanId") or ""), "name": str(raw.get("name") or "")[:200],
            "kind": raw.get("kind"), "start_ns": int(raw.get("startTimeUnixNano") or 0), "end_ns": int(raw.get("endTimeUnixNano") or 0), "attrs": _attrs(raw.get("attributes")),
            "resource": resource, "scope": scope, "error": st.get("code") in (2, "STATUS_CODE_ERROR", "2")}


def from_json(doc: Any) -> List[Dict[str, Any]]:
    try:
        return _from_json(doc)
    except TelemetryError:
        raise
    except (AttributeError, TypeError, ValueError, KeyError):
        raise TelemetryError("The body is not a valid OTLP traces request (a field has the wrong shape).")


def _from_json(doc: Any) -> List[Dict[str, Any]]:
    if not isinstance(doc, dict):
        raise TelemetryError("The body is not an OTLP traces request.")
    out: List[Dict[str, Any]] = []
    for rs in doc.get("resourceSpans") or []:
        resource = _attrs((rs.get("resource") or {}).get("attributes"))
        for ss in rs.get("scopeSpans") or rs.get("instrumentationLibrarySpans") or []:
            scope = str((ss.get("scope") or ss.get("instrumentationLibrary") or {}).get("name") or "")
            for sp in ss.get("spans") or []:
                out.append(_span(sp, resource, scope))
                if len(out) > MAX_SPANS:
                    raise TelemetryError(f"More than {MAX_SPANS} spans in one request; send smaller batches.")
    return out


def from_protobuf(raw: bytes) -> List[Dict[str, Any]]:
    try:
        from google.protobuf.json_format import MessageToDict
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
    except ImportError:                                              # pragma: no cover - the dependency is part of the image
        raise TelemetryError("This deployment cannot read protobuf; send OTLP as JSON (otlphttp exporter with encoding: json).")
    req = ExportTraceServiceRequest()
    try:
        req.ParseFromString(raw)
    except Exception:
        raise TelemetryError("The body is not a valid OTLP protobuf message.")
    out: List[Dict[str, Any]] = []
    for rs in req.resource_spans:
        resource = _attrs(MessageToDict(rs.resource).get("attributes"))
        for ss in rs.scope_spans:
            for sp in ss.spans:
                d = MessageToDict(sp, preserving_proto_field_name=False)
                d["traceId"], d["spanId"], d["parentSpanId"] = sp.trace_id.hex(), sp.span_id.hex(), sp.parent_span_id.hex()      # protobuf carries the ids as bytes
                d.pop("events", None)
                d.pop("links", None)
                out.append(_span(d, resource, ss.scope.name))
                if len(out) > MAX_SPANS:
                    raise TelemetryError(f"More than {MAX_SPANS} spans in one request; send smaller batches.")
    return out


def decode(raw: bytes, content_type: str, encoding: str = "") -> List[Dict[str, Any]]:
    if (encoding or "").lower() == "gzip":
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(raw, MAX_BODY)
            if d.unconsumed_tail:
                raise TelemetryError("The request is larger than the limit once decompressed.")
        except zlib.error:
            raise TelemetryError("The body is not valid gzip.")
    elif encoding and encoding.lower() not in ("identity", ""):
        raise TelemetryError(f"Content-Encoding {encoding} is not supported; use gzip or none.")
    if len(raw) > MAX_BODY:
        raise TelemetryError("The request is larger than the limit.")
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct == "application/x-protobuf":
        return from_protobuf(raw)
    if ct in ("application/json", "", "text/json"):
        try:
            return from_json(json.loads(raw.decode("utf-8") or "{}"))
        except (ValueError, UnicodeDecodeError):
            raise TelemetryError("The body is not valid JSON.")
    raise TelemetryError("Send OTLP as application/x-protobuf or application/json.")


# ── Reading the spans ───────────────────────────────────────────────────────

class SpanCache:
    """Which agent a recent span belonged to, so a tool span can find its agent even when the agent's own span arrived in an earlier request."""

    def __init__(self, size: int = 50_000):
        self.size, self.d = size, OrderedDict()

    def get(self, trace: str, span: str) -> Optional[str]:
        v = self.d.get((trace, span))
        if v is not None:
            self.d.move_to_end((trace, span))
        return v

    def put(self, trace: str, span: str, agent: str) -> None:
        self.d[(trace, span)] = agent
        self.d.move_to_end((trace, span))
        while len(self.d) > self.size:
            self.d.popitem(last=False)


class PendingPool:
    """Spans that could not be placed yet, kept for a short while.

    A span is exported when it ends, and a child ends before its parent, so a tool call usually reaches ASTRA before the agent run that contains it.
    Those spans wait here, by trace; when the agent's own span arrives, the waiting spans of that trace are read again and find their agent. A span
    still unplaced after the wait is dropped and counted. Held in memory only: a restart forgets what was waiting, which loses a few seconds of telemetry."""

    def __init__(self, ttl: float = 120.0, cap: int = 20_000):
        self.ttl, self.cap = ttl, cap
        self.d: "OrderedDict[Tuple[str, str], Tuple[float, Dict[str, Any]]]" = OrderedDict()
        self.by_trace: Dict[str, set] = {}

    def _drop(self, k: Tuple[str, str]) -> Optional[Dict[str, Any]]:
        item = self.d.pop(k, None)
        if item is None:
            return None
        group = self.by_trace.get(k[0])
        if group is not None:
            group.discard(k)
            if not group:
                self.by_trace.pop(k[0], None)
        return item[1]

    def take(self, traces: set) -> List[Dict[str, Any]]:
        out = []
        for t in traces:
            for k in list(self.by_trace.get(t, ())):
                sp = self._drop(k)
                if sp is not None:
                    out.append(sp)
        return out

    def add(self, sp: Dict[str, Any], now: float) -> List[Dict[str, Any]]:
        k = (sp["trace"], sp["span"])
        self.d[k] = (now + self.ttl, sp)
        self.by_trace.setdefault(sp["trace"], set()).add(k)
        over = []
        while len(self.d) > self.cap:
            over.append(self._drop(next(iter(self.d))))
        return [s for s in over if s is not None]

    def sweep(self, now: float) -> List[Dict[str, Any]]:
        gone = []
        for k in [k for k, (exp, _s) in self.d.items() if exp <= now]:
            sp = self._drop(k)
            if sp is not None:
                gone.append(sp)
        return gone


def _kind(a: Dict[str, Any]) -> str:
    """What the span is: agent, tool, llm, mcp, handoff, data or other, by whichever convention it follows."""
    oi = str(a.get("openinference.span.kind") or "").upper()
    tl = str(a.get("traceloop.span.kind") or "").lower()
    op = str(a.get("gen_ai.operation.name") or "").lower()
    if op in ("invoke_agent", "create_agent") or oi == "AGENT" or tl == "agent":
        return "agent"
    if a.get("mcp.method.name") or a.get("mcp.server.name") or a.get("rpc.system") == "mcp":
        return "mcp"                      # before "tool": a tools/call to an MCP server is a server and the tool called on it
    if op == "execute_tool" or oi == "TOOL" or tl == "tool" or a.get("gen_ai.tool.name") or a.get("tool.name"):
        return "tool"
    if a.get("db.system") and (a.get("db.namespace") or a.get("db.name")):
        return "data"
    if op in ("chat", "text_completion", "generate_content") or oi == "LLM" or a.get("gen_ai.request.model") or a.get("llm.model_name"):
        return "llm"
    return "other"


def _agent_name(sp: Dict[str, Any]) -> Optional[str]:
    a = sp["attrs"]
    n = a.get("gen_ai.agent.name")
    if n:
        return _clean(n, 80)
    if _kind(a) == "agent":
        return _clean(a.get("traceloop.entity.name") or sp["name"].removeprefix("invoke_agent ").removeprefix("agent ").strip() or "", 80) or None
    return None


def _tool_name(sp: Dict[str, Any]) -> str:
    a = sp["attrs"]
    n = a.get("gen_ai.tool.name") or a.get("tool.name") or a.get("traceloop.entity.name") or sp["name"].removeprefix("execute_tool ").removeprefix("tool ").removesuffix(".tool")
    return _clean(n, 200)


def _framework(scope: str, resource: Dict[str, Any]) -> Optional[str]:
    low = scope.lower().replace("-", "_")
    for needle, label in FRAMEWORKS:
        if needle in low:
            return label
    return None


def map_spans(spans: List[Dict[str, Any]], agent_from_service: bool, cache: Optional[SpanCache] = None, now: Optional[datetime] = None, pending: Optional[PendingPool] = None) -> Dict[str, Any]:
    """Spans to per-agent event lists plus statistics about what was and was not understood.
    `pending` holds spans from earlier requests that had no agent yet (see PendingPool); with none given, a span that cannot be placed is dropped at once."""
    cache = cache if cache is not None else SpanCache()
    pool = pending if pending is not None else PendingPool(ttl=0)
    now = now or datetime.now(timezone.utc)
    clock = now.timestamp()
    new_count = len(spans)
    spans = pool.take({s["trace"] for s in spans}) + list(spans)
    by_id = {(s["trace"], s["span"]): s for s in spans}
    stats = {"spans": new_count, "mapped": 0, "ignored": 0, "unattributed": 0, "waiting": 0, "kinds": {}}
    samples: List[str] = []
    agents: Dict[str, Dict[str, Any]] = {}
    dropped: List[Dict[str, Any]] = []

    def owner(sp: Dict[str, Any], depth: int = 0) -> Optional[str]:
        own = _agent_name(sp)
        if own:
            return own
        pid = sp["parent"]
        while pid and depth < 40:
            hit = cache.get(sp["trace"], pid)
            if hit:
                return hit
            parent = by_id.get((sp["trace"], pid))
            if parent is None:
                break
            own = _agent_name(parent)
            if own:
                return own
            pid, depth = parent["parent"], depth + 1
        if agent_from_service:
            svc = sp["resource"].get("service.name")
            return _clean(svc, 80) if svc else None
        return None

    def bucket(name: str, sp: Dict[str, Any]) -> Dict[str, Any]:
        b = agents.setdefault(name, {"name": name, "framework": None, "events": [], "calls": 0, "errors": 0, "tokens_in": 0, "tokens_out": 0, "models": set(), "last": None})
        b["framework"] = b["framework"] or _framework(sp["scope"], sp["resource"])
        return b

    def at(sp: Dict[str, Any]) -> datetime:
        ns = sp["end_ns"] or sp["start_ns"]
        return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc) if ns else now

    for sp in spans:
        a, kind = sp["attrs"], _kind(sp["attrs"])
        stats["kinds"][kind] = stats["kinds"].get(kind, 0) + 1
        own = _agent_name(sp)
        agent = owner(sp)
        if agent:
            cache.put(sp["trace"], sp["span"], agent)
        if agent is None:
            dropped += pool.add(sp, clock)                                  # waits for its agent's span, which arrives after its children
            stats["waiting"] += 1
            continue
        if kind == "other" and "handoff" not in sp["name"].lower():
            stats["ignored"] += 1
            continue
        b = bucket(agent, sp)
        ts = at(sp)
        b["last"] = max(b["last"], ts) if b["last"] else ts
        dur = int((sp["end_ns"] - sp["start_ns"]) / 1e6) if sp["end_ns"] and sp["start_ns"] and sp["end_ns"] >= sp["start_ns"] else None
        base = {"at": ts.isoformat(), "trace_id": sp["trace"][:64] or None, "error": True if sp["error"] else None, "duration_ms": dur, "via": "otlp"}
        events: List[Dict[str, Any]] = []
        if kind == "tool":
            name = _tool_name(sp)
            if str(a.get("gen_ai.tool.type") or "").lower() == "datastore":
                events.append({**base, "type": "data_access", "name": name})
            elif name:
                events.append({**base, "type": "tool_call", "name": name, "write": True if WRITE_WORDS.search(name) else None})
        elif kind == "mcp":
            server = _clean(a.get("mcp.server.name") or a.get("server.address") or a.get("peer.service") or "server", 120)
            events.append({**base, "type": "mcp_connect", "name": f"mcp://{server}"})
            if str(a.get("mcp.method.name") or "") == "tools/call" and (a.get("gen_ai.tool.name") or a.get("tool.name")):
                tn = _tool_name(sp)
                events.append({**base, "type": "tool_call", "name": tn, "write": True if WRITE_WORDS.search(tn) else None})
        elif kind == "data":
            sql = str(a.get("db.query.text") or "")                        # only its first word is looked at, never kept
            op = str(a.get("db.operation.name") or a.get("db.operation") or "")
            events.append({**base, "type": "data_access", "name": _clean(f"{a['db.system']}:{a.get('db.namespace') or a.get('db.name')}", 120),
                           "write": True if (WRITE_SQL.match(sql) or WRITE_SQL.match(op)) else None})
        elif kind == "agent":
            parent = None
            pid = sp["parent"]
            for _ in range(40):
                if not pid:
                    break
                pa = _agent_name(by_id[(sp["trace"], pid)]) if (sp["trace"], pid) in by_id else cache.get(sp["trace"], pid)
                if pa:
                    parent = pa
                    break
                pid = by_id[(sp["trace"], pid)]["parent"] if (sp["trace"], pid) in by_id else ""
            if parent and own and parent != own:
                pb = bucket(parent, sp)
                pb["events"].append({**base, "type": "delegation", "name": own})
                stats["mapped"] += 1
        elif kind == "llm":
            b["calls"] += 1
            m = a.get("gen_ai.response.model") or a.get("gen_ai.request.model") or a.get("llm.model_name")
            if m:
                b["models"].add(_clean(m, 80))
            b["tokens_in"] += int(a.get("gen_ai.usage.input_tokens") or a.get("llm.token_count.prompt") or 0)
            b["tokens_out"] += int(a.get("gen_ai.usage.output_tokens") or a.get("llm.token_count.completion") or 0)
        else:                                                              # a handoff span of the OpenAI Agents SDK
            to = a.get("to_agent") or a.get("handoff.to_agent")
            if to:
                events.append({**base, "type": "delegation", "name": _clean(to, 80)})
        if sp["error"]:
            b["errors"] += 1
        if events:
            b["events"] += events
            stats["mapped"] += len(events)
        elif kind in ("llm", "agent"):
            stats["mapped"] += 1
        else:
            stats["ignored"] += 1
    for sp in dropped + pool.sweep(clock):                                  # waited long enough: counted, so the person setting this up can see what was not understood
        if _kind(sp["attrs"]) == "other" and "handoff" not in sp["name"].lower():
            stats["ignored"] += 1
            continue
        stats["unattributed"] += 1
        if sp["name"] and sp["name"] not in samples and len(samples) < 6:
            samples.append(sp["name"])
    for b in agents.values():
        b["models"] = sorted(b["models"])
    return {"agents": agents, "stats": stats, "unattributed_samples": samples}
