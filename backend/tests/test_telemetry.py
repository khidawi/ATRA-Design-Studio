"""
Tests for telemetry discovery: telemetry_otlp.py (reading OTLP and mapping spans to runtime events) and telemetry.py (the endpoint, the
observed profiles and the design built from them).

    docker compose exec backend python -m tests.test_telemetry
"""
import gzip
import json
import sys
import time

from telemetry_otlp import MAX_SPANS, PendingPool, SpanCache, TelemetryError, decode, from_json, map_spans

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:500] if detail and not ok else ""))
    if not ok:
        fails.append(name)


NOW = int(time.time() * 1e9)
SECRET_PROMPT = "PATIENT-SSN-123-45-6789 prompt text"
SECRET_ARGS = "tool arguments with a password hunter2"


def attr(k, v):
    return {"key": k, "value": ({"stringValue": v} if isinstance(v, str) else {"boolValue": v} if isinstance(v, bool) else {"intValue": str(v)})}


def sp(trace, span, parent, name, attrs=None, scope="opentelemetry.instrumentation.openai_agents", status=0, dur_ms=50):
    return {"traceId": trace, "spanId": span, "parentSpanId": parent, "name": name, "kind": 1, "startTimeUnixNano": str(NOW), "endTimeUnixNano": str(NOW + dur_ms * 1_000_000),
            "attributes": [attr(k, v) for k, v in (attrs or {}).items()], "status": {"code": status}, "_scope": scope}


def req(spans, service="support-service"):
    by_scope = {}
    for s in spans:
        s = dict(s)
        by_scope.setdefault(s.pop("_scope", "opentelemetry.instrumentation.openai_agents"), []).append(s)
    return {"resourceSpans": [{"resource": {"attributes": [attr("service.name", service)]}, "scopeSpans": [{"scope": {"name": k}, "spans": v} for k, v in by_scope.items()]}]}


def mapped(spans, from_service=False, cache=None, service="support-service"):
    return map_spans(from_json(req(spans, service)), from_service, cache)


def events(r, agent):
    return [(e["type"], e["name"]) for e in r["agents"][agent]["events"]]


# ── GenAI semantic conventions
T = "a" * 32
r = mapped([
    sp(T, "1" * 16, "", "invoke_agent Refund agent", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "Refund agent"}),
    sp(T, "2" * 16, "1" * 16, "execute_tool lookup_order", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup_order", "gen_ai.tool.arguments": SECRET_ARGS}),
    sp(T, "3" * 16, "1" * 16, "execute_tool issue_refund", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "issue_refund"}, status=2),
    sp(T, "4" * 16, "1" * 16, "chat gpt-4.1", {"gen_ai.operation.name": "chat", "gen_ai.request.model": "gpt-4.1", "gen_ai.usage.input_tokens": 120, "gen_ai.usage.output_tokens": 30, "gen_ai.prompt": SECRET_PROMPT}),
])
a = r["agents"]["Refund agent"]
check("GenAI conventions: agent, tools, model and tokens", events(r, "Refund agent") == [("tool_call", "lookup_order"), ("tool_call", "issue_refund")] and a["models"] == ["gpt-4.1"] and a["tokens_in"] == 120 and a["tokens_out"] == 30, events(r, "Refund agent"))
check("a write is inferred from the tool's name, a read is left unmarked, errors are carried", [e.get("write") for e in a["events"]] == [None, True] and a["events"][1].get("error") is True and a["errors"] == 1)
check("the framework comes from the instrumentation scope", a["framework"] == "OpenAI Agents SDK")
check("prompts, tool arguments and results are never in the result", SECRET_PROMPT not in json.dumps(r, default=str) and SECRET_ARGS not in json.dumps(r, default=str) and "hunter2" not in json.dumps(r, default=str))
check("timings and trace ids are kept", a["events"][0]["duration_ms"] == 50 and a["events"][0]["trace_id"] == T)

# ── OpenInference
T2 = "b" * 32
r = mapped([
    sp(T2, "1" * 16, "", "Support agent", {"openinference.span.kind": "AGENT"}, scope="openinference.instrumentation.langchain"),
    sp(T2, "2" * 16, "1" * 16, "search_kb", {"openinference.span.kind": "TOOL", "tool.name": "search_kb", "input.value": SECRET_ARGS}, scope="openinference.instrumentation.langchain"),
    sp(T2, "3" * 16, "2" * 16, "ChatOpenAI", {"openinference.span.kind": "LLM", "llm.model_name": "gpt-4o", "llm.token_count.prompt": 10, "llm.token_count.completion": 5}, scope="openinference.instrumentation.langchain"),
])
check("OpenInference conventions: an AGENT span names the agent, a TOOL span a tool, LLM spans the model", events(r, "Support agent") == [("tool_call", "search_kb")] and r["agents"]["Support agent"]["models"] == ["gpt-4o"] and r["agents"]["Support agent"]["framework"] == "LangGraph", r["agents"].keys())

# ── Traceloop / OpenLLMetry
r = mapped([sp("c" * 32, "1" * 16, "", "triage.agent", {"traceloop.span.kind": "agent", "traceloop.entity.name": "triage"}, scope="opentelemetry.instrumentation.crewai"),
            sp("c" * 32, "2" * 16, "1" * 16, "send_email.tool", {"traceloop.span.kind": "tool", "traceloop.entity.name": "send_email"}, scope="opentelemetry.instrumentation.crewai")])
check("Traceloop conventions", events(r, "triage") == [("tool_call", "send_email")] and r["agents"]["triage"]["events"][0]["write"] is True and r["agents"]["triage"]["framework"] == "CrewAI")

# ── delegation, handoff, MCP, data
T3 = "d" * 32
r = mapped([
    sp(T3, "1" * 16, "", "invoke_agent Triage", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "Triage"}),
    sp(T3, "2" * 16, "1" * 16, "invoke_agent Billing", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "Billing"}),
    sp(T3, "3" * 16, "2" * 16, "tools/call", {"mcp.method.name": "tools/call", "mcp.server.name": "orders", "gen_ai.tool.name": "get_order", "gen_ai.tool.type": "extension"}),
    sp(T3, "4" * 16, "2" * 16, "SELECT ledger", {"db.system": "postgresql", "db.namespace": "ledger", "db.operation.name": "INSERT"}),
    sp(T3, "5" * 16, "1" * 16, "handoff", {"to_agent": "Billing"}),
])
check("an agent run inside another is a delegation by the parent", ("delegation", "Billing") in events(r, "Triage"), events(r, "Triage"))
check("MCP spans become a server and the tool called on it", events(r, "Billing")[:2] == [("mcp_connect", "mcp://orders"), ("tool_call", "get_order")], events(r, "Billing"))
check("a database span is a data access, with a write when the operation is one", ("data_access", "postgresql:ledger") in events(r, "Billing") and [e for e in r["agents"]["Billing"]["events"] if e["type"] == "data_access"][0]["write"] is True)
check("a handoff span is a delegation too", events(r, "Triage").count(("delegation", "Billing")) == 2)

# ── attribution
orphan = [sp("e" * 32, "1" * 16, "9" * 16, "execute_tool refund", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund"})]
r = mapped(orphan)
check("a span that cannot be placed creates nothing and is counted, with its name kept for the setup", r["agents"] == {} and r["stats"]["unattributed"] == 1 and r["unattributed_samples"] == ["execute_tool refund"])
r = mapped(orphan, from_service=True, service="payments-service")
check("with the service-name setting, it belongs to the agent named like its service", list(r["agents"]) == ["payments-service"] and events(r, "payments-service") == [("tool_call", "refund")])
cache = SpanCache()
mapped([sp("f" * 32, "1" * 16, "", "invoke_agent Late", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "Late"})], cache=cache)
r = mapped([sp("f" * 32, "2" * 16, "1" * 16, "execute_tool x", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "late_tool"})], cache=cache)
check("a tool span finds its agent from an earlier request", events(r, "Late") == [("tool_call", "late_tool")])
check("spans that are neither agent, tool, model, MCP nor data are ignored", mapped([sp("1" * 32, "1" * 16, "", "GET /health", {"http.method": "GET"})])["stats"]["ignored"] == 1)

# ── children arrive before their agent: a span is exported when it ends, and the agent's own span ends last
pool = PendingPool(ttl=60)
TC = "9" * 32
child = [sp(TC, "2" * 16, "3" * 16, "execute_tool refund", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund"})]
middle = [sp(TC, "3" * 16, "1" * 16, "RunnableSequence", {"langgraph.node": "tools"})]                                  # a chain span in between, itself not an agent
root = [sp(TC, "1" * 16, "", "invoke_agent Late agent", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "Late agent"})]
r1 = map_spans(from_json(req(child)), False, SpanCache(), pending=pool)
check("a tool span with no agent yet waits instead of being lost", r1["agents"] == {} and r1["stats"]["unattributed"] == 0 and len(pool.d) == 1)
r2 = map_spans(from_json(req(middle)), False, SpanCache(), pending=pool)
check("so does a span in between", r2["agents"] == {} and len(pool.d) == 2)
r3 = map_spans(from_json(req(root)), False, SpanCache(), pending=pool)
check("when the agent's span arrives, the tool call finds its agent through the waiting chain", events(r3, "Late agent") == [("tool_call", "refund")] and len(pool.d) == 0 and r3["stats"]["spans"] == 1, r3["stats"])
pool = PendingPool(ttl=60)
map_spans(from_json(req(child)), False, SpanCache(), pending=pool)
later = map_spans(from_json(req([sp("8" * 32, "1" * 16, "", "other trace", {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m"})])), False, SpanCache(), pending=pool)
check("spans of another trace do not claim it", len(pool.d) == 2 and later["stats"]["unattributed"] == 0)
expired = map_spans([], False, SpanCache(), now=__import__("datetime").datetime.now(__import__("datetime").timezone.utc) + __import__("datetime").timedelta(seconds=61), pending=pool)
check("a span that waited too long is dropped and counted, with its name kept", expired["stats"]["unattributed"] == 2 and "execute_tool refund" in expired["unattributed_samples"] and len(pool.d) == 0, expired["stats"])
small = PendingPool(ttl=60, cap=3)
for i in range(5):
    small.add({"trace": "t", "span": str(i), "parent": "", "name": f"s{i}", "attrs": {}}, 0)
check("the waiting room is bounded", len(small.d) == 3)

# ── reading the request
body = json.dumps(req([sp(T, "1" * 16, "", "invoke_agent X", {"gen_ai.agent.name": "X"})])).encode()
check("JSON is read", len(decode(body, "application/json")) == 1)
check("gzip is read", len(decode(gzip.compress(body), "application/json", "gzip")) == 1)
for what, args in [("not JSON", (b"{nope", "application/json")), ("a wrong type", (body, "text/plain")), ("bad gzip", (b"xx", "application/json", "gzip")), ("an unknown encoding", (body, "application/json", "br"))]:
    try:
        decode(*args)
        check(f"refused: {what}", False)
    except TelemetryError:
        check(f"refused: {what}", True)
bomb = gzip.compress(b" " * (20 * 1024 * 1024))
try:
    decode(bomb, "application/json", "gzip")
    check("a gzip bomb is refused", False)
except TelemetryError:
    check("a gzip bomb is refused", True)
many = {"resourceSpans": [{"scopeSpans": [{"spans": [{"traceId": "1", "spanId": str(i)} for i in range(MAX_SPANS + 1)]}]}]}
try:
    from_json(many)
    check("too many spans in one request are refused", False)
except TelemetryError:
    check("too many spans in one request are refused", True)

# protobuf
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from google.protobuf.json_format import ParseDict


def proto_bytes(spans, service="svc"):
    msg = ExportTraceServiceRequest()
    d = req(spans, service)
    for rs in d["resourceSpans"]:
        for ss in rs["scopeSpans"]:
            for s in ss["spans"]:
                for k in ("traceId", "spanId", "parentSpanId"):
                    s[k] = __import__("base64").b64encode(bytes.fromhex(s[k])).decode() if s[k] else ""
    ParseDict(d, msg)
    return msg.SerializeToString()


pb = proto_bytes([sp(T, "1" * 16, "", "invoke_agent Refund agent", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "Refund agent"}),
                  sp(T, "2" * 16, "1" * 16, "execute_tool lookup_order", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup_order"})])
r = map_spans(decode(pb, "application/x-protobuf"), False)
check("protobuf is read, with the ids as hex so parents are found", events(r, "Refund agent") == [("tool_call", "lookup_order")], r["stats"])
try:
    decode(b"\xff\xff\xff", "application/x-protobuf")
    check("garbage protobuf is refused", False)
except TelemetryError:
    check("garbage protobuf is refused", True)

# ── the endpoint
import runtime
from fastapi.testclient import TestClient
from db.models import Agent, Design, DriftItem, Finding, RuntimeEvent, TelemetryIngest, TelemetrySettings
from db.session import SessionLocal
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup
from tests.test_runtime import KEY, keyed, ratified, wipe

NAMES = ["zz-test-tele-agent", "zz-test-tele-helper", KEY]


import telemetry
telemetry._PENDING.ttl = 0                                   # in these tests a span that cannot be placed is counted at once, not after the wait


def tidy():
    wipe()
    cleanup(*NAMES)
    with SessionLocal() as s:
        for m in (TelemetryIngest, TelemetrySettings):
            s.query(m).delete()
        for a in s.query(Agent).filter(Agent.agent_key.like("zz-test%")).all():
            s.delete(a)
        s.commit()


def trace(agent, tools, helper=None, extra=None):
    t = "ab" * 16
    spans = [sp(t, "1" * 16, "", f"invoke_agent {agent}", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": agent})]
    for i, tool in enumerate(tools):
        spans.append(sp(t, f"{i + 2:016d}", "1" * 16, f"execute_tool {tool}", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool}))
    spans.append(sp(t, "9" * 16, "1" * 16, "chat gpt-4.1", {"gen_ai.operation.name": "chat", "gen_ai.request.model": "gpt-4.1", "gen_ai.usage.input_tokens": 100, "gen_ai.usage.output_tokens": 20}))
    return req(spans + (extra or []))


try:
    with authed_client("admin", "Compliance lead") as admin:
        tidy()
        k = admin.post("/api/keys", json={"name": "zz-test-otel", "role": "collector"}).json()
        c = keyed(k["key"])
        post = lambda cl, d, **kw: cl.post("/api/telemetry/v1/traces", content=json.dumps(d), headers={"content-type": "application/json", **kw.get("headers", {})})
        check("no key, no entry", TestClient(app).post("/api/telemetry/v1/traces", content=b"{}", headers={"content-type": "application/json"}).status_code == 401 and keyed("astra_deadbeef_x").post("/api/telemetry/v1/traces", content=b"{}").status_code == 401)
        check("a collector key can send telemetry and read nothing else", c.get("/api/telemetry/status").status_code == 403 and c.get("/api/agents").status_code == 403)
        aud_key = admin.post("/api/keys", json={"name": "zz-test-otel-aud", "role": "auditor"}).json()
        check("an auditor key cannot send telemetry", post(keyed(aud_key["key"]), trace("zz-test-tele-agent", ["a"])).status_code == 403)

        r = post(c, trace("zz-test-tele-agent", ["lookup_order", "issue_refund"], extra=[]))
        check("OTLP JSON is accepted and answered in kind", r.status_code == 200 and r.json() == {}, r.text)
        ag = next(x for x in admin.get("/api/agents").json() if x["agent_key"] == "zz-test-tele-agent")
        check("the agent was discovered: unowned, from telemetry, framework from the scope", ag["origin"] == "DISCOVERED" and ag["status"] == "UNOWNED" and ag["framework"] == "OpenAI Agents SDK", ag)
        with SessionLocal() as s:
            evs = s.query(RuntimeEvent).filter(RuntimeEvent.agent_key == "zz-test-tele-agent").all()
            check("events were recorded, marked as OTLP, with no content", {e.name for e in evs if e.type == "tool_call"} == {"lookup_order", "issue_refund"} and all(e.attrs.get("via") == "otlp" for e in evs) and not any("prompt" in json.dumps(e.attrs) for e in evs))
            hb = [e for e in evs if e.type == "heartbeat"][0]
            check("a heartbeat carries the model and token counts", hb.attrs.get("model") == "gpt-4.1" and hb.attrs.get("tokens_in") == 100 and hb.attrs.get("calls") == 1, hb.attrs)
        gz = c.post("/api/telemetry/v1/traces", content=gzip.compress(json.dumps(trace("zz-test-tele-agent", ["lookup_order"])).encode()), headers={"content-type": "application/json", "content-encoding": "gzip"})
        check("gzip is accepted", gz.status_code == 200)
        pbr = c.post("/api/telemetry/v1/traces", content=proto_bytes([sp("cd" * 16, "1" * 16, "", "invoke_agent zz-test-tele-helper", {"gen_ai.agent.name": "zz-test-tele-helper"}),
                                                                       sp("cd" * 16, "2" * 16, "1" * 16, "execute_tool read_x", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "read_x"})]), headers={"content-type": "application/x-protobuf"})
        check("protobuf is accepted and answered as protobuf", pbr.status_code == 200 and pbr.headers["content-type"].startswith("application/x-protobuf"), pbr.headers)
        check("a bad body is a 400 with a reason, not a crash", post(c, {"resourceSpans": "x"}).status_code == 400 and post(c, {"resourceSpans": [{"scopeSpans": [{"spans": [{"startTimeUnixNano": "abc"}]}]}]}).status_code == 400 and c.post("/api/telemetry/v1/traces", content=b"{nope", headers={"content-type": "application/json"}).status_code == 400)
        check("a too large declared body is refused", c.post("/api/telemetry/v1/traces", content=b"{}", headers={"content-type": "application/json", "content-length": str(99 * 1024 * 1024)}).status_code in (413, 400))

        st = admin.get("/api/telemetry/status").json()
        check("status: what arrived, and nothing unattributed yet", st["requests_24h"] >= 3 and st["spans_24h"] > 0 and st["events_24h"] > 0 and st["unattributed_24h"] == 0 and st["last_received_at"], st)
        post(c, req([sp("ee" * 16, "1" * 16, "9" * 16, "execute_tool floating", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "floating"})]))
        st = admin.get("/api/telemetry/status").json()
        check("status: spans that could not be placed are counted with their names", st["unattributed_24h"] == 1 and "execute_tool floating" in st["samples"], st["samples"])
        check("settings: use the service name", admin.put("/api/telemetry/settings", json={"agent_from_service": True, "discover": True}).json()["agent_from_service"] is True)
        post(c, req([sp("ff" * 16, "1" * 16, "9" * 16, "execute_tool floating", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "floating"})], service="zz-test-tele-svc"))
        check("with it on, the span belongs to the service's agent", any(x["agent_key"] == "zz-test-tele-svc" for x in admin.get("/api/agents").json()))
        admin.put("/api/telemetry/settings", json={"agent_from_service": False, "discover": False})
        before = len(admin.get("/api/agents").json())
        post(c, trace("zz-test-tele-brandnew", ["x"]))
        check("with discovery off an unknown agent is not registered, and the status says so", len(admin.get("/api/agents").json()) == before and admin.get("/api/telemetry/status").json()["unknown_agents_24h"] >= 1)
        admin.put("/api/telemetry/settings", json={"agent_from_service": False, "discover": True})

        # the real order of arrival: the tool call's request comes first, the agent run's after it
        telemetry._PENDING.ttl = 60
        t9 = "99" * 16
        post(c, req([sp(t9, "2" * 16, "1" * 16, "execute_tool late_tool", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "late_tool"})]))
        with SessionLocal() as s:
            early = s.query(RuntimeEvent).filter(RuntimeEvent.name == "late_tool").count()
        post(c, req([sp(t9, "1" * 16, "", "invoke_agent zz-test-tele-agent", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "zz-test-tele-agent"})]))
        with SessionLocal() as s:
            late = s.query(RuntimeEvent).filter(RuntimeEvent.name == "late_tool", RuntimeEvent.agent_key == "zz-test-tele-agent").count()
        telemetry._PENDING.ttl = 0
        check("through the endpoint: a tool call sent before its agent's span is attributed once that arrives", early == 0 and late == 1, (early, late))

        # what it was seen doing, and a design from that
        prof = {p["agent_key"]: p for p in admin.get("/api/telemetry/agents?days=7").json()}
        pa = prof["zz-test-tele-agent"]
        check("observed profile: tools with counts, the model and tokens", {t["name"]: t["count"] for t in pa["tools"]} == {"lookup_order": 2, "issue_refund": 1, "late_tool": 1} and pa["models"] == ["gpt-4.1"] and pa["tokens_in"] > 0 and any(t["write"] for t in pa["tools"] if t["name"] == "issue_refund"), pa["tools"])
        d = admin.post("/api/telemetry/agents/zz-test-tele-agent/design", json={"days": 7})
        check("a draft design is built from what it did", d.status_code == 200 and d.json()["outcome"] == "created", d.text)
        with SessionLocal() as s:
            dd = s.query(Design).filter(Design.name == "zz-test-tele-agent").one()
            tools = {n["name"]: n["p"]["write"] for n in dd.document["nodes"] if n["type"] == "tool"}
            check("the design holds the observed tools, says where it came from, and warns that the evidence is thin", tools == {"lookup_order": False, "issue_refund": True, "late_tool": False} and dd.document["provenance"]["source"] == "telemetry" and "not verified" in dd.document["provenance"]["label"], tools)
        post(c, trace("zz-test-tele-agent", ["new_tool"]))
        d2 = admin.post("/api/telemetry/agents/zz-test-tele-agent/design", json={"days": 7}).json()
        with SessionLocal() as s:
            dd = s.query(Design).filter(Design.name == "zz-test-tele-agent").one()
            names = {n["name"] for n in dd.document["nodes"] if n["type"] == "tool"}
        check("a second run merges what is new into the design that is there", d2["merged"] is True and names == {"lookup_order", "issue_refund", "late_tool", "new_tool"}, (d2, names))
        check("no telemetry, no design", admin.post("/api/telemetry/agents/zz-test-nothing/design", json={}).status_code == 404)

        # an agent with a contract is checked against it
        tidy()
        admin.post("/api/keys", json={"name": "zz-test-otel", "role": "collector"})
        k = admin.post("/api/keys", json={"name": "zz-test-otel2", "role": "collector"}).json()
        c = keyed(k["key"])
        ratified(admin)
        post(c, trace(KEY, ["ehr.records.read"]))
        check("a tool the contract allows is conforming", admin.get("/api/findings").json() == [] and admin.get("/api/drift").json() == [])
        post(c, trace(KEY, ["shell.exec"]))
        fs = admin.get("/api/findings").json()
        check("a tool the contract does not allow becomes a finding", len(fs) == 1 and "shell.exec" in json.dumps(fs[0]), fs)
        dr = [x for x in admin.get("/api/drift").json() if x.get("source") == "RUNTIME"]
        check("and a runtime drift item for compliance to decide", len(dr) == 1, admin.get("/api/drift").json())
        check("an agent with an active contract is not redesigned from telemetry", admin.post(f"/api/telemetry/agents/{KEY}/design", json={}).status_code == 409)

        # rate limiting
        saved = runtime.RATE_PER_MINUTE
        runtime.RATE_PER_MINUTE = 3
        runtime._window.clear()
        r = post(c, trace(KEY, ["ehr.records.read", "ehr.records.read", "ehr.records.read", "ehr.records.read"]))
        runtime.RATE_PER_MINUTE = saved
        runtime._window.clear()
        check("too many events: 429 with Retry-After, which exporters honour", r.status_code == 429 and int(r.headers["retry-after"]) >= 1, (r.status_code, r.headers))
finally:
    tidy()
    with SessionLocal() as s:
        from db.models import ApiKey
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()

sys.exit(1 if fails else 0)
