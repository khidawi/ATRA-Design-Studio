# astra-runtime

Report what an AI agent does while it runs to an ASTRA platform, so every tool call, handoff, MCP connection and data access is compared
with the agent's ratified contract as it happens. Anything outside the contract becomes a finding and a runtime drift item for compliance.

Standard library only. Python 3.8+.

```bash
pip install ./sdk/python          # from the repository; add [openai-agents] or [langchain] for those adapters' dependencies
```

## 1. Get a key

An administrator opens **Users → API keys** and creates a key with the **Collector** role (one per agent or team). A collector can
only send events and read the contract summary of the agent it reports for: it cannot read anything else and cannot sign anything off.
The key is shown once.

## 2. Report

```python
import os
import astra_runtime as astra

astra.init(url="https://astra.example.com", api_key=os.environ["ASTRA_KEY"], agent="refund-agent")
print(astra.check())                       # {'ok': True, 'key': 'API key: ...', 'role': 'collector'}

astra.tool_call("stripe.refunds.create", write=True)
astra.delegation("notification-agent")
astra.mcp_connect("mcp://orders", signed=True)
astra.data_access("order-store")
astra.memory_write("long_term")

@astra.tool("lookup_order")               # report every call of a function (sync or async)
def lookup_order(order_id): ...
```

Configuration can come from the environment: `ASTRA_URL`, `ASTRA_KEY`, `ASTRA_AGENT`.
The first time an agent the platform has never heard of reports, it is registered **unowned, origin "discovered"** (it counts against
ASI10 until someone owns it). Pass `discover=False` to turn that off.

### Frameworks

```python
# OpenAI Agents SDK: tool calls, handoffs and MCP connections from its own tracing (tested against openai-agents 0.23)
from astra_runtime.adapters.openai_agents import install
install()                                  # add_trace_processor; install(replace=True) sends traces only to ASTRA

# LangChain / LangGraph: tool calls and retrievers through callbacks
from astra_runtime.adapters.langchain import handler
graph.invoke(inputs, config={"callbacks": [handler()]})
```

For an agent framework with no adapter, call `astra.tool_call(...)` where it runs a tool, or use the `@astra.tool` decorator. A process that
hosts several agents can report for each with `with client.as_agent("name"):`.

## What it sends, and what it never does

* **Names only.** The kind of event and one name (a tool, a server, an agent, a store), a timestamp and, where you give it, `write`/`signed`/`scope`.
  Never arguments, results, prompts or data.
* **Never raises into your agent and never blocks it.** Events go on a bounded in-memory queue (5,000; the oldest are dropped and counted in
  `client.dropped`) and a background thread sends batches of up to 50, retrying with back-off, honouring `Retry-After`. A refused key
  disables reporting with one warning. A heartbeat every 30 s keeps a quiet agent showing as live.
* **No dependencies.** `urllib` and `threading`, nothing to conflict with your agent's own packages.
* **Flushes at exit.** `astra.flush()` forces it; `client.close()` flushes and stops the thread.

## Enforcement (optional, off by default)

```python
astra.init(url=..., api_key=..., agent="refund-agent", enforce=True)

@astra.tool("shell.exec")
def shell(cmd): ...                        # raises astra_runtime.AstraBlocked if the active contract does not allow it
```

An enforcing client fetches a summary of what the contract allows (cached 60 s) and refuses a decorated tool call before it runs. If the agent has
no contract, or the platform cannot be reached, it **allows** (fail open), so an outage never stops your agent; pass `strict=True` to refuse instead.
Enforcement only covers calls you wrap; the OpenAI Agents SDK adapter observes and cannot stop a call already in progress, so wrap the tool function too.

## What you see in ASTRA

**Live runtime**: which agents are live, silent or never seen; events and divergences in the last hour; a live feed with a verdict on each event;
and, for agents with a contract, the tools the contract allows but that were never used in 30 days (a least-privilege hint).
A divergence is a **finding** (the same open finding is not raised again within ten minutes), and a new capability (a tool, MCP server, delegation, data
store or long-term memory) is also a **runtime drift item**: the ratified design plus what was observed, for compliance to approve (a new contract that includes
it) or decline (it keeps raising findings; a declined observation never opens another item).

## Not included yet

Other languages (a TypeScript and a Java SDK would follow the same wire format: `POST /api/runtime/events`), an OpenTelemetry exporter, blocking at the
network level, and an adapter for CrewAI. The wire format is plain JSON, so any language can report today:

```bash
curl -X POST "$ASTRA/api/runtime/events" -H "Authorization: Bearer $ASTRA_KEY" -H "Content-Type: application/json" \
  -d '{"agent": "refund-agent", "events": [{"type": "tool_call", "name": "stripe.refunds.create", "write": true}]}'
```

Event types: `tool_call`, `delegation`, `mcp_connect`, `memory_write`, `data_access`, `heartbeat`; up to 200 events per call, 1,200 events a minute per key.

## Tests

`python -m unittest discover -s tests` runs the SDK against a local server that behaves like the platform (delivery, retry order, 401/429 handling,
bounded queue, enforcement, async decorator, multi-agent batching, the OpenAI adapter's span handling).
