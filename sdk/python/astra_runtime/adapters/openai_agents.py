"""
OpenAI Agents SDK adapter: reports an agent's tool calls, handoffs and MCP connections from the SDK's own tracing.

    from astra_runtime.adapters.openai_agents import install
    install()            # after astra_runtime.init(...)

The Agents SDK emits a span for every function tool call, handoff and MCP tool listing. This processor turns them into ASTRA events, with the
agent that did it taken from the enclosing agent span. Arguments and results are never read. It adds a trace processor next to the SDK's
own, so existing tracing (including OpenAI's) keeps working; to send traces only to ASTRA use install(replace=True).

Tracing observes; it cannot stop a call that is already happening. To refuse calls the contract does not allow, wrap the tool function with
the client's @tool decorator on an enforcing client.
"""
import re
from typing import Any, Dict, Optional

from .. import client as _client_mod

_WRITE = re.compile(r"(create|write|send|delete|remove|update|post|put|patch|insert|execute|exec|run|transfer|pay|refund|charge|deploy|commit|publish|upload|drop|kill|modify|set|email)", re.I)
_READ = re.compile(r"(read|get|list|search|query|fetch|view|find|lookup|retrieve)", re.I)


def guess_write(name: str) -> Optional[bool]:
    """A tool's name says little; this only reports a guess when it is clear, and None when it is not (the platform then treats it as read)."""
    if _WRITE.search(name):
        return True
    return False if _READ.search(name) else None


class AstraTracingProcessor:
    """Implements the Agents SDK's TracingProcessor interface by duck typing, so importing this module does not require the SDK."""

    def __init__(self, client: Optional[_client_mod.Client] = None, write_tools: Optional[set] = None, read_tools: Optional[set] = None) -> None:
        self.client = client
        self.write_tools, self.read_tools = set(write_tools or ()), set(read_tools or ())
        self._parent: Dict[str, Optional[str]] = {}    # span id -> parent span id
        self._agent: Dict[str, str] = {}               # span id -> agent name, for the spans that are agents

    def _c(self) -> Optional[_client_mod.Client]:
        if self.client is not None:
            return self.client
        import astra_runtime
        return astra_runtime.client()

    def _agent_for(self, span_id: Optional[str]) -> Optional[str]:
        """The nearest agent span above this one."""
        for _ in range(30):
            if not span_id:
                return None
            if span_id in self._agent:
                return self._agent[span_id]
            span_id = self._parent.get(span_id)
        return None

    def on_trace_start(self, trace: Any) -> None:
        pass

    def on_trace_end(self, trace: Any) -> None:
        pass

    def on_span_start(self, span: Any) -> None:
        sid = getattr(span, "span_id", None)
        if sid:
            self._parent[sid] = getattr(span, "parent_id", None)
        data = getattr(span, "span_data", None)
        if sid and getattr(data, "type", None) == "agent" and getattr(data, "name", None):
            self._agent[sid] = str(data.name)

    def on_span_end(self, span: Any) -> None:
        c = self._c()
        data = getattr(span, "span_data", None)
        if c is None or data is None:
            return
        sid, kind = getattr(span, "span_id", None), getattr(data, "type", None)
        try:
            agent = self._agent_for(getattr(span, "parent_id", None))
            if kind == "function" and getattr(data, "name", None):
                name = str(data.name)
                write = True if name in self.write_tools else (False if name in self.read_tools else guess_write(name))
                c.tool_call(name, write=write, agent=agent)
            elif kind == "handoff" and getattr(data, "to_agent", None):
                c.delegation(str(data.to_agent), agent=str(getattr(data, "from_agent", None) or agent or "") or None)
            elif kind == "mcp_tools" and getattr(data, "server", None):
                c.mcp_connect(f"mcp://{data.server}", signed=None, agent=agent)
            elif kind == "agent" and sid:
                self._agent.pop(sid, None)
                self._parent.pop(sid, None)
        except Exception:                                # reporting must never break the agent
            pass

    def shutdown(self) -> None:
        c = self._c()
        if c:
            c.flush(2.0)

    def force_flush(self) -> None:
        c = self._c()
        if c:
            c.flush(2.0)


def install(client: Optional[_client_mod.Client] = None, *, replace: bool = False, **options: Any) -> AstraTracingProcessor:
    """Register the processor with the Agents SDK. Raises ImportError with a clear message if the SDK is not installed."""
    try:
        from agents import add_trace_processor, set_trace_processors
    except ImportError as exc:
        raise ImportError("The OpenAI Agents SDK is not installed (pip install openai-agents)") from exc
    proc = AstraTracingProcessor(client, **options)
    if replace:
        set_trace_processors([proc])
    else:
        add_trace_processor(proc)
    return proc
