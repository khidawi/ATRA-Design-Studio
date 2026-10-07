"""
astra_runtime: report what your AI agent does while it runs, so ASTRA can compare it with the agent's ratified contract in real time.

    import astra_runtime as astra
    astra.init(url="https://astra.example.com", api_key=os.environ["ASTRA_KEY"], agent="refund-agent")

    astra.tool_call("stripe.refunds.create", write=True)        # something happened
    @astra.tool("lookup_order")                                  # or report every call of a function
    def lookup_order(order_id): ...

    from astra_runtime.adapters.openai_agents import install     # or hook a framework
    install()

See README.md for the adapters (OpenAI Agents SDK, LangChain/LangGraph), enforcement and the cost of each choice.
"""
from typing import Any, Callable, Dict, Optional

from .client import AstraBlocked, Client, __version__

_default: Optional[Client] = None
_warned = False


def init(url: Optional[str] = None, api_key: Optional[str] = None, agent: Optional[str] = None, **options: Any) -> Client:
    """Create the process-wide client (see Client for the options). Calling it again replaces the previous one."""
    global _default
    if _default is not None:
        _default.close()
    _default = Client(url, api_key, agent, **options)
    return _default


def client() -> Optional[Client]:
    return _default


def _use() -> Optional[Client]:
    global _warned
    if _default is None and not _warned:
        _warned = True
        import logging
        logging.getLogger("astra_runtime").warning("astra_runtime.init() has not been called, so nothing is reported")
    return _default


def tool_call(name: str, **kw: Any) -> None:
    c = _use()
    if c:
        c.tool_call(name, **kw)


def delegation(to_agent: str, **kw: Any) -> None:
    c = _use()
    if c:
        c.delegation(to_agent, **kw)


def mcp_connect(server: str, **kw: Any) -> None:
    c = _use()
    if c:
        c.mcp_connect(server, **kw)


def data_access(store: str, **kw: Any) -> None:
    c = _use()
    if c:
        c.data_access(store, **kw)


def memory_write(scope: str = "session", **kw: Any) -> None:
    c = _use()
    if c:
        c.memory_write(scope, **kw)


def heartbeat(**kw: Any) -> None:
    c = _use()
    if c:
        c.heartbeat(**kw)


def tool(name: Optional[str] = None, **kw: Any) -> Callable:
    def deco(fn: Callable) -> Callable:
        c = _use()
        return c.tool(name, **kw)(fn) if c else fn
    return deco


def flush(timeout: float = 5.0) -> bool:
    return _default.flush(timeout) if _default else True


def check() -> Dict[str, Any]:
    return _default.check() if _default else {"ok": False, "error": "init() has not been called"}


__all__ = ["init", "client", "Client", "AstraBlocked", "tool_call", "delegation", "mcp_connect", "data_access", "memory_write", "heartbeat", "tool", "flush", "check", "__version__"]
