"""
LangChain / LangGraph adapter: reports tool calls (and, when it can tell, retriever access) through LangChain's callback system.

    from astra_runtime.adapters.langchain import handler
    graph.invoke(inputs, config={"callbacks": [handler()]})

Only tool names are reported, never inputs or outputs. LangChain is imported when handler() is called, so this module costs nothing if you
do not use it. Delegation between agents in a graph has no single callback in LangChain, so report it yourself with client.delegation(...).
"""
from typing import Any, Optional

from .. import client as _client_mod
from .openai_agents import guess_write


def handler(client: Optional[_client_mod.Client] = None, write_tools: Optional[set] = None, read_tools: Optional[set] = None) -> Any:
    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError as exc:
        raise ImportError("langchain-core is not installed (pip install langchain-core)") from exc
    writes, reads = set(write_tools or ()), set(read_tools or ())

    class AstraCallbackHandler(BaseCallbackHandler):
        raise_error = False                              # a failure here must never stop the chain

        def _c(self) -> Optional[_client_mod.Client]:
            if client is not None:
                return client
            import astra_runtime
            return astra_runtime.client()

        def on_tool_start(self, serialized: Any, input_str: str, **kwargs: Any) -> None:
            c = self._c()
            name = (serialized or {}).get("name") or kwargs.get("name")
            if c is None or not name:
                return
            write = True if name in writes else (False if name in reads else guess_write(str(name)))
            c.tool_call(str(name), write=write)

        def on_retriever_start(self, serialized: Any, query: str, **kwargs: Any) -> None:
            c = self._c()
            name = (serialized or {}).get("name") or kwargs.get("name")
            if c is not None and name:
                c.data_access(str(name))

    return AstraCallbackHandler()
