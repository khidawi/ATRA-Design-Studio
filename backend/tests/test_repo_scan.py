"""
Tests for repo_scan.py: finding LangGraph, OpenAI Agents SDK and CrewAI agents, and MCP configurations, in source that is only ever read.

    docker compose exec backend python -m tests.test_repo_scan
"""
import json
import sys

from repo_scan import scan_files

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:300] if detail and not ok else ""))
    if not ok:
        fails.append(name)


OPENAI = '''
import requests
from agents import Agent, Runner, function_tool, WebSearchTool, FileSearchTool

@function_tool
def lookup_order(order_id: str) -> dict:
    """Look up an order by id."""
    return requests.get(f"https://orders.internal/{order_id}").json()

@function_tool
def issue_refund(order_id: str, amount: float) -> str:
    """Refund an order."""
    requests.post("https://payments.internal/refunds", json={"order": order_id, "amount": amount})
    return "ok"

async def pii_redaction(ctx, agent, output):
    return output

notify = Agent(name="Notification agent", instructions="Send the customer a message.")

refund = Agent(
    name="Refund agent",
    handoff_description="Handles customer refund requests within policy",
    instructions="You resolve refund requests. Check the order first.",
    model="gpt-4.1",
    tools=[lookup_order, issue_refund, WebSearchTool(), FileSearchTool(vector_store_ids=["vs_policy"])],
    handoffs=[notify],
    output_guardrails=[pii_redaction],
)
'''

CREW_PY = '''
from crewai import Agent, Crew, Task
from crewai_tools import SerperDevTool

researcher = Agent(role="Senior research analyst", goal="Find supplier risk reports", backstory="x", tools=[SerperDevTool()], allow_delegation=True)
writer = Agent(role="Report writer", goal="Write the weekly brief", backstory="y", tools=[])
t1 = Task(description="research", agent=researcher, human_input=True)
crew = Crew(agents=[researcher, writer], tasks=[t1], memory=True)
'''

CREW_YAML_PY = '''
from crewai import Agent
from crewai.project import CrewBase, agent

@CrewBase
class Team:
    @agent
    def triager(self) -> Agent:
        return Agent(config=self.agents_config["triager"], verbose=True)
'''
AGENTS_YAML = "triager:\n  role: Ticket triager\n  goal: Route support tickets to the right queue\n  tools:\n    - read_ticket\norphan:\n  role: Unused\n  goal: Defined only in yaml\n"

LANGGRAPH = '''
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode, create_react_agent
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.types import interrupt
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
import smtplib

@tool
def search_kb(query: str) -> str:
    """Search the knowledge base."""
    return ""

@tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    smtplib.SMTP("mail").sendmail("a", to, body)
    return "sent"

client = MultiServerMCPClient({"orders": {"url": "https://example.test/mcp", "transport": "streamable_http"}})

def approve(state):
    interrupt("approve?")
    return state

builder = StateGraph(dict)
builder.add_node("agent", lambda s: s)
builder.add_node("tools", ToolNode([search_kb, send_email]))
builder.add_node("approve", approve)
claims_graph = builder.compile(checkpointer=PostgresSaver(None), interrupt_before=["tools"])

react = create_react_agent("openai:gpt-4.1", tools=[search_kb], checkpointer=None, name="faq-agent")
'''
LANGGRAPH_JSON = json.dumps({"graphs": {"claims_agent": "./src/claims.py:claims_graph"}, "env": ".env"})

MCP = json.dumps({"mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]},
    "github": {"command": "npx", "args": ["@modelcontextprotocol/server-github@1.2.3"], "env": {"GITHUB_TOKEN": "ghp_" + "a" * 36}},
    "remote": {"url": "https://example.test/mcp", "headers": {"Authorization": "${MCP_TOKEN}"}},
}})


def by_name(r, name):
    return next((a for a in r["agents"] if a["name"] == name), None)


files = {"app/refund.py": OPENAI, "crew/team.py": CREW_PY, "crew2/team.py": CREW_YAML_PY, "crew2/config/agents.yaml": AGENTS_YAML,
         "src/claims.py": LANGGRAPH, "langgraph.json": LANGGRAPH_JSON, "services/billing/.mcp.json": MCP, ".cursor/mcp.json": MCP.replace("filesystem", "dev-fs"),
         "tests/test_x.py": "from agents import Agent\nAgent(name='tester', instructions='x')\n", "app/broken.py": "def (:\n  agents"}
r = scan_files(files, "acme-platform")

ref = by_name(r, "Refund agent")
check("OpenAI Agents SDK agent found", ref is not None and ref["framework"] == "OpenAI Agents SDK" and ref["confidence"] == "high", [a["name"] for a in r["agents"]])
if ref:
    m = ref["manifest"]
    tools = {t["name"]: t["write"] for t in m["tools"]}
    check("function tools read from code: reads vs writes", tools.get("lookup_order") is False and tools.get("issue_refund") is True, tools)
    check("hosted tools recognised", tools.get("web_search") is False and "file_search" in tools)
    check("web search results are an untrusted input", any(i["name"] == "web-search-results" and i["untrusted"] for i in m["inputs"]))
    check("vector store becomes data", any(d.startswith("vector-store:vs_policy") for d in m["data"]))
    check("handoff becomes a delegation by agent name", m["delegates"] == ["Notification agent"], m["delegates"])
    check("output guardrail found", [g["name"] for g in m["guardrails"]] == ["pii_redaction"])
    check("goal from the handoff description, prompt not kept", "refund requests" in m["goal"] and "Check the order" not in json.dumps(m))
    check("write reason is explained", any("issue_refund" in x and "requests.post" in x for x in m["inferred"]))
check("a sibling agent in the same file is found too", by_name(r, "Notification agent") is not None)
check("scan_files reads every file it is given (the connector decides which files to give)", by_name(r, "tester") is not None)

cr = by_name(r, "Senior research analyst")
check("CrewAI agent found with delegation, approval and memory", cr is not None and cr["manifest"]["delegates"] == ["Report writer"] and cr["manifest"]["approvals"] and cr["manifest"]["memory"], cr and cr["manifest"])
check("CrewAI agent from agents.yaml config key", by_name(r, "triager") is not None and by_name(r, "triager")["manifest"]["goal"].startswith("Route support tickets"))
check("agents.yaml-only agent is reported with a warning", (by_name(r, "orphan") or {}).get("manifest", {}).get("warnings") is not None)

lg = by_name(r, "claims_agent")
check("LangGraph graph named from langgraph.json", lg is not None and lg["confidence"] == "high", [a["name"] for a in r["agents"]])
if lg:
    m = lg["manifest"]
    check("LangGraph tools from ToolNode, with write detection", {t["name"]: t["write"] for t in m["tools"]} == {"search_kb": False, "send_email": True}, m["tools"])
    check("LangGraph interrupt_before and interrupt() become approvals", len(m["approvals"]) >= 2, m["approvals"])
    check("LangGraph database checkpointer is long-term memory", m["memory"] and m["memory"][0]["long"] is True, m["memory"])
    check("LangGraph MCP client server named, address not kept", m["mcp"] == [{"name": "mcp://orders", "signed": False}] and "example.test" not in json.dumps(m))
check("create_react_agent found by its name", by_name(r, "faq-agent") is not None)

servers = {(s["path"], s["name"]): s for s in r["mcp_servers"] if s["transport"] != "client"}
fs = servers[("services/billing/.mcp.json", "filesystem")]
check("MCP server: unpinned package flagged", fs["pinned"] is False and fs["package"] == "@modelcontextprotocol/server-filesystem")
gh = servers[("services/billing/.mcp.json", "github")]
check("MCP server: pinned package, inline token found by key, value never kept", gh["pinned"] is True and gh["credentials_inline"] == ["env.GITHUB_TOKEN"] and "ghp_" not in json.dumps(r["mcp_servers"]), gh)
check("MCP server: an environment reference is not a leaked credential", servers[("services/billing/.mcp.json", "remote")]["credentials_inline"] == [])
check("developer-tool MCP config is told apart from an application one", servers[(".cursor/mcp.json", "dev-fs")]["scope"] == "developer-tool" and fs["scope"] == "application")
check("MCP notes tell what to fix", any("inline credential" in n for n in r["notes"]) and any("unpinned" in n for n in r["notes"]), r["notes"])
check("an application MCP config is offered as an agent, developer tooling is not", by_name(r, "acme-platform-mcp-client") is not None and len([a for a in r["agents"] if a["framework"] == "MCP configuration"]) == 1)
check("an unparseable Python file is noted, not fatal", any("broken.py" in n for n in r["notes"]))
check("no command line or address is stored anywhere in the result", "npx" not in json.dumps(r) and "example.test" not in json.dumps(r))
a1 = scan_files(files, "acme-platform")["agents"]
check("fingerprints are stable and change with the definition", [a["fingerprint"] for a in a1] == [a["fingerprint"] for a in r["agents"]] and len({a["fingerprint"] for a in a1}) == len(a1))
changed = scan_files({**files, "app/refund.py": OPENAI.replace("tools=[lookup_order, issue_refund,", "tools=[lookup_order,")}, "acme-platform")
check("a removed tool changes the fingerprint", by_name(changed, "Refund agent")["fingerprint"] != ref["fingerprint"])
dup = scan_files({"a/x.py": "from agents import Agent\nAgent(name='Same', instructions='x')\n", "b/y.py": "from agents import Agent\nAgent(name='Same', instructions='x')\n"})
check("two agents with one name are told apart by file", sorted(a["name"] for a in dup["agents"]) == ["Same-x", "Same-y"], [a["name"] for a in dup["agents"]])
check("a repository with nothing in it finds nothing", scan_files({"README.md": "x", "a.py": "print(1)"})["agents"] == [])

# tools defined in another module are followed: absolute and relative imports, a list constant, a decorated tool
TOOLS_PY = """from langchain_core.tools import tool
import requests

@tool
def cancel_order(order_id: str) -> str:
    requests.delete('https://x/' + order_id)
    return 'ok'

@tool
def find_order(q: str) -> str:
    return requests.get('https://x/' + q).text

TOOLS = [cancel_order, find_order]
"""
xfiles = {
    "src/shop/tools.py": TOOLS_PY,
    "src/shop/graph.py": "from langgraph.prebuilt import create_react_agent\nfrom .tools import TOOLS\n\nagent = create_react_agent('openai:gpt-4.1', tools=TOOLS)\n",
    "src/shop/other.py": "from langgraph.graph import StateGraph, END\nfrom shop.tools import cancel_order\nfrom langgraph.prebuilt import ToolNode\n\nb = StateGraph(dict)\nb.add_node('tools', ToolNode([cancel_order]))\ngraph = b.compile(name='Order desk')\n",
    "langgraph.json": json.dumps({"graphs": {"agent": "./src/shop/graph.py:agent"}}),
}
xr = scan_files(xfiles, "shop-platform")
xa = {a["name"]: a for a in xr["agents"]}
check("a tools list imported from another file is followed (relative import)", "shop-platform-agent" in xa and {t["name"]: t["write"] for t in xa["shop-platform-agent"]["manifest"]["tools"]} == {"cancel_order": True, "find_order": False}, {k: v["manifest"]["tools"] for k, v in xa.items()})
check("a tool imported by absolute path is followed too", "Order desk" in xa and [t["name"] for t in xa["Order desk"]["manifest"]["tools"]] == ["cancel_order"], list(xa))
check("compile(name=...) names the graph; a generic langgraph.json name gets the repository in front of it", "Order desk" in xa and "shop-platform-agent" in xa)

sys.exit(1 if fails else 0)
