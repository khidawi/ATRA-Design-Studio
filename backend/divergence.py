"""
Findings: checking an observed event against an agent's contract (Task 7c). Pure functions, no database.

A collector (or the simulator, which only produces events) reports something the agent did. The check compares it with
what the active contract allows (agent_contract.view) and returns a finding if it diverges, or nothing if it conforms.
The checks are deterministic string comparisons against the contract: no model is involved.

Event types:
    tool_call     {name, write?}     a tool was called
    delegation    {name}             the agent handed work to another agent
    mcp_connect   {name, signed?}    the agent connected to an MCP server
    memory_write  {scope}            the agent wrote to memory ("long_term" or "session")
    data_access   {name}             the agent read or wrote a data store

Severities are judgement values: a write-capable tool outside the contract is High; the rest are Medium, and a
long-term memory write the contract does not allow is Low.
"""
import hashlib
import json
from typing import Any, Dict, List, Optional

EVENT_TYPES = ("tool_call", "delegation", "mcp_connect", "memory_write", "data_access")

CLASSES = {
    "tool_call": ("DVG-TOOL", "tools", "ASI02 Tool misuse and exploitation"),
    "delegation": ("DVG-DEL", "delegates_to", "ASI07 Insecure inter-agent communication"),
    "mcp_connect": ("DVG-SUP", "mcp_servers", "ASI04 Agentic supply chain vulnerabilities"),
    "memory_write": ("DVG-MEM", "memory", "ASI06 Memory and context poisoning"),
    "data_access": ("DVG-DATA", "data", "ASI03 Identity and privilege abuse"),
}


def evidence_hash(agent: str, contract_id: str, event: Dict[str, Any]) -> str:
    canonical = json.dumps({"agent": agent, "contract": contract_id, "event": event}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def check_event(view: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The divergence an event represents against the contract view, or None if it conforms."""
    kind, name = event.get("type"), str(event.get("name", "")).strip()
    tools = {t["name"] for t in view["tools"]}
    out: Dict[str, Any]
    if kind == "tool_call":
        if name in tools:
            return None
        write = bool(event.get("write"))
        out = dict(severity="High" if write else "Medium", title=f"Called a tool the contract does not list: {name}",
                   observed=f"{name} ({'write' if write else 'read'})", permitted="tools: " + (", ".join(sorted(tools)) or "none"))
    elif kind == "delegation":
        if name in view["delegates_to"]:
            return None
        out = dict(severity="Medium", title=f"Delegated to {name} without a declared delegation",
                   observed=f"handoff to {name}", permitted="delegates_to: " + (", ".join(view["delegates_to"]) or "none"))
    elif kind == "mcp_connect":
        declared = {m["name"]: m for m in view["mcp_servers"]}
        if name in declared and (declared[name]["signed"] is False or event.get("signed", True)):
            return None
        why = "is not in the contract" if name not in declared else "has no valid signature"
        out = dict(severity="Medium", title=f"Connected to an MCP server that {why}: {name}",
                   observed=f"{name} ({'signed' if event.get('signed', True) else 'unsigned'})",
                   permitted="mcp_servers: " + (", ".join(f"{m['name']} ({'signed' if m['signed'] else 'unsigned'})" for m in view["mcp_servers"]) or "none"))
    elif kind == "memory_write":
        scope = str(event.get("scope", "session"))
        if scope != "long_term" or any(m["long_term"] for m in view["memory"]):
            return None
        out = dict(severity="Low", title="Wrote to long-term memory, which the contract does not allow",
                   observed="memory.write scope=long_term", permitted="memory: " + (", ".join(m["name"] + " (session)" for m in view["memory"]) or "none"))
    elif kind == "data_access":
        if name in view["data"]:
            return None
        out = dict(severity="Medium", title=f"Accessed a data store the contract does not list: {name}",
                   observed=name, permitted="data: " + (", ".join(view["data"]) or "none"))
    else:
        raise ValueError(f"Unknown event type {kind!r}; expected one of {', '.join(EVENT_TYPES)}.")
    code, element, threat = CLASSES[kind]
    out.update(class_code=code, element=element, threat=threat)
    return out


def draft_test_spec(agent: str, version: str, finding: Dict[str, Any], event: Dict[str, Any]) -> str:
    """A regression check drafted from a finding: the same event must be refused or flagged under the contract."""
    lines = [f"# Drafted from {finding['key']} against {agent} contract v{version}",
             f"test: {finding['class_code']} must not recur",
             f"agent: {agent}", "given:", f"  contract_version: {version}", "when:", f"  event: {json.dumps(event, sort_keys=True)}",
             "expect:", f"  finding_class: {finding['class_code']}", f"  threat: {finding['threat'].split(' ')[0]}",
             "note: runs against recorded traces; it passes while the contract keeps refusing this behaviour."]
    return "\n".join(lines) + "\n"


# ── Simulator: it produces events only; the checks above decide whether anything is a finding ──────────────────────

SCENARIOS = [
    ("tool_outside", "A tool call outside the contract", "tool_call"),
    ("write_tool_outside", "A write tool call outside the contract", "tool_call"),
    ("delegation_outside", "A delegation outside the contract", "delegation"),
    ("unsigned_mcp", "Connecting to an unsigned MCP server", "mcp_connect"),
    ("memory_long_term", "A long-term memory write", "memory_write"),
    ("data_outside", "Reading a data store outside the contract", "data_access"),
    ("conforming_call", "A tool call the contract allows (no finding expected)", "tool_call"),
]


def scenario_event(scenario: str, view: Dict[str, Any]) -> Dict[str, Any]:
    if scenario == "tool_outside":
        return {"type": "tool_call", "name": "shell.exec", "write": False}
    if scenario == "write_tool_outside":
        return {"type": "tool_call", "name": "payments.transfer.create", "write": True}
    if scenario == "delegation_outside":
        return {"type": "delegation", "name": "unlisted-agent"}
    if scenario == "unsigned_mcp":
        return {"type": "mcp_connect", "name": "mcp://docs-search", "signed": False}
    if scenario == "memory_long_term":
        return {"type": "memory_write", "scope": "long_term"}
    if scenario == "data_outside":
        return {"type": "data_access", "name": "customer-documents"}
    if scenario == "conforming_call":
        if not view["tools"]:
            raise ValueError("This contract lists no tools, so there is no conforming call to simulate.")
        return {"type": "tool_call", "name": view["tools"][0]["name"], "write": view["tools"][0]["write"]}
    raise ValueError(f"Unknown scenario {scenario!r}.")
