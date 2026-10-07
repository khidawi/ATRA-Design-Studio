"""
Import an agent from a definition file (JSON or YAML) and generate its Secure Tropos model (Task 10).

An organisation already has its agents described somewhere: an agent manifest kept next to the code, a CrewAI agents.yaml, an MCP client
configuration, an A2A agent card, a langgraph.json. This module reads such a file with a fixed conversion rulebook (no language model, no
code execution) and proposes the agent's design: the primary agent, its goal, tools (read or write), MCP servers, memory, data stores, inputs,
delegations, approval steps, guardrails and constraints, wired with the studio's own relations.

What it will not do is vouch for the file. Every element is a proposal; things the file does not say are left out rather than assumed
(a server is never marked signed, a guardrail is never invented); anything it guessed (whether a tool writes, whether an input is untrusted)
is reported under "inferred" for a person to confirm; keys it did not use, and anything that could hold a secret (env, headers, tokens, args), are
reported as ignored and are never stored. Only the file's hash is kept as provenance, not its content.

A file for an agent that already has an active contract does not overwrite anything: it becomes a drift item, compared with that contract,
for compliance to approve or decline (the same review a design edit gets).
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import secrets as _secrets
from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_registry import AGENT_DOMAIN, AgentOut, _graph, _out, agent_key
from auth import AuthUser, current_user
from db.models import Agent, Contract, Design, DriftItem
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/agents/import", tags=["agent-import"])

MAX_BYTES = 512_000
MAX_NODES = 60
NAME_LEN = 80
SECRET_KEYS = re.compile(r"(env|header|token|secret|password|key|credential|auth|cookie)", re.I)
AUTONOMY = {"suggests_only": "suggests", "suggests": "suggests", "suggest": "suggests", "acts_with_approval": "approval", "approval": "approval",
            "human_in_the_loop": "approval", "hitl": "approval", "autonomous": "autonomous", "auto": "autonomous", "full": "autonomous"}
WRITE_WORDS = re.compile(r"(create|write|send|delete|remove|update|post|put|patch|insert|execute|exec|run|transfer|pay|refund|charge|deploy|commit|publish|upload|drop|kill|modify|set|email|sms|mail)", re.I)
READ_WORDS = re.compile(r"(read|get|list|search|query|fetch|view|find|lookup|retrieve|describe|show)", re.I)
UNTRUSTED_WORDS = re.compile(r"(email|inbox|mail|web|public|user|upload|customer|ticket|chat|form|scrape|internet|external|support|request|message|webhook|feed)", re.I)


class ImportProblem(ValueError):
    """The file cannot be turned into a design; the message says why, in words a person can act on."""


def _clean(value: Any, limit: int = NAME_LEN) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value if value is not None else "")).strip()[:limit]


# ── Reading the file ────────────────────────────────────────────────────────

def parse(content: str) -> Any:
    if len(content.encode("utf-8")) > MAX_BYTES:
        raise ImportProblem(f"The file is larger than {MAX_BYTES // 1000} KB; an agent definition should not be.")
    text = content.strip()
    if not text:
        raise ImportProblem("The file is empty.")
    if text[0] in "{[":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ImportProblem(f"The JSON could not be read: {exc.msg} (line {exc.lineno}, column {exc.colno}).")
    try:
        for ev in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(ev, yaml.AliasEvent):
                raise ImportProblem("YAML anchors and aliases are not accepted in an agent definition.")
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
        raise ImportProblem(f"The YAML could not be read{where}: {getattr(exc, 'problem', None) or 'invalid syntax'}.")


FORMATS = {
    "astra": "ASTRA agent manifest",
    "crewai": "CrewAI agents.yaml",
    "mcp-config": "MCP client configuration (mcpServers)",
    "agent-card": "A2A agent card",
    "langgraph": "langgraph.json",
    "openai-agents": "OpenAI Agents SDK agent definition",
}


def detect(doc: Any) -> str:
    if isinstance(doc, dict):
        if "mcpServers" in doc or "servers" in doc and isinstance(doc.get("servers"), dict) and not doc.get("agent") and not doc.get("name"):
            return "mcp-config"
        if isinstance(doc.get("graphs"), dict):
            return "langgraph"
        if "skills" in doc and "name" in doc and ("capabilities" in doc or "url" in doc or "protocolVersion" in doc):
            return "agent-card"
        listed = doc.get("agents")
        if ("instructions" in doc and "name" in doc) or (isinstance(listed, list) and listed and isinstance(listed[0], dict) and "instructions" in listed[0]):
            return "openai-agents"
        if doc and all(isinstance(v, dict) for v in doc.values()) and all("role" in v or "goal" in v for v in doc.values()) and "agent" not in doc and "name" not in doc:
            return "crewai"
        if "agent" in doc or "name" in doc or isinstance(doc.get("agents"), list):
            return "astra"
    raise ImportProblem("The file is not in a format this importer recognises. Supported: " + "; ".join(FORMATS.values()) + ". Choose the format by hand if detection guessed wrong.")


# ── The rulebook: file -> a normalised manifest ─────────────────────────────

def _items(value: Any) -> List[Any]:
    return value if isinstance(value, list) else ([] if value in (None, "", {}) else [value])


def _name_of(item: Any) -> str:
    if isinstance(item, dict):
        return _clean(item.get("name") or item.get("id") or item.get("title") or item.get("identity") or "")
    return _clean(item)


def _manifest(name: str) -> Dict[str, Any]:
    return {"name": name, "owner": None, "framework": None, "autonomy": None, "goal": None, "actors": [], "inputs": [], "tools": [], "mcp": [],
            "memory": [], "data": [], "delegates": [], "approvals": [], "guardrails": [], "constraints": [], "recognised": [], "inferred": [], "ignored": [], "warnings": []}


def _tool(m: Dict[str, Any], item: Any) -> None:
    name = _name_of(item)
    if not name:
        return
    explicit = None
    if isinstance(item, dict):
        if isinstance(item.get("write"), bool):
            explicit = item["write"]
        elif str(item.get("access", item.get("mode", ""))).lower() in ("write", "read_write", "readwrite", "rw"):
            explicit = True
        elif str(item.get("access", item.get("mode", ""))).lower() in ("read", "readonly", "read_only", "ro"):
            explicit = False
        elif isinstance(item.get("readonly"), bool):
            explicit = not item["readonly"]
    if explicit is None:
        write = bool(WRITE_WORDS.search(name)) and not (READ_WORDS.search(name) and not WRITE_WORDS.search(name))
        m["inferred"].append(f"tool {name}: treated as {'write-capable' if write else 'read-only'} from its name; confirm it")
    else:
        write = explicit
    m["tools"].append({"name": name, "write": write})


def _from_astra(doc: Dict[str, Any], pick: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    agents = doc["agents"] if isinstance(doc.get("agents"), list) else [doc]
    names = [_clean(a.get("agent") or a.get("name")) for a in agents if isinstance(a, dict)]
    if not names or not all(names):
        raise ImportProblem("Every agent in the file needs a name (agent: or name:).")
    idx = names.index(pick) if pick in names else 0
    a = agents[idx]
    m = _manifest(names[idx])
    used = {"agent", "name", "version"}
    m["owner"] = _clean(a.get("owner") or a.get("team") or (a.get("metadata") or {}).get("owner") or "", 120) or None
    m["framework"] = _clean(a.get("framework") or "", 80) or None
    m["goal"] = _clean(a.get("goal") or a.get("purpose") or "", 200) or None
    raw = str(a.get("autonomy", "")).lower()
    if raw:
        m["autonomy"] = AUTONOMY.get(raw)
        if m["autonomy"] is None:
            m["warnings"].append(f"autonomy '{raw}' is not one of suggests_only, acts_with_approval, autonomous; acts_with_approval was used")
    used |= {"owner", "team", "framework", "goal", "purpose", "autonomy", "metadata"}
    for it in _items(a.get("actors") or a.get("humans")):
        m["actors"].append(_name_of(it))
    for it in _items(a.get("inputs")):
        n = _name_of(it)
        if isinstance(it, dict) and isinstance(it.get("untrusted"), bool):
            m["inputs"].append({"name": n, "untrusted": it["untrusted"]})
        else:
            m["inputs"].append({"name": n, "untrusted": bool(UNTRUSTED_WORDS.search(n))})
            m["inferred"].append(f"input {n}: treated as {'untrusted' if UNTRUSTED_WORDS.search(n) else 'trusted'} from its name; confirm it")
    for it in _items(a.get("tools")):
        _tool(m, it)
    for it in _items(a.get("mcp_servers") or a.get("mcp")):
        m["mcp"].append({"name": _name_of(it), "signed": bool(isinstance(it, dict) and it.get("signed") is True)})
    for it in _items(a.get("memory")):
        long = isinstance(it, dict) and (str(it.get("retention", "")).lower() in ("long_term", "long", "persistent") or it.get("long") is True)
        m["memory"].append({"name": _name_of(it), "long": long})
    m["data"] = [_name_of(x) for x in _items(a.get("data") or a.get("data_stores"))]
    m["delegates"] = [_name_of(x) for x in _items(a.get("delegates_to") or a.get("delegates"))]
    m["approvals"] = [_name_of(x) for x in _items(a.get("human_approval") or a.get("approvals"))]
    for key, bucket in (("guardrails", "guardrails"), ("constraints", "constraints")):
        for it in _items(a.get(key)):
            m[bucket].append({"name": _name_of(it), "kind": _clean(it.get("kind"), 30).lower() if isinstance(it, dict) and it.get("kind") else None})
    used |= {"actors", "humans", "inputs", "tools", "mcp_servers", "mcp", "memory", "data", "data_stores", "delegates_to", "delegates", "human_approval", "approvals", "guardrails", "constraints"}
    m["ignored"] = [f"{k} (not used by the converter)" if not SECRET_KEYS.search(k) else f"{k} (could hold a secret; not read)" for k in a if k not in used]
    return m, names


def _from_crewai(doc: Dict[str, Any], pick: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    names = list(doc.keys())
    key = pick if pick in names else names[0]
    a = doc[key]
    m = _manifest(_clean(key))
    m["framework"] = "CrewAI"
    m["goal"] = _clean(a.get("goal") or "", 200) or None
    for t in _items(a.get("tools")):
        _tool(m, t)
    if a.get("allow_delegation") is True:
        m["delegates"] = [_clean(n) for n in names if n != key]
        m["recognised"].append("allow_delegation: true, so the other agents in the file are delegation targets")
    else:
        others = [n for n in names if n != key]
        if others:
            m["ignored"].append(f"other agents in the file ({', '.join(others)}) are separate agents; import each one on its own")
    m["inferred"].append("autonomy: CrewAI does not say; acts_with_approval was assumed")
    m["ignored"] += [f"{k} ({'could hold a secret; not read' if SECRET_KEYS.search(k) else 'not used by the converter'})" for k in a if k not in ("goal", "tools", "allow_delegation")]
    return m, names


def _from_mcp(doc: Dict[str, Any], pick: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    servers = doc.get("mcpServers") or doc.get("servers") or {}
    if not isinstance(servers, dict) or not servers:
        raise ImportProblem("The MCP configuration lists no servers.")
    m = _manifest(_clean(pick) if pick else "mcp-client-agent")
    for name, cfg in servers.items():
        m["mcp"].append({"name": f"mcp://{_clean(name)}", "signed": False})
        if isinstance(cfg, dict):
            hidden = [k for k in cfg if SECRET_KEYS.search(k) or k in ("args", "command")]
            if hidden:
                m["ignored"].append(f"{name}: {', '.join(sorted(hidden))} (commands, arguments and credentials are never read or stored)")
    m["inferred"].append("An MCP configuration names servers, not an agent: the agent is called mcp-client-agent unless you rename it, and its owner, tools and goal are unknown")
    m["warnings"].append("No server is marked signed: a configuration cannot attest that")
    return m, [m["name"]]


def _from_card(doc: Dict[str, Any], pick: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    m = _manifest(_clean(doc.get("name")))
    m["goal"] = _clean(doc.get("description") or "", 200) or None
    m["owner"] = _clean((doc.get("provider") or {}).get("organization") if isinstance(doc.get("provider"), dict) else "", 120) or None
    for s in _items(doc.get("skills")):
        _tool(m, {"name": _name_of(s)})
    m["inferred"].append("autonomy: an agent card does not say; acts_with_approval was assumed")
    m["ignored"] += [f"{k} (not used by the converter)" for k in doc if k not in ("name", "description", "skills", "provider")]
    return m, [m["name"]]


def _from_langgraph(doc: Dict[str, Any], pick: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    names = list(doc["graphs"].keys())
    m = _manifest(_clean(pick if pick in names else names[0]))
    m["framework"] = "LangGraph"
    m["warnings"].append("langgraph.json lists graphs but not their tools, data or approvals; add an agent manifest for a useful model")
    m["ignored"] += [f"{k} ({'could hold a secret; not read' if SECRET_KEYS.search(k) else 'not used by the converter'})" for k in doc if k != "graphs"]
    return m, names


# The OpenAI Agents SDK is configured in Python, not in a file, so there is no standard file to read. This converter reads the declarative
# form of an agent that mirrors the SDK's Agent(...) fields (name, instructions, tools, handoffs, guardrails, mcp_servers), written as YAML
# or JSON: for example a dump of an Agent's settings that a team keeps beside the code.
OPENAI_TOOL_TYPES = {"web_search", "web_search_preview", "file_search", "code_interpreter", "computer", "computer_use_preview", "image_generation", "mcp", "function",
                     "local_shell", "shell"}


def _first_sentence(text: str, limit: int = 160) -> str:
    one = re.sub(r"\s+", " ", _clean(text, 600))
    m = re.match(r"(.+?[.!?])(\s|$)", one)
    return (m.group(1) if m else one)[:limit]


def _from_openai(doc: Dict[str, Any], pick: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    agents = doc["agents"] if isinstance(doc.get("agents"), list) else [doc]
    names = [_clean(a.get("name")) for a in agents if isinstance(a, dict)]
    if not names or not all(names):
        raise ImportProblem("Every agent in the file needs a name.")
    a = agents[names.index(pick) if pick in names else 0]
    m = _manifest(_clean(a.get("name")))
    m["framework"] = "OpenAI Agents SDK"
    m["owner"] = _clean(a.get("owner") or (a.get("metadata") or {}).get("owner") or "", 120) or None
    goal = a.get("handoff_description") or a.get("instructions")
    if goal:
        m["goal"] = _first_sentence(goal, 200)
        m["inferred"].append("goal: taken from the " + ("handoff description" if a.get("handoff_description") else "first sentence of the instructions") + "; confirm it. The instructions (the prompt) themselves are not stored")
    for t in _items(a.get("tools")):
        if isinstance(t, str):
            _tool(m, t)
            continue
        if not isinstance(t, dict):
            continue
        kind = str(t.get("type", "function")).lower()
        if kind not in OPENAI_TOOL_TYPES:
            m["warnings"].append(f"tool of type '{kind}' is not one this importer knows, so it was left out")
            continue
        if kind == "function":
            fn = t.get("function") if isinstance(t.get("function"), dict) else t
            _tool(m, {"name": _name_of(fn), **({"write": t["write"]} if isinstance(t.get("write"), bool) else {})})
        elif kind in ("web_search", "web_search_preview"):
            m["tools"].append({"name": "web_search", "write": False})
            m["inputs"].append({"name": "web-search-results", "untrusted": True})
            m["inferred"].append("web search: its results are treated as an untrusted input")
        elif kind == "file_search":
            m["tools"].append({"name": "file_search", "write": False})
            for vs in _items(t.get("vector_store_ids")):
                m["data"].append(f"vector-store:{_clean(vs, 40)}")
        elif kind == "code_interpreter":
            m["tools"].append({"name": "code_interpreter", "write": True})
            m["inferred"].append("code_interpreter: treated as write-capable because it executes code")
        elif kind in ("computer", "computer_use_preview", "local_shell", "shell"):
            m["tools"].append({"name": {"computer": "computer-use", "computer_use_preview": "computer-use", "local_shell": "local-shell", "shell": "shell"}[kind], "write": True})
            m["inferred"].append(f"{kind}: treated as write-capable because it acts on a machine")
        elif kind == "image_generation":
            m["tools"].append({"name": "image_generation", "write": False})
        elif kind == "mcp":
            label = _clean(t.get("server_label") or t.get("name") or "server")
            m["mcp"].append({"name": f"mcp://{label}", "signed": False})
            if str(t.get("require_approval", "")).lower() == "always":
                m["approvals"].append(f"{label}-tool-approval")
                m["recognised"].append(f"mcp {label}: require_approval is 'always', so a human approval step was added")
            hidden = [k for k in t if SECRET_KEYS.search(k) or k in ("server_url", "allowed_tools")]
            if hidden:
                m["ignored"].append(f"mcp {label}: {', '.join(sorted(hidden))} (addresses, tool lists and credentials are not read or stored)")
    for srv in _items(a.get("mcp_servers")):
        label = _name_of(srv)
        if label:
            m["mcp"].append({"name": f"mcp://{label}", "signed": False})
            if isinstance(srv, dict):
                hidden = [k for k in srv if SECRET_KEYS.search(k) or k in ("command", "args", "url", "params")]
                if hidden:
                    m["ignored"].append(f"mcp {label}: {', '.join(sorted(hidden))} (commands, arguments and credentials are never read or stored)")
    for h in _items(a.get("handoffs")):
        target = _name_of(h.get("agent") if isinstance(h, dict) and isinstance(h.get("agent"), dict) else h) or (_clean(h.get("agent_name")) if isinstance(h, dict) else "")
        if target:
            m["delegates"].append(target)
    for key in ("input_guardrails", "output_guardrails"):
        for g in _items(a.get(key)):
            n = _name_of(g)
            if n:
                m["guardrails"].append({"name": n, "kind": None})
    others = [n for n in names if n != m["name"]]
    if others:
        m["ignored"].append(f"other agents in the file ({', '.join(others)}) are separate agents; import each one on its own, or pick one with the 'which agent' choice")
    m["inferred"].append("autonomy: the SDK does not say; acts_with_approval was assumed")
    used = {"name", "instructions", "handoff_description", "tools", "mcp_servers", "handoffs", "input_guardrails", "output_guardrails", "owner", "metadata", "model", "agents"}
    m["ignored"] += [f"{k} ({'could hold a secret; not read' if SECRET_KEYS.search(k) else 'not used by the converter'})" for k in a if k not in used]
    if a.get("model"):
        m["recognised"].append(f"model: {_clean(a['model'], 60)} (not part of the agent model)")
    return m, names


CONVERTERS = {"astra": _from_astra, "crewai": _from_crewai, "mcp-config": _from_mcp, "agent-card": _from_card, "langgraph": _from_langgraph, "openai-agents": _from_openai}


# ── The model: manifest -> design nodes and edges ───────────────────────────

GUARD_KIND = [(re.compile(r"inject|prompt"), "injection"), (re.compile(r"rate|limit|throttle"), "rate"), (re.compile(r"disclos|ai-label|transparen"), "disclosure")]
CONSTRAINT_KIND = [(re.compile(r"retent|ttl|expir|delete-after"), "retention"), (re.compile(r"egress|outbound|allowlist|domain"), "egress")]


def _kind(name: str, explicit: Optional[str], table, allowed: set, m: Dict[str, Any], what: str) -> str:
    if explicit in allowed:
        return explicit
    for rx, kind in table:
        if rx.search(name.lower()):
            m["inferred"].append(f"{what} {name}: kind '{kind}' taken from its name; confirm it")
            return kind
    m["warnings"].append(f"{what} {name}: its kind is unknown, so no check credits it")
    return "other"


def build(m: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, str]] = []
    count: Dict[str, int] = {}

    def add(type_: str, name: str, p: Dict[str, Any], primary: bool = False) -> str:
        count[type_] = count.get(type_, 0) + 1
        nid = {"agent": "a", "human": "h", "input": "i", "goal": "g", "tool": "t", "mcp": "m", "data": "d", "memory": "mem", "approval": "ap", "guardrail": "gr", "constraint": "c"}[type_] + str(count[type_])
        nodes.append({"id": nid, "type": type_, "name": _clean(name) or type_, "p": p, "primary": primary})
        return nid

    primary = add("agent", m["name"], {"owner": m["owner"] or "", "auto": m["autonomy"] or "approval"}, True)
    link = lambda a, b, label: edges.append({"from": a, "to": b, "label": label})
    for n in m["actors"]:
        if n:
            link(add("human", n, {}), primary, "requests")
    for i in m["inputs"]:
        if i["name"]:
            link(add("input", i["name"], {"untrusted": i["untrusted"]}), primary, "feeds")
    if m["goal"]:
        link(primary, add("goal", m["goal"], {}), "pursues")
    first_write = None
    for t in m["tools"]:
        tid = add("tool", t["name"], {"write": t["write"]})
        link(primary, tid, "uses")
        if t["write"] and first_write is None:
            first_write = tid
    for s in m["mcp"]:
        if s["name"]:
            link(primary, add("mcp", s["name"], {"signed": s["signed"]}), "connects")
    first_memory = None
    for x in m["memory"]:
        if x["name"]:
            mid = add("memory", x["name"], {"long": x["long"]})
            link(primary, mid, "stores")
            first_memory = first_memory or mid
    for d in m["data"]:
        if d:
            link(primary, add("data", d, {}), "reads")
    for d in m["delegates"]:
        if d:
            link(primary, add("agent", d, {"owner": "", "auto": "approval"}), "delegates")
    for a in m["approvals"]:
        if a:
            link(add("approval", a, {}), first_write or primary, "gates")
    for g in m["guardrails"]:
        if g["name"]:
            link(add("guardrail", g["name"], {"kind": _kind(g["name"], g["kind"], GUARD_KIND, {"injection", "rate", "disclosure"}, m, "guardrail")}), primary, "limits")
    for c in m["constraints"]:
        if c["name"]:
            kind = _kind(c["name"], c["kind"], CONSTRAINT_KIND, {"retention", "egress"}, m, "constraint")
            link(add("constraint", c["name"], {"kind": kind}), first_memory if kind == "retention" and first_memory else primary, "restricts")
    if len(nodes) > MAX_NODES:
        raise ImportProblem(f"The file describes {len(nodes)} elements; an agent model holds at most {MAX_NODES}.")
    return nodes, edges


class Converted(BaseModel):
    format: str
    format_label: str
    sha256: str
    agents_found: List[str]
    agent_name: str
    owner: Optional[str]
    framework: Optional[str]
    autonomy: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, str]]
    recognised: List[str]
    inferred: List[str]
    ignored: List[str]
    warnings: List[str]


def convert(content: str, fmt: Optional[str] = None, primary: Optional[str] = None, rename: Optional[str] = None) -> Converted:
    doc = parse(content)
    if not isinstance(doc, dict):
        raise ImportProblem("The file must hold an object (key: value pairs) at its top level.")
    kind = fmt if fmt in FORMATS else detect(doc)
    try:
        m, found = CONVERTERS[kind](doc, primary)
    except (KeyError, TypeError, AttributeError, IndexError):
        raise ImportProblem(f"The file does not match the {FORMATS[kind]} layout. Check it against the example for that format.")
    if rename and _clean(rename):
        m["name"] = _clean(rename)
    if not m["name"]:
        raise ImportProblem("The agent has no name. Give it one in the file (agent: or name:).")
    if len(agent_key(m["name"])) < 2:
        raise ImportProblem("The agent's name needs letters or digits.")
    if m["autonomy"] is None and kind == "astra":
        m["inferred"].append("autonomy: not stated; acts_with_approval was assumed")
    nodes, edges = build(m)
    counts = {t: sum(1 for n in nodes if n["type"] == t) for t in ("tool", "mcp", "memory", "data", "input", "guardrail", "constraint", "approval")}
    m["recognised"] += [f"{v} {k}{'s' if v != 1 else ''}" for k, v in counts.items() if v]
    return Converted(format=kind, format_label=FORMATS[kind], sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(), agents_found=found, agent_name=m["name"],
                     owner=m["owner"], framework=m["framework"], autonomy=m["autonomy"] or "approval", nodes=nodes, edges=edges, recognised=m["recognised"],
                     inferred=m["inferred"], ignored=m["ignored"], warnings=m["warnings"])


# ── Examples ────────────────────────────────────────────────────────────────

EXAMPLES = {
    "astra": ("agent.model.yaml", """agent: payouts-agent
owner: Payments eng
framework: LangGraph
autonomy: acts_with_approval        # suggests_only | acts_with_approval | autonomous
goal: Pay approved supplier invoices on schedule
actors:
  - Finance approver
inputs:
  - name: supplier-invoices
    untrusted: true
tools:
  - name: erp.invoices.read
    access: read
  - name: stripe.payouts.create
    access: write
mcp_servers:
  - name: mcp://erp
    signed: true
memory:
  - name: case-memory
    retention: session
data:
  - billing-store
delegates_to:
  - notify-agent
human_approval:
  - finance-approval
guardrails:
  - name: prompt-injection-filter
    kind: injection
constraints:
  - name: egress-allowlist
    kind: egress
"""),
    "crewai": ("agents.yaml", """researcher:
  role: Senior research analyst
  goal: Find and summarise supplier risk reports
  tools:
    - web_search
    - read_file
  allow_delegation: true
writer:
  role: Report writer
  goal: Write the weekly risk brief
  tools:
    - send_email
"""),
    "mcp-config": ("mcp.json", """{
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]},
    "github": {"url": "https://example.test/mcp", "headers": {"Authorization": "Bearer ..."}}
  }
}
"""),
    "agent-card": ("agent-card.json", """{
  "name": "invoice-agent",
  "description": "Reads supplier invoices and prepares payments",
  "url": "https://agents.example.test/invoice",
  "provider": {"organization": "Finance ops eng"},
  "capabilities": {"streaming": true},
  "skills": [{"id": "read-invoice", "name": "invoices.read"}, {"id": "prepare-payment", "name": "payments.create"}]
}
"""),
    "openai-agents": ("openai-agent.yaml", """name: Refund agent
handoff_description: Handles customer refund requests within policy
instructions: |
  You resolve refund requests. Check the order first, then refund only within policy.
model: gpt-4.1
tools:
  - type: function
    name: lookup_order
    description: Look up an order by id
  - type: function
    name: issue_refund
    description: Refund an order through the payments provider
  - type: web_search
  - type: file_search
    vector_store_ids: [vs_policy_docs]
  - type: mcp
    server_label: orders
    server_url: https://example.test/mcp
    require_approval: always
handoffs:
  - Notification agent
input_guardrails:
  - name: prompt_injection_check
output_guardrails:
  - name: pii_redaction
owner: Payments eng
api_key: never-read
"""),
    "langgraph": ("langgraph.json", """{
  "graphs": {"refund_agent": "./agents/refund.py:graph"},
  "dependencies": ["."],
  "env": ".env"
}
"""),
}


class FormatOut(BaseModel):
    id: str
    label: str
    filename: str
    example: str


@router.get("/formats", response_model=List[FormatOut])
def formats() -> List[FormatOut]:
    return [FormatOut(id=k, label=FORMATS[k], filename=EXAMPLES[k][0], example=EXAMPLES[k][1]) for k in FORMATS]


# ── Preview and import ──────────────────────────────────────────────────────

class ImportRequest(BaseModel):
    content: str = Field(min_length=1)
    filename: Optional[str] = Field(None, max_length=200)
    format: Optional[str] = None
    primary: Optional[str] = Field(None, max_length=NAME_LEN)       # which agent in a multi-agent file
    name: Optional[str] = Field(None, max_length=NAME_LEN)          # rename the agent
    profile: Optional[str] = Field(None, max_length=64)             # the regulatory requirement set to score against


class PreviewOut(Converted):
    analysis: Dict[str, Any]
    existing: Dict[str, Any]


def _active(session: Session, key: str) -> Optional[Contract]:
    return session.scalar(select(Contract).where(Contract.object_type == "AGENT", Contract.deployment_id == key, Contract.status == "ACTIVE").order_by(Contract.issued_at.desc()))


def _convert_or_422(body: ImportRequest) -> Converted:
    try:
        return convert(body.content, body.format, body.primary, body.name)
    except ImportProblem as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/preview", response_model=PreviewOut)
def preview(body: ImportRequest, session: Session = Depends(get_session)) -> PreviewOut:
    """What the file would become, with the threat checks on it. Writes nothing."""
    c = _convert_or_422(body)
    analysis = analyse_agent(AgentAnalyseRequest(graph=_graph({"nodes": c.nodes, "edges": c.edges}), domain=AGENT_DOMAIN), session)
    key = agent_key(c.agent_name)
    agent = session.scalar(select(Agent).where(Agent.agent_key == key))
    contract = _active(session, key) if agent else None
    will = "drift" if contract else ("update" if agent and agent.design_id else "create")
    return PreviewOut(**c.model_dump(), analysis=analysis.model_dump(mode="json"),
                      existing={"agent_exists": agent is not None, "has_active_contract": contract is not None, "will": will, "agent_key": key,
                                "contract_version": contract.document["version"] if contract else None})


class ImportOut(BaseModel):
    outcome: str                       # created | updated | drift
    agent: AgentOut
    design_key: str
    drift_id: Optional[str]
    summary: str


@router.post("", response_model=ImportOut, status_code=201)
def import_agent(body: ImportRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ImportOut:
    from drift import _build            # imported here: drift imports agent_registry, which this module also uses
    c = _convert_or_422(body)
    key = agent_key(c.agent_name)
    org = current_organisation(session)
    prov = {"source": "file", "format": c.format, "filename": _clean(body.filename or "pasted text", 200), "sha256": c.sha256, "imported_by": user.name,
            "imported_at": datetime.now(timezone.utc).isoformat(), "note": "Generated from a file; nothing here is verified against code."}
    agent = session.scalar(select(Agent).where(Agent.agent_key == key))
    if agent is not None and agent.origin == "DEMO":
        raise HTTPException(status_code=409, detail=f"{key} is a demo agent. Remove the demo agents or rename this one.")
    design = session.get(Design, agent.design_id) if agent is not None and agent.design_id else None
    base = dict(design.document) if design is not None else {}
    doc = {**base, "nodes": c.nodes, "edges": c.edges, "n": 100 + len(c.nodes), "profile": body.profile or base.get("profile") or "payments",
           "req": base.get("req") or {}, "policy": base.get("policy") or "block", "ratified": False, "provenance": prov}
    contract = _active(session, key) if agent is not None else None

    if contract is not None and design is not None:
        label = f"Imported from {prov['filename']} (sha256:{c.sha256[:12]}), not verified against code"
        item = _build(session, agent, contract, doc, "IMPORT", label, design.design_key)
        for old in session.scalars(select(DriftItem).where(DriftItem.agent_key == key, DriftItem.status == "OPEN", DriftItem.source == "IMPORT")):
            old.status, old.decision_note = "SUPERSEDED", "Replaced by a newer import."
        session.add(item)
        session.commit()
        session.refresh(item)
        return ImportOut(outcome="drift", agent=_out(session, agent), design_key=design.design_key, drift_id=str(item.id),
                         summary=f"{key} already has contract {contract.document['version']}, so nothing was overwritten: the file is waiting in Drift review as a proposed change.")

    tools = sum(1 for n in c.nodes if n["type"] in ("tool", "mcp"))
    if design is not None:
        design.document, design.version, design.name = doc, design.version + 1, c.agent_name
        outcome, summary = "updated", f"The draft design for {key} was replaced with the file's model."
    else:
        design = Design(design_key="d-" + _secrets.token_hex(5), organisation_id=org.id, subject="AGENT", name=c.agent_name, domain_key=AGENT_DOMAIN, document=doc)
        session.add(design)
        session.flush()
        outcome, summary = "created", f"A draft design for {key} was generated from the file. Review it, add what the file could not say, then ratify."
    if agent is None:
        agent = Agent(agent_key=key, organisation_id=org.id, name=c.agent_name, origin="REGISTERED", mode="OBSERVE")
        session.add(agent)
    agent.design_id, agent.tools_count = design.id, tools
    agent.framework = c.framework or agent.framework or "Not recorded"
    if c.owner and not agent.owner:
        agent.owner = c.owner
    if agent.status not in ("DESIGNED", "ASSURED"):
        agent.status = "TO_RATIFY" if agent.owner else "UNOWNED"
    session.commit()
    session.refresh(agent)
    return ImportOut(outcome=outcome, agent=_out(session, agent), design_key=design.design_key, drift_id=None, summary=summary)


# ── Raw file bodies, for pipelines ──────────────────────────────────────────
#   curl -X POST "$ASTRA/api/agents/import/file?filename=agent.model.yaml" -H "Authorization: Bearer $KEY" --data-binary @agent.model.yaml

async def _raw(request: Request, filename: Optional[str], format: Optional[str], primary: Optional[str], name: Optional[str], profile: Optional[str]) -> ImportRequest:
    raw = await request.body()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail="The file must be UTF-8 text.")
    if not text.strip():
        raise HTTPException(status_code=422, detail="The request body is empty: send the file's content as the body.")
    return ImportRequest(content=text, filename=filename, format=format, primary=primary, name=name, profile=profile)


@router.post("/file-preview", response_model=PreviewOut)
async def preview_file(request: Request, filename: Optional[str] = None, format: Optional[str] = None, primary: Optional[str] = None, name: Optional[str] = None,
                       session: Session = Depends(get_session)) -> PreviewOut:
    return preview(await _raw(request, filename, format, primary, name, None), session)


@router.post("/file", response_model=ImportOut, status_code=201)
async def import_file(request: Request, filename: Optional[str] = None, format: Optional[str] = None, primary: Optional[str] = None, name: Optional[str] = None,
                      profile: Optional[str] = None, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ImportOut:
    return import_agent(await _raw(request, filename, format, primary, name, profile), session, user)
