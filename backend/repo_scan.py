"""
Finds AI agents in a repository's source: LangGraph, the OpenAI Agents SDK and CrewAI definitions, plus MCP configurations.

The scan is static. It reads source text and parses Python with the `ast` module; it never imports, runs or evaluates anything from the
repository, and it never reads files that usually hold secrets (.env, keys, certificates). What it finds are proposals, in the same shape
the file importer uses (agent_import's manifest), so everything downstream (the model, the threat analysis, the drift review) is shared.

It is honest about what static analysis cannot know. A tool that is built dynamically, an agent assembled in a loop, a prompt kept in a database:
none of those are seen. Whatever the scanner guessed (a tool writes because its body calls requests.post, an input is untrusted because it is
web content) is reported under "inferred" for a person to confirm, and each agent carries a confidence: high when the framework and the name
are explicit, medium when the name was derived, low when only the shape of the call identified it.

MCP configurations are a special case: a configuration names servers, and may hold credentials. The scanner reports each server's name and
transport, whether its package is pinned, and which keys hold an inline credential. It never keeps a command line, an address or a value.
"""
import ast
import hashlib
import json
import os
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

from agent_import import WRITE_WORDS, _clean, _first_sentence, _manifest, agent_key

MAX_PY_BYTES = 400_000
MAX_CONFIG_BYTES = 200_000
GENERIC_VAR = {"graph", "app", "workflow", "agent", "compiled", "compiled_graph", "builder", "g", "main", "runnable", "chain"}
TOKEN_RX = re.compile(r"(sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|(?i:bearer)\s+[A-Za-z0-9._~+/=-]{20,})")
ENV_REF = re.compile(r"^\s*(\$\{?(env:|input:)?[A-Za-z_][A-Za-z0-9_.:-]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|<[^>]+>|\{\{.*\}\}|\.\.\.|xxx+|your[-_ ].*|changeme)\s*$", re.I)
CRED_KEYS = re.compile(r"(key|token|secret|password|passwd|authorization|credential|cookie|bearer)", re.I)

MCP_FILES = {".mcp.json", "mcp.json", "mcp_config.json", "mcp-config.json", "claude_desktop_config.json"}
DEV_TOOL_MARKERS = (".cursor/", ".vscode/", ".windsurf/", ".claude/", "claude_desktop_config.json", ".idea/", ".zed/")
WRITE_ATTRS = {"post", "put", "patch", "delete", "send", "sendmail", "send_message", "send_mail", "insert", "insert_one", "insert_many", "update", "update_one", "update_many",
               "remove", "unlink", "rmtree", "write", "writelines", "write_text", "write_bytes", "commit", "put_object", "delete_object", "publish", "create", "refund", "charge",
               "transfer", "execute_write", "mkdir", "rename", "replace", "kill", "terminate", "upload_file", "upload", "push", "merge"}
READ_NETWORK = {"get", "urlopen", "fetch", "request"}
WRITE_SQL = re.compile(r"^\s*(insert|update|delete|drop|alter|create|truncate|merge|replace|grant)\b", re.I)
HOSTED_TOOLS = {"WebSearchTool": ("web_search", False, "web"), "FileSearchTool": ("file_search", False, None), "CodeInterpreterTool": ("code_interpreter", True, None),
                "ComputerTool": ("computer-use", True, None), "LocalShellTool": ("local-shell", True, None), "ImageGenerationTool": ("image_generation", False, None),
                "HostedMCPTool": ("mcp", False, None)}
MCP_CLASSES = {"MCPServerStdio": "stdio", "MCPServerSse": "sse", "MCPServerStreamableHttp": "http", "MultiServerMCPClient": None}
DB_BACKED = re.compile(r"(postgres|sqlite|redis|mongo|dynamo|mysql|sql)", re.I)


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _const(node: Optional[ast.AST], consts: Dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.JoinedStr):
        return None
    return None


def _kw(call: ast.Call, name: str) -> Optional[ast.AST]:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _elements(node: Optional[ast.AST]) -> List[ast.AST]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return list(node.elts)
    return []


class _Tool:
    def __init__(self, name: str, write: Optional[bool], reason: str, untrusted_input: bool = False, doc: str = ""):
        self.name, self.write, self.reason, self.untrusted_input, self.doc = name, write, reason, untrusted_input, doc


def _body_effect(fn: ast.AST) -> Tuple[Optional[bool], str, bool]:
    """Does the function's body change something (True), only read (False), or can't we tell (None)? Plus whether it reads from the open network."""
    writes, reads, net = [], [], False
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        d = _dotted(node.func)
        last = d.rsplit(".", 1)[-1]
        root = d.split(".", 1)[0]
        if d in ("os.system", "os.remove", "os.unlink", "os.rename", "shutil.rmtree", "shutil.move", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "eval", "exec"):
            writes.append(d)
        elif last == "open" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str) and re.search(r"[wax+]", node.args[1].value):
            writes.append("open(..., write)")
        elif last in ("execute", "executemany", "query", "run", "exec_driver_sql") and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            (writes if WRITE_SQL.match(node.args[0].value) else reads).append(f"{last}(sql)")
        elif last in WRITE_ATTRS and root not in ("self",) and (root in ("requests", "httpx", "session", "client", "smtplib", "boto3", "s3", "stripe", "db", "cursor", "conn", "collection") or "." in d):
            writes.append(d)
        elif last in READ_NETWORK and root in ("requests", "httpx", "urllib", "aiohttp", "session", "client"):
            reads.append(d)
            net = True
    if writes:
        return True, f"its body calls {sorted(set(writes))[0]}", net
    if reads:
        return False, f"its body only reads ({sorted(set(reads))[0]})", net
    return None, "", net


class _Index:
    """The parsed Python files of one repository, found by module path, so `from agent.tools import TOOLS` can be followed."""

    def __init__(self) -> None:
        self.by_path: Dict[str, "_FileFacts"] = {}

    def add(self, facts: "_FileFacts") -> None:
        key = facts.path[:-3] if facts.path.endswith(".py") else facts.path
        if key.endswith("/__init__"):
            key = key[: -len("/__init__")]
        self.by_path[key] = facts

    def find_module(self, dotted: str) -> Optional["_FileFacts"]:
        want = dotted.replace(".", "/")
        best = None
        for key, f in self.by_path.items():
            if key == want or key.endswith("/" + want):
                if best is None or len(key) < len(best[0]):
                    best = (key, f)
        return best[1] if best else None


def _tool_args(node: Optional[ast.AST]) -> List[ast.AST]:
    """What a tools= argument stands for: the items of a literal list, or the one name or call it is."""
    if node is None:
        return []
    els = _elements(node)
    if els or isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return els
    return [node] if isinstance(node, (ast.Name, ast.Call, ast.Starred)) else []


class _FileFacts:
    """Everything one Python file says about agents, collected without running it."""

    def __init__(self, path: str, text: str):
        self.path, self.text = path, text
        self.index: Optional[_Index] = None
        self.lists: Dict[str, List[ast.AST]] = {}
        self.tree = ast.parse(text)
        self.origin: Dict[str, str] = {}
        self.consts: Dict[str, Any] = {}
        self.funcs: Dict[str, ast.AST] = {}
        self.tools: Dict[str, _Tool] = {}
        self.assigns: Dict[str, ast.AST] = {}
        self.calls: List[Tuple[Optional[str], ast.Call, Optional[str]]] = []      # (assigned name, call, enclosing function)
        self.graphs: Dict[str, Dict[str, Any]] = {}
        self._collect()

    # imports, constants, functions, tools
    def _collect(self) -> None:
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.origin[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and (n.module or n.level):
                if n.level:                                      # a relative import: worked out from this file's folder
                    parts = self.path.split("/")[:-1]
                    parts = parts[: max(0, len(parts) - (n.level - 1))]
                    mod = ".".join(parts + ([n.module] if n.module else []))
                else:
                    mod = n.module
                for a in n.names:
                    self.origin[a.asname or a.name] = f"{mod}.{a.name}"
        for n in self.tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Constant):
                self.consts[n.targets[0].id] = n.value.value
            tgt = n.targets[0] if isinstance(n, ast.Assign) and len(n.targets) == 1 else (n.target if isinstance(n, ast.AnnAssign) else None)
            if isinstance(tgt, ast.Name) and isinstance(getattr(n, "value", None), (ast.List, ast.Tuple)):
                self.lists[tgt.id] = list(n.value.elts)
        for n in ast.walk(self.tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[n.name] = n
                self._tool_from_function(n)
        self._walk(self.tree, None)

    def resolve(self, node: ast.AST) -> str:
        """The dotted origin of a name or attribute, through the file's imports."""
        d = _dotted(node)
        if not d:
            return ""
        head, _, rest = d.partition(".")
        base = self.origin.get(head, head)
        return f"{base}.{rest}" if rest else base

    def _tool_from_function(self, fn: ast.AST) -> None:
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            o = self.resolve(target)
            if o.split(".")[-1] not in ("function_tool", "tool", "tool_function") or not o.split(".")[0] in ("agents", "langchain_core", "langchain", "crewai", "crewai_tools", "langchain_community", "langgraph"):
                continue
            name = fn.name
            if isinstance(dec, ast.Call):
                a0 = dec.args[0] if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str) else None
                nm = _kw(dec, "name") or _kw(dec, "name_override") or a0
                if isinstance(nm, ast.Constant) and isinstance(nm.value, str):
                    name = nm.value
                elif isinstance(nm, str):
                    name = nm
            write, reason, net = _body_effect(fn)
            doc = ast.get_docstring(fn) or ""
            self.tools[fn.name] = _Tool(name, write, reason, net, _first_sentence(doc, 120))
            return

    def _walk(self, node: ast.AST, fn: Optional[str]) -> None:
        for child in ast.iter_child_nodes(node):
            cur = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            if isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name) and isinstance(child.value, ast.Call):
                var = child.targets[0].id
                self.assigns[var] = child.value
                self.calls.append((var, child.value, fn))
                for inner in ast.walk(child.value):
                    if isinstance(inner, ast.Call) and inner is not child.value:
                        self.calls.append((None, inner, fn))
            elif isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                for inner in ast.walk(child.value):
                    if isinstance(inner, ast.Call):
                        self.calls.append((None, inner, fn))
            elif isinstance(child, (ast.Return, ast.Assign, ast.AnnAssign)):
                val = getattr(child, "value", None)
                if val is not None:
                    for inner in ast.walk(val):
                        if isinstance(inner, ast.Call):
                            self.calls.append((None, inner, fn))
            self._walk(child, cur)

    # what a node in a tools=[...] list stands for
    def tool_of(self, el: ast.AST, m: Dict[str, Any], delegates: List[str], depth: int = 0) -> None:
        if isinstance(el, ast.Starred):
            el = el.value
            if not isinstance(el, ast.Name):
                m["warnings"].append("a tools list is built with * from an expression that was not followed")
                return
        if isinstance(el, ast.Name):
            if el.id in self.lists and depth < 3:
                for e in self.lists[el.id]:
                    self.tool_of(e, m, delegates, depth + 1)
                return
            o = self.origin.get(el.id)
            if o and self.index is not None and el.id not in self.tools and depth < 3:
                mod, _, nm = o.rpartition(".")
                other = self.index.find_module(mod) if mod else None
                if other is not None and other is not self:
                    if nm in other.tools:
                        self._add_tool(m, other.tools[nm])
                        return
                    if nm in other.lists:
                        for e in other.lists[nm]:
                            other.tool_of(e, m, delegates, depth + 1)
                        return
                    if nm in other.funcs:
                        write, reason, net = _body_effect(other.funcs[nm])
                        self._add_tool(m, _Tool(nm, write, reason, net))
                        return
            if el.id in self.tools:
                t = self.tools[el.id]
                self._add_tool(m, t)
                return
            val = self.assigns.get(el.id)
            if isinstance(val, ast.Call):
                self.tool_of(val, m, delegates, depth + 1)
                return
            if el.id in self.funcs:
                write, reason, net = _body_effect(self.funcs[el.id])
                self._add_tool(m, _Tool(el.id, write, reason, net))
                return
            m["inferred"].append(f"tool {el.id}: defined elsewhere, so it was taken by name only")
            self._add_tool(m, _Tool(el.id, None, ""))
            return
        if isinstance(el, ast.Attribute) and el.attr == "as_tool" or (isinstance(el, ast.Call) and isinstance(el.func, ast.Attribute) and el.func.attr == "as_tool"):
            call = el if isinstance(el, ast.Call) else None
            who = _dotted(call.func.value) if call is not None else _dotted(el.value)
            tgt = self._agent_name_of(who)
            if tgt:
                delegates.append(tgt)
                m["recognised"].append(f"agent {tgt} is used as a tool, so it is a delegation target")
            return
        if isinstance(el, ast.Call):
            d = self.resolve(el.func)
            cls = d.split(".")[-1]
            if cls in HOSTED_TOOLS:
                name, write, flavour = HOSTED_TOOLS[cls]
                m["tools"].append({"name": name, "write": write})
                if flavour == "web":
                    m["inputs"].append({"name": "web-search-results", "untrusted": True})
                    m["inferred"].append("web search: its results are treated as an untrusted input")
                if cls == "FileSearchTool":
                    for vs in _elements(_kw(el, "vector_store_ids")):
                        v = _const(vs, self.consts)
                        m["data"].append(f"vector-store:{_clean(v if v else 'store', 40)}")
                if cls == "HostedMCPTool":
                    cfg = _kw(el, "tool_config")
                    label = "server"
                    if isinstance(cfg, ast.Dict):
                        for k, v in zip(cfg.keys, cfg.values):
                            if isinstance(k, ast.Constant) and k.value == "server_label":
                                label = _clean(_const(v, self.consts) or "server")
                            if isinstance(k, ast.Constant) and k.value == "require_approval" and _const(v, self.consts) == "always":
                                m["approvals"].append(f"{label}-tool-approval")
                    m["tools"].pop()
                    m["mcp"].append({"name": f"mcp://{label}", "signed": False})
                if write:
                    m["inferred"].append(f"{name}: treated as write-capable because it acts on a machine or runs code")
                return
            if cls in MCP_CLASSES and cls != "MultiServerMCPClient":
                self._mcp_server(el, cls, m)
                return
            nm = _const(_kw(el, "name"), self.consts) if _kw(el, "name") else None
            name = _clean(nm or _snake(cls).replace("_tool", "") or cls)
            self._add_tool(m, _Tool(name, None, ""))
            return
        m["warnings"].append("a tool entry is built dynamically and was not followed")

    def _add_tool(self, m: Dict[str, Any], t: _Tool) -> None:
        write = t.write
        if write is None:
            write = bool(WRITE_WORDS.search(t.name))
            m["inferred"].append(f"tool {t.name}: treated as {'write-capable' if write else 'read-only'} from its name; confirm it")
        else:
            m["inferred"].append(f"tool {t.name}: {'write-capable' if write else 'read-only'} because {t.reason}; confirm it")
        m["tools"].append({"name": _clean(t.name), "write": write})
        if t.untrusted_input:
            m["inputs"].append({"name": f"{_clean(t.name)}-results", "untrusted": True})
            m["inferred"].append(f"tool {t.name} reads from the network: its results are treated as an untrusted input")

    def _mcp_server(self, call: ast.Call, cls: str, m: Dict[str, Any]) -> None:
        nm = _const(_kw(call, "name"), self.consts)
        label = _clean(nm or MCP_CLASSES.get(cls) or "server")
        m["mcp"].append({"name": f"mcp://{label}", "signed": False})
        m["ignored"].append(f"mcp {label}: command, arguments, address and credentials are not read or stored")

    def _agent_name_of(self, var: str) -> str:
        call = self.assigns.get(var)
        if isinstance(call, ast.Call):
            n = _const(_kw(call, "name"), self.consts) or _const(_kw(call, "role"), self.consts)
            return _clean(n) if n else var
        return var


def _mcp_servers_in_code(f: _FileFacts) -> List[Tuple[str, str, int]]:
    out = []
    for _, call, _fn in f.calls:
        cls = f.resolve(call.func).split(".")[-1]
        if cls == "MultiServerMCPClient" and call.args and isinstance(call.args[0], ast.Dict):
            for k in call.args[0].keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    out.append((_clean(k.value), "client", call.lineno))
    return out


# ── The three frameworks ────────────────────────────────────────────────────

def _openai_agents(f: _FileFacts) -> List[Dict[str, Any]]:
    found = []
    evidence = any(o.split(".")[0] == "agents" and o.split(".")[-1] in ("Runner", "function_tool", "handoff", "WebSearchTool", "FileSearchTool", "AgentOutputSchema") for o in f.origin.values())
    for var, call, fn in f.calls:
        o = f.resolve(call.func)
        is_agent = o in ("agents.Agent", "agents.agent.Agent")
        low = False
        if not is_agent and _dotted(call.func).split(".")[-1] == "Agent" and _kw(call, "instructions") is not None and f.origin.get("Agent", "").split(".")[0] not in ("crewai", "langgraph", "langchain"):
            is_agent, low = True, True
        if not is_agent:
            continue
        name = _const(_kw(call, "name"), f.consts)
        derived = name is None
        name = _clean(name or var or f"agent-line-{call.lineno}")
        m = _manifest(name)
        m["framework"] = "OpenAI Agents SDK"
        delegates: List[str] = []
        goal = _const(_kw(call, "handoff_description"), f.consts)
        if goal:
            m["goal"] = _first_sentence(goal, 200)
            m["inferred"].append("goal: taken from the handoff description; confirm it")
        else:
            ins = _const(_kw(call, "instructions"), f.consts)
            if ins:
                m["goal"] = _first_sentence(ins, 200)
                m["inferred"].append("goal: taken from the first sentence of the instructions; confirm it. The instructions (the prompt) themselves are not stored")
        for el in _tool_args(_kw(call, "tools")):
            f.tool_of(el, m, delegates)
        for el in _elements(_kw(call, "mcp_servers")):
            if isinstance(el, ast.Call):
                f._mcp_server(el, f.resolve(el.func).split(".")[-1], m)
            elif isinstance(el, ast.Name) and isinstance(f.assigns.get(el.id), ast.Call):
                f._mcp_server(f.assigns[el.id], f.resolve(f.assigns[el.id].func).split(".")[-1], m)
        for el in _elements(_kw(call, "handoffs")):
            tgt = ""
            if isinstance(el, ast.Name):
                tgt = f._agent_name_of(el.id)
            elif isinstance(el, ast.Call) and f.resolve(el.func).split(".")[-1] == "handoff" and el.args:
                tgt = f._agent_name_of(_dotted(el.args[0])) if isinstance(el.args[0], ast.Name) else ""
            if tgt:
                m["delegates"].append(tgt)
        m["delegates"] += delegates
        for key in ("input_guardrails", "output_guardrails"):
            for el in _elements(_kw(call, key)):
                g = _dotted(el) or (_dotted(el.func) if isinstance(el, ast.Call) else "")
                if g:
                    m["guardrails"].append({"name": _clean(g.split(".")[-1]), "kind": None})
        mdl = _const(_kw(call, "model"), f.consts)
        if mdl:
            m["recognised"].append(f"model: {_clean(mdl, 60)} (not part of the agent model)")
        m["inferred"].append("autonomy: the SDK does not say; acts_with_approval was assumed")
        found.append({"manifest": m, "line": call.lineno, "confidence": "low" if low else ("medium" if derived or not evidence else "high"), "var": var})
    return found


def _crewai(f: _FileFacts, yaml_agents: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    found = []
    agent_vars: Dict[str, str] = {}
    crews: List[ast.Call] = []
    tasks: List[ast.Call] = []
    for var, call, fn in f.calls:
        o = f.resolve(call.func)
        if o in ("crewai.Crew", "crewai.crew.Crew"):
            crews.append(call)
        elif o in ("crewai.Task", "crewai.task.Task"):
            tasks.append(call)
    memory_on = any(_const(_kw(c, "memory"), f.consts) is True for c in crews)
    crew_agents = []
    for c in crews:
        crew_agents += [e.id for e in _elements(_kw(c, "agents")) if isinstance(e, ast.Name)]
    human_agents = set()
    for t in tasks:
        if _const(_kw(t, "human_input"), f.consts) is True:
            ag = _kw(t, "agent")
            human_agents.add(_dotted(ag) if ag is not None else "")
    for var, call, fn in f.calls:
        o = f.resolve(call.func)
        low = False
        if o not in ("crewai.Agent", "crewai.agent.Agent"):
            if _dotted(call.func).split(".")[-1] == "Agent" and _kw(call, "role") is not None and _kw(call, "goal") is not None and f.origin.get("Agent", "").split(".")[0] not in ("agents", "langgraph"):
                low = True
            else:
                continue
        role = _const(_kw(call, "role"), f.consts)
        cfg_key = None
        cfg = _kw(call, "config")
        if isinstance(cfg, ast.Subscript) and isinstance(cfg.slice, ast.Constant) and isinstance(cfg.slice.value, str):
            cfg_key = cfg.slice.value
        ydoc = yaml_agents.get(cfg_key or "", {})
        derived = role is None
        name = _clean(cfg_key or role or ydoc.get("role") or var or fn or f"agent-line-{call.lineno}")
        m = _manifest(name)
        m["framework"] = "CrewAI"
        goal = _const(_kw(call, "goal"), f.consts) or ydoc.get("goal")
        if goal:
            m["goal"] = _first_sentence(str(goal), 200)
        delegates: List[str] = []
        for el in _tool_args(_kw(call, "tools")):
            f.tool_of(el, m, delegates)
        for t in (ydoc.get("tools") or []) if isinstance(ydoc.get("tools"), list) else []:
            f._add_tool(m, _Tool(_clean(t), None, ""))
        if _const(_kw(call, "allow_delegation"), f.consts) is True or ydoc.get("allow_delegation") is True:
            others = [f._agent_name_of(v) for v in crew_agents if v != var]
            m["delegates"] += others
            m["recognised"].append("allow_delegation: true, so the other agents in the crew are delegation targets")
        if var and (var in human_agents) or (fn and fn in human_agents):
            m["approvals"].append("task-human-input")
            m["recognised"].append("a task of this agent sets human_input, so a human approval step was added")
        if memory_on and (var in crew_agents or not crew_agents):
            m["memory"].append({"name": "crew-memory", "long": True})
            m["inferred"].append("memory: the crew sets memory=True; CrewAI keeps it across runs, so it is treated as long-term")
        m["inferred"].append("autonomy: CrewAI does not say; acts_with_approval was assumed")
        if cfg_key:
            m["recognised"].append(f"configuration key {cfg_key} (from agents.yaml)")
        found.append({"manifest": m, "line": call.lineno, "confidence": "low" if low else ("medium" if derived and not cfg_key else "high"), "var": var, "cfg_key": cfg_key})
    return found


def _langgraph(f: _FileFacts, graph_names: Dict[Tuple[str, str], str], label: str = "") -> List[Dict[str, Any]]:
    found = []
    builders: Dict[str, Dict[str, Any]] = {}
    for var, call, fn in f.calls:
        o = f.resolve(call.func)
        if o.split(".")[-1] in ("StateGraph", "MessageGraph") and o.split(".")[0] == "langgraph":
            if var:
                builders[var] = {"nodes": [], "line": call.lineno, "fn": fn}
    # chained or separate add_node / compile calls
    compiled: List[Tuple[Optional[str], ast.Call, Optional[str], Optional[str]]] = []
    for var, call, fn in f.calls:
        if isinstance(call.func, ast.Attribute):
            root = call.func.value
            while isinstance(root, ast.Call) and isinstance(root.func, ast.Attribute):
                root = root.func.value
            rname = root.id if isinstance(root, ast.Name) else (None if not isinstance(root, ast.Call) else None)
            if call.func.attr == "add_node" and rname in builders and call.args:
                n = _const(call.args[0], f.consts)
                if isinstance(n, str):
                    builders[rname]["nodes"].append(n)
            if call.func.attr == "compile" and rname in builders:
                compiled.append((var, call, fn, rname))
    tool_nodes: List[ast.AST] = []
    bound: List[ast.AST] = []
    interrupts = 0
    for var, call, fn in f.calls:
        o = f.resolve(call.func)
        last = o.split(".")[-1]
        if last == "ToolNode" and call.args:
            tool_nodes += _tool_args(call.args[0])
        if isinstance(call.func, ast.Attribute) and call.func.attr == "bind_tools" and call.args:
            bound += _tool_args(call.args[0])
        if last == "interrupt" and o.split(".")[0] == "langgraph":
            interrupts += 1
    mcp = _mcp_servers_in_code(f)

    def common(m: Dict[str, Any], call: ast.Call, node_tools: List[ast.AST]) -> None:
        delegates: List[str] = []
        seen = set()
        for el in node_tools:
            key = ast.dump(el)
            if key in seen:
                continue
            seen.add(key)
            f.tool_of(el, m, delegates)
        m["delegates"] += delegates
        cp = _kw(call, "checkpointer")
        if cp is not None:
            cls = f.resolve(cp.func if isinstance(cp, ast.Call) else cp).split(".")[-1] or "checkpointer"
            long = bool(DB_BACKED.search(cls))
            m["memory"].append({"name": _clean(cls or "checkpointer"), "long": long})
            m["inferred"].append(f"memory {cls}: {'kept in a database, so long-term' if long else 'in-process, so session-scoped'}; confirm it")
        if _kw(call, "store") is not None:
            m["memory"].append({"name": "long-term-store", "long": True})
        for key in ("interrupt_before", "interrupt_after"):
            for el in _elements(_kw(call, key)):
                n = _const(el, f.consts)
                if n:
                    m["approvals"].append(f"{key.replace('_', '-')}:{_clean(n, 40)}")
        for hook in ("pre_model_hook", "post_model_hook"):
            h = _kw(call, hook)
            if h is not None and _dotted(h):
                m["guardrails"].append({"name": _clean(_dotted(h).split(".")[-1]), "kind": None})
                m["inferred"].append(f"{hook} {_dotted(h)} was taken as a guardrail; confirm what it checks")
        for name, _kind, _line in mcp:
            m["mcp"].append({"name": f"mcp://{name}", "signed": False})
        if mcp:
            m["ignored"].append("mcp servers: commands, arguments, addresses and credentials are not read or stored")
        m["inferred"].append("autonomy: LangGraph does not say; acts_with_approval was assumed")

    for var, call, fn in f.calls:
        o = f.resolve(call.func)
        if o.split(".")[-1] == "create_react_agent" and o.split(".")[0] in ("langgraph", "langchain"):
            explicit = _const(_kw(call, "name"), f.consts)
            nm = _clean(explicit or _specific(graph_names.get((f.path, var or "")), label) or var or f"agent-line-{call.lineno}")
            m = _manifest(nm)
            m["framework"] = "LangGraph"
            tools = _tool_args(_kw(call, "tools")) or (_tool_args(call.args[1]) if len(call.args) > 1 else [])
            common(m, call, tools)
            if _kw(call, "tools") is None and len(call.args) <= 1:
                m["warnings"].append("the agent's tools were not found in the call")
            found.append({"manifest": m, "line": call.lineno, "confidence": "high" if explicit or graph_names.get((f.path, var or "")) else "medium", "var": var})
    for var, call, fn, rname in compiled:
        b = builders[rname]
        explicit = _const(_kw(call, "name"), f.consts)
        mapped = graph_names.get((f.path, var or ""))
        base = explicit or _specific(mapped, label) or (var if var and var not in GENERIC_VAR else None)
        stem = posixpath.splitext(posixpath.basename(f.path))[0].replace("_", "-")
        nm = _clean(base or _specific(stem, label) or rname)
        m = _manifest(nm)
        m["framework"] = "LangGraph"
        in_scope = [t for t in tool_nodes + bound]
        common(m, call, in_scope)
        if interrupts:
            m["approvals"].append("interrupt()-in-node")
            m["recognised"].append(f"{interrupts} interrupt() call(s) in this file, so a human approval step was added")
        m["recognised"].append(f"graph nodes: {', '.join(b['nodes'][:12])}{' …' if len(b['nodes']) > 12 else ''}" if b["nodes"] else "a StateGraph with no named nodes found")
        m["warnings"].append("a graph's nodes are not modelled one by one; tools come from ToolNode and bind_tools calls in the file")
        found.append({"manifest": m, "line": call.lineno, "confidence": "high" if (explicit or mapped) else ("medium" if base else "low"), "var": var})
    return found


def _specific(name: Optional[str], label: str) -> Optional[str]:
    """A name like 'agent' or 'graph' says nothing in an inventory of many agents, so the repository's name goes in front of it."""
    if not name:
        return None
    return f"{label}-{name}" if label and name.lower() in GENERIC_VAR else name


# ── Configuration files ─────────────────────────────────────────────────────

def _is_mcp_config(path: str) -> bool:
    base = posixpath.basename(path).lower()
    return base in MCP_FILES or path.lower().endswith(("/.cursor/mcp.json", "/.vscode/mcp.json", "/.claude/mcp.json", "/.windsurf/mcp.json")) or path.lower() in (".cursor/mcp.json", ".vscode/mcp.json", ".claude/mcp.json")


def _literal_credential(key: str, value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    if ENV_REF.match(value):
        return False
    if TOKEN_RX.search(value):
        return True
    return bool(CRED_KEYS.search(key)) and len(value) >= 8


PKG_RX = re.compile(r"^(@?[A-Za-z0-9][A-Za-z0-9._/-]*)(?:@([A-Za-z0-9._^~<>=*-]+))?$")


def scan_mcp_config(path: str, text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    notes: List[str] = []
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [], [f"{path}: not valid JSON, skipped"]
    servers = doc.get("mcpServers") or (doc.get("servers") if isinstance(doc.get("servers"), dict) else None) or (doc.get("mcp", {}).get("servers") if isinstance(doc.get("mcp"), dict) else None)
    if not isinstance(servers, dict):
        return [], []
    scope = "developer-tool" if any(mk in path.lower() or path.lower().startswith(mk.rstrip("/")) for mk in DEV_TOOL_MARKERS) else "application"
    out = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        transport = "stdio" if cfg.get("command") else ("http" if cfg.get("url") or cfg.get("serverUrl") else "unknown")
        creds = []
        for group in ("env", "headers"):
            if isinstance(cfg.get(group), dict):
                creds += [f"{group}.{k}" for k, v in cfg[group].items() if _literal_credential(k, v)]
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        for a in args:
            if isinstance(a, str) and TOKEN_RX.search(a):
                creds.append("args (a token-shaped value)")
                break
        url = cfg.get("url") or cfg.get("serverUrl")
        if isinstance(url, str) and re.match(r"^[a-z]+://[^/\s:@]+:[^/\s@]+@", url):
            creds.append("url (credentials in the address)")
        pkg, pinned = None, None
        cmd = posixpath.basename(str(cfg.get("command") or "")).lower()
        if cmd in ("npx", "uvx", "pipx", "bunx", "pnpm", "dlx"):
            cand = [a for a in args if isinstance(a, str) and not a.startswith("-")]
            if cand:
                mt = PKG_RX.match(cand[0])
                if mt:
                    pkg, pinned = mt.group(1), bool(mt.group(2))
        out.append({"name": _clean(name), "transport": transport, "scope": scope, "path": path, "package": pkg, "pinned": pinned, "credentials_inline": sorted(set(creds))})
    return out, notes


def _mcp_manifest(repo_label: str, servers: List[Dict[str, Any]]) -> Dict[str, Any]:
    m = _manifest(f"{repo_label}-mcp-client")
    m["framework"] = "MCP configuration"
    for s in servers:
        m["mcp"].append({"name": f"mcp://{s['name']}", "signed": False})
    m["inferred"].append("An MCP configuration names servers, not an agent: the agent is called after the repository, and its owner, tools and goal are unknown")
    m["ignored"].append("commands, arguments, addresses and credentials are never read or stored")
    m["warnings"].append("No server is marked signed: a configuration cannot attest that")
    return m


# ── The scan ────────────────────────────────────────────────────────────────

def _fingerprint(m: Dict[str, Any]) -> str:
    core = {k: m[k] for k in ("name", "framework", "goal", "tools", "mcp", "memory", "data", "inputs", "delegates", "approvals", "guardrails", "constraints")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _yaml_load(text: str) -> Any:
    try:
        for ev in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(ev, yaml.AliasEvent):
                return None
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def scan_files(files: Dict[str, str], repo_label: str = "repository") -> Dict[str, Any]:
    """files: repository-relative path (forward slashes) -> text. Returns agents, MCP servers and notes. Pure: no network, no disk."""
    notes: List[str] = []
    stats = {"files": len(files), "python": 0, "parsed": 0, "unparsed": 0}
    graph_names: Dict[Tuple[str, str], str] = {}
    yaml_agents: Dict[str, Dict[str, Any]] = {}
    yaml_path: Dict[str, str] = {}
    mcp_servers: List[Dict[str, Any]] = []
    cards: List[Tuple[str, Dict[str, Any]]] = []
    for path, text in sorted(files.items()):
        base = posixpath.basename(path).lower()
        if base == "langgraph.json":
            try:
                doc = json.loads(text)
            except ValueError:
                notes.append(f"{path}: not valid JSON, skipped")
                continue
            folder = posixpath.dirname(path)
            for gname, target in (doc.get("graphs") or {}).items() if isinstance(doc.get("graphs"), dict) else []:
                if isinstance(target, str) and ":" in target:
                    p, var = target.rsplit(":", 1)
                    graph_names[(posixpath.normpath(posixpath.join(folder, p)), var)] = _clean(gname)
        elif base in ("agents.yaml", "agents.yml"):
            doc = _yaml_load(text)
            if isinstance(doc, dict) and doc and all(isinstance(v, dict) for v in doc.values()) and all("role" in v or "goal" in v for v in doc.values()):
                for k, v in doc.items():
                    yaml_agents[str(k)] = v
                    yaml_path[str(k)] = path
        elif _is_mcp_config(path):
            servers, n = scan_mcp_config(path, text)
            mcp_servers += servers
            notes += n
        elif base in ("agent-card.json", "agent.json") and ".well-known" in path or base == "agent-card.json":
            try:
                doc = json.loads(text)
                if isinstance(doc, dict) and doc.get("name") and "skills" in doc:
                    cards.append((path, doc))
            except ValueError:
                pass
    agents: List[Dict[str, Any]] = []
    used_yaml = set()
    index = _Index()
    parsed: List[_FileFacts] = []
    for path, text in sorted(files.items()):
        if not path.endswith(".py"):
            continue
        stats["python"] += 1
        try:
            facts = _FileFacts(path, text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            stats["unparsed"] += 1
            if re.search(r"agents|crewai|langgraph|langchain|mcp", text):
                notes.append(f"{path}: could not be parsed as Python, so it was not scanned")
            continue
        facts.index = index
        index.add(facts)
        parsed.append(facts)
    for facts in parsed:
        path, text = facts.path, facts.text
        if not re.search(r"agents|crewai|langgraph|langchain|mcp", text):
            continue
        stats["parsed"] += 1
        for fr in _openai_agents(facts) + _crewai(facts, yaml_agents) + _langgraph(facts, graph_names, agent_key(repo_label)):
            m = fr["manifest"]
            if fr.get("cfg_key"):
                used_yaml.add(fr["cfg_key"])
            agents.append({"name": m["name"], "framework": m["framework"], "path": path, "line": fr["line"], "confidence": fr["confidence"], "manifest": m})
        for name, _k, line in _mcp_servers_in_code(facts):
            mcp_servers.append({"name": name, "transport": "client", "scope": "application", "path": path, "package": None, "pinned": None, "credentials_inline": []})
    for k, doc in yaml_agents.items():
        if k in used_yaml:
            continue
        m = _manifest(_clean(k))
        m["framework"] = "CrewAI"
        m["goal"] = _first_sentence(str(doc.get("goal") or ""), 200) or None
        probe = _FileFacts("agents.yaml.py", "")
        for t in doc.get("tools") or []:
            probe._add_tool(m, _Tool(_clean(t), None, ""))
        m["inferred"].append("autonomy: CrewAI does not say; acts_with_approval was assumed")
        m["warnings"].append("defined in agents.yaml only: no Python in this repository was matched to it")
        agents.append({"name": m["name"], "framework": "CrewAI", "path": yaml_path[k], "line": 1, "confidence": "medium", "manifest": m})
    for path, doc in cards:
        m = _manifest(_clean(doc.get("name")))
        m["goal"] = _first_sentence(str(doc.get("description") or ""), 200) or None
        probe = _FileFacts("card.py", "")
        for s in doc.get("skills") or []:
            if isinstance(s, dict) and s.get("name"):
                probe._add_tool(m, _Tool(_clean(s["name"]), None, ""))
        m["inferred"].append("autonomy: an agent card does not say; acts_with_approval was assumed")
        agents.append({"name": m["name"], "framework": "A2A agent card", "path": path, "line": 1, "confidence": "high", "manifest": m})
    app_servers = [s for s in mcp_servers if s["scope"] == "application" and s["transport"] != "client"]
    if app_servers:
        m = _mcp_manifest(agent_key(repo_label) or "repository", app_servers)
        agents.append({"name": m["name"], "framework": "MCP configuration", "path": app_servers[0]["path"], "line": 1, "confidence": "low", "manifest": m})
    # the same name twice in one repository: tell them apart by file
    seen: Dict[str, int] = {}
    for a in agents:
        seen[a["name"]] = seen.get(a["name"], 0) + 1
    for a in agents:
        if seen[a["name"]] > 1:
            stem = posixpath.splitext(posixpath.basename(a["path"]))[0].replace("_", "-")
            a["manifest"]["name"] = a["name"] = _clean(f"{a['name']}-{stem}")
            a["manifest"]["warnings"].append("the same agent name appears more than once in this repository; the file name was added to tell them apart")
    out_agents = []
    for a in agents:
        m = a["manifest"]
        key = agent_key(m["name"])
        if len(key) < 2:
            continue
        m["recognised"] += [f"{len(m[k])} {k}" for k in ("tools", "mcp", "memory", "data", "inputs", "guardrails", "approvals") if m[k]]
        out_agents.append({"key": key, "name": m["name"], "framework": a["framework"], "path": a["path"], "line": a["line"], "confidence": a["confidence"],
                           "fingerprint": _fingerprint(m), "manifest": m,
                           "counts": {k: len(m[k]) for k in ("tools", "mcp", "memory", "data", "inputs", "delegates", "approvals", "guardrails")}})
    for s in mcp_servers:
        if s["credentials_inline"]:
            notes.append(f"{s['path']}: MCP server {s['name']} has an inline credential in {', '.join(s['credentials_inline'])}. It was not read; move it to a secret manager and rotate it.")
        if s["pinned"] is False:
            notes.append(f"{s['path']}: MCP server {s['name']} runs the unpinned package {s['package']} (any new release is trusted automatically); pin a version.")
    return {"agents": out_agents, "mcp_servers": mcp_servers, "notes": notes, "stats": stats}
