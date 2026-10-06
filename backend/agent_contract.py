"""
What an agent contract says, and how one version differs from the one before (Task 7b).

All of it is derived from the design snapshot stored in the contract, never from a page:
  * view():          the capabilities the contract allows, and a readable agent.contract.yaml;
  * change_between(): what a new version widens or narrows compared with the previous one.

A capability is something the agent can do or reach (a tool, an MCP server, a data store, a delegation, a
level of autonomy, an input it reads). A safeguard is something that limits it (a human approval step, a
guardrail, a constraint). A version WIDENS the agent if it adds a capability, raises its autonomy, or removes a
safeguard; it NARROWS if it removes a capability, lowers its autonomy, or adds a safeguard. The change is recorded
in the contract. Scoring is cheap and deterministic, so every version is still scored; the flag tells a reviewer
whether the earlier approval can be read as still covering the new version (narrowing or no change) or not (widening).
"""
from typing import Any, Dict, List, Set

AUTONOMY = {"suggests": 0, "approval": 1, "autonomous": 2}
AUTONOMY_LABEL = {"suggests": "suggests_only", "approval": "acts_with_approval", "autonomous": "autonomous"}
CAPABILITY_TYPES = {"tool", "mcp", "data", "memory", "input", "external"}
SAFEGUARD_TYPES = {"approval", "guardrail", "constraint"}


def _nodes(snapshot: Dict[str, Any], *types: str) -> List[Dict[str, Any]]:
    return [n for n in snapshot.get("nodes", []) if n.get("type") in types]


def _primary(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return next((n for n in snapshot.get("nodes", []) if n.get("primary")), {})


def _autonomy(snapshot: Dict[str, Any]) -> str:
    return (_primary(snapshot).get("p") or {}).get("auto") or "approval"


def capabilities(snapshot: Dict[str, Any]) -> Set[str]:
    caps: Set[str] = set()
    for n in _nodes(snapshot, "tool"):
        caps.add(f"tool {n['name']} ({'write' if (n.get('p') or {}).get('write') else 'read'})")
    for n in _nodes(snapshot, "mcp"):
        caps.add(f"MCP server {n['name']}")
    for n in _nodes(snapshot, "data"):
        caps.add(f"data store {n['name']}")
    for n in _nodes(snapshot, "memory"):
        caps.add(f"memory {n['name']} ({'long-term' if (n.get('p') or {}).get('long') else 'session'})")
    for n in _nodes(snapshot, "input", "external"):
        caps.add(f"input {n['name']}")
    by_id = {n["id"]: n for n in snapshot.get("nodes", [])}
    for e in snapshot.get("edges", []):
        a, b = by_id.get(e.get("from")), by_id.get(e.get("to"))
        if a and b and a.get("type") == "agent" and b.get("type") == "agent":
            caps.add(f"delegation {a['name']} to {b['name']}")
    return caps


def safeguards(snapshot: Dict[str, Any]) -> Set[str]:
    return {f"{n['type']} {n['name']}" for n in _nodes(snapshot, *SAFEGUARD_TYPES)}


def change_between(previous: Dict[str, Any], new: Dict[str, Any], previous_version: str) -> Dict[str, Any]:
    widened = sorted(f"added {c}" for c in capabilities(new) - capabilities(previous))
    narrowed = sorted(f"removed {c}" for c in capabilities(previous) - capabilities(new))
    widened += sorted(f"removed safeguard {s}" for s in safeguards(previous) - safeguards(new))
    narrowed += sorted(f"added safeguard {s}" for s in safeguards(new) - safeguards(previous))
    before, after = AUTONOMY.get(_autonomy(previous), 1), AUTONOMY.get(_autonomy(new), 1)
    if after > before:
        widened.append(f"autonomy raised to {AUTONOMY_LABEL[_autonomy(new)]}")
    elif after < before:
        narrowed.append(f"autonomy lowered to {AUTONOMY_LABEL[_autonomy(new)]}")
    return {"previous_version": previous_version, "widens": bool(widened), "widened": widened, "narrowed": narrowed}


def first_version() -> Dict[str, Any]:
    return {"previous_version": None, "widens": False, "widened": [], "narrowed": []}


def view(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    primary = _primary(snapshot)
    p = primary.get("p") or {}
    by_id = {n["id"]: n for n in snapshot.get("nodes", [])}
    delegates = [by_id[e["to"]]["name"] for e in snapshot.get("edges", [])
                 if e.get("from") == primary.get("id") and by_id.get(e.get("to"), {}).get("type") == "agent"]
    tools = [{"name": n["name"], "write": bool((n.get("p") or {}).get("write"))} for n in _nodes(snapshot, "tool")]
    mcps = [{"name": n["name"], "signed": bool((n.get("p") or {}).get("signed"))} for n in _nodes(snapshot, "mcp")]
    memory = [{"name": n["name"], "long_term": bool((n.get("p") or {}).get("long"))} for n in _nodes(snapshot, "memory")]
    data = [n["name"] for n in _nodes(snapshot, "data")]
    inputs = [{"name": n["name"], "untrusted": bool((n.get("p") or {}).get("untrusted"))} for n in _nodes(snapshot, "input", "external")]
    approvals = [n["name"] for n in _nodes(snapshot, "approval")]
    guardrails = [n["name"] for n in _nodes(snapshot, "guardrail")]
    constraints = [n["name"] for n in _nodes(snapshot, "constraint")]
    goals = [n["name"] for n in _nodes(snapshot, "goal")]
    out = {"owner": p.get("owner") or None, "autonomy": AUTONOMY_LABEL.get(_autonomy(snapshot), "acts_with_approval"),
           "goal": goals[0] if goals else None, "tools": tools, "mcp_servers": mcps, "memory": memory, "data": data,
           "inputs": inputs, "delegates_to": delegates, "approvals": approvals, "guardrails": guardrails, "constraints": constraints}
    out["yaml"] = to_yaml(snapshot.get("name", ""), out)
    return out


def to_yaml(name: str, v: Dict[str, Any]) -> str:
    lines = [f"agent: {name}", f"owner: {v['owner'] or 'null'}", f"autonomy: {v['autonomy']}"]
    if v["goal"]:
        lines.append(f'goal: "{v["goal"]}"')

    def block(key: str, items: List[str]) -> None:
        if items:
            lines.append(f"{key}:")
            lines.extend(f"  - {i}" for i in items)

    block("inputs", [i["name"] + ("  # untrusted" if i["untrusted"] else "") for i in v["inputs"]])
    block("tools", [t["name"] + ("  # write" + (", approval required" if v["approvals"] else "") if t["write"] else "  # read") for t in v["tools"]])
    block("mcp_servers", [m["name"] + ("  # signed" if m["signed"] else "  # unsigned") for m in v["mcp_servers"]])
    block("memory", [m["name"] + ("  # long_term" if m["long_term"] else "  # session") for m in v["memory"]])
    block("data", v["data"])
    block("delegates_to", v["delegates_to"])
    block("human_approval", v["approvals"])
    block("guardrails", v["guardrails"])
    block("constraints", v["constraints"])
    return "\n".join(lines) + "\n"
