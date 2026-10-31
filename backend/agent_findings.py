"""
Findings for an AI agent's design: what is wrong with the design itself, and the step that fixes each thing.

The model designer checks a design against the Secure Tropos model (design_findings.py). An agent has its own vocabulary of elements and relationships (policies.py, VOCABULARY["AGENT"]):
the primary agent pursues a goal, uses tools, connects to MCP servers, reads data, stores to memory; people request, inputs feed, approvals gate, guardrails limit, constraints restrict.
The design is correct when it is made of those relationships: one named primary agent, and every other element joined to it by the relationship that gives the element its meaning.

Risk itself is not decided here: the OWASP Agentic checks (agent_analysis.py) and the regulatory compliance score with its gate (rcr.py) stay as they are. This module adds the design
checks they do not make, and the fix for each. A fix is plain data the studio acts on; nothing here changes a design.
"""
import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from compliance_schema import Finding
from rule_checks import DesignGraph

# The relationship that gives each kind of element its meaning, and where the line is drawn from (the studio draws it the same way when it adds the element).
#   type -> (labels that count, the line runs from the primary agent "out", to it "in", or either way "any")
MEANING: Dict[str, Tuple[Set[str], str]] = {
    "agent": ({"delegates"}, "in"),        # a sub-agent: an agent delegates to it
    "human": ({"requests", "writes"}, "any"),   # a person requests from the agent, or writes to the input that feeds it (the studio's own sample is drawn so)
    "input": ({"feeds"}, "out"),
    "goal": ({"pursues"}, "in"),
    "tool": ({"uses"}, "in"),
    "mcp": ({"connects"}, "in"),
    "data": ({"reads", "writes", "stores"}, "any"),
    "memory": ({"stores"}, "in"),
    "approval": ({"gates"}, "out"),
    "guardrail": ({"limits"}, "out"),
    "constraint": ({"restricts"}, "out"),
}
LABELS = {"requests", "feeds", "pursues", "delegates", "uses", "connects", "reads", "stores", "gates", "limits", "restricts", "writes", "calls"}   # "calls": an external system the agent reaches
KIND = {"agent": "sub-agent", "human": "human actor", "input": "input source", "goal": "goal", "tool": "tool", "mcp": "MCP server", "data": "data store", "memory": "memory",
        "approval": "approval", "guardrail": "guardrail", "constraint": "constraint", "external": "external system"}
VERB = {"delegates": "delegates to", "requests": "requests from", "feeds": "feeds", "pursues": "pursues", "uses": "uses", "connects": "connects to", "reads": "reads", "stores": "stores to",
        "gates": "gates", "limits": "limits", "restricts": "restricts"}


def _name(n) -> str:
    return str((n.props or {}).get("name") or n.type)


def formal_findings(graph: Optional[DesignGraph]) -> List[Finding]:
    if graph is None:
        return []
    nodes, edges = list(graph.nodes), list(graph.edges)
    out: List[Finding] = []
    primaries = [n for n in nodes if n.type == "agent" and n.primary]
    if not primaries:
        out.append(Finding(finding_id="primary-missing", severity="error", title="No primary agent", detail="The design has no primary agent: nothing says which agent this design is about.",
                           why="Every element is joined to the primary agent: it is the agent that is scored, ratified and monitored.", blocks=["ratify"],
                           fix={"type": "info", "instruction": "Start the design from an agent, or mark one of its agents as the primary."}))
        return out
    if len(primaries) > 1:
        out.append(Finding(finding_id="primary-many", severity="error", title=f"{len(primaries)} agents are marked primary", detail="Only one agent can be the primary: the others are sub-agents it delegates to.",
                           why="The score, the contract and the monitoring are about one agent.", blocks=["ratify"], node_id=primaries[1].id,
                           fix={"type": "info", "instruction": "Keep one primary agent and make the others sub-agents of it."}))
    primary = primaries[0]
    if not str((primary.props or {}).get("name", "")).strip():
        out.append(Finding(finding_id="primary-unnamed", severity="error", title="The primary agent has no name", detail="A contract is issued to an agent by name.",
                           why="The agent's name is how the contract, the inventory and the monitoring find each other.", blocks=["ratify"], node_id=primary.id,
                           fix={"type": "edit_element", "node_id": primary.id, "field": "name", "instruction": "Name the primary agent."}))

    ids = {n.id for n in nodes}
    for n in nodes:
        rule = MEANING.get(n.type)
        if rule is None or n.id == primary.id:
            continue
        labels, direction = rule
        near = [e for e in edges if e.label in labels and n.id in (e.from_id, e.to_id)]
        if near:
            continue
        label = "requests" if n.type == "human" else sorted(labels)[0]
        a, b = (primary.id, n.id) if direction in ("in", "any") and n.type != "human" else (n.id, primary.id)
        if n.type == "approval":
            tool = next((t for t in nodes if t.type == "tool" and (t.props or {}).get("write")), None)
            b = tool.id if tool else primary.id
        out.append(Finding(
            finding_id=f"unconnected-{n.id}", severity="error", title=f"{_name(n)} is not connected ({KIND.get(n.type, n.type)})",
            detail=f"It is drawn on its own: nothing joins it to the agent by the relationship that gives a {KIND.get(n.type, n.type)} its meaning ({', '.join(sorted(labels))}).",
            why="An element means something in the design only through its relationship to the agent: what it uses, what it reads, who gates it, what limits it. One on its own is not part of the design.",
            blocks=["ratify"], node_id=n.id,
            fix={"type": "connect", "a": a, "b": b, "label": label, "instruction": f"Connect it to {_name(primary) if b == primary.id or a == primary.id else 'the agent'}: the {label} relationship."}))

    for e in edges:
        if e.label not in LABELS and e.from_id in ids and e.to_id in ids:
            out.append(Finding(
                finding_id=f"edge-{e.from_id}-{e.to_id}", severity="warning", title=f"A line the model gives no meaning to ({e.label or 'unlabelled'})",
                detail="The design vocabulary has no such relationship, so this line says nothing about the agent.",
                why="A line should be one of the model's relationships: " + ", ".join(sorted(LABELS)) + ".", node_id=e.from_id,
                fix={"type": "unlink", "a": e.from_id, "b": e.to_id, "label": e.label, "instruction": "Remove the line, or draw the relationship the model does define."}))
    return out


def design_fingerprint(doc: Dict[str, Any]) -> str:
    """What a review applies to: the agent as designed and the declarations behind it. The drift policy, the ratified flag and the provenance are not part of the design."""
    body = {"nodes": doc.get("nodes", []), "edges": doc.get("edges", []), "profile": doc.get("profile"), "req": doc.get("req") or {}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
