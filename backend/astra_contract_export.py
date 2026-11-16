"""
The behavioural contract of an agent design, in the Appendix A format of the ASTRA specification (ASTRA phase 5). Pure: a design and its assessment in, a document out.

What the document says is only what the design and its assessment say:
    permitted goals         the goals the design pursues (the design needs at least one)
    permitted tasks         the tools the agent uses, each with whether it reads or writes (the design needs at least one)
    autonomy                tools that can run without a person (every tool without an approval on its route) and the tools that need a forced confirmation
    resource scopes         the data it reads (read-write when the agent has a write tool: the design does not say which data a write tool changes) and its memory
    delegation              the agents it may delegate to, in execution mode
    constraints             the controls the design declares and the assessment did not find violated, as OWASP agentic constraints
    regulatory mappings     the article-level anchors of the specification for those constraints (indicative: clause-level mapping is still open)
The agent's owner has to be an email address, as the schema requires; where it comes from is decided by the caller.
"""
import re
from typing import Any, Dict, List, Optional, Tuple

import astra_estate as AE
import astra_schema

# control kind -> (ASI row, control name written into the contract)
CONSTRAINT_OF = {
    "iso": ("ASI01", "prompt_injection_guardrail_on_untrusted_routes"),
    "hitl": ("ASI02", "human_approval_on_every_write_tool"),
    "least": ("ASI03", "tool_scopes_declared"),
    "supply": ("ASI04", "signed_mcp_servers"),
    "memval": ("ASI06", "memory_retention_constraint"),
    "deleg": ("ASI07", "delegations_declared"),
    "ident": ("ASI10", "named_owner_holds_kill_switch"),
    "life": ("ASI10", "named_owner_holds_kill_switch"),
}
# article-level anchors of the specification (section 6); indicative
CLAUSES = {
    "ASI01": ["EU-AI-Act:Art.15", "EU-AI-Act:Art.14"], "ASI02": ["EU-AI-Act:Art.15", "EU-AI-Act:Art.9"], "ASI03": ["EU-AI-Act:Art.15", "EU-AI-Act:Art.12"],
    "ASI04": ["EU-AI-Act:Art.15", "EU-AI-Act:Art.10", "EU-AI-Act:Art.11", "ISO-42001:supplier-controls"], "ASI06": ["EU-AI-Act:Art.10", "EU-AI-Act:Art.15"],
    "ASI07": ["EU-AI-Act:Art.15"], "ASI10": ["EU-AI-Act:Art.14", "EU-AI-Act:Art.12", "EU-AI-Act:Art.9"],
}
LIFECYCLE = ("development", "staging", "production", "retired")


def contract_agent_id(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64].strip("-")


def build_document(doc: Dict[str, Any], assessment: Dict[str, Any], *, owner_email: Optional[str], version: str, lifecycle_status: str, expires: str) -> Tuple[Dict[str, Any], List[str]]:
    """(document, problems). Problems are things a person has to fix in the design; the document is still returned so it can be shown as a draft."""
    prim = AE._primary(doc)
    problems: List[str] = []
    agent_id = contract_agent_id(prim["name"])
    if len(agent_id) < 2:
        problems.append("The primary agent's name needs at least two letters or digits to become the contract's agent id.")
    goals = [n["name"] for n in AE._targets(doc, prim["id"], "pursues") if str(n.get("name", "")).strip()]
    if not goals:
        problems.append("The design needs a goal: the contract states what the agent is permitted to pursue.")
    tools = AE._targets(doc, prim["id"], "uses")
    if not tools:
        problems.append("The design needs at least one tool: the contract states what the agent is permitted to do.")
    if not owner_email:
        problems.append("The agent's owner has to be an email address. Put the owner's email in the design, or add the owner as a person of the platform.")
    by_id = {n["id"]: n for n in doc.get("nodes", [])}
    gated = {by_id[e["to"]]["name"] for e in doc.get("edges", []) if e.get("label") == "gates" and e.get("to") in by_id and by_id[e["to"]].get("type") == "tool"
             and by_id.get(e.get("from"), {}).get("type") == "approval"}
    write = {t["name"] for t in tools if (t.get("p") or {}).get("write")}
    ids = {t["name"]: f"T{i}" for i, t in enumerate(tools, 1)}
    memory = AE._targets(doc, prim["id"], "stores")
    data = AE._targets(doc, prim["id"], "reads")
    delegates = [contract_agent_id(n["name"]) for n in AE._targets(doc, prim["id"], "delegates")]

    seen: Dict[str, set] = {}
    for p in assessment.get("paths", []):
        for c in p["controls"]:
            if c["agent"] == prim["name"]:
                seen.setdefault(c["kind"], set()).add(c["status"])
    constraints, mappings, listed = [], [], set()
    for kind, (asi, control) in CONSTRAINT_OF.items():
        st = seen.get(kind)
        if not st or "VIO" in st or st <= {"NA"} or control in listed:
            continue
        listed.add(control)
        constraints.append({"asi": asi, "control": control})
        if asi in CLAUSES:
            mappings.append({"control": control, "clauses": list(CLAUSES[asi])})

    document: Dict[str, Any] = {
        "schema_version": "0.1",
        "agent": {"id": agent_id, "owner": owner_email or "", "lifecycle": {"status": lifecycle_status, "expires": expires}, "model_version": version},
        "permitted_goals": [{"id": f"G{i}", "statement": g} for i, g in enumerate(goals, 1)],
        "permitted_tasks": [{"id": ids[t["name"]], "tool": t["name"], "scope": {"access": "write" if t["name"] in write else "read"}} for t in tools],
        "resource_scopes": {"data": [{"resource": n["name"], "access": "read-write" if write else "read"} for n in data]},
        "delegation": {"may_delegate_to": delegates, "accepts_delegation_from": [], "mode": "execution_only"},
        "autonomy": {"unattended_actions": [ids[t["name"]] for t in tools if t["name"] not in gated],
                     "human_in_the_loop": [{"action": f"{t['name']} (write)", "require": "forced_confirmation"} for t in tools if t["name"] in gated and t["name"] in write]},
        "constraints": constraints,
        "regulatory_mappings": mappings,
    }
    if memory:
        validated = bool(seen.get("memval")) and "VIO" not in seen["memval"]
        document["resource_scopes"]["memory"] = {"writes": "validated" if validated else "unrestricted",
                                                 "default_context": "persistent" if any((n.get("p") or {}).get("long") for n in memory) else "ephemeral"}
    if lifecycle_status not in LIFECYCLE:
        problems.append(f"The lifecycle status must be one of {', '.join(LIFECYCLE)}.")
    problems += [f"The contract would not be valid: {e}" for e in astra_schema.validate(document)] if not problems else []
    return document, problems
