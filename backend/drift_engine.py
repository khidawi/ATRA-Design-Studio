"""
Drift: how a proposed change to an agent's design differs from its ratified contract (Task 7c). Pure functions.

detailed_changes() lists each difference as a reviewable line: what was added, removed or modified, why it matters, and
whether it WIDENS (more capability or fewer safeguards), NARROWS, or needs human REVIEW (ownership or goal changed).
The same vocabulary as agent_contract.change_between, but item by item.

The simulator edits a copy of the ratified snapshot to stand in for a code or runtime change that nothing observed. The
drift it produces is then compared and scored exactly like a real design change.
"""
import copy
from typing import Any, Dict, List, Optional

from agent_contract import AUTONOMY, AUTONOMY_LABEL, CAPABILITY_TYPES, SAFEGUARD_TYPES

LABEL = {"tool": "tool", "mcp": "mcp_server", "data": "data", "memory": "memory", "input": "input", "external": "input",
         "approval": "approval", "guardrail": "guardrail", "constraint": "constraint"}
CAPABILITY_NOTE = {"tool": "a new tool the agent can call", "mcp": "a new MCP server the agent can reach",
                   "data": "adds a data store to scope", "memory": "adds memory the agent can write", "input": "a new input the agent reads",
                   "external": "a new input the agent reads"}


def _item(op: str, text: str, note: str, cls: str) -> Dict[str, Any]:
    return {"op": op, "text": text, "note": note, "class": cls, "pill": {"Widening": "bad", "Narrowing": "ok", "Review": "warn", "Safeguard": "ok"}[cls]}


def _detail(n: Dict[str, Any]) -> str:
    p, t = n.get("p") or {}, n.get("type")
    if t == "tool":
        return " (write)" if p.get("write") else " (read)"
    if t == "mcp":
        return " (signed)" if p.get("signed") else " (unsigned)"
    if t == "memory":
        return " (long-term)" if p.get("long") else " (session)"
    if t in ("input", "external") and p.get("untrusted"):
        return " (untrusted)"
    return ""


def detailed_changes(prev: Dict[str, Any], new: Dict[str, Any]) -> List[Dict[str, Any]]:
    tracked = CAPABILITY_TYPES | SAFEGUARD_TYPES
    key = lambda n: (n["type"], n["name"])
    pn = {key(n): n for n in prev.get("nodes", []) if n.get("type") in tracked}
    nn = {key(n): n for n in new.get("nodes", []) if n.get("type") in tracked}
    items: List[Dict[str, Any]] = []
    for k, n in nn.items():
        if k not in pn:
            if n["type"] in SAFEGUARD_TYPES:
                items.append(_item("add", f"{LABEL[n['type']]}: {n['name']}", "a safeguard added", "Safeguard"))
            else:
                bad = n["type"] == "mcp" and not (n.get("p") or {}).get("signed")
                items.append(_item("add", f"{LABEL[n['type']]}: {n['name']}{_detail(n)}", CAPABILITY_NOTE[n["type"]] + ("; unsigned" if bad else ""), "Widening"))
    for k, n in pn.items():
        if k not in nn:
            if n["type"] in SAFEGUARD_TYPES:
                items.append(_item("del", f"{LABEL[n['type']]}: {n['name']}", "a safeguard removed", "Widening"))
            else:
                items.append(_item("del", f"{LABEL[n['type']]}: {n['name']}{_detail(n)}", "no longer in the design", "Narrowing"))
    flips = {"tool": ("write", "now write-capable", "no longer write-capable"), "mcp": ("signed", "now signed", "no longer signed"),
             "input": ("untrusted", "now marked untrusted", "no longer untrusted"), "memory": ("long", "now long-term", "now session only")}
    for k in pn.keys() & nn.keys():
        t = k[0]
        if t in flips:
            prop, on, off = flips[t]
            before, after = bool((pn[k].get("p") or {}).get(prop)), bool((nn[k].get("p") or {}).get(prop))
            if before != after:
                widens = after if t != "mcp" else not after            # signing is a safeguard
                items.append(_item("mod", f"{LABEL[t]}: {k[1]}", on if after else off, "Widening" if widens else "Narrowing"))
    by_id_p = {n["id"]: n for n in prev.get("nodes", [])}
    by_id_n = {n["id"]: n for n in new.get("nodes", [])}

    def delegations(snap: Dict[str, Any], by_id: Dict[str, Any]) -> set:
        return {(by_id[e["from"]]["name"], by_id[e["to"]]["name"]) for e in snap.get("edges", [])
                if by_id.get(e.get("from"), {}).get("type") == "agent" and by_id.get(e.get("to"), {}).get("type") == "agent"}
    dp, dn = delegations(prev, by_id_p), delegations(new, by_id_n)
    items += [_item("add", f"delegation: {a} to {b}", "the agent can hand work to another agent", "Widening") for a, b in sorted(dn - dp)]
    items += [_item("del", f"delegation: {a} to {b}", "no longer delegates", "Narrowing") for a, b in sorted(dp - dn)]
    pp = next((n for n in prev.get("nodes", []) if n.get("primary")), {})
    np_ = next((n for n in new.get("nodes", []) if n.get("primary")), {})
    a0, a1 = (pp.get("p") or {}).get("auto") or "approval", (np_.get("p") or {}).get("auto") or "approval"
    if AUTONOMY.get(a1, 1) != AUTONOMY.get(a0, 1):
        raised = AUTONOMY.get(a1, 1) > AUTONOMY.get(a0, 1)
        items.append(_item("mod", f"autonomy: {AUTONOMY_LABEL.get(a0)} to {AUTONOMY_LABEL.get(a1)}",
                           "the agent acts with less oversight" if raised else "the agent acts with more oversight", "Widening" if raised else "Narrowing"))
    if ((pp.get("p") or {}).get("owner") or "") != ((np_.get("p") or {}).get("owner") or ""):
        items.append(_item("mod", f"owner: {(pp.get('p') or {}).get('owner') or 'none'} to {(np_.get('p') or {}).get('owner') or 'none'}", "ownership changed; needs human review", "Review"))
    g0 = [n["name"] for n in prev.get("nodes", []) if n.get("type") == "goal"]
    g1 = [n["name"] for n in new.get("nodes", []) if n.get("type") == "goal"]
    if g0 != g1:
        items.append(_item("mod", "goal changed", "may shift what the agent is for; needs human review", "Review"))
    return items


def kind_of(items: List[Dict[str, Any]]) -> Optional[str]:
    classes = {i["class"] for i in items}
    if "Widening" in classes:
        return "Widening"
    if "Review" in classes:
        return "Review"
    return "Narrowing" if items else None


# ── Simulator ───────────────────────────────────────────────────────────────

SCENARIOS = [
    ("add_write_tool", "Add a write-capable tool"),
    ("add_unsigned_mcp", "Connect an unsigned MCP server"),
    ("add_untrusted_input", "Read a new untrusted input"),
    ("raise_autonomy", "Raise autonomy to fully autonomous"),
    ("remove_approval", "Remove the human approval step"),
    ("remove_tool", "Remove a tool (a narrowing change)"),
]


def apply_scenario(scenario: str, doc: Dict[str, Any]) -> Dict[str, Any]:
    """A modified copy of a design document (studio format), standing in for a change nobody scanned."""
    d = copy.deepcopy(doc)
    nodes, edges = d["nodes"], d["edges"]
    primary = next((n for n in nodes if n.get("primary")), None)
    if primary is None:
        raise ValueError("The design has no primary agent.")

    def add(type_: str, name: str, p: Dict[str, Any], label: str) -> None:
        nid = f"sim{len(nodes) + 1}"
        nodes.append({"id": nid, "type": type_, "name": name, "p": p})
        edges.append({"from": nid, "to": primary["id"], "label": label} if label == "feeds" else {"from": primary["id"], "to": nid, "label": label})

    if scenario == "add_write_tool":
        add("tool", "payments.transfer.create", {"write": True}, "uses")
    elif scenario == "add_unsigned_mcp":
        add("mcp", "mcp://web-search", {"signed": False}, "connects")
    elif scenario == "add_untrusted_input":
        add("input", "public-web-content", {"untrusted": True}, "feeds")
    elif scenario == "raise_autonomy":
        if (primary.get("p") or {}).get("auto") == "autonomous":
            raise ValueError("This agent is already fully autonomous.")
        primary.setdefault("p", {})["auto"] = "autonomous"
    elif scenario == "remove_approval":
        gone = {n["id"] for n in nodes if n.get("type") == "approval"}
        if not gone:
            raise ValueError("This design has no approval step to remove.")
        d["nodes"] = [n for n in nodes if n["id"] not in gone]
        d["edges"] = [e for e in edges if e["from"] not in gone and e["to"] not in gone]
    elif scenario == "remove_tool":
        tools = [n for n in nodes if n.get("type") == "tool"]
        if not tools:
            raise ValueError("This design has no tool to remove.")
        gone = tools[-1]["id"]
        d["nodes"] = [n for n in nodes if n["id"] != gone]
        d["edges"] = [e for e in edges if e["from"] != gone and e["to"] != gone]
    else:
        raise ValueError(f"Unknown scenario {scenario!r}.")
    d["ratified"] = False
    return d
