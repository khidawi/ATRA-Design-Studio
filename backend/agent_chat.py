"""
ASTRA Agent design studio — "Draft model with AI".

Turns a plain-English description of an AI agent into the element graph the
Agent design studio edits (agent, tools, MCP servers, memory, goal, human
actors, approvals, guardrails, constraints), using a local Ollama model.

Division of labour, on purpose:
  * the model only PROPOSES elements (nodes) — it is the part that has to
    understand English;
  * everything else is deterministic code: which element is the primary
    agent, how elements connect to it (port of the studio's own studioAdd
    rules), which domain applies, and which controls survive.

The last point matters for the same reason the Model studio's assistant can
never mark a constraint satisfied: a drafter that adds an approval step, a
guardrail or a signed MCP server the user never described would make the
live OWASP analysis look better than the design really is. So controls the
description does not mention are dropped (and reported), MCP servers are
never drafted as signed, and an owner is only kept if the user named it.
"""
import re
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ollama_client import chat_json

NodeType = Literal[
    "agent", "human", "input", "external", "goal", "tool", "mcp",
    "data", "memory", "approval", "guardrail", "constraint",
]
ControlKind = Literal["", "injection", "rate", "disclosure", "egress", "retention"]

# The owner choices the studio's Properties panel offers.
KNOWN_OWNERS = ["CX eng", "Payments eng", "Platform", "Compliance lead"]
MAX_NODES = 14


# ── What the model is asked to produce (kept small: a CPU model is slow) ──────

Flag = Literal[
    "", "untrusted", "write", "long_term", "autonomous", "suggests",
    "injection", "rate", "disclosure", "egress", "retention",
]


class AgentNodeProposal(BaseModel):
    type: NodeType
    name: str
    # One optional modifier keeps the output (and a CPU model's wait) short:
    #   input: untrusted | tool: write | memory: long_term | agent: autonomous or suggests
    #   guardrail: injection, rate or disclosure | constraint: egress or retention
    flag: Flag = ""


class AgentDraftProposal(BaseModel):
    nodes: List[AgentNodeProposal] = Field(default_factory=list)


# ── What the studio receives (exactly the shape its own state uses) ───────────

class AgentDraftRequest(BaseModel):
    description: str = Field(min_length=1, max_length=4000)


class DesignNode(BaseModel):
    id: str
    type: NodeType
    name: str
    p: Dict[str, Any] = Field(default_factory=dict)
    primary: bool = False


class DesignEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_id: str = Field(alias="from")
    to_id: str = Field(alias="to")
    label: str


class AgentDesign(BaseModel):
    reply: str
    domain: Literal["payments", "healthcare"]
    nodes: List[DesignNode] = Field(default_factory=list)
    edges: List[DesignEdge] = Field(default_factory=list)


SYSTEM_PROMPT = """You are the design assistant inside ASTRA's Agent design studio. Turn a plain-English description of an AI agent into the elements of its design model. Respond with ONLY one JSON object matching the schema you were given — no prose, no markdown.

Each element has a "type", a short "name" and an optional "flag" (use "" when none applies).

Types:
- agent: the agent being designed (list it first), or another agent it hands work to. flag: autonomous (acts without approval) or suggests (only recommends); otherwise ""
- human: a person who makes requests or reviews work (e.g. Customer, Clinician)
- input: a source of content the agent reads (inbox, form, documents). flag: untrusted when the content comes from outside the organisation (customers, email, the web)
- external: an external system the agent only sends data to or receives data from
- goal: what the agent is trying to achieve, one short sentence (include exactly one)
- tool: a function the agent can call, named system.resource.action (e.g. stripe.refunds.create). flag: write if it changes data, sends messages or moves money
- mcp: an MCP server the agent connects to, named mcp://name
- data: a data store the agent reads
- memory: something the agent remembers. flag: long_term if it persists across sessions
- approval: a human approval step the description says is required
- guardrail: only if the description names one. flag: injection, rate or disclosure
- constraint: only if the description names a restriction. flag: egress or retention

Rules:
- Include only what the description says or clearly implies. Never invent approvals, guardrails, constraints or owners.
- Prefer a tool (system.resource.action) over an external system when the agent performs an action.
- Use lower-case-with-hyphens names for agents (e.g. refund-assist-agent). At most 14 elements.

Example. Description: "A helpdesk agent reads tickets from employees, looks up the user in the directory, resets passwords through the identity provider, and keeps a log. Password resets need manager approval."
Output: {"nodes":[{"type":"agent","name":"helpdesk-agent","flag":""},{"type":"human","name":"Employee","flag":""},{"type":"input","name":"ticket-queue","flag":""},{"type":"goal","name":"Resolve helpdesk tickets","flag":""},{"type":"tool","name":"directory.users.read","flag":""},{"type":"tool","name":"idp.passwords.reset","flag":"write"},{"type":"memory","name":"ticket-log","flag":"long_term"},{"type":"approval","name":"manager-approval","flag":""}]}
"""


# ── Deterministic post-processing ────────────────────────────────────────────

# A control survives only if the description actually mentions it.
_CONTROL_EVIDENCE: Dict[Tuple[str, str], str] = {
    ("approval", ""): r"approv|sign[- ]?off|human review|review(ed|s)? by|confirm",
    ("guardrail", "injection"): r"inject|sanitis|sanitiz|filter",
    ("guardrail", "rate"): r"rate[- ]?limit|throttl|per (hour|minute|day)|at most \d+",
    ("guardrail", "disclosure"): r"disclos|told (they|that)|tell (the )?(customer|user)s?\b.*\b(ai|bot)|ai disclosure",
    ("constraint", "egress"): r"egress|only (email|send)|allow[- ]?list|permitted domain|domain",
    ("constraint", "retention"): r"retention|retain|delete[sd]? after|forget|\d+[- ]day",
}
_GUARDRAIL_KINDS = {"injection", "rate", "disclosure"}
_CONSTRAINT_KINDS = {"egress", "retention"}
_ID_PREFIX = {
    "agent": "a", "human": "h", "input": "i", "external": "x", "goal": "g", "tool": "t",
    "mcp": "m", "data": "d", "memory": "mem", "approval": "ap", "guardrail": "gr", "constraint": "c",
}


def _clean(name: str) -> str:
    return re.sub(r"\s+", " ", name or "").strip()[:80]


def _domain_for(description: str) -> str:
    return "healthcare" if re.search(r"patient|clinic|health|medical|hospital|\bnhs\b|diagnos", description, re.I) else "payments"


def _control_supported(node_type: str, kind: str, description: str) -> bool:
    pattern = _CONTROL_EVIDENCE.get((node_type, "" if node_type == "approval" else kind))
    return bool(pattern and re.search(pattern, description, re.I))


def build_design(proposal: AgentDraftProposal, description: str) -> AgentDesign:
    """Turn the model's proposed elements into the studio's graph."""
    domain = _domain_for(description)
    kept: List[Tuple[AgentNodeProposal, str, str]] = []  # (proposal, clean name, resolved kind)
    dropped: List[str] = []
    seen = set()

    for n in proposal.nodes:
        name = _clean(n.name)
        if not name:
            continue
        key = (n.type, name.lower())
        if key in seen:
            continue
        seen.add(key)

        kind = n.flag
        if n.type == "guardrail":
            kind = kind if kind in _GUARDRAIL_KINDS else "injection"
        elif n.type == "constraint":
            kind = kind if kind in _CONSTRAINT_KINDS else "egress"

        if n.type in ("approval", "guardrail", "constraint") and not _control_supported(n.type, kind, description):
            dropped.append(name)
            continue
        kept.append((n, name, kind))
        if len(kept) >= MAX_NODES:
            break

    if not kept:
        return AgentDesign(
            reply="I couldn't find an agent in that description. Say what the agent does, which tools "
                  "or systems it uses, and who it works for.",
            domain=domain,
        )

    # Exactly one primary agent: the first agent proposed, or a placeholder if the model gave none.
    if not any(n.type == "agent" for n, _, _ in kept):
        kept.insert(0, (AgentNodeProposal(type="agent", name="new-agent"), "new-agent", ""))

    # The owner is a fact about the organisation, so it is only filled in when the user named
    # exactly one of the known owners; the model never chooses one.
    named = [o for o in KNOWN_OWNERS if o.lower() in description.lower()]
    owner = named[0] if len(named) == 1 else ""

    counters: Dict[str, int] = {}
    nodes: List[DesignNode] = []
    primary_id: Optional[str] = None
    for n, name, kind in kept:
        counters[n.type] = counters.get(n.type, 0) + 1
        node_id = f"{_ID_PREFIX[n.type]}{counters[n.type]}"
        is_primary = n.type == "agent" and primary_id is None
        if is_primary:
            primary_id = node_id

        p: Dict[str, Any] = {}
        if n.type == "agent":
            auto = n.flag if n.flag in ("autonomous", "suggests") else "approval"
            p = {"owner": owner if is_primary else "", "auto": auto}
        elif n.type == "input":
            p = {"untrusted": n.flag == "untrusted"}
        elif n.type == "tool":
            p = {"write": n.flag == "write"}
        elif n.type == "mcp":
            p = {"signed": False}  # a draft can never attest that a server is signed
        elif n.type == "memory":
            p = {"long": n.flag == "long_term"}
        elif n.type in ("guardrail", "constraint"):
            p = {"kind": kind}
        nodes.append(DesignNode(id=node_id, type=n.type, name=name, p=p, primary=is_primary))

    # Connect everything to the primary agent with the studio's own relation rules.
    edges: List[DesignEdge] = []

    def link(src: Optional[str], dst: Optional[str], label: str) -> None:
        if src and dst:
            edges.append(DesignEdge(**{"from": src, "to": dst, "label": label}))

    first_write_tool = next((x.id for x in nodes if x.type == "tool" and x.p.get("write")), None)
    first_memory = next((x.id for x in nodes if x.type == "memory"), None)
    for x in nodes:
        if x.primary:
            continue
        if x.type == "agent":
            link(primary_id, x.id, "delegates")
        elif x.type == "human":
            link(x.id, primary_id, "requests")
        elif x.type in ("input", "external"):
            link(x.id, primary_id, "feeds")
        elif x.type == "goal":
            link(primary_id, x.id, "pursues")
        elif x.type == "tool":
            link(primary_id, x.id, "uses")
        elif x.type == "mcp":
            link(primary_id, x.id, "connects")
        elif x.type == "data":
            link(primary_id, x.id, "reads")
        elif x.type == "memory":
            link(primary_id, x.id, "stores")
        elif x.type == "approval":
            link(x.id, first_write_tool or primary_id, "gates")
        elif x.type == "guardrail":
            link(x.id, primary_id, "limits")
        elif x.type == "constraint":
            link(x.id, first_memory if x.p.get("kind") == "retention" and first_memory else primary_id, "restricts")

    primary_name = next(x.name for x in nodes if x.primary)
    reply = f"Drafted {len(nodes)} elements for {primary_name}. Every element is proposed until you ratify."
    if dropped:
        reply += (
            f" Left out {len(dropped)} control(s) you didn't describe ({', '.join(dropped)}), "
            "so the analysis doesn't credit protections that aren't in the design."
        )
    return AgentDesign(reply=reply, domain=domain, nodes=nodes, edges=edges)


def generate_agent_design(req: AgentDraftRequest) -> AgentDesign:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": req.description},
    ]
    raw = chat_json(messages, AgentDraftProposal.model_json_schema(), max_tokens=1100)
    try:
        proposal = AgentDraftProposal.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(status_code=502, detail=f"Model returned a malformed proposal: {exc}") from exc
    return build_design(proposal, req.description)
