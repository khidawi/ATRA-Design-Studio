"""
Runtime conformity against the signed behavioural contract (ASTRA phase 6).

An agent that has a signed contract (astra_contract_api.py) is judged here, with the conformity predicate of the formal model (astra_model/events.py): every divergence class
that can be checked from an event is checked, and the outcome is one of CONFORMS, DIVERGES, UNVERIFIED (an attribute is missing, the contract is not valid, or the agent is not
known: never read as conforming) or PENDING (a semantic class a person has to adjudicate). An agent that never had a signed contract keeps the legacy check (divergence.py).
Once an agent has had a signed contract the legacy check is never used for it again: a revoked, expired or tampered contract means events are UNVERIFIED, not waved through.

Two parts:
    pure       agent_from_contract, to_event, finding_fields, CLASS_STATE (no database)
    database   Judge: loads the agent's contract and bindings once per batch, judges events, raises findings (de-duplicated within ten minutes)

What the contract format (Appendix A) cannot say, and how the model reads it:
    * parameter bounds: a task scope entry that is a list of two numbers is an inclusive bound on the parameter of that name;
    * write tools: a task whose scope says access "write"; a tool named in a human-in-the-loop action counts as needing confirmation;
    * autonomy: a write tool that may run neither unattended nor with a confirmation is suggest-only (a call to it is an autonomy-boundary breach); "suggest" when all of them are;
    * spawn: an agent it may delegate to is an agent it may spawn; the child also has to be registered on the platform (the collector's claim is not believed);
    * sandbox and egress: the contract has no field for them, so a sandboxed execution is fine and any other host is outside the (empty) egress list;
    * the lifecycle check reads the server's clock, never the collector's.
"""
import fnmatch
import hashlib
import json
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

import astra_signing as SG
from astra_model.classes import CLASSES, EVENT_CONTROL
from astra_model.estate import Agent, Estate
from astra_model.events import conforms

LEGACY_TYPES = ("tool_call", "delegation", "mcp_connect", "memory_write", "data_access")
NEW_TYPES = ("exec", "goal_set", "msg", "id", "life", "spawn", "component", "delegation_in")
DEDUPE_MINUTES = 10

# the event type the collector sends -> the kind of event the model judges
KIND = {"tool_call": "tool_call", "delegation": "deleg_out", "delegation_in": "deleg_in", "data_access": "res_access", "memory_write": "mem_write", "mcp_connect": "component",
        "component": "component", "exec": "exec", "goal_set": "goal_set", "msg": "msg", "id": "id", "life": "life", "spawn": "spawn"}
# the wire types that carry each kind (to count what a collector really sends)
WIRE = {}
for _w, _k in KIND.items():
    WIRE.setdefault(_k, []).append(_w)

ASI_NAMES = {"ASI01": "Agent goal hijack", "ASI02": "Tool misuse and exploitation", "ASI03": "Identity and privilege abuse", "ASI04": "Agentic supply chain vulnerabilities",
             "ASI05": "Unexpected code execution", "ASI06": "Memory and context poisoning", "ASI07": "Insecure inter-agent communication", "ASI08": "Cascading failures",
             "ASI09": "Human-agent trust exploitation", "ASI10": "Rogue agents"}

# What a class needs from the collector, shown instead of claiming coverage the platform cannot have.
NEEDS = {
    "goal_set": "a goal_set event with the goal and where it came from (a semantic judgement arrives in its 'semantic' field)",
    "tool_call": "a tool_call event; parameters (numbers only) for bounds, 'prev_tool' for chains, 'confirmed' with 'presented_hash' and 'executed_hash' for write tools that need a person",
    "exec": "an exec event saying whether the code ran in the sandbox, and the host it reached",
    "res_access": "a data_access event with whether it wrote",
    "mem_write": "a memory_write event saying whether the write was validated and had provenance",
    "deleg_out": "a delegation event with its mode (and depth)",
    "deleg_in": "a delegation_in event with the source agent",
    "msg": "a msg event with the sender, the payload and its signature (or the collector's own verified flag)",
    "id": "an id event with the identity the agent claims",
    "life": "any life event (the server's clock decides)",
    "spawn": "a spawn event naming the child agent",
    "component": "a component event (or an mcp_connect) with whether it is signed and in the AIBOM",
    "score": "the behavioural baseline (a later phase)",
}


def class_state(cid: str) -> str:
    """What the platform can do about a class today: monitored | pending | later."""
    c = CLASSES[cid]
    return "later" if c.basis == "baseline" else ("pending" if c.basis == "semantic" else "monitored")


# ── Pure: the contract document as an agent of the model ────────────────────────────────────────────────────────

def _bounds(scope: Dict[str, Any]) -> Dict[str, Tuple[float, float]]:
    out = {}
    for k, v in (scope or {}).items():
        if isinstance(v, list) and len(v) == 2 and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in v) and v[0] <= v[1]:
            out[k] = (v[0], v[1])
    return out


def agent_from_contract(doc: Dict[str, Any]) -> Agent:
    ag = doc["agent"]
    tasks = doc.get("permitted_tasks", [])
    by_id = {t["id"]: t["tool"] for t in tasks}
    tools = {t["tool"]: _bounds(t.get("scope")) for t in tasks}
    write = {t["tool"] for t in tasks if (t.get("scope") or {}).get("access") == "write"}
    unattended = {by_id[i] for i in (doc.get("autonomy") or {}).get("unattended_actions", []) if i in by_id}
    hitl_text = [h.get("action", "") for h in (doc.get("autonomy") or {}).get("human_in_the_loop", [])]
    hitl = {t for t in tools if any(t in a for a in hitl_text)}
    chains = set()
    for t in tasks:
        for c in t.get("prohibited_chains", []):
            a, _, b = c.partition(" -> ")
            chains.add((by_id.get(a.strip(), a.strip()), by_id.get(b.strip(), b.strip())))
    rs, mem, dele = doc.get("resource_scopes") or {}, (doc.get("resource_scopes") or {}).get("memory") or {}, doc.get("delegation") or {}
    exp = date.fromisoformat(ag["lifecycle"]["expires"]).toordinal()
    suggest_only = write - (unattended | hitl)
    autonomy = "suggest" if write and suggest_only == write else "approve"
    return Agent(name=ag["id"], dept="", autonomy=autonomy, expires=exp, status=ag["lifecycle"]["status"], identity=ag["id"], tools=tools, write_tools=write,
                 hitl_tools=hitl, suggest_only_tools=suggest_only, prohibited_chains=chains, resources={d["resource"]: ("read" if d["access"] == "read" else "write") for d in rs.get("data", [])},
                 validated_memory=mem.get("writes", "unrestricted") == "validated", provenance_required=mem.get("writes", "unrestricted") == "validated",
                 long_term_memory=mem.get("default_context") == "persistent", may_delegate_to=set(dele.get("may_delegate_to", [])), accepts_from=set(dele.get("accepts_delegation_from", [])),
                 deleg_mode=dele.get("mode", "execution_only"), may_spawn=set(dele.get("may_delegate_to", [])))


def estate_of(agent: Agent) -> Estate:
    return Estate(agents={agent.name: agent}, res={}, tau={})


def apply_binding(bindings: List[Tuple[str, str, str]], element: str, name: str) -> str:
    """The contract name for an observed name: the first binding of that element whose selector (a glob) matches; otherwise the name itself."""
    for el, selector, target in bindings:
        if el == element and fnmatch.fnmatchcase(name, selector):
            return target
    return name


def verify_message(payload: str, signature: str, public: Optional[Ed25519PublicKey]) -> bool:
    if public is None:
        return False
    try:
        public.verify(bytes.fromhex(signature), payload.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def to_event(agent_id: str, wire: str, data: Dict[str, Any], bindings: List[Tuple[str, str, str]], today: int, *, registered: bool = False, peer: Optional[Ed25519PublicKey] = None) -> Dict[str, Any]:
    """The event the model judges, from what a collector sent. Attributes the collector left out stay absent, so the model reads the event as unverified."""
    kind = KIND[wire]
    name = str(data.get("name", "")).strip()
    ev: Dict[str, Any] = {"kind": kind, "agent": agent_id, "t": today}
    if kind == "tool_call":
        ev["tool"] = apply_binding(bindings, "tool", name)
        for k in ("params", "prev_tool", "confirmed", "presented_hash", "executed_hash"):
            if k in data:
                ev[k] = data[k]
        if "prev_tool" in ev:
            ev["prev_tool"] = apply_binding(bindings, "tool", ev["prev_tool"])
    elif kind == "deleg_out":
        ev["target"] = apply_binding(bindings, "delegate", name)
        for k in ("mode", "depth"):
            if k in data:
                ev[k] = data[k]
    elif kind == "deleg_in":
        ev["source"] = apply_binding(bindings, "delegate", name)
    elif kind == "res_access":
        ev["resource"] = apply_binding(bindings, "resource", name)
        ev["mode"] = "write" if data.get("write") else "read"
    elif kind == "mem_write":
        for k in ("validated", "provenance"):
            if k in data:
                ev[k] = data[k]
        if "scope" in data:
            ev["scope"] = data["scope"]
    elif kind == "component":
        ev["name"] = apply_binding(bindings, "component", name)
        if "signed" in data:
            ev["signed"] = bool(data["signed"]) and data.get("provenance") is not False         # provenance is part of being trusted (SUP-01)
        if "in_aibom" in data:
            ev["in_aibom"] = data["in_aibom"]
    elif kind == "exec":
        if "sandboxed" in data:
            ev["sandboxed"] = data["sandboxed"]
        if data.get("host"):
            ev["host"] = data["host"]
    elif kind == "goal_set":
        ev["goal"], ev["source"] = name, data.get("source", "")
        if "source" not in data:
            ev.pop("source")
        if data.get("semantic"):
            ev["semantic"] = data["semantic"]
        if not name:
            ev.pop("goal")
    elif kind == "msg":
        if data.get("signature") and data.get("payload") is not None:
            ev["verified"] = verify_message(str(data["payload"]), str(data["signature"]), peer)            # checked here, never taken from the collector
        elif "verified" in data:
            ev["verified"] = bool(data["verified"])
            ev["asserted"] = True
        ev["sender"] = name
    elif kind == "id":
        if name:
            ev["claimed"] = name
    elif kind == "life":
        ev["now_t"] = today                                                                              # the server's clock
    elif kind == "spawn":
        if name:
            ev["child"] = apply_binding(bindings, "delegate", name)
            ev["inventoried"] = registered                                                                   # the platform's own inventory
    return ev


def _permitted(agent: Agent, cid: str) -> str:
    return {"TOOL": "tools: " + (", ".join(sorted(agent.tools)) or "none"), "RES": "data: " + (", ".join(sorted(agent.resources)) or "none"),
            "DEL": "delegates to: " + (", ".join(sorted(agent.may_delegate_to)) or "none") + " (" + agent.deleg_mode + ")", "MEM": "memory writes: " + ("validated" if agent.validated_memory else "unrestricted"),
            "ID": "identity: " + str(agent.identity), "LIFE": f"status {agent.status}, expires day {agent.expires}", "SPAWN": "may spawn: " + (", ".join(sorted(agent.may_spawn)) or "none"),
            "AUT": "human in the loop: " + (", ".join(sorted(agent.hitl_tools)) or "none"), "EXEC": "sandboxed, no egress listed", "SUP": "signed and in the AIBOM",
            "COMM": "authenticated messages", "GOAL": "the permitted goals"}.get(cid.split("-")[1], "see the contract")


def _observed(ev: Dict[str, Any]) -> str:
    skip = {"agent", "t", "kind", "presented_hash", "executed_hash"}
    return ev["kind"] + " " + ", ".join(f"{k}={v}" for k, v in sorted(ev.items()) if k not in skip)[:240]


def finding_fields(cid: str, ev: Dict[str, Any], agent: Agent, pending: bool, contract_id: str, version: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    c = CLASSES[cid]
    obs = _observed(ev)
    evidence_hash = hashlib.sha256(json.dumps({"agent": ev["agent"], "contract": contract_id, "event": raw}, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return dict(severity="High" if c.severity == "Critical" else c.severity, class_severity=c.severity, title=f"{c.name}: {obs}"[:300], class_code=cid, observed=obs, permitted=_permitted(agent, cid),
                element=c.element[:40], threat=f"{c.asi[0]} {ASI_NAMES.get(c.asi[0], '')}".strip(), detection_basis=c.basis, contract_element=c.element[:60], construct=c.construct[:60],
                asi_signal=list(c.asi), evidence=f"sha256:{evidence_hash[:16]} · event {uuid.uuid4().hex[:6]}", contract_id=contract_id, contract_version=version,
                adjudication="PENDING" if pending else None)


# ── Database ────────────────────────────────────────────────────────────────────────────────────────────────

class Judge:
    """One agent's signed contract, bindings and peer keys, loaded once for a batch."""

    def __init__(self, key: str, org_id: uuid.UUID, row: Any, why: List[str], agent: Optional[Agent], bindings: List[Tuple[str, str, str]], peers: Dict[str, Tuple[str, Ed25519PublicKey]]):
        self.key, self.org_id, self.row, self.why, self.agent, self.bindings, self.peers = key, org_id, row, why, agent, bindings, peers
        self.today = date.today().toordinal()

    @classmethod
    def load(cls, session: Session, org_id: uuid.UUID, key: str) -> Optional["Judge"]:
        from db.models import AstraBinding, AstraPeerKey, AstraSignedContract
        rows = list(session.scalars(select(AstraSignedContract).where(AstraSignedContract.organisation_id == org_id, AstraSignedContract.agent_key == key).order_by(AstraSignedContract.signed_at.desc())))
        if not rows:
            return None
        row = next((r for r in rows if r.status == "ACTIVE"), None)
        why: List[str] = []
        agent = None
        if row is None:
            why = [f"its latest signed contract is {rows[0].status.lower()}"]
        else:
            try:
                keys = SG.load_public_keys()
            except SG.SigningError as exc:
                keys, why = {}, [str(exc)]
            now = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
            why = why or SG.verify({"document": row.document, "contract_hash": row.contract_hash, "key_id": row.key_id, "signature": row.signature, "not_before": row.not_before,
                                    "expires_at": row.expires_at, "status": row.status}, keys, now)
            if not why:
                agent = agent_from_contract(row.document)
        binds = [(b.element, b.selector, b.contract_name) for b in session.scalars(select(AstraBinding).where(AstraBinding.organisation_id == org_id, AstraBinding.agent_key == key).order_by(AstraBinding.created_at))]
        peers = {p.key_id: (p.agent_key, Ed25519PublicKey.from_public_bytes(SG._b64d(p.public_key))) for p in session.scalars(select(AstraPeerKey).where(AstraPeerKey.organisation_id == org_id))}
        return cls(key, org_id, row, why, agent, binds, peers)

    @property
    def version(self) -> Optional[str]:
        return self.row.version if self.row is not None else None

    def run(self, session: Session, wire: str, data: Dict[str, Any], now: datetime) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """(verdict, finding key, attributes to record). Verdicts: CONFORMING, DIVERGENT, UNVERIFIED, PENDING."""
        from db.models import Agent as AgentRow
        from db.models import Finding
        if self.agent is None:
            return "UNVERIFIED", None, {"missing": ["a valid contract: " + "; ".join(self.why)], "basis": "contract"}
        agent_id = self.agent.name
        registered = False
        peer = None
        if wire == "spawn":
            from agent_registry import agent_key
            registered = session.scalar(select(AgentRow.id).where(AgentRow.organisation_id == self.org_id, AgentRow.agent_key == agent_key(str(data.get("name", ""))))) is not None
        if wire == "msg" and data.get("key_id") in self.peers:
            owner, pub = self.peers[data["key_id"]]
            peer = pub if owner == str(data.get("name", "")).strip() else None                 # a key only speaks for the agent it was registered for
        ev = to_event(agent_id, wire, data, self.bindings, self.today, registered=registered, peer=peer)
        res = conforms(estate_of(self.agent), ev)
        extra: Dict[str, Any] = {"classes": res["classes"], "missing": res["missing"]}
        if ev.get("asserted"):
            extra["asserted"] = True
        if res["outcome"] == "CONFORMS" or res["outcome"] == "ADVISORY":
            return "CONFORMING", None, {k: v for k, v in extra.items() if v}
        if res["outcome"] == "UNVERIFIED":
            return "UNVERIFIED", None, {k: v for k, v in extra.items() if v}
        pending = res["outcome"] == "PENDING"
        recent = now - timedelta(minutes=DEDUPE_MINUTES)
        first = None
        for cid in res["classes"]:
            f = finding_fields(cid, ev, self.agent, pending, str(self.row.id), self.row.version, data)
            twin = session.scalar(select(Finding).where(Finding.agent_key == self.key, Finding.class_code == cid, Finding.observed == f["observed"], Finding.status == "OPEN",
                                                        Finding.created_at > recent).order_by(Finding.created_at.desc()))
            if twin is None:
                twin = Finding(organisation_id=self.org_id, agent_key=self.key, event=data, source="COLLECTED", **f)
                session.add(twin)
                session.flush()
            first = first or f"F-{twin.seq}"
        return ("PENDING" if pending else "DIVERGENT"), first, {k: v for k, v in extra.items() if v}
