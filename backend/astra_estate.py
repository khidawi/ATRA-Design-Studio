"""
The estate builder (ASTRA phase 3): an agent design, the organisation and the risk layer become the formal model of astra_model, and the model is read back as
attack paths and a risk vector. Pure functions over plain data; astra_assessment_api.py fetches what they need from the database.

What the design says becomes the estate:
    uses -> tools (write-capable when the tool says so), gated by an approval -> the tools that need human confirmation
    reads / stores -> resources (data, memory); feeds (untrusted input) -> the inputs a path starts from
    connects -> MCP servers (components whose signature is required); delegates -> other agents
Where the organisation graph knows the agent, its department is the agent's. A data node that matches a data store of the organisation by name takes that store's department
and its ratified impact tier. Everything that does not match is kept, and reported, with the strictest reading: tier 4 in the agent's department.

Control statuses come from the existing OWASP checks run on the design (rows: id, status, why), never from a second set of rules:
    a check that fails (Gap, or Partial with a reason that is not an invalid check)    VIOLATED: the design shows the control is missing
    a check that passes                                                                UNVERIFIED, unless an attested, unexpired, intact evidence record
                                                                                        with control key "astra:<kind>" backs it: then SATISFIED until it lapses
    no check for the control, or a check that does not apply                           UNVERIFIED: nothing in the design or the evidence supports it
    no MCP servers declared                                                            NOT_APPLICABLE, with the check's own reason as the rationale
A design that fails a check is not rescued by evidence: the gap wins and the evidence is reported.

Approximations, all in the strict direction, and listed in the result's "limits":
    * the design does not say which data a write tool changes, so when the agent has any write tool every data node is treated as writable;
    * a path starts only at an untrusted input the design declares, so a design that declares none has no paths;
    * an agent it delegates to that is not in the inventory with a saved design is included with no resources and its controls unassessed, and its reach is reported as unknown.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from astra_model import estate as E_
from astra_model import exposure, gate, statuses
from astra_model.estate import Agent, Estate
from astra_model.statuses import NA, SAT, UNV, VIO, State
import risk_layer

UNASSIGNED = "(unassigned)"
ASI_OF = {"iso": "ASI01", "hitl": "ASI02", "least": "ASI03", "supply": "ASI04", "memval": "ASI06", "deleg": "ASI07", "ident": "ASI10", "life": "ASI10"}
AUTONOMY = {"suggests": "suggest", "approval": "approve", "autonomous": "auto"}
LIMITS = [
    "The design does not say which data a write tool changes, so when the agent has a write tool every data node counts as writable.",
    "A path starts only at an untrusted input that the design declares; a design that declares none has no paths.",
    "Control statuses come from the existing OWASP checks on the design and from attested evidence records with the control key astra:<kind>; the Probe adds more in a later phase.",
    "An agent it delegates to that is not in the inventory with a saved design is included with no resources: what it can reach is unknown.",
]


@dataclass
class Source:
    """One agent design as the builder reads it."""
    doc: Dict[str, Any]
    rows: List[Dict[str, Any]]                       # the OWASP check rows: id, status (Covered, Partial, Gap, Not applicable), why
    evidence: Dict[str, Optional[int]] = field(default_factory=dict)      # control key -> day number its attestation lapses (None: it does not)


@dataclass
class Ctx:
    dept_of_agent: Dict[str, str] = field(default_factory=dict)          # lower-case agent name -> department ext id
    dept_names: Dict[str, str] = field(default_factory=dict)
    stores: Dict[str, Dict[str, Any]] = field(default_factory=dict)      # lower-case data store name -> {"ext", "department"}
    tiers: Dict[str, int] = field(default_factory=dict)                  # data store ext id -> ratified impact tier
    tolerance: Dict[str, int] = field(default_factory=dict)              # department ext id -> ratified tolerance
    others: Dict[str, Source] = field(default_factory=dict)              # lower-case agent name -> its saved design, for the agents it delegates to


@dataclass
class Built:
    estate: Estate
    state: State
    why: Dict[Tuple[str, str], str]
    resources: Dict[str, Dict[str, Any]]
    notes: List[str]
    unmapped: List[Dict[str, str]]
    primary: str


def _targets(doc: Dict[str, Any], src_id: str, label: str) -> List[Dict[str, Any]]:
    by_id = {n["id"]: n for n in doc.get("nodes", [])}
    return [by_id[e["to"]] for e in doc.get("edges", []) if e.get("from") == src_id and e.get("label") == label and e["to"] in by_id]


def _primary(doc: Dict[str, Any]) -> Dict[str, Any]:
    p = next((n for n in doc.get("nodes", []) if n.get("primary") and n.get("type") == "agent"), None)
    if p is None or not str(p.get("name", "")).strip():
        raise ValueError("The design needs a primary agent with a name.")
    return p


def _norm(s: Any) -> str:
    return " ".join(str(s or "").split()).lower()


def _statuses_for(name: str, src: Source, built: "Built") -> None:
    rows = {r["id"]: r for r in src.rows}
    S, why = built.state, built.why
    for kind, code in ASI_OF.items():
        r = rows.get(code)
        ctl = (kind, name)
        if r is None:
            why[ctl] = f"no check for {code} on this design"
            continue
        st, text = r["status"], r.get("why") or ""
        invalid = text.startswith("This check is invalid")
        if st == "Gap" or (st == "Partial" and not invalid):
            statuses.adverse(S, ctl, VIO)
            why[ctl] = f"{code}: {text}"
        elif st == "Not applicable":
            if kind == "supply":
                statuses.mark_not_applicable(S, ctl, text or "no MCP servers declared")
                why[ctl] = f"{code}: {text}"
            else:
                why[ctl] = f"{code} does not apply to this design: {text}"
        elif st == "Covered":
            key = f"astra:{kind}"
            if key in src.evidence:
                statuses.support(S, ctl, "attestation", 0, float("inf") if src.evidence[key] is None else src.evidence[key])
                S.fresh[ctl] = float("inf") if src.evidence[key] is None else src.evidence[key]
                why[ctl] = f"{code}: {text}. Attested evidence on file."
            else:
                why[ctl] = f"{code}: {text}. Declared in the design; no attested evidence."
        else:
            why[ctl] = f"{code}: {text}"
    why.setdefault(("auth", name), "the design does not say how delegated messages are authenticated")


def _make_agent(name: str, src: Source, ctx: Ctx, built: "Built", seen: Set[str]) -> Agent:
    doc = src.doc
    prim = _primary(doc)
    tools = _targets(doc, prim["id"], "uses")
    write = {t["name"] for t in tools if (t.get("p") or {}).get("write")}
    by_id = {n["id"]: n for n in doc.get("nodes", [])}
    gated = {by_id[e["to"]]["name"] for e in doc.get("edges", []) if e.get("label") == "gates" and e.get("to") in by_id and by_id[e["to"]].get("type") == "tool"
             and by_id.get(e.get("from"), {}).get("type") == "approval"}
    dept = ctx.dept_of_agent.get(_norm(name))
    if dept is None:
        dept = UNASSIGNED
        built.notes.append(f"{name} is not linked to a department in the organisation: its resources fall in {UNASSIGNED}, which accepts nothing.")
    untrusted = {n["name"] for n in doc.get("nodes", []) if n.get("type") in ("input", "external") and (n.get("p") or {}).get("untrusted")
                 and any(e.get("from") == n["id"] and e.get("to") == prim["id"] for e in doc.get("edges", []))}
    resources: Dict[str, str] = {}
    for kind, label in (("data", "reads"), ("memory", "stores")):
        for n in _targets(doc, prim["id"], label):
            store = ctx.stores.get(_norm(n["name"])) if kind == "data" else None
            if store is not None:
                rid, rdept, tier = store["ext"], store.get("department") or dept, ctx.tiers.get(store["ext"], risk_layer.DEFAULT_TIER)
                declared = store["ext"] in ctx.tiers
            else:
                rid, rdept, tier, declared = f"unmapped:{name}:{n['name']}", dept, risk_layer.DEFAULT_TIER, False
                built.unmapped.append({"agent": name, "node": n["name"], "kind": kind, "reason": "not a data store of the organisation" if kind == "data" else "agent memory has no organisation record"})
            built.estate.res[rid] = (rdept, tier, "data" if kind == "data" else "memory")
            built.resources[rid] = {"name": n["name"], "department_ext": rdept, "tier": tier, "declared": declared, "matched": store is not None}
            resources[rid] = "write" if (kind == "memory" or write) else "read"
    delegates = [n["name"] for n in _targets(doc, prim["id"], "delegates")]
    agent = Agent(name, dept, autonomy=AUTONOMY.get((prim.get("p") or {}).get("auto"), "approve"), tools={t["name"]: {} for t in tools}, write_tools=write, hitl_tools=write & gated,
                  resources=resources, may_delegate_to=set(delegates), components={n["name"]: True for n in _targets(doc, prim["id"], "connects")}, inputs=untrusted,
                  long_term_memory=any((n.get("p") or {}).get("long") for n in _targets(doc, prim["id"], "stores")))
    built.estate.agents[name] = agent
    _statuses_for(name, src, built)
    seen.add(_norm(name))
    for d in delegates:
        if _norm(d) in seen or d in built.estate.agents:
            continue
        other = ctx.others.get(_norm(d))
        if other is not None:
            _make_agent(d, other, ctx, built, seen)
        else:
            built.estate.agents[d] = Agent(d, UNASSIGNED)
            built.notes.append(f"{d} is not in the inventory with a saved design: what it can reach is unknown.")
            built.unmapped.append({"agent": d, "node": d, "kind": "agent", "reason": "delegate with no saved design"})
    return agent


def build(primary: Source, ctx: Ctx) -> Built:
    name = str(_primary(primary.doc)["name"]).strip()
    built = Built(Estate({}, {}, {}), State(), {}, {}, [], [], name)
    _make_agent(name, primary, ctx, built, set())
    for _rid, (dept, _tier, _kind) in built.estate.res.items():
        built.estate.tau.setdefault(dept, ctx.tolerance.get(dept, risk_layer.DEFAULT_TOLERANCE))
    bad = E_.problems(built.estate)
    if bad:
        raise ValueError("The estate could not be built: " + "; ".join(bad[:3]))
    return built


# What closes a control that the design shows to be missing. "fix" is an action the studio already offers for the check (studio FIX[asi]); the rest a person does.
FIXES = {
    "iso": ("ASI01", "Add a prompt-injection filter", "Untrusted input can reach the agent without a filter that limits it."),
    "hitl": ("ASI02", "Put a human approval on every write tool", "A write action on a severe asset can run without a person confirming it."),
    "supply": ("ASI04", "Require signed MCP servers", "An MCP server the agent connects to is not signed."),
    "memval": ("ASI06", "Limit how long memory is kept", "Long-term memory has no retention limit."),
}
OWNER = ("Name an accountable owner for the agent", "The agent has no named owner, so nobody holds its identity and lifecycle.")


def suggest(b: Built, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The controls that keep the verdict down, with what to do about each, the most severe first. Only paths that are not approved count: a path the department accepts needs nothing."""
    need: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for p in paths:
        if p["verdict"] == "APPROVED":
            continue
        for c in p["controls"]:
            if c["status"] in ("VIO", "UNV"):
                e = need.setdefault((c["kind"], c["agent"]), {"state": c["status"], "tier": 0, "paths": 0, "why": c["why"]})
                e["tier"], e["paths"] = max(e["tier"], p["tier"]), e["paths"] + 1
                if c["status"] == "VIO":
                    e["state"], e["why"] = "VIO", c["why"]
    out = []
    for (kind, agent), e in need.items():
        mine = agent == b.primary
        s = {"id": f"{kind}:{agent}", "kind": kind, "agent": agent, "state": e["state"], "tier": e["tier"], "paths": e["paths"], "control_key": f"astra:{kind}", "asi": None}
        if e["state"] == "VIO" and mine and kind in FIXES:
            s.update(action="fix", asi=FIXES[kind][0], label=FIXES[kind][1], why=FIXES[kind][2])
        elif e["state"] == "VIO" and mine and kind in ("ident", "life"):
            s.update(action="manual", label=OWNER[0], why=OWNER[1])
        elif e["state"] == "VIO":
            s.update(action="manual", label=f"Close the gap in {kind} for {agent}" + ("" if mine else f": fix it in the design of {agent}"), why=e["why"])
        else:
            s.update(action="manual", label=f"Attach attested evidence for {kind}" + ("" if mine else f" ({agent})"),
                     why=f"Declared but unverified: {e['why']} A record with control key astra:{kind}, attested by someone independent, makes it satisfied.")
        out.append(s)
    out.sort(key=lambda s: (s["state"] != "VIO", -s["tier"], s["kind"], s["agent"]))
    return out


def describe(b: Built, ctx: Ctx, now: float) -> Dict[str, Any]:
    """The result the API serves: verdict, risk vector, paths with their controls."""
    E, S = b.estate, b.state
    paths, per_dept = [], {}
    for i, p in enumerate(exposure.paths(E), 1):
        v = gate.path_verdict(E, S, now, p)
        rid = p[2]
        meta = b.resources.get(rid, {"name": rid})
        dept = E.res[rid][0]
        ctls = []
        for c in sorted(exposure.required(E, p)):
            st = S.status(c, now)
            ctls.append({"kind": c[0], "agent": c[1], "status": st, "why": S.rationale.get(c) or b.why.get(c) or "nothing in the design or the evidence supports it"})
        paths.append({"id": f"P{i}", "input": p[0], "chain": list(p[1]), "resource": rid, "resource_name": meta.get("name", rid), "mode": p[3], "tier": E.res[rid][1],
                      "department_ext": dept, "department": ctx.dept_names.get(dept, dept), "tier_declared": meta.get("declared", False), "verdict": gate.VERDICT_NAME[v], "controls": ctls})
        per_dept[dept] = min(per_dept.get(dept, gate.APPROVED), v)
    risk = gate.department_risk(E, S, now)
    depts = [{"department_ext": d, "department": ctx.dept_names.get(d, d), "highest_open_tier": risk.get(d, 0), "tolerance": t, "tolerance_declared": d in ctx.tolerance,
              "verdict": gate.VERDICT_NAME[per_dept.get(d, gate.APPROVED)]} for d, t in sorted(E.tau.items())]
    v = gate.gate(E, S, now)
    return {"agent": b.primary, "verdict": gate.VERDICT_NAME[v], "runtime_name": gate.RUNTIME_NAME[v], "departments": depts, "paths": paths,
            "agents": sorted(E.agents), "suggestions": suggest(b, paths), "unmapped": b.unmapped, "notes": b.notes, "limits": LIMITS}
