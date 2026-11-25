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

Four readings go beyond the OWASP rows, because the rows cannot see them (found by the seeded-flaw test, docs/validation/astra-design-time-benchmark-2026-11-25):
    * least privilege (ASI03): the check is satisfied by declaring tool scopes, so it cannot see an agent that reaches a store it does not need. A data store above the tolerance of its
      department counts as needed only if the design says why (a purpose on the data node); without one the control cannot be satisfied, whatever the evidence says;
    * cascading failure (ASI08): a missing rate limit is a gap in the delegation control of an agent that delegates, where a failure can cascade; for an agent that delegates to no one it is
      reported as advisory, with ASI09 (disclosure, a transparency duty, not an exposure path);
    * code execution (ASI05): a tool marked as running code makes the sandbox control required, and a design with no sandbox constraint violates it;
    * a delegate with no saved design is read at its strictest: it may write to a tier-4 resource in no known department, until its design is saved;
    * an agent the organisation does not know (no department) cannot have its identity control satisfied, whatever the evidence says: nobody in the organisation is accountable for it;
    * an approval that gates the agent itself covers every tool the agent uses, so the confirmation is carried into the contract as it is by the check;
    * the injection check (ASI01) applies only where an injected instruction can change something: an agent with no write-capable tool has that control not applicable, with the reason recorded.

Approximations, all in the strict direction, and listed in the result's "limits":
    * the design does not say which data a write tool changes, so when the agent has any write tool every data node is treated as writable;
    * a path starts only at an untrusted input the design declares, so a design that declares none has no paths;
    * an agent it delegates to that is not in the inventory with a saved design is assumed to reach a tier-4 resource in no known department, and its controls are unassessed.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from astra_model import estate as E_
from astra_model import exposure, gate, statuses
from astra_model.estate import Agent, Estate
from astra_model.statuses import NA, SAT, UNV, VIO, State
import risk_layer

UNASSIGNED = "(unassigned)"
WARN_PATHS = 500                                  # beyond this the assessment says the design is large
MAX_PATHS = 5000                                  # beyond this it is refused: the number of paths multiplies with every input, delegation and resource
ASI_OF = {"iso": "ASI01", "hitl": "ASI02", "least": "ASI03", "supply": "ASI04", "memval": "ASI06", "deleg": "ASI07", "ident": "ASI10", "life": "ASI10"}
AUTONOMY = {"suggests": "suggest", "approval": "approve", "autonomous": "auto"}
LIMITS = [
    "The design does not say which data a write tool changes, so when the agent has a write tool every data node counts as writable.",
    "A path starts only at an untrusted input that the design declares; a design that declares none has no paths.",
    "Control statuses come from the existing OWASP checks on the design and from attested evidence records with the control key astra:<kind>; an ASTRA Probe run of this version of the design adds more (a pass for a control the design does not show to be missing, a miss for any).",
    "An agent it delegates to that is not in the inventory with a saved design is assumed to be able to write to a tier-4 resource in no known department: what it can reach is unknown, so the strictest reading applies until its design is saved.",
    "A data store above its department's tolerance counts as needed only if the design gives a purpose on the data node; the design cannot yet say which of an agent's tools needs which store.",
    "A missing rate limit (ASI08) lowers the verdict only for an agent that delegates, and a missing AI disclosure (ASI09) is advisory: neither is an exposure path.",
]


@dataclass
class Source:
    """One agent design as the builder reads it."""
    doc: Dict[str, Any]
    rows: List[Dict[str, Any]]                       # the OWASP check rows: id, status (Covered, Partial, Gap, Not applicable), why
    evidence: Dict[str, Optional[int]] = field(default_factory=dict)      # control key -> day number its attestation lapses (None: it does not)
    probe: Dict[str, Tuple[bool, Optional[int]]] = field(default_factory=dict)   # control kind -> (the newest Probe run passed, the day number a pass lapses)
    monitored: bool = False                                                       # a behavioural baseline is calibrated for this agent: its baseline control is required


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
    advisory: List[Dict[str, str]] = field(default_factory=list)      # failing checks that are reported but are not part of the verdict


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
            elif kind == "iso" and not built.estate.agents[name].write_tools:        # the check applies only where an injected instruction can change something
                statuses.mark_not_applicable(S, ctl, "no write-capable tool, so an injected instruction has nothing to change")
                why[ctl] = f"{code}: {text}. The agent has no write-capable tool."
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
    if built.estate.agents[name].baseline_monitored:
        ctl = ("base", name)
        text = "A behavioural baseline is calibrated for this agent, so the baseline control is required. It stays unverified until an ASTRA Probe run or an attested record with the control key astra:base validates the calibration."
        if "astra:base" in src.evidence:
            statuses.support(S, ctl, "attestation", 0, float("inf") if src.evidence["astra:base"] is None else src.evidence["astra:base"])
            S.fresh[ctl] = float("inf") if src.evidence["astra:base"] is None else src.evidence["astra:base"]
            text += " Attested evidence on file."
        why[ctl] = text
    for kind, (ok, until) in sorted(src.probe.items()):
        ctl = (kind, name)
        if not ok:
            statuses.adverse(S, ctl, VIO)                    # a planted defect that was not caught: the control does not work
            why[ctl] = f"ASTRA Probe: a scenario for {kind} was not caught by the reconciler. " + why.get(ctl, "")
        elif S.st.get(ctl) not in (VIO, NA) and not (S.st.get(ctl) == SAT and S.fresh.get(ctl, float("inf")) >= (float("inf") if until is None else until)):    # a pass never rescues a control the design shows to be missing
            statuses.support(S, ctl, "probe_pass", 0, float("inf") if until is None else until)
            S.fresh[ctl] = float("inf") if until is None else until
            why[ctl] = (why.get(ctl, "") + " Verified by an ASTRA Probe run.").strip()
    agent = built.estate.agents[name]
    r8 = rows.get("ASI08")
    if r8 is not None and _failing(r8):
        if agent.may_delegate_to:                        # a failure here can cascade to the agents it delegates to
            statuses.adverse(S, ("deleg", name), VIO)
            why[("deleg", name)] = f"ASI08: {r8.get('why') or 'no rate limit'}. The agent delegates, so one failure can cascade."
        else:
            built.advisory.append({"agent": name, "code": "ASI08", "why": r8.get("why") or "no rate limit", "reason": "the agent delegates to no one, so there is no path for a cascade: reported, not part of the verdict"})
    r9 = rows.get("ASI09")
    if r9 is not None and _failing(r9):
        built.advisory.append({"agent": name, "code": "ASI09", "why": r9.get("why") or "no AI disclosure", "reason": "a transparency duty, not an exposure path: reported, not part of the verdict"})
    if agent.runs_code:
        ctl = ("sandbox", name)
        if not any(n.get("type") == "constraint" and (n.get("p") or {}).get("kind") == "sandbox" for n in src.doc.get("nodes", [])):
            statuses.adverse(S, ctl, VIO)
            why[ctl] = "ASI05: the agent can run code and the design declares no sandbox constraint"
        elif "astra:sandbox" in src.evidence and S.st.get(ctl) != VIO:         # a failed Probe scenario is not rescued by an attestation
            statuses.support(S, ctl, "attestation", 0, float("inf") if src.evidence["astra:sandbox"] is None else src.evidence["astra:sandbox"])
            S.fresh[ctl] = float("inf") if src.evidence["astra:sandbox"] is None else src.evidence["astra:sandbox"]
            why[ctl] = "ASI05: a sandbox is declared in the design. Attested evidence on file."
        else:
            why[ctl] = "ASI05: a sandbox is declared in the design; no attested evidence."
    if "astra:auth" in src.evidence and agent.may_delegate_to and S.st.get(("auth", name)) != VIO:      # an attested record that delegated messages are authenticated
        statuses.support(S, ("auth", name), "attestation", 0, float("inf") if src.evidence["astra:auth"] is None else src.evidence["astra:auth"])
        S.fresh[("auth", name)] = float("inf") if src.evidence["astra:auth"] is None else src.evidence["astra:auth"]
        why[("auth", name)] = "Delegated messages are authenticated. Attested evidence on file."
    why.setdefault(("auth", name), "the design does not say how delegated messages are authenticated")


def _failing(r: Dict[str, Any]) -> bool:
    return r["status"] == "Gap" or (r["status"] == "Partial" and not (r.get("why") or "").startswith("This check is invalid"))


def _make_agent(name: str, src: Source, ctx: Ctx, built: "Built", seen: Set[str]) -> Agent:
    doc = src.doc
    prim = _primary(doc)
    tools = _targets(doc, prim["id"], "uses")
    write = {t["name"] for t in tools if (t.get("p") or {}).get("write")}
    by_id = {n["id"]: n for n in doc.get("nodes", [])}
    gated = {by_id[e["to"]]["name"] for e in doc.get("edges", []) if e.get("label") == "gates" and e.get("to") in by_id and by_id[e["to"]].get("type") == "tool"
             and by_id.get(e.get("from"), {}).get("type") == "approval"}
    gates_agent = any(e.get("label") == "gates" and e.get("to") == prim["id"] and by_id.get(e.get("from"), {}).get("type") == "approval" for e in doc.get("edges", []))   # an approval on the agent covers every tool it uses
    dept = ctx.dept_of_agent.get(_norm(name))
    unlinked = dept is None
    if dept is None:
        dept = UNASSIGNED
        built.notes.append(f"{name} is not linked to a department in the organisation: its resources fall in {UNASSIGNED}, which accepts nothing.")
    untrusted = {n["name"] for n in doc.get("nodes", []) if n.get("type") in ("input", "external") and (n.get("p") or {}).get("untrusted")
                 and any(e.get("from") == n["id"] and e.get("to") == prim["id"] for e in doc.get("edges", []))}
    resources: Dict[str, str] = {}
    unjustified: List[str] = []                                   # data stores above the department's tolerance for which the design gives no purpose
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
            if kind == "data" and tier > ctx.tolerance.get(rdept, risk_layer.DEFAULT_TOLERANCE) and not str((n.get("p") or {}).get("purpose") or "").strip():
                unjustified.append(f"{n['name']} (tier {tier})")
    delegates =[n["name"] for n in _targets(doc, prim["id"], "delegates")]
    agent = Agent(name, dept, autonomy=AUTONOMY.get((prim.get("p") or {}).get("auto"), "approve"), tools={t["name"]: {} for t in tools}, write_tools=write, hitl_tools=write if gates_agent else write & gated,
                  resources=resources, may_delegate_to=set(delegates), components={n["name"]: True for n in _targets(doc, prim["id"], "connects")}, inputs=untrusted, baseline_monitored=src.monitored,
                  long_term_memory=any((n.get("p") or {}).get("long") for n in _targets(doc, prim["id"], "stores")),
                  runs_code=any((t.get("p") or {}).get("code") for t in tools))
    built.estate.agents[name] = agent
    _statuses_for(name, src, built)
    if unlinked:                                                   # nobody in the organisation is accountable for an agent it does not know; evidence cannot stand in for that
        statuses.adverse(built.state, ("ident", name), UNV)
        built.why[("ident", name)] = (f"ASI10: {name} is not linked to a department in the organisation, so nobody in it is accountable for the agent. "
                                      "Add the agent to the organisation.")
    if unjustified:                                                # least privilege: access the department does not accept has to be explained, and evidence cannot stand in for that
        statuses.adverse(built.state, ("least", name), UNV)
        built.why[("least", name)] = (f"ASI03: the design gives no purpose for {', '.join(unjustified)}, which the department's tolerance does not accept; "
                                      "declared tool scopes do not show that the agent needs this data. Add a purpose to the data node.")
    seen.add(_norm(name))
    for d in delegates:
        if _norm(d) in seen or d in built.estate.agents:
            continue
        other = ctx.others.get(_norm(d))
        if other is not None:
            _make_agent(d, other, ctx, built, seen)
        else:
            rid = f"unknown-reach:{d}"                                 # the strictest reading: it may write to a tier-4 resource in no known department
            built.estate.res[rid] = (UNASSIGNED, 4, "data")
            built.resources[rid] = {"name": f"what {d} can reach (unknown)", "department_ext": UNASSIGNED, "tier": 4, "declared": False, "matched": False}
            built.estate.agents[d] = Agent(d, UNASSIGNED, resources={rid: "write"})
            built.notes.append(f"{d} is not in the inventory with a saved design: what it can reach is unknown, so it is read at its strictest (a write to a tier-4 resource) until its design is saved.")
            built.unmapped.append({"agent": d, "node": d, "kind": "agent", "reason": "delegate with no saved design"})
    return agent


def bound(E: Estate, notes: List[str]) -> int:
    """Check the size of the estate before any path is built: refuse one that is too large, and warn about one that is large. Returns the number of paths (or the limit it stopped at)."""
    n = exposure.count_paths(E, MAX_PATHS)
    if n > MAX_PATHS:
        raise ValueError(f"The estate has more than {MAX_PATHS} attack paths (an untrusted input times every delegation chain times every resource). Narrow the design: fewer untrusted inputs, fewer delegations or fewer data stores.")
    if n > WARN_PATHS:
        notes.append(f"This estate has {n} attack paths, which is large: the assessment is slow to read and the verdict is dominated by the worst of them. Consider narrowing the design.")
    return n


def build(primary: Source, ctx: Ctx) -> Built:
    name = str(_primary(primary.doc)["name"]).strip()
    built = Built(Estate({}, {}, {}), State(), {}, {}, [], [], name, [])
    _make_agent(name, primary, ctx, built, set())
    for _rid, (dept, _tier, _kind) in built.estate.res.items():
        built.estate.tau.setdefault(dept, ctx.tolerance.get(dept, risk_layer.DEFAULT_TOLERANCE))
    bad = E_.problems(built.estate)
    if bad:
        raise ValueError("The estate could not be built: " + "; ".join(bad[:3]))
    bound(built.estate, built.notes)
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
        elif e["state"] == "UNV" and kind == "ident" and "not linked to a department" in e["why"]:
            s.update(action="manual", label="Add the agent to the organisation, in a department" + ("" if mine else f" ({agent})"), why=e["why"])
        elif e["state"] == "UNV" and kind == "least" and "gives no purpose" in e["why"]:
            s.update(action="manual", label="Say why the agent needs this data: add a purpose to the data node" + ("" if mine else f" ({agent})"), why=e["why"])
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
            "agents": sorted(E.agents), "suggestions": suggest(b, paths), "unmapped": b.unmapped, "notes": b.notes, "advisory": b.advisory, "limits": LIMITS}
