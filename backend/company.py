"""
The organisation model (Task 13): departments, people and roles, outside parties, the AI agents and models that work for them,
the data they touch, and the modelling elements around them (goals, operations, policies, threats, protections, rules, breach plan steps).

One model, several views: the Studio draws the organisation map, the organisational view, agents and tasks, data mapping,
privacy by design, the breach response plan and the model view from the same nodes and edges. Nothing here changes the agent
inventory, contracts or findings: the model only READS them, to show whether a handoff drawn between two agents is declared in the
sender's active contract and whether the runtime SDK has seen it, and which registered agents are not in the organisation yet.

Input is a JSON or YAML file, a plain-English description to a local model (proposals only), or editing by hand. An import adds and
updates by the company's own ids (EMP-1042, D-CX); it never deletes. Checks are deterministic code over the stored model.
"""
import hashlib
import json
import re
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

import agent_contract
import audit
from agent_registry import agent_key as to_agent_key
from auth import AuthUser, current_user
from db.models import Agent, CompanyDraftCache, CompanyEdge, CompanyNode, Contract, Design, DriftItem, Finding, RuntimeEvent
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/company", tags=["company"])

MAX_FILE = 512_000
NODE_TYPES = ("department", "person", "role", "external", "agent", "model", "data_store", "goal", "operation", "policy",
              "threat", "protection", "rule", "environment", "step", "decision")
ELEMENT_TYPES = ("goal", "operation", "policy", "threat", "protection", "rule", "environment", "step", "decision")
EDGE_KINDS = ("works_with", "task", "access", "performs", "triggers", "gates", "achieves", "governs", "targets", "mitigates",
              "applies_to", "next", "hosts", "relates")
PREFIX = {"department": "D", "person": "EMP", "role": "ROLE", "external": "EXT", "agent": "AG", "model": "MD", "data_store": "DS",
          "goal": "G", "operation": "OP", "policy": "POL", "threat": "TH", "protection": "PR", "rule": "RULE", "environment": "ENV",
          "step": "ST", "decision": "ST"}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
PEOPLE = ("person", "role")

# What each type may carry. "ref:" values must name an existing node of that kind ("person" accepts a role as well).
STR, INT, BOOL = "str", "int", "bool"
SYSTEM = {"department": "ref:department", "owner": "ref:person", "agent_key": STR, "purpose": STR, "version": STR,
          "risk_class": STR, "origin": STR, "data_note": STR}
NOTE = {"sub": STR, "department": "ref:department"}
PROPS: Dict[str, Dict[str, str]] = {
    "department": {"parent": "ref:department", "head": "ref:person"},
    "person": {"title": STR, "department": "ref:department"},
    "role": {"title": STR, "department": "ref:department", "headcount": INT},
    "external": {"title": STR},
    "agent": SYSTEM, "model": SYSTEM,
    "data_store": {"department": "ref:department", "sensitivity": STR, "sub": STR},
    "goal": NOTE, "operation": NOTE, "policy": NOTE, "threat": NOTE, "protection": NOTE, "environment": NOTE,
    "rule": {"sub": STR, "rule_id": STR, "status": STR},
    "step": {"lane": "ref:department", "order": INT, "who": "ref:person", "deputy": "ref:person", "when": STR, "sub": STR, "astra": STR, "legal_deadline": BOOL},
    "decision": {"lane": "ref:department", "order": INT, "who": "ref:person", "deputy": "ref:person", "when": STR, "sub": STR, "astra": STR, "legal_deadline": BOOL},
}
REF_KEYS = {"parent", "head", "department", "owner", "lane", "who", "deputy"}
ANY = None
EDGE_RULES: Dict[str, Tuple[Optional[Set[str]], Optional[Set[str]]]] = {
    "works_with": ({"agent", "model"}, {"person", "role", "external"}),
    "task": ({"agent"}, {"agent"}),
    "access": ({"agent", "model"}, {"data_store"}),
    "performs": ({"person", "role", "external", "agent", "model"}, {"operation"}),
    "triggers": ({"operation"}, {"operation"}),
    "gates": ({"operation"}, {"operation"}),
    "achieves": ({"operation"}, {"goal"}),
    "governs": ({"policy"}, {"operation", "agent", "model", "data_store"}),
    "targets": ({"threat"}, {"data_store", "agent", "model"}),
    "mitigates": ({"protection", "policy", "rule"}, {"threat"}),
    "applies_to": ({"rule"}, ANY),
    "next": ({"step", "decision"}, {"step", "decision"}),
    "hosts": ({"environment"}, {"agent", "model"}),
    "relates": (ANY, ANY),
}
ROLE_LABELS = {"trains": "trainer", "validates": "validator", "deploys": "deployer"}


# ── Cleaning and validating ────────────────────────────────────────────────

def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").upper()[:36] or "ITEM"


def clean_props(type_: str, props: Dict[str, Any]) -> Dict[str, Any]:
    spec, out = PROPS[type_], {}
    for k, v in (props or {}).items():
        if k not in spec:
            raise ValueError(f"A {type_} has no field called '{k}'.")
        if v is None or v == "":
            continue                                           # an empty field is simply not set
        kind = spec[k]
        if kind == INT:
            if isinstance(v, bool) or not isinstance(v, (int, float, str)) or not str(v).lstrip("-").isdigit():
                raise ValueError(f"'{k}' must be a whole number.")
            out[k] = int(v)
        elif kind == BOOL:
            if not isinstance(v, bool):
                raise ValueError(f"'{k}' must be true or false.")
            out[k] = v
        else:
            if not isinstance(v, (str, int, float)) or isinstance(v, bool):
                raise ValueError(f"'{k}' must be text.")
            v = str(v).strip()
            if len(v) > 300:
                raise ValueError(f"'{k}' is longer than 300 characters.")
            if v:
                out[k] = v
    return out


def check_refs(type_: str, props: Dict[str, Any], types: Dict[str, str], where: str) -> List[str]:
    """Problems with the references in props, given every known id and its type."""
    problems = []
    for k, kind in PROPS[type_].items():
        if k in props and kind.startswith("ref:"):
            want = {"department"} if kind == "ref:department" else set(PEOPLE)
            have = types.get(props[k])
            if have is None:
                problems.append(f"{where}: '{k}' names {props[k]}, which is not in the organisation or the file.")
            elif have not in want:
                problems.append(f"{where}: '{k}' must be a {'department' if kind == 'ref:department' else 'person or role'}, but {props[k]} is a {have}.")
    return problems


def check_edge(kind: str, a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None or b is None:
        return "one end of the connection does not exist"
    frm, to = EDGE_RULES[kind]
    if frm is not None and a not in frm:
        return f"'{kind}' cannot start at a {a}"
    if to is not None and b not in to:
        return f"'{kind}' cannot end at a {b}"
    return None


# ── Reading the stored model ───────────────────────────────────────────────

def load(session: Session) -> Tuple[Any, List[CompanyNode], List[CompanyEdge]]:
    org = current_organisation(session)
    nodes = list(session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id).order_by(CompanyNode.created_at, CompanyNode.ext_id)))
    edges = list(session.scalars(select(CompanyEdge).where(CompanyEdge.organisation_id == org.id).order_by(CompanyEdge.created_at)))
    return org, nodes, edges


def node_out(n: CompanyNode) -> Dict[str, Any]:
    return {"id": n.ext_id, "type": n.type, "name": n.name, "props": n.props or {}}


def edge_out(e: CompanyEdge) -> Dict[str, Any]:
    return {"id": str(e.id), "from": e.from_ext, "to": e.to_ext, "kind": e.kind, "label": e.label, "props": e.props or {}}


# ── Live link to the agent inventory, contracts and runtime (read only) ────

def _active_view(session: Session, key: str) -> Optional[Dict[str, Any]]:
    c = session.scalar(select(Contract).where(Contract.object_type == "AGENT", Contract.deployment_id == key, Contract.status == "ACTIVE").order_by(Contract.issued_at.desc()))
    return None if c is None else {"version": c.document.get("version"), **agent_contract.view(c.document["design_snapshot"])}


def live_links(session: Session, org_id: uuid.UUID, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    agents = {a.agent_key: a for a in session.scalars(select(Agent).where(Agent.organisation_id == org_id))}
    org_agents = {n["id"]: n for n in nodes if n["type"] == "agent"}
    key_of = {i: n["props"].get("agent_key") or to_agent_key(n["name"]) for i, n in org_agents.items()}
    by_key = {k: i for i, k in key_of.items()}
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=30)
    observed: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    keys = [k for k in key_of.values() if k in agents]
    if keys:
        for ak, name, n, last in session.execute(select(RuntimeEvent.agent_key, RuntimeEvent.name, func.count(), func.max(RuntimeEvent.at)).where(
                RuntimeEvent.organisation_id == org_id, RuntimeEvent.type == "delegation", RuntimeEvent.agent_key.in_(keys), RuntimeEvent.at >= since
        ).group_by(RuntimeEvent.agent_key, RuntimeEvent.name)):
            observed[ak][to_agent_key(name)] = {"name": name, "count": n, "last": last.isoformat()}
    agent_live: Dict[str, Any] = {}
    views: Dict[str, Optional[Dict[str, Any]]] = {}
    for i, k in key_of.items():
        a = agents.get(k)
        v = _active_view(session, k) if a else None
        views[i] = v
        agent_live[i] = {"registered": a is not None, "agent_key": k, "origin": a.origin if a else None, "status": a.status if a else None,
                         "last_seen_at": a.last_seen_at.isoformat() if a and a.last_seen_at else None,
                         "contract_version": v["version"] if v else None, "registered_owner": a.owner if a else None,
                         "declares_data": [to_agent_key(x) for x in v["data"]] if v else None}
    task_live: Dict[str, Any] = {}
    modelled: Set[Tuple[str, str]] = set()
    for e in edges:
        if e["kind"] != "task" or e["from"] not in org_agents or e["to"] not in org_agents:
            continue
        v = views.get(e["from"])
        tk = key_of[e["to"]]
        modelled.add((e["from"], tk))
        seen = observed.get(key_of[e["from"]], {}).get(tk)
        declared = None if v is None else any(to_agent_key(d) == tk for d in v["delegates_to"])
        task_live[e["id"]] = {"declared": declared, "contract_version": v["version"] if v else None, "observed": seen["count"] if seen else 0, "last_seen": seen["last"] if seen else None}
    unmodelled = []
    for ak, seen_map in observed.items():
        src = by_key.get(ak)
        for tk, s in seen_map.items():
            if src and (src, tk) not in modelled:
                unmodelled.append({"from": src, "to_name": s["name"], "to": by_key.get(tk), "count": s["count"], "last_seen": s["last"],
                                   "declared": None if views.get(src) is None else any(to_agent_key(d) == tk for d in views[src]["delegates_to"])})
    unmapped = [{"agent_key": a.agent_key, "name": a.name, "origin": a.origin, "owner": a.owner} for k, a in sorted(agents.items()) if k not in by_key]
    models: Dict[str, Any] = {}
    org_models = [n for n in nodes if n["type"] == "model"]
    if org_models:
        from db.models import Design
        for d in session.scalars(select(Design).where(Design.subject == "MODEL").order_by(Design.updated_at.desc())):
            ref = ((d.document or {}).get("org") or {}).get("id")
            if ref and ref not in models:
                models[ref] = {"design_key": d.design_key, "design_name": d.name, "designs": 0}
            if ref:
                models[ref]["designs"] += 1
        for n in org_models:
            models.setdefault(n["id"], {"design_key": None, "design_name": None, "designs": 0})
    return {"agents": agent_live, "tasks": task_live, "unmodelled": unmodelled, "unmapped_agents": unmapped, "models": models}


# ── Checks (deterministic) ─────────────────────────────────────────────────

def run_checks(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], live: Dict[str, Any]) -> Dict[str, Any]:
    N = {n["id"]: n for n in nodes}
    P = lambda i: (N[i]["name"] if i in N else str(i))
    out: List[Dict[str, Any]] = []

    def add(key: str, level: str, title: str, detail: str, refs: List[str], action: str = "") -> None:
        out.append({"key": key, "level": level, "title": title, "detail": detail, "refs": refs, "action": action})

    systems = [n for n in nodes if n["type"] in ("agent", "model")]
    violations: Dict[str, str] = {}
    for m in (n for n in nodes if n["type"] == "model"):
        holders: Dict[str, List[str]] = defaultdict(list)
        for e in edges:
            if e["kind"] == "works_with" and e["from"] == m["id"] and e["label"].lower() in ROLE_LABELS:
                holders[ROLE_LABELS[e["label"].lower()]].append(e["to"])
        for a, b, why in (("validator", "deployer", "Separate duties: someone else should deploy (rule SC-RCF-1)."),
                          ("trainer", "validator", "Separate duties: someone else should validate the model.")):
            both = sorted(set(holders[a]) & set(holders[b]))
            for pid in both:
                add("role_concentration", "bad", "Role concentration", f"{m['name']}: {P(pid)} is both {a} and {b}. {why}", [m["id"], pid], "Assign another person")
                if (a, b) == ("validator", "deployer"):
                    violations["separate_validator_deployer"] = f"{P(pid)} is both validator and deployer."
    for s in systems:
        if not s["props"].get("owner"):
            add("no_owner", "warn", "No owner", f"{s['name']} has no accountable person." + (" An agent without an owner counts against ASI10." if s["type"] == "agent" else ""), [s["id"]], "Assign an owner")
    for d in (n for n in nodes if n["type"] == "department"):
        if not d["props"].get("head") and any(n["props"].get("department") == d["id"] for n in nodes if n["type"] != "department"):
            add("no_head", "warn", "No head", f"Department {d['name']} has no head.", [d["id"]], "Assign a head")
    governed = {e["to"] for e in edges if e["kind"] == "governs"}
    for e in edges:
        if e["kind"] != "task" or e["from"] not in N or e["to"] not in N:
            continue
        a, b = N[e["from"]], N[e["to"]]
        da, db = a["props"].get("department"), b["props"].get("department")
        data = e["props"].get("data") or []
        if da and db and da != db and not e["props"].get("policy") and not ({a["id"], b["id"]} & governed):
            add("cross_department", "warn", "Crosses departments", f"{a['name']} → {b['name']} ({P(da)} → {P(db)})." + (f" Passes: {', '.join(data)}." if data else "") + " No policy covers it.", [a["id"], b["id"]], "Add a policy")
        lv = live["tasks"].get(e["id"])
        if lv and lv["declared"] is False:
            add("not_in_contract", "bad", "Not in the contract", f"{a['name']} → {b['name']} is drawn here, but {a['name']}'s contract v{lv['contract_version']} does not declare the handoff.", [a["id"], b["id"]], "Review in Agent assurance")
    for u in live["unmodelled"]:
        add("seen_not_modelled", "bad" if u["declared"] is False else "info", "Seen at runtime, not in the organisation",
            f"{P(u['from'])} handed work to {u['to_name']} {u['count']} time(s) in the last 30 days" + ("; its contract does not declare it." if u["declared"] is False else "."), [u["from"]] + ([u["to"]] if u["to"] else []), "Add the task link")
    for s in systems:
        if s["type"] == "agent" and not live["agents"].get(s["id"], {}).get("registered"):
            add("not_registered", "info", "Not in Agent assurance", f"{s['name']} is in the organisation but not registered as an agent yet.", [s["id"]], "")
    if live["unmapped_agents"]:
        names = ", ".join(a["name"] for a in live["unmapped_agents"][:4]) + (f" and {len(live['unmapped_agents']) - 4} more" if len(live["unmapped_agents"]) > 4 else "")
        add("unmapped_agents", "info", "Agents not in the organisation", f"{len(live['unmapped_agents'])} registered agent(s) have no place in the organisation yet: {names}.", [], "Add them")
    for m in (n for n in nodes if n["type"] == "model"):
        if live.get("models", {}).get(m["id"], {}).get("designs", 1) == 0:
            add("no_model_design", "info", "Not in the Model studio", f"{m['name']} is in the organisation but has no design in the Model studio yet.", [m["id"]], "Create it")
    for t in (n for n in nodes if n["type"] == "threat"):
        if not any(e["kind"] == "mitigates" and e["to"] == t["id"] for e in edges):
            add("threat_unprotected", "bad", "Threat with no protection", f"{t['name']}: nothing mitigates it yet.", [t["id"]], "Add a protection")
    steps = [n for n in nodes if n["type"] in ("step", "decision")]
    if systems and not steps:
        add("no_breach_plan", "info", "No breach response plan yet", "There are AI systems but no steps for what to do if one leaks or misuses data.", [], "Add steps")
    for st in steps:
        p = st["props"]
        if not p.get("who"):
            add("breach_no_owner", "warn", "Breach plan gap", f"Step '{st['name']}' has no responsible person.", [st["id"]], "Assign a person")
        elif not p.get("deputy") and (st["type"] == "decision" or p.get("legal_deadline")):
            add("breach_no_deputy", "warn", "Breach plan gap", f"Step '{st['name']}' depends on {P(p['who'])} alone. No deputy named.", [st["id"]], "Name a deputy")
    order = {"bad": 0, "warn": 1, "info": 2}
    out.sort(key=lambda c: order[c["level"]])
    return {"checks": out, "violations": violations}


def state(session: Session) -> Dict[str, Any]:
    org, ns, es = load(session)
    nodes, edges = [node_out(n) for n in ns], [edge_out(e) for e in es]
    live = live_links(session, org.id, nodes, edges)
    res = run_checks(nodes, edges, live)
    counts: Dict[str, int] = defaultdict(int)
    for n in nodes:
        counts[n["type"]] += 1
    return {"organisation": {"name": org.name}, "nodes": nodes, "edges": edges, "live": live, "checks": res["checks"], "violations": res["violations"], "counts": dict(counts)}


# ── The organisation's agents become entries in Agent assurance ────────────

def register_org_agents(session: Session, org: Any, only: Optional[List[str]] = None) -> List[str]:
    """Creates the Agent assurance inventory entry for each AI agent of the organisation that has none, so it can be designed and ratified there. An
    entry that exists is left alone. The agents come first; the AI models follow when the Model studio starts a design from them. Does not commit."""
    import removal
    nodes = {n.ext_id: n for n in session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id).order_by(CompanyNode.created_at, CompanyNode.ext_id))}
    have = {k for (k,) in session.execute(select(Agent.agent_key))}
    made: List[str] = []
    for n in nodes.values():
        if n.type != "agent" or (only is not None and n.ext_id not in only):
            continue
        key = removal.node_key(n)
        if len(key) < 2 or key in have:
            continue
        owner, dept = nodes.get((n.props or {}).get("owner", "")), nodes.get((n.props or {}).get("department", ""))
        session.add(Agent(agent_key=key, organisation_id=org.id, name=n.name[:80], owner=owner.name[:120] if owner else None, framework="Not built yet", tools_count=0,
                          status="TO_RATIFY" if owner else "UNOWNED", mode="NOT_RUNNING", origin="ORG", note=("From the organisation" + (f": {dept.name}" if dept else ""))[:200]))
        have.add(key)
        made.append(key)
    return made


@router.post("/sync-agents")
def sync_agents(session: Session = Depends(get_session)) -> Dict[str, Any]:
    """Creates the Agent assurance entry for every agent, then the Model studio design for every model, of the organisation that has none yet (idempotent)."""
    org = current_organisation(session)
    made = register_org_agents(session, org)
    models = register_org_models(session, org)
    session.commit()
    return {"created": made, "models_created": models}


# ── The organisation's models become designs in the Model studio ───────────

ACTOR_EDGE = {"TRAINER": ("TRAINS", "trains"), "VALIDATOR": ("VALIDATES", "validates"), "DEPLOYER": ("DEPLOYS", "deploys"), "OPERATOR": ("OPERATES", "operates")}


def build_model_document(res: Dict[str, Any], ext_id: str) -> Dict[str, Any]:
    """A Model studio design document for one organisation model: the departments, the people in each lifecycle role, the model, where it runs
    and what it was trained on, with the same positions the studio gives an imported description (applyGenerated). Pure code."""
    desc = res["description"]
    counter = [1]
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()
    tmap: Dict[str, Dict[str, Any]] = {}

    def nid() -> str:
        counter[0] += 1
        return f"n{counter[0] - 1}"

    def add(kind: str, data: Dict[str, Any], x: int, y: int, **extra: Any) -> Dict[str, Any]:
        node = {"id": nid(), "kind": kind, "x": x, "y": y, "data": data, **extra}
        nodes.append(node)
        return node

    def edge(a: str, b: str, type_: str, label: str) -> None:
        if (a, b, type_) in seen:
            return
        seen.add((a, b, type_))
        edges.append({"id": f"e{counter[0]}", "source": a, "target": b, "type": type_, "label": label})
        counter[0] += 1

    base = 40
    for i, d in enumerate(desc["departments"]):
        tmap[d["temp_id"]] = add("DEPARTMENT", {"name": d["name"], "reportsToDepartmentId": ""}, base + i * 290, 40, w=260, h=200)
    for d in desc["departments"]:
        parent = tmap.get(d.get("reports_to_temp_id") or "")
        if parent is not None:
            tmap[d["temp_id"]]["data"]["reportsToDepartmentId"] = parent["id"]
            edge(tmap[d["temp_id"]]["id"], parent["id"], "REPORTS_TO", "reports_to")
    slots: Dict[str, int] = {}
    placed: Dict[int, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
    for i, a in enumerate(desc["actors"]):                          # people inside a department first: they decide how tall the departments are
        dept = tmap.get(a.get("department_temp_id") or "")
        if dept is None:
            continue
        k = slots[dept["id"]] = slots.get(dept["id"], 0) + 1
        if k > 2:
            dept["h"] = max(dept["h"], 50 + k * 70)
        n = add("ACTOR", {"subtype": a["subtype"], "identity": a.get("identity", ""), "departmentId": dept["id"]}, dept["x"] + 35, dept["y"] + 40 + (k - 1) * 70)
        n["parent"] = dept["id"]
        placed[i] = (a, n)
    below = max([d["y"] + d["h"] for d in tmap.values()] or [240]) + 40       # outside parties go under the tallest department, not over it
    free = 0
    for i, a in enumerate(desc["actors"]):
        if i in placed:
            continue
        placed[i] = (a, add("ACTOR", {"subtype": a["subtype"], "identity": a.get("identity", ""), "departmentId": ""}, base + (free % 2) * 220, below + (free // 2) * 90))
        free += 1
    actor_nodes = [placed[i] for i in sorted(placed)]
    row_y = below + -(-free // 2) * 90 + (20 if free else 0)
    models = [add("AI_MODEL", {"name": m["name"], "modelType": m["model_type"], "aiCriticality": m["ai_criticality"], "domain": m.get("domain") or "",
                               "dataSensitivity": m["data_sensitivity"], "hostingEnvironment": m["hosting_environment"]}, base + 460, row_y + i * 90) for i, m in enumerate(desc["ai_models"])]
    envs = [add("DEPLOYMENT_ENV", {"name": e["name"], "description": e.get("description", "")}, base + 700, row_y + i * 90) for i, e in enumerate(desc["deployment_environments"])]
    sets = [add("TRAINING_DATASET", {"name": name, "description": ""}, base + 700, row_y + (len(envs) + i) * 90) for i, name in enumerate(res.get("datasets", []))]
    model = models[0]
    for a, n in actor_nodes:
        if a["subtype"] == "CONSUMER":
            edge(model["id"], n["id"], "CONSUMED_BY", "consumed_by")
        elif a["subtype"] in ACTOR_EDGE:
            edge(n["id"], model["id"], *ACTOR_EDGE[a["subtype"]])
    for e in envs:
        edge(model["id"], e["id"], "RUNS_IN", "runs_in")
    for d in sets:
        edge(model["id"], d["id"], "TRAINED_ON", "trained_on")
    return {"nodes": nodes, "edges": edges, "n": counter[0], "org": {"id": ext_id, "name": res["name"]}}


def register_org_models(session: Session, org: Any, only: Optional[List[str]] = None) -> List[str]:
    """Creates a Model studio design for each AI model of the organisation that has none, so the model appears in the ST-AI studio the moment the
    company is described, as its agents appear in Agent assurance. The design starts from what the organisation knows and the constraints start
    as not yet determined. A design that exists is left alone. Does not commit; returns the ids of the models that got a design."""
    import secrets

    import removal
    from db.models import Domain
    domain = session.scalar(select(Domain.domain_key).where(Domain.subject == "MODEL").order_by(Domain.domain_key != "GENERAL", Domain.position, Domain.domain_key))
    if domain is None:
        return []
    made: List[str] = []
    for n in session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.type == "model").order_by(CompanyNode.created_at, CompanyNode.ext_id)):
        if (only is not None and n.ext_id not in only) or removal.model_designs(session, n.ext_id):
            continue
        try:
            res = model_description(session, n.ext_id)
        except HTTPException:
            continue
        session.add(Design(design_key="d-" + secrets.token_hex(5), organisation_id=org.id, subject="MODEL", name=n.name[:200], domain_key=domain, document=build_model_document(res, n.ext_id)))
        made.append(n.ext_id)
    return made


# ── Import ─────────────────────────────────────────────────────────────────

class DocIn(BaseModel):
    content: str = Field(max_length=MAX_FILE)
    filename: str = Field("", max_length=200)
    skip: List[str] = Field(default_factory=list, max_length=500)


def parse_doc(content: str) -> Dict[str, Any]:
    if not content.strip():
        raise HTTPException(status_code=422, detail="The file is empty.")
    try:
        doc = yaml.safe_load(content)                      # JSON is YAML too
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=422, detail=f"The file is neither valid JSON nor valid YAML: {str(exc).splitlines()[0] if str(exc) else exc}")
    if not isinstance(doc, dict):
        raise HTTPException(status_code=422, detail="The file must describe an organisation: an object with 'company' and 'departments'.")
    return doc


def _list(doc: Dict[str, Any], key: str, errors: List[str]) -> List[Dict[str, Any]]:
    v = doc.get(key)
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, dict) for x in v):
        errors.append(f"'{key}' must be a list of objects.")
        return []
    return v


def doc_to_graph(doc: Dict[str, Any], existing_ids: Set[str]) -> Dict[str, Any]:
    """The file's content as nodes and edges (ids filled in where missing), with every problem found."""
    errors: List[str] = []
    warnings: List[str] = []
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}
    taken = set(existing_ids)

    def add_node(type_: str, raw: Dict[str, Any], props: Dict[str, Any], where: str) -> Optional[str]:
        name = str(raw.get("name") or "").strip()
        if not name:
            errors.append(f"{where}: every entry needs a name.")
            return None
        ext = str(raw.get("id") or "").strip()
        if not ext:
            base = f"{PREFIX[type_]}-{slug(name)}"
            ext, n = base, 2
            while ext in taken or ext in seen:
                ext, n = f"{base}-{n}", n + 1
            warnings.append(f"{name} had no id; using {ext}.")
        if not ID_RE.match(ext):
            errors.append(f"{where}: the id '{ext}' may only use letters, digits and . _ : - (up to 64 characters).")
            return None
        if ext in seen:
            errors.append(f"The id {ext} appears twice ({seen[ext]}, {name}). Ids must be unique.")
            return None
        seen[ext] = name
        nodes.append({"id": ext, "type": type_, "name": name[:160], "props": props})
        return ext

    def edge(a: str, b: str, kind: str, label: str = "", props: Optional[Dict[str, Any]] = None) -> None:
        edges.append({"from": a, "to": b, "kind": kind, "label": (label or "")[:80], "props": props or {}})

    company = doc.get("company")
    if company is not None and not isinstance(company, dict):
        errors.append("'company' must be an object with a name.")
    pending_edges: List[Tuple[str, Any, str, str, Dict[str, Any], str]] = []        # (from, to-ref, kind, label, props, where)
    for i, d in enumerate(_list(doc, "departments", errors), 1):
        props = {"parent": d.get("reports_to") or d.get("parent"), "head": d.get("head")}
        add_node("department", d, props, f"departments[{i}]")
    for i, p in enumerate(_list(doc, "people", errors), 1):
        role = str(p.get("kind") or "person").lower() == "role"
        props = {"title": p.get("title"), "department": p.get("department")}
        if role:
            props["headcount"] = p.get("headcount")
        add_node("role" if role else "person", p, props, f"people[{i}]")
    for i, p in enumerate(_list(doc, "external", errors), 1):
        add_node("external", p, {"title": p.get("title") or p.get("kind")}, f"external[{i}]")
    for i, s in enumerate(_list(doc, "data_stores", errors), 1):
        add_node("data_store", s, {"department": s.get("department"), "sensitivity": s.get("sensitivity"), "sub": s.get("sub")}, f"data_stores[{i}]")
    for i, s in enumerate(_list(doc, "ai_systems", errors), 1):
        t = str(s.get("type") or "").lower()
        where = f"ai_systems[{i}]"
        if t not in ("agent", "model"):
            errors.append(f"{where}: type must be 'agent' or 'model'.")
            continue
        details = s.get("details") if isinstance(s.get("details"), dict) else {}
        props = {"department": s.get("department"), "owner": s.get("owner"), "agent_key": s.get("agent_key")}
        props.update({k: v for k, v in details.items() if k in SYSTEM})
        ext = add_node(t, s, props, where)
        if not ext:
            continue
        for q in s.get("people") or []:
            if isinstance(q, dict) and q.get("id"):
                pending_edges.append((ext, q["id"], "works_with", str(q.get("role") or ""), {}, where))
        for h in s.get("hands_tasks_to") or []:
            if isinstance(h, dict) and h.get("agent"):
                data = h.get("data") if isinstance(h.get("data"), list) else []
                pending_edges.append((ext, h["agent"], "task", str(h.get("task") or ""), {"data": [str(x)[:60] for x in data][:10], **({"policy": str(h["policy"])[:120]} if h.get("policy") else {})}, where))
        for u in s.get("uses_data") or []:
            if isinstance(u, dict) and u.get("store"):
                pending_edges.append((ext, u["store"], "access", str(u.get("access") or "read"), {}, where))
    for i, el in enumerate(_list(doc, "elements", errors), 1):
        t = str(el.get("type") or "").lower()
        if t not in ELEMENT_TYPES:
            errors.append(f"elements[{i}]: type must be one of {', '.join(ELEMENT_TYPES)}.")
            continue
        add_node(t, el, {k: v for k, v in el.items() if k in PROPS[t]}, f"elements[{i}]")
    for i, l in enumerate(_list(doc, "links", errors), 1):
        kind = str(l.get("kind") or "relates")
        if kind not in EDGE_KINDS:
            errors.append(f"links[{i}]: kind must be one of {', '.join(EDGE_KINDS)}.")
            continue
        if not l.get("from") or not l.get("to"):
            errors.append(f"links[{i}]: needs 'from' and 'to'.")
            continue
        pending_edges.append((str(l["from"]), l["to"], kind, str(l.get("label") or ""), {}, f"links[{i}]"))
    for a, b, kind, label, props, where in pending_edges:
        edge(a, str(b), kind, label, props)
    if not nodes and not edges and not errors:
        errors.append("The file contains nothing to import. Expected 'departments', 'people', 'ai_systems', 'data_stores', 'elements' or 'links'.")
    return {"nodes": nodes, "edges": edges, "errors": errors, "warnings": warnings, "company_name": (company or {}).get("name") if isinstance(company, dict) else None}


def plan(session: Session, doc: Dict[str, Any], skip: List[str]) -> Dict[str, Any]:
    """What importing the file would do, and every problem that stops it. Writes nothing."""
    org, ns, es = load(session)
    cur = {n.ext_id: n for n in ns}
    g = doc_to_graph(doc, set(cur))
    errors, warnings = list(g["errors"]), list(g["warnings"])
    skipped = set(skip)
    new_nodes = [n for n in g["nodes"] if f"node:{n['id']}" not in skipped]
    types = {i: n.type for i, n in cur.items()}
    types.update({n["id"]: n["type"] for n in new_nodes})
    items: List[Dict[str, Any]] = []
    for n in new_nodes:
        try:
            props = clean_props(n["type"], n["props"])
        except ValueError as exc:
            errors.append(f"{n['name']}: {exc}")
            continue
        n["props"] = props
        errors += check_refs(n["type"], props, types, n["name"])
        old = cur.get(n["id"])
        if old is not None and old.type != n["type"]:
            errors.append(f"{n['id']} is already a {old.type}; the file says {n['type']}. Ids cannot change type.")
            continue
        if old is None:
            action = "create"
        else:
            merged = {**(old.props or {}), **props}
            action = "unchanged" if old.name == n["name"] and merged == (old.props or {}) else "update"
        items.append({"key": f"node:{n['id']}", "what": "node", "type": n["type"], "id": n["id"], "name": n["name"], "action": action})
        n["_action"] = action
    existing_edges = {(e.from_ext, e.to_ext, e.kind, e.label) for e in es}
    new_edges = []
    for e in g["edges"]:
        key = f"edge:{e['from']}|{e['kind']}|{e['to']}|{e['label']}"
        if key in skipped or f"node:{e['from']}" in skipped or f"node:{e['to']}" in skipped:
            continue
        why = check_edge(e["kind"], types.get(e["from"]), types.get(e["to"]))
        if why:
            errors.append(f"Connection {e['from']} → {e['to']} ({e['kind']}): {why}.")
            continue
        if e["from"] == e["to"]:
            errors.append(f"Connection {e['from']} → {e['to']}: cannot connect something to itself.")
            continue
        exists = (e["from"], e["to"], e["kind"], e["label"]) in existing_edges
        new_edges.append(e)
        items.append({"key": key, "what": "edge", "kind": e["kind"], "from": e["from"], "to": e["to"], "label": e["label"], "action": "unchanged" if exists else "create",
                      "from_name": next((n["name"] for n in new_nodes if n["id"] == e["from"]), cur[e["from"]].name if e["from"] in cur else e["from"]),
                      "to_name": next((n["name"] for n in new_nodes if n["id"] == e["to"]), cur[e["to"]].name if e["to"] in cur else e["to"])})
    count = lambda w, a: sum(1 for i in items if i["what"] == w and i["action"] == a)
    return {"ok": not errors, "errors": errors, "warnings": warnings, "company_name": g["company_name"], "organisation_name": org.name, "items": items,
            "summary": {"create": sum(1 for i in items if i["action"] == "create"), "update": sum(1 for i in items if i["action"] == "update"), "unchanged": sum(1 for i in items if i["action"] == "unchanged"),
                        "nodes": sum(1 for i in items if i["what"] == "node"), "edges": sum(1 for i in items if i["what"] == "edge"),
                        "agents": sum(1 for i in items if i.get("type") == "agent"), "models": sum(1 for i in items if i.get("type") == "model"),
                        "departments": sum(1 for i in items if i.get("type") == "department"), "people": sum(1 for i in items if i.get("type") in PEOPLE),
                        "task_links": sum(1 for i in items if i.get("kind") == "task"), "new_nodes": count("node", "create")},
            "_nodes": new_nodes, "_edges": new_edges}


def apply_plan(session: Session, p: Dict[str, Any], user: AuthUser) -> Dict[str, int]:
    org = current_organisation(session)
    cur = {n.ext_id: n for n in session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id))}
    made = changed = 0
    t0, tick = datetime.now(timezone.utc), [0]

    def stamp() -> datetime:                                  # file order is kept: rows of one import would otherwise share a timestamp
        tick[0] += 1
        return t0 + timedelta(microseconds=tick[0])

    for n in p["_nodes"]:
        old = cur.get(n["id"])
        if old is None:
            row = CompanyNode(organisation_id=org.id, ext_id=n["id"], type=n["type"], name=n["name"], props=n["props"], created_at=stamp())
            session.add(row)
            cur[n["id"]] = row
            made += 1
        elif n["_action"] == "update":
            old.name = n["name"]
            old.props = {**(old.props or {}), **n["props"]}
            changed += 1
    session.flush()
    have = {(e.from_ext, e.to_ext, e.kind, e.label) for e in session.scalars(select(CompanyEdge).where(CompanyEdge.organisation_id == org.id))}
    links = 0
    for e in p["_edges"]:
        k = (e["from"], e["to"], e["kind"], e["label"])
        if k not in have:
            session.add(CompanyEdge(organisation_id=org.id, from_ext=e["from"], to_ext=e["to"], kind=e["kind"], label=e["label"], props=e["props"], created_at=stamp()))
            have.add(k)
            links += 1
    session.flush()
    agents_created = register_org_agents(session, org, [n["id"] for n in p["_nodes"] if n["type"] == "agent"])      # agents first,
    models_created = register_org_models(session, org, [n["id"] for n in p["_nodes"] if n["type"] == "model"])      # then the models
    renamed = None
    name = p.get("company_name")
    if name and str(name).strip() and str(name).strip() != org.name and user.role == "admin":
        org.name = str(name).strip()[:120]
        renamed = org.name
    session.commit()
    return {"created": made, "updated": changed, "connections": links, "renamed": renamed, "agents_created": agents_created, "models_created": models_created}


def public_plan(p: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in p.items() if not k.startswith("_")}


@router.get("")
def get_company(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return state(session)


@router.post("/import/preview")
def import_preview(body: DocIn, session: Session = Depends(get_session)) -> Dict[str, Any]:
    return public_plan(plan(session, parse_doc(body.content), body.skip))


@router.post("/import")
def import_apply(body: DocIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    p = plan(session, parse_doc(body.content), body.skip)
    if not p["ok"]:
        raise HTTPException(status_code=422, detail="Nothing was imported. " + " ".join(p["errors"][:6]))
    result = apply_plan(session, p, user)
    return {**result, "plan": public_plan(p), "company": state(session)}


# ── Editing by hand ────────────────────────────────────────────────────────

class NodeIn(BaseModel):
    type: Literal[NODE_TYPES]                              # type: ignore[valid-type]
    name: str = Field(min_length=1, max_length=160)
    id: Optional[str] = Field(None, max_length=64)
    props: Dict[str, Any] = Field(default_factory=dict)


class NodePatch(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=160)
    props: Optional[Dict[str, Any]] = None


class EdgeIn(BaseModel):
    from_: str = Field(alias="from", max_length=64)
    to: str = Field(max_length=64)
    kind: Literal[EDGE_KINDS]                              # type: ignore[valid-type]
    label: str = Field("", max_length=80)
    props: Dict[str, Any] = Field(default_factory=dict)
    model_config = {"populate_by_name": True}


class EdgePatch(BaseModel):
    label: Optional[str] = Field(None, max_length=80)
    props: Optional[Dict[str, Any]] = None


def _types(session: Session, org_id: uuid.UUID) -> Dict[str, str]:
    return {i: t for i, t in session.execute(select(CompanyNode.ext_id, CompanyNode.type).where(CompanyNode.organisation_id == org_id))}


def _clean_edge_props(kind: str, props: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if kind == "task":
        data = props.get("data")
        if data is not None:
            if not isinstance(data, list) or not all(isinstance(x, (str, int, float)) for x in data):
                raise HTTPException(status_code=422, detail="'data' must be a list of names.")
            out["data"] = [str(x)[:60] for x in data][:10]
        if props.get("policy"):
            out["policy"] = str(props["policy"])[:120]
    return out


class ClearIn(BaseModel):
    confirm: str = Field(max_length=200)                      # the organisation's name, typed out: a stray API call cannot clear it
    new_name: Optional[str] = Field(None, max_length=120)     # optionally start the new company under its own name
    remove_everywhere: bool = True                            # also clear Agent assurance and the Model studio: start from scratch


def clear_impact(session: Session) -> Dict[str, Any]:
    """What starting from scratch would remove, for the confirmation: the company, and everything built on it."""
    from db.models import CoverageAssignment, EvidencePack
    org = current_organisation(session)
    ns = list(session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id)))
    n = lambda model, *where: session.scalar(select(func.count()).select_from(model).where(*where)) or 0
    return {"nodes": len(ns), "connections": n(CompanyEdge, CompanyEdge.organisation_id == org.id),
            "agents_in_organisation": sum(1 for x in ns if x.type == "agent"), "models_in_organisation": sum(1 for x in ns if x.type == "model"),
            "agents": n(Agent), "agent_designs": n(Design, Design.subject == "AGENT"), "model_designs": n(Design, Design.subject == "MODEL"),
            "contracts": n(Contract), "findings": n(Finding), "drift_items": n(DriftItem), "runtime_events": n(RuntimeEvent),
            "evidence_packs": n(EvidencePack), "coverage_assignments": n(CoverageAssignment)}


@router.get("/clear-impact")
def get_clear_impact(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return clear_impact(session)


@router.delete("")
def clear_company(body: ClearIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    """Starts from scratch. Deletes the company (every node and connection) and, unless remove_everywhere is false, everything built on it: the
    organisation, Agent assurance and the Model studio are one platform, so every agent and AI model, their designs, every contract, finding,
    drift item and runtime event, the evidence packs and the coverage assignments go with it. Users, API keys, policies, regulations and the audit
    log are kept (and the audit log records who did this and what it took). Administrators only."""
    from db.models import CoverageAssignment, EvidencePack, RemovedContract
    org = current_organisation(session)
    if body.confirm.strip() != org.name:
        raise HTTPException(status_code=422, detail="Type the organisation's name exactly as it is shown to confirm.")
    impact = clear_impact(session)
    if body.remove_everywhere:
        for model in (Contract, Finding, DriftItem, RuntimeEvent, EvidencePack, RemovedContract, CoverageAssignment, Agent, Design):
            session.execute(delete(model))                    # contracts first: they point at designs
    session.execute(delete(CompanyEdge).where(CompanyEdge.organisation_id == org.id))
    session.execute(delete(CompanyNode).where(CompanyNode.organisation_id == org.id))
    if body.new_name and body.new_name.strip():
        org.name = body.new_name.strip()
    session.commit()
    done = {"deleted_nodes": impact["nodes"], "deleted_connections": impact["connections"], "organisation": org.name, "platform_cleared": body.remove_everywhere,
            **({k: impact[k] for k in ("agents", "agent_designs", "model_designs", "contracts", "findings", "drift_items", "runtime_events", "evidence_packs", "coverage_assignments")} if body.remove_everywhere else {})}
    audit.record(user.name, user.role, "platform.cleared" if body.remove_everywhere else "organisation.cleared", "ok", done)
    return done


@router.post("/nodes", status_code=201)
def add_node(body: NodeIn, session: Session = Depends(get_session)) -> Dict[str, Any]:
    org = current_organisation(session)
    types = _types(session, org.id)
    ext = (body.id or "").strip()
    if not ext:
        base = f"{PREFIX[body.type]}-{slug(body.name)}"
        ext, n = base, 2
        while ext in types:
            ext, n = f"{base}-{n}", n + 1
    if not ID_RE.match(ext):
        raise HTTPException(status_code=422, detail="The id may only use letters, digits and . _ : - (up to 64 characters).")
    if ext in types:
        raise HTTPException(status_code=409, detail=f"The id {ext} is already used.")
    try:
        props = clean_props(body.type, body.props)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    problems = check_refs(body.type, props, types, body.name)
    if problems:
        raise HTTPException(status_code=422, detail=" ".join(problems))
    session.add(CompanyNode(organisation_id=org.id, ext_id=ext, type=body.type, name=body.name.strip(), props=props))
    session.flush()
    if body.type == "agent":
        register_org_agents(session, org, [ext])
    elif body.type == "model":
        register_org_models(session, org, [ext])
    session.commit()
    return {"id": ext}


@router.patch("/nodes/{ext_id}")
def patch_node(ext_id: str, body: NodePatch, session: Session = Depends(get_session)) -> Dict[str, Any]:
    org = current_organisation(session)
    row = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id == ext_id))
    if row is None:
        raise HTTPException(status_code=404, detail="That item is not in the organisation.")
    if body.name is not None:
        if not body.name.strip():
            raise HTTPException(status_code=422, detail="The name cannot be empty.")
        row.name = body.name.strip()
    if body.props is not None:
        try:
            merged = {**(row.props or {}), **{k: v for k, v in body.props.items()}}
            props = clean_props(row.type, merged)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        problems = check_refs(row.type, props, _types(session, org.id), row.name)
        if problems:
            raise HTTPException(status_code=422, detail=" ".join(problems))
        if row.type == "department" and props.get("parent") == ext_id:
            raise HTTPException(status_code=422, detail="A department cannot report to itself.")
        row.props = props
        if row.type == "agent" and "owner" in body.props:
            import removal
            inv = session.scalar(select(Agent).where(Agent.agent_key == removal.node_key(row)))
            if inv is not None and inv.origin == "ORG" and inv.design_id is None:        # not yet designed: the organisation is still its source
                who = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id == props.get("owner", "")))
                inv.owner = who.name[:120] if who else None
                inv.status = "TO_RATIFY" if who else "UNOWNED"
    session.commit()
    return {"id": ext_id}


def drop_node(session: Session, org: Any, row: CompanyNode) -> None:
    """Deletes a node and every connection to it, and clears it as anyone's owner, head or deputy. Does not commit."""
    ext_id = row.ext_id
    others = list(session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id != ext_id)))
    for o in others:
        gone = [k for k in REF_KEYS if o.props.get(k) == ext_id]
        if gone:
            o.props = {k: v for k, v in o.props.items() if k not in gone}
    session.execute(delete(CompanyEdge).where(CompanyEdge.organisation_id == org.id, (CompanyEdge.from_ext == ext_id) | (CompanyEdge.to_ext == ext_id)))
    session.delete(row)


@router.get("/nodes/{ext_id}/removal-impact")
def node_removal_impact(ext_id: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """For an agent or a model: what removing it would take with it across the platform, for the confirmation."""
    import removal
    org = current_organisation(session)
    row = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id == ext_id))
    if row is None:
        raise HTTPException(status_code=404, detail="That item is not in the organisation.")
    if row.type == "agent":
        return {"type": "agent", **removal.agent_impact(session, removal.node_key(row))}
    if row.type == "model":
        return {"type": "model", **removal.model_impact(session, ext_id)}
    return {"type": row.type, "name": row.name, "organisation_connections": session.scalar(select(func.count()).select_from(CompanyEdge).where(
        CompanyEdge.organisation_id == org.id, (CompanyEdge.from_ext == ext_id) | (CompanyEdge.to_ext == ext_id))) or 0}


@router.delete("/nodes/{ext_id}")
def delete_node(ext_id: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    """Deletes an item. An AI agent or AI model is removed from the whole platform with it (Agent assurance and the Model studio are the same
    platform as the organisation), which only an administrator may do."""
    import removal
    org = current_organisation(session)
    row = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id == ext_id))
    if row is None:
        raise HTTPException(status_code=404, detail="That item is not in the organisation.")
    if row.type in ("agent", "model"):
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="Only an administrator can remove an AI agent or model: it is removed from Agent assurance and the Model studio as well.")
        done = removal.remove_agent(session, removal.node_key(row), user) if row.type == "agent" else removal.remove_model(session, ext_id, user)
        return {"deleted": ext_id, "removed": done}
    others = list(session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id != ext_id)))
    users = [o for o in others if any(o.props.get(k) == ext_id for k in ("parent", "department", "lane"))]
    if row.type == "department" and users:
        raise HTTPException(status_code=409, detail=f"{row.name} still has {len(users)} item(s) in it ({', '.join(u.name for u in users[:3])}{'…' if len(users) > 3 else ''}). Move or delete them first.")
    drop_node(session, org, row)
    session.commit()
    return {"deleted": ext_id}


@router.post("/edges", status_code=201)
def add_edge(body: EdgeIn, session: Session = Depends(get_session)) -> Dict[str, Any]:
    org = current_organisation(session)
    types = _types(session, org.id)
    if body.from_ == body.to:
        raise HTTPException(status_code=422, detail="Something cannot be connected to itself.")
    why = check_edge(body.kind, types.get(body.from_), types.get(body.to))
    if why:
        raise HTTPException(status_code=422, detail=why[0].upper() + why[1:] + ".")
    if session.scalar(select(CompanyEdge).where(CompanyEdge.organisation_id == org.id, CompanyEdge.from_ext == body.from_, CompanyEdge.to_ext == body.to,
                                                 CompanyEdge.kind == body.kind, CompanyEdge.label == body.label.strip())):
        raise HTTPException(status_code=409, detail="That connection already exists.")
    e = CompanyEdge(organisation_id=org.id, from_ext=body.from_, to_ext=body.to, kind=body.kind, label=body.label.strip(), props=_clean_edge_props(body.kind, body.props))
    session.add(e)
    session.commit()
    return {"id": str(e.id)}


@router.patch("/edges/{edge_id}")
def patch_edge(edge_id: uuid.UUID, body: EdgePatch, session: Session = Depends(get_session)) -> Dict[str, Any]:
    org = current_organisation(session)
    e = session.scalar(select(CompanyEdge).where(CompanyEdge.organisation_id == org.id, CompanyEdge.id == edge_id))
    if e is None:
        raise HTTPException(status_code=404, detail="That connection does not exist.")
    if body.label is not None:
        e.label = body.label.strip()
    if body.props is not None:
        e.props = _clean_edge_props(e.kind, {**(e.props or {}), **body.props})
    try:
        session.commit()
    except Exception:
        session.rollback()
        raise HTTPException(status_code=409, detail="That connection already exists.")
    return {"id": str(e.id)}


@router.delete("/edges/{edge_id}")
def delete_edge(edge_id: uuid.UUID, session: Session = Depends(get_session)) -> Dict[str, Any]:
    org = current_organisation(session)
    n = session.execute(delete(CompanyEdge).where(CompanyEdge.organisation_id == org.id, CompanyEdge.id == edge_id)).rowcount
    session.commit()
    if not n:
        raise HTTPException(status_code=404, detail="That connection does not exist.")
    return {"deleted": str(edge_id)}


# ── Export, templates, the sample company ──────────────────────────────────

def export_doc(session: Session) -> Dict[str, Any]:
    """The stored model in the same format the importer reads, so an export can be imported into another install."""
    s = state(session)
    N = {n["id"]: n for n in s["nodes"]}
    doc: Dict[str, Any] = {"company": {"name": s["organisation"]["name"]}, "departments": [], "people": [], "external": [], "data_stores": [], "ai_systems": [], "elements": [], "links": []}
    for n in s["nodes"]:
        p, t = n["props"], n["type"]
        if t == "department":
            doc["departments"].append({"id": n["id"], "name": n["name"], **({"reports_to": p["parent"]} if p.get("parent") else {}), **({"head": p["head"]} if p.get("head") else {})})
        elif t in PEOPLE:
            doc["people"].append({"id": n["id"], "name": n["name"], "kind": "role" if t == "role" else "person", **{k: v for k, v in p.items()}})
        elif t == "external":
            doc["external"].append({"id": n["id"], "name": n["name"], **({"title": p["title"]} if p.get("title") else {})})
        elif t == "data_store":
            doc["data_stores"].append({"id": n["id"], "name": n["name"], **p})
        elif t in ("agent", "model"):
            sysd = {"id": n["id"], "type": t, "name": n["name"], **({"department": p["department"]} if p.get("department") else {}), **({"owner": p["owner"]} if p.get("owner") else {})}
            det = {k: v for k, v in p.items() if k not in ("department", "owner")}
            if det:
                sysd["details"] = det
            sysd["people"] = [{"id": e["to"], "role": e["label"]} for e in s["edges"] if e["kind"] == "works_with" and e["from"] == n["id"]]
            sysd["hands_tasks_to"] = [{"agent": e["to"], "task": e["label"], **e["props"]} for e in s["edges"] if e["kind"] == "task" and e["from"] == n["id"]]
            sysd["uses_data"] = [{"store": e["to"], "access": e["label"] or "read"} for e in s["edges"] if e["kind"] == "access" and e["from"] == n["id"]]
            doc["ai_systems"].append({k: v for k, v in sysd.items() if v != []})
        else:
            doc["elements"].append({"id": n["id"], "type": t, "name": n["name"], **p})
    plain = {"works_with", "task", "access"}
    doc["links"] = [{"from": e["from"], "to": e["to"], "kind": e["kind"], **({"label": e["label"]} if e["label"] else {})} for e in s["edges"]
                    if e["kind"] not in plain and e["from"] in N and e["to"] in N]
    return {k: v for k, v in doc.items() if v != [] or k == "departments"}


@router.get("/export")
def export_company(session: Session = Depends(get_session)) -> Dict[str, Any]:
    return export_doc(session)


TEMPLATE = {
    "company": {"name": "Your company"},
    "departments": [{"id": "D-EXEC", "name": "Executive"}, {"id": "D-OPS", "name": "Operations", "reports_to": "D-EXEC", "head": "EMP-1001"}],
    "people": [{"id": "EMP-1001", "name": "Alex Example", "title": "Head of operations", "department": "D-OPS"},
               {"id": "ROLE-SUP", "name": "Support team", "kind": "role", "headcount": 12, "department": "D-OPS"}],
    "external": [{"id": "EXT-CUST", "name": "Customers", "kind": "customer"}],
    "ai_systems": [{"id": "AG-HELPER", "type": "agent", "name": "helper-agent", "department": "D-OPS", "owner": "EMP-1001",
                    "people": [{"id": "EXT-CUST", "role": "asks questions"}, {"id": "ROLE-SUP", "role": "escalate to"}]}],
}

STARTERS = {
    "empty": ("An empty company", {"company": {"name": "Your company"}, "departments": [{"id": "D-EXEC", "name": "Executive"}]}),
    "software": ("A small software company", {"company": {"name": "Your company"}, "departments": [
        {"id": "D-EXEC", "name": "Executive"}, {"id": "D-ENG", "name": "Engineering", "reports_to": "D-EXEC"},
        {"id": "D-SUP", "name": "Customer Support", "reports_to": "D-EXEC"}, {"id": "D-SEC", "name": "Security and Compliance", "reports_to": "D-EXEC"}]}),
    "bank": ("A bank", {"company": {"name": "Your bank"}, "departments": [
        {"id": "D-EXEC", "name": "Executive"}, {"id": "D-RET", "name": "Retail Banking", "reports_to": "D-EXEC"}, {"id": "D-RISK", "name": "Risk and Compliance", "reports_to": "D-EXEC"},
        {"id": "D-FIN", "name": "Finance Operations", "reports_to": "D-EXEC"}, {"id": "D-TECH", "name": "Technology", "reports_to": "D-EXEC"}],
        "external": [{"id": "EXT-CUST", "name": "Customers", "kind": "customer"}, {"id": "EXT-REG", "name": "Financial regulator", "kind": "regulator"}]}),
    "hospital": ("A hospital", {"company": {"name": "Your hospital"}, "departments": [
        {"id": "D-EXEC", "name": "Executive"}, {"id": "D-CLIN", "name": "Clinical Services", "reports_to": "D-EXEC"}, {"id": "D-CAI", "name": "Clinical AI", "reports_to": "D-EXEC"},
        {"id": "D-IT", "name": "IT and Security", "reports_to": "D-EXEC"}, {"id": "D-DPO", "name": "Data Protection", "reports_to": "D-EXEC"}],
        "external": [{"id": "EXT-PAT", "name": "Patients", "kind": "patient"}, {"id": "EXT-DPA", "name": "Data protection authority", "kind": "regulator"}]}),
}


@router.get("/template")
def template() -> Dict[str, Any]:
    return TEMPLATE


@router.get("/starters")
def starters() -> List[Dict[str, str]]:
    return [{"id": k, "name": v[0]} for k, v in STARTERS.items()]


@router.get("/starters/{name}")
def starter(name: str) -> Dict[str, Any]:
    if name not in STARTERS:
        raise HTTPException(status_code=404, detail="Unknown starting point.")
    return STARTERS[name][1]


def _sample() -> Dict[str, Any]:
    d = lambda i, n, p=None, h=None: {"id": i, "name": n, **({"reports_to": p} if p else {}), **({"head": h} if h else {})}
    ppl = lambda i, n, t, dp, **k: {"id": i, "name": n, "title": t, "department": dp, **k}
    el = lambda i, t, n, **k: {"id": i, "type": t, "name": n, **k}
    return {
        "company": {"name": "Acme Payments"},
        "departments": [d("D-EXEC", "Executive", None, "EMP-0007"), d("D-ENG", "Payments Engineering", "D-EXEC", "EMP-1042"), d("D-CX", "Customer Experience", "D-EXEC", "EMP-3105"),
                        d("D-RISK", "Risk & Compliance", "D-EXEC", "EMP-2210"), d("D-FIN", "Finance Operations", "D-EXEC"), d("D-CLIN", "Clinical AI", "D-EXEC", "EMP-4401"),
                        d("D-PLAT", "Platform & Security", "D-EXEC", "EMP-5120")],
        "people": [ppl("EMP-0007", "Maria Lopez", "CTO", "D-EXEC"), ppl("EMP-0001", "Tom Reyes", "CEO", "D-EXEC"), ppl("EMP-1042", "Sam Okoye", "Payments eng lead", "D-ENG"),
                   ppl("EMP-1090", "Li Wei", "Backend engineer", "D-ENG"), ppl("EMP-3105", "Jonas Weber", "CX lead", "D-CX"), ppl("ROLE-SUP", "Support agents", "Role", "D-CX", kind="role", headcount=24),
                   ppl("EMP-2210", "Priya Nair", "Compliance lead", "D-RISK"), ppl("EMP-6001", "Daniel Kim", "Finance ops (acting)", "D-FIN"),
                   ppl("ROLE-APR", "Finance approver", "Role", "D-FIN", kind="role"), ppl("EMP-4401", "Aiko Tanaka", "Data scientist", "D-CLIN"),
                   ppl("EMP-4410", "Omar Haddad", "Clinical safety officer", "D-CLIN"), ppl("ROLE-NUR", "Triage nurses", "Role", "D-CLIN", kind="role", headcount=40),
                   ppl("EMP-5120", "Lena Fischer", "Platform ops lead", "D-PLAT")],
        "external": [{"id": "EXT-CUST", "name": "Customers", "kind": "customer"}, {"id": "EXT-PAT", "name": "Patients", "kind": "patient"},
                     {"id": "EXT-DPA", "name": "Data protection authority", "kind": "regulator"}, {"id": "EXT-STR", "name": "Stripe", "kind": "vendor"}],
        "data_stores": [{"id": "DS-ORD", "name": "Order store", "department": "D-CX", "sensitivity": "Internal"},
                        {"id": "DS-EMAIL", "name": "Customer email addresses", "department": "D-CX", "sensitivity": "Personal data"},
                        {"id": "DS-RISK", "name": "Customer risk flags", "department": "D-RISK", "sensitivity": "Confidential"},
                        {"id": "DS-LEDG", "name": "Payments ledger", "department": "D-FIN", "sensitivity": "Confidential"},
                        {"id": "DS-IBAN", "name": "IBAN and amounts", "department": "D-FIN", "sensitivity": "Confidential"},
                        {"id": "DS-PHI", "name": "Patient records", "department": "D-CLIN", "sensitivity": "Special category"},
                        {"id": "DS-TRAIN", "name": "Training data set", "department": "D-CLIN", "sensitivity": "Special category", "sub": "de-identified notes"}],
        "ai_systems": [
            {"id": "AG-REFUND", "type": "agent", "name": "refund-agent", "department": "D-CX", "owner": "EMP-1042",
             "people": [{"id": "EXT-CUST", "role": "requests refunds"}, {"id": "EMP-3105", "role": "approves refunds over €100"}, {"id": "ROLE-SUP", "role": "escalate to"}, {"id": "EXT-STR", "role": "pays through"}],
             "hands_tasks_to": [{"agent": "AG-NOTIFY", "task": "Send confirmation email", "data": ["customer email", "order id"]},
                                {"agent": "AG-KYC", "task": "Check customer risk flag", "data": ["customer id"], "policy": "KYC data-sharing policy"},
                                {"agent": "AG-PAYOUT", "task": "Pay out refund over €500", "data": ["order id", "amount", "IBAN"]}],
             "uses_data": [{"store": "DS-ORD", "access": "read"}, {"store": "DS-EMAIL", "access": "read"}, {"store": "DS-RISK", "access": "read"}, {"store": "DS-LEDG", "access": "read"}]},
            {"id": "AG-NOTIFY", "type": "agent", "name": "notification-agent", "department": "D-PLAT", "owner": "EMP-5120",
             "people": [{"id": "EXT-CUST", "role": "emails"}, {"id": "EMP-5120", "role": "operates"}], "uses_data": [{"store": "DS-ORD", "access": "read"}, {"store": "DS-EMAIL", "access": "read"}]},
            {"id": "AG-KYC", "type": "agent", "name": "kyc-agent", "department": "D-RISK", "owner": "EMP-2210", "people": [{"id": "EMP-2210", "role": "owns"}], "uses_data": [{"store": "DS-RISK", "access": "write"}]},
            {"id": "AG-PAYOUT", "type": "agent", "name": "payouts-agent", "department": "D-FIN", "people": [{"id": "ROLE-APR", "role": "approved by"}], "uses_data": [{"store": "DS-LEDG", "access": "write"}]},
            {"id": "MD-TRIAGE", "type": "model", "name": "clinical-triage-llm", "department": "D-CLIN", "owner": "EMP-4401",
             "details": {"purpose": "Suggest a triage level to nurses", "version": "2.3", "risk_class": "High", "origin": "In-house", "data_note": "Patient records (special category)"},
             "people": [{"id": "EMP-4401", "role": "trains"}, {"id": "EMP-4410", "role": "validates"}, {"id": "EMP-4410", "role": "deploys"}, {"id": "EMP-2210", "role": "approves release"},
                        {"id": "ROLE-NUR", "role": "operates"}, {"id": "EXT-PAT", "role": "decides about"}, {"id": "EXT-DPA", "role": "oversight by"}],
             "uses_data": [{"store": "DS-TRAIN", "access": "trained on"}, {"store": "DS-PHI", "access": "reads"}]}],
        "elements": [
            el("OP-REQ", "operation", "Request refund"), el("OP-APPR", "operation", "Approve refund >€100"), el("OP-ISSUE", "operation", "Issue refund"), el("OP-CONF", "operation", "Send confirmation"),
            el("OP-RISK", "operation", "Check risk flag"), el("OP-AUDIT", "operation", "Review audit trail"),
            el("G-RESOLVE", "goal", "Resolve refunds within policy"), el("G-INFORM", "goal", "Keep customers informed"),
            el("POL-REFUND", "policy", "Refund approval policy"), el("POL-KYC", "policy", "KYC data policy"), el("POL-RET", "policy", "Retention 30 days"),
            el("TH-INJ", "threat", "Prompt injection via support inbox"), el("TH-EMAIL", "threat", "Email shared too widely"), el("TH-PAYOUT", "threat", "Undeclared payout handoff"),
            el("TH-FLAGS", "threat", "Risk flags exposed to another agent"), el("TH-LEAK", "threat", "Training data leakage"),
            el("PR-ALLOW", "protection", "Contract tool allow-list", sub="Only tools the ratified contract lists can run"), el("PR-MIN", "protection", "Send order id only (minimise)"),
            el("PR-MON", "protection", "Runtime drift monitoring", sub="Anything outside the contract becomes a finding"),
            el("RULE-SC", "rule", "Separate validator and deployer", sub="rule SC-RCF-1", rule_id="separate_validator_deployer"),
            el("RULE-HUMAN", "rule", "A nurse reviews every decision", sub="human oversight", status="in_place"),
            el("ENV-PLAT", "environment", "Platform & Security", sub="hosting environment", department="D-PLAT"),
            el("ST-1", "step", "Detect", sub="Finding or drift raised", lane="D-PLAT", order=1, who="EMP-5120", when="Immediately", astra="Live runtime flags an event outside the contract and raises a finding."),
            el("ST-2", "step", "Contain", sub="Pause agent, revoke key", lane="D-PLAT", order=2, who="EMP-5120", when="Within 1 hour", astra="Revoke the agent's API key."),
            el("ST-3", "decision", "Personal data?", sub="Assess the impact", lane="D-RISK", order=3, who="EMP-2210", when="Within 24 hours", astra="Data mapping shows which data stores the agent touched."),
            el("ST-4", "step", "Tell regulator", sub="Data protection authority", lane="D-RISK", order=4, who="EMP-2210", deputy="EMP-0007", when="Within 72 hours", legal_deadline=True, astra="A pack of the findings and the contract is exported as evidence."),
            el("ST-5", "step", "Tell customers", sub="If high risk to them", lane="D-CX", order=5, who="EMP-3105", when="Without undue delay", astra="The list of affected customers comes from the data store owner."),
            el("ST-6", "step", "Fix and review", sub="New contract, lessons", lane="D-ENG", order=6, who="EMP-1042", when="Within 30 days", astra="The fix becomes a new contract version that compliance ratifies.")],
        "links": [
            {"from": "EXT-CUST", "to": "OP-REQ", "kind": "performs"}, {"from": "EMP-3105", "to": "OP-APPR", "kind": "performs"}, {"from": "AG-REFUND", "to": "OP-ISSUE", "kind": "performs"},
            {"from": "AG-NOTIFY", "to": "OP-CONF", "kind": "performs"}, {"from": "AG-KYC", "to": "OP-RISK", "kind": "performs"}, {"from": "EMP-2210", "to": "OP-AUDIT", "kind": "performs"},
            {"from": "OP-REQ", "to": "OP-ISSUE", "kind": "triggers", "label": "triggers"}, {"from": "OP-APPR", "to": "OP-ISSUE", "kind": "gates", "label": "gates"},
            {"from": "OP-ISSUE", "to": "OP-CONF", "kind": "triggers", "label": "hands task to"}, {"from": "OP-ISSUE", "to": "OP-RISK", "kind": "triggers", "label": "hands task to"},
            {"from": "OP-APPR", "to": "G-RESOLVE", "kind": "achieves"}, {"from": "OP-ISSUE", "to": "G-RESOLVE", "kind": "achieves"}, {"from": "OP-CONF", "to": "G-INFORM", "kind": "achieves"},
            {"from": "POL-REFUND", "to": "OP-APPR", "kind": "governs"}, {"from": "POL-KYC", "to": "OP-RISK", "kind": "governs"}, {"from": "POL-RET", "to": "OP-AUDIT", "kind": "governs"},
            {"from": "TH-INJ", "to": "DS-EMAIL", "kind": "targets"}, {"from": "TH-INJ", "to": "DS-IBAN", "kind": "targets"}, {"from": "TH-EMAIL", "to": "DS-EMAIL", "kind": "targets"},
            {"from": "TH-PAYOUT", "to": "DS-IBAN", "kind": "targets"}, {"from": "TH-FLAGS", "to": "DS-RISK", "kind": "targets"}, {"from": "TH-LEAK", "to": "DS-PHI", "kind": "targets"},
            {"from": "PR-ALLOW", "to": "TH-INJ", "kind": "mitigates"}, {"from": "PR-MIN", "to": "TH-EMAIL", "kind": "mitigates"}, {"from": "PR-MON", "to": "TH-PAYOUT", "kind": "mitigates"},
            {"from": "POL-KYC", "to": "TH-FLAGS", "kind": "mitigates"},
            {"from": "RULE-SC", "to": "EMP-4410", "kind": "applies_to"}, {"from": "RULE-HUMAN", "to": "ROLE-NUR", "kind": "applies_to"}, {"from": "ENV-PLAT", "to": "MD-TRIAGE", "kind": "hosts"},
            {"from": "ST-1", "to": "ST-2", "kind": "next"}, {"from": "ST-2", "to": "ST-3", "kind": "next"}, {"from": "ST-3", "to": "ST-4", "kind": "next", "label": "yes"},
            {"from": "ST-4", "to": "ST-5", "kind": "next", "label": "high risk"}, {"from": "ST-5", "to": "ST-6", "kind": "next"}, {"from": "ST-3", "to": "ST-6", "kind": "next", "label": "no personal data"}]}


@router.get("/sample")
def sample() -> Dict[str, Any]:
    return _sample()


# ── Describe it to the assistant (proposals only; nothing is saved until the person accepts) ──

class DraftIn(BaseModel):
    description: str = Field(min_length=10, max_length=4000)
    history: List[str] = Field(default_factory=list, max_length=6)       # what the person said earlier in this conversation


# Every field is required on purpose. With optional fields a local model, constrained to the schema, is allowed to answer {} and does;
# required fields make it fill each list (with nothing in it, if the description says nothing).
class DraftDept(BaseModel):
    name: str = Field(description="Department name exactly as written")
    reports_to: str = Field(description="Name of the department it reports to, or empty")
    head: str = Field(description="Full name of the person who leads it, or empty")


class DraftPerson(BaseModel):
    name: str = Field(description="Full name as written, or the group name such as 'support agents'")
    title: str = Field(description="Job title, or empty")
    department: str = Field(description="Department they belong to, or empty")
    is_group: bool = Field(description="true for a group of people, false for one person")


class DraftOutside(BaseModel):
    name: str = Field(description="A party outside the company, such as customers, patients, a regulator or a supplier")
    kind: str = Field(description="customer, patient, regulator or vendor")


class DraftSystem(BaseModel):
    name: str = Field(description="Name of the AI agent or AI model as written")
    type: Literal["agent", "model"]
    department: str = Field(description="Department it belongs to, or empty")
    owner: str = Field(description="Person accountable for it, or empty")
    purpose: str = Field(description="What it does, in a few words, or empty")


class DraftRole(BaseModel):
    system: str = Field(description="Name of the AI agent or model")
    person: str = Field(description="Name of the person, group or outside party it deals with")
    role: str = Field(description="How, e.g. requests refunds, approves payouts over 100, escalate to, trains, validates, deploys, operates, decides about")


class DraftTask(BaseModel):
    from_agent: str
    to_agent: str
    task: str = Field(description="What is handed over")
    data: List[str] = Field(description="Kinds of data passed with it, or an empty list")


class DraftStore(BaseModel):
    name: str = Field(description="A data store or kind of data, as written")
    department: str = Field(description="Department that owns it, or empty")
    sensitivity: str = Field(description="personal data, health data, confidential, internal or public, or empty")


class DraftUse(BaseModel):
    system: str
    store: str
    access: Literal["read", "write"]


class DraftProposal(BaseModel):
    company_name: str = Field(description="Name of the company, or empty")
    departments: List[DraftDept]
    people: List[DraftPerson]
    outside_parties: List[DraftOutside]
    ai_systems: List[DraftSystem]
    roles: List[DraftRole]
    task_links: List[DraftTask]
    data_stores: List[DraftStore]
    data_use: List[DraftUse]


FULL_DRAFT_PROMPT = (
    "You turn a plain-English description of a company into a draft organisation, as JSON. Include everything the description says and nothing it does not: "
    "departments, people (with title and department), outside parties (customers, patients, regulators, suppliers), the AI agents and models and who owns them, "
    "who each one deals with and in what role, tasks one AI agent hands to another (with the data passed), and the data stores and who reads or writes them. "
    "Use the exact names written. Never invent a person, surname, department, agent or data store that is not described; leave a field empty instead of guessing. "
    "If something earlier in the conversation is still true, keep it: always return the whole organisation described so far, not only the newest message.\n\n"
    "Example. Description: 'Acme runs support. Dana Cole leads Support, which has a refund-agent owned by Dana. Customers ask it for refunds, and it hands "
    "payments to the ledger-agent in Finance (led by Omar Ali) with the order id. Omar approves payments over 100. The order database holds personal data.' "
    "Result: company_name Acme; departments Support (head Dana Cole) and Finance (head Omar Ali); people Dana Cole (title leader of Support, department Support) and "
    "Omar Ali (department Finance); outside_parties Customers (customer); ai_systems refund-agent (agent, Support, owner Dana Cole) and ledger-agent (agent, Finance); "
    "roles refund-agent / Customers / requests refunds and ledger-agent / Omar Ali / approves payments over 100; task_links refund-agent to ledger-agent, task make the payment, data order id; "
    "data_stores order database (personal data); data_use refund-agent reads order database. A department 'reports_to' only ever names another department, never a person.")


GROUP = {"department": "d", "person": "p", "role": "p", "external": "p", "agent": "s", "model": "s", "data_store": "x"}


# ── The format the model is actually asked for: one short line per item ──
# The object-per-item schema above is clear but long: every empty field is written out, and a CPU model writes about five tokens a second.
# One "a | b | c" string per item says the same in a third of the tokens. The lines are parsed here, in code, into the proposal above.

class DraftCompact(BaseModel):
    company: str
    departments: List[str]
    people: List[str]
    outside: List[str]
    systems: List[str]
    roles: List[str]
    handoffs: List[str]
    data: List[str]
    uses: List[str]


COMPACT_PROMPT = (
    "You turn a plain-English description of a company into a draft organisation, as JSON with these lists. Each item is ONE text line with fields separated by ' | ' "
    "(leave a field empty if the description does not say):\n"
    "company: the company name.\n"
    "departments: 'name | reports to (another department) | head (a person)'.\n"
    "people: 'full name | job title | department | group' (write the word group only for a group of people, such as support agents).\n"
    "outside: 'name | customer, patient, regulator or vendor' (parties outside the company).\n"
    "systems: 'name | agent or model | department | owner (a person) | what it does'.\n"
    "roles: 'AI system | person or party | their role', for example requests refunds, approves payouts over 100, escalate to, trains, validates, deploys, operates.\n"
    "handoffs: 'from agent | to agent | what is handed over | data passed, comma separated'.\n"
    "data: 'data store | department | sensitivity (personal data, health data, confidential, internal or public)'.\n"
    "uses: 'AI system | data store | read or write'.\n"
    "Include everything the description says and nothing it does not. Use the exact names written. Never invent a person, department, agent or data store; leave a field empty instead. "
    "A department's 'reports to' names a department, never a person. Return the whole organisation described so far, not only the newest message.\n\n"
    "Example. Description: 'Acme runs support. Dana Cole leads Support, which has a refund-agent owned by Dana. Customers ask it for refunds, and it hands payments to the "
    "ledger-agent in Finance (led by Omar Ali) with the order id. Omar approves payments over 100. The order database holds personal data.' Result: "
    '{"company":"Acme","departments":["Support | | Dana Cole","Finance | | Omar Ali"],"people":["Dana Cole | leader of Support | Support |","Omar Ali | | Finance |"],'
    '"outside":["Customers | customer"],"systems":["refund-agent | agent | Support | Dana Cole | decides refunds","ledger-agent | agent | Finance | | makes payments"],'
    '"roles":["refund-agent | Customers | requests refunds","ledger-agent | Omar Ali | approves payments over 100"],"handoffs":["refund-agent | ledger-agent | make the payment | order id"],'
    '"data":["order database | Support | personal data"],"uses":["refund-agent | order database | read"]}')


def _fields(line: str, n: int) -> List[str]:
    parts = [p.strip() for p in str(line).split("|")]
    return (parts + [""] * n)[:n]


def parse_compact(c: DraftCompact) -> DraftProposal:
    """The model's one-line items as a DraftProposal. Missing fields are empty, a line with no name is skipped; nothing here can fail on a malformed line."""
    flag = lambda v: bool(re.search(r"group|true|yes", v, re.I))
    return DraftProposal(
        company_name=c.company.strip(),
        departments=[DraftDept(name=f[0], reports_to=f[1], head=f[2]) for f in (_fields(x, 3) for x in c.departments) if f[0]],
        people=[DraftPerson(name=f[0], title=f[1], department=f[2], is_group=flag(f[3])) for f in (_fields(x, 4) for x in c.people) if f[0]],
        outside_parties=[DraftOutside(name=f[0], kind=f[1]) for f in (_fields(x, 2) for x in c.outside) if f[0]],
        ai_systems=[DraftSystem(name=f[0], type="model" if re.search(r"model|llm", f[1], re.I) else "agent", department=f[2], owner=f[3], purpose=f[4]) for f in (_fields(x, 5) for x in c.systems) if f[0]],
        roles=[DraftRole(system=f[0], person=f[1], role=f[2]) for f in (_fields(x, 3) for x in c.roles) if f[0] and f[1] and f[2]],
        task_links=[DraftTask(from_agent=f[0], to_agent=f[1], task=f[2], data=[d.strip() for d in f[3].split(",") if d.strip()]) for f in (_fields(x, 4) for x in c.handoffs) if f[0] and f[1]],
        data_stores=[DraftStore(name=f[0], department=f[1], sensitivity=f[2]) for f in (_fields(x, 3) for x in c.data) if f[0]],
        data_use=[DraftUse(system=f[0], store=f[1], access="write" if re.search(r"write", f[2], re.I) else "read") for f in (_fields(x, 3) for x in c.uses) if f[0] and f[1]])


def proposal_to_doc(prop: DraftProposal, existing: Dict[str, CompanyNode]) -> Dict[str, Any]:
    """Names become ids: an existing item with the same name is reused, a new one gets a generated id. Anyone or anything the description names is
    added if it is not there yet, so a reference never dangles. A model sometimes puts a person where a department belongs (or the reverse): such a
    reference is ignored rather than turned into a department called after a person. Pure code, no model."""
    section = {"department": "departments", "person": "people", "role": "people", "external": "external", "agent": "ai_systems", "model": "ai_systems", "data_store": "data_stores"}
    by_name: Dict[Tuple[str, str], Tuple[str, str]] = {(GROUP[n.type], n.name.strip().lower()): (n.ext_id, n.type) for n in existing.values() if n.type in GROUP}
    doc: Dict[str, Any] = {k: [] for k in ("departments", "people", "external", "ai_systems", "data_stores")}
    objs: Dict[str, Dict[str, Any]] = {}
    taken = set(existing)
    low = lambda s: s.strip().lower()
    claimed = {low(x.name) for x in prop.people + prop.outside_parties + prop.ai_systems + prop.data_stores}      # names the description gave to something that is not a department
    dept_names = {low(d.name) for d in prop.departments} | {k[1] for k in by_name if k[0] == "d"}

    def make(name: str, type_: str) -> str:
        key = (GROUP[type_], low(name))
        if key in by_name:
            return by_name[key][0]
        base = f"{PREFIX[type_]}-{slug(name)}"
        i, n = base, 2
        while i in taken:
            i, n = f"{base}-{n}", n + 1
        taken.add(i)
        by_name[key] = (i, type_)
        o: Dict[str, Any] = {"id": i, "name": name.strip()}
        if type_ in ("agent", "model"):
            o["type"] = type_
        if type_ == "role":
            o["kind"] = "role"
        doc[section[type_]].append(o)
        objs[i] = o
        return i

    def dref(name: str) -> Optional[str]:
        """A department reference, unless the name belongs to a person, an AI system or data."""
        if not name.strip() or low(name) in claimed or any(k[0] != "d" and k[1] == low(name) for k in by_name):
            return None
        return make(name, "department")

    def pref(name: str) -> Optional[str]:
        """A person reference, unless the name is a department."""
        if not name.strip() or (low(name) in dept_names and low(name) not in claimed):
            return None
        return make(name, "person")

    def obj(i: str, type_: str, name: str) -> Dict[str, Any]:
        """The file entry for an item, so fields can be added to it; an item already in the organisation gets a stub (an import leaves it unchanged)."""
        if i not in objs:
            o: Dict[str, Any] = {"id": i, "name": name}
            if type_ in ("agent", "model"):
                o["type"] = type_
            doc[section[type_]].append(o)
            objs[i] = o
        return objs[i]

    typ = lambda i: next((t for (j, t) in by_name.values() if j == i), "person")
    for d in prop.departments[:20]:
        if d.name.strip() and low(d.name) not in claimed:
            i = make(d.name, "department")
            o = objs.get(i)
            if o is not None:
                parent = dref(d.reports_to) if low(d.reports_to) != low(d.name) else None
                if parent:
                    o["reports_to"] = parent
                head = pref(d.head)
                if head:
                    o["head"] = head
    for p in prop.people[:30]:
        if p.name.strip():
            i = make(p.name, "role" if p.is_group else "person")
            o = objs.get(i)
            if o is not None:
                if p.title.strip():
                    o["title"] = p.title.strip()
                dep = dref(p.department)
                if dep:
                    o["department"] = dep
    for x in prop.outside_parties[:15]:
        if x.name.strip():
            i = make(x.name, "external")
            if i in objs and x.kind.strip():
                objs[i]["kind"] = x.kind.strip()
    for s in prop.ai_systems[:20]:
        if s.name.strip():
            i = make(s.name, s.type)
            o = objs.get(i)
            if o is not None:
                dep = dref(s.department)
                if dep:
                    o["department"] = dep
                own = pref(s.owner)
                if own:
                    o["owner"] = own
                if s.purpose.strip():
                    o["details"] = {"purpose": s.purpose.strip()[:300]}
    for st in prop.data_stores[:20]:
        if st.name.strip():
            i = make(st.name, "data_store")
            o = objs.get(i)
            if o is not None:
                dep = dref(st.department)
                if dep:
                    o["department"] = dep
                if st.sensitivity.strip():
                    o["sensitivity"] = st.sensitivity.strip()
    for r in prop.roles[:40]:
        if r.system.strip() and r.person.strip() and r.role.strip():
            si = make(r.system, "agent")
            pi = make(r.person, "person")
            o = obj(si, typ(si) if typ(si) in ("agent", "model") else "agent", r.system.strip())
            o.setdefault("people", []).append({"id": pi, "role": r.role.strip()})
    for t in prop.task_links[:30]:
        if t.from_agent.strip() and t.to_agent.strip() and low(t.from_agent) != low(t.to_agent):
            a = make(t.from_agent, "agent")
            b = make(t.to_agent, "agent")
            o = obj(a, "agent", t.from_agent.strip())
            o.setdefault("hands_tasks_to", []).append({"agent": b, "task": t.task.strip(), "data": [x.strip() for x in t.data if x.strip()][:10]})
    for u in prop.data_use[:40]:
        if u.system.strip() and u.store.strip():
            si = make(u.system, "agent")
            di = make(u.store, "data_store")
            o = obj(si, typ(si) if typ(si) in ("agent", "model") else "agent", u.system.strip())
            o.setdefault("uses_data", []).append({"store": di, "access": u.access})
    out = {k: v for k, v in doc.items() if v}
    if prop.company_name.strip():
        out = {"company": {"name": prop.company_name.strip()[:120]}, **out}
    return out


# The same description must give the same draft. Every generation setting is fixed here, not left to the model's defaults: greedy decoding
# (temperature 0, top_k 1), a fixed seed, and a fixed context window and repetition penalty. Change one of these and the drafts change with it.
DRAFT_OPTIONS: Dict[str, Any] = {"temperature": 0, "top_k": 1, "top_p": 1.0, "repeat_penalty": 1.1, "seed": 42, "num_ctx": 4096, "num_predict": 1400}
DRAFT_CACHE_KEEP = 500


def draft_key(messages: List[Dict[str, str]], schema: Dict[str, Any]) -> str:
    """The fingerprint of everything that decides the model's answer. Change the model, the prompt, the schema, a setting or one word of the
    description and it changes; otherwise the earlier answer is reused. This is what makes the same description give the same draft: even with a
    fixed seed and temperature 0, Ollama's prompt cache lets the first and a later run differ in the last digit of a calculation, and now and then in a word."""
    import ollama_client
    blob = json.dumps({"model": ollama_client.OLLAMA_MODEL, "messages": messages, "schema": schema, "options": DRAFT_OPTIONS}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


DRAFT_TIMEOUT = 900.0                                    # a CPU-only model writing a whole organisation can take several minutes
JOB_KEEP = 1800
_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _run_draft(job_id: str, body: DraftIn) -> None:
    """Runs in a thread: asks the model, turns its answer into a file, and checks it against the stored organisation. Never raises."""
    from db.session import SessionLocal
    import ollama_client
    try:
        with SessionLocal() as session:
            org, ns, es = load(session)
            # The model is deliberately not shown what is already stored: a small model mixes it into its answer and gets slower.
            # Items with the same name are matched to the stored ones afterwards, in code.
            user = ""
            if body.history:
                user += "Earlier in this conversation the person said:\n" + "\n".join(f"- {h.strip()[:1500]}" for h in body.history if h.strip()) + "\n\nNow they add:\n"
            user += body.description.strip()
            def progress(n: int) -> None:
                with _jobs_lock:
                    _jobs[job_id]["pieces"] = n
            messages = [{"role": "system", "content": COMPACT_PROMPT}, {"role": "user", "content": user}]
            schema = DraftCompact.model_json_schema()
            key = draft_key(messages, schema)
            hit = session.scalar(select(CompanyDraftCache).where(CompanyDraftCache.key == key))
            cached = hit is not None
            raw = hit.raw if hit else ollama_client.chat_json(messages, schema, temperature=0, timeout=DRAFT_TIMEOUT, on_progress=progress, options=DRAFT_OPTIONS)
            try:
                prop = parse_compact(DraftCompact.model_validate(raw))
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"The model returned a malformed proposal: {exc}")
            if not cached:                                       # only a usable draft is kept
                try:
                    session.add(CompanyDraftCache(key=key, raw=raw))
                    session.execute(delete(CompanyDraftCache).where(CompanyDraftCache.id.in_(
                        select(CompanyDraftCache.id).order_by(CompanyDraftCache.created_at.desc()).offset(DRAFT_CACHE_KEEP))))
                    session.commit()
                except Exception:                                # a second identical draft finishing at the same moment: the first one stands
                    session.rollback()
            doc = proposal_to_doc(prop, {n.ext_id: n for n in ns})
            result = {"doc": doc, "cached": cached, "plan": public_plan(plan(session, doc, [])) if any(k != "company" for k in doc) else None}
        outcome: Dict[str, Any] = {"status": "done", "result": result}
    except HTTPException as exc:
        outcome = {"status": "error", "error": {"status": exc.status_code, "detail": str(exc.detail)}}
    except Exception as exc:                                 # a thread must not die silently
        outcome = {"status": "error", "error": {"status": 500, "detail": f"The draft failed: {exc}"}}
    with _jobs_lock:
        _jobs[job_id].update(outcome, finished=time.time())


_warm = {"at": 0.0}


@router.post("/assistant/warm", status_code=202)
def warm_assistant() -> Dict[str, Any]:
    """Asks the local model to load now (it takes a couple of minutes from cold on a CPU) so the first draft is quick. Does at most one warm-up every ten minutes."""
    import ollama_client
    now = time.time()
    with _jobs_lock:
        if now - _warm["at"] < 600:
            return {"warming": False}
        _warm["at"] = now
    threading.Thread(target=lambda: ollama_client.warm(), daemon=True).start()
    return {"warming": True}


@router.post("/draft", status_code=202)
def draft(body: DraftIn, user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    """Starts a draft and returns at once; poll GET /draft/{job}. Nothing is saved: the result is a proposal."""
    now = time.time()
    with _jobs_lock:
        for k in [k for k, j in _jobs.items() if now - j["started"] > JOB_KEEP]:
            del _jobs[k]
        if sum(1 for j in _jobs.values() if j["status"] == "running" and j["user"] == str(user.id)) >= 2:
            raise HTTPException(status_code=429, detail="Two drafts are already running for you. Wait for one to finish.")
        job_id = uuid.uuid4().hex[:16]
        _jobs[job_id] = {"status": "running", "started": now, "user": str(user.id)}
    threading.Thread(target=_run_draft, args=(job_id, body), daemon=True).start()
    return {"job": job_id}


@router.get("/draft/{job_id}")
def draft_status(job_id: str, user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    with _jobs_lock:
        j = _jobs.get(job_id)
        if j is None or j["user"] != str(user.id):
            raise HTTPException(status_code=404, detail="That draft is no longer available. Send the description again.")
        return {"status": j["status"], "elapsed": int((j.get("finished") or time.time()) - j["started"]), "pieces": j.get("pieces", 0), "result": j.get("result"), "error": j.get("error")}


# ── Starting points for the two studios (read only: the organisation is not changed) ──

VENDOR = re.compile(r"vendor|supplier|provider|processor|partner", re.I)
APPROVES = re.compile(r"approv", re.I)
WRITES = re.compile(r"write|rw|read\s*/\s*write", re.I)
MODEL_ROLES = [(re.compile(r"train", re.I), "TRAINER"), (re.compile(r"validat|review", re.I), "VALIDATOR"), (re.compile(r"deploy", re.I), "DEPLOYER"),
               (re.compile(r"operat", re.I), "OPERATOR"), (re.compile(r"decid|consum|affect|about", re.I), "CONSUMER")]
SENSITIVITY = [("PUBLIC", re.compile(r"public", re.I)), ("INTERNAL", re.compile(r"internal", re.I)), ("CONFIDENTIAL", re.compile(r"confidential", re.I)),
               ("SENSITIVE_PERSONAL", re.compile(r"personal|patient|health", re.I)), ("SPECIAL_CATEGORY", re.compile(r"special", re.I))]


def _graph(session: Session) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    _, ns, es = load(session)
    return {n.ext_id: node_out(n) for n in ns}, [edge_out(e) for e in es]


def _system(N: Dict[str, Dict[str, Any]], ext_id: str, kind: str) -> Dict[str, Any]:
    n = N.get(ext_id)
    if n is None or n["type"] != kind:
        raise HTTPException(status_code=404, detail=f"That {kind} is not in the organisation.")
    return n


def _dept_name(N: Dict[str, Dict[str, Any]], i: Optional[str]) -> str:
    d = N.get(N[i]["props"].get("department", "")) if i and i in N else None
    return d["name"] if d else ""


def _crosses(N: Dict[str, Dict[str, Any]], a: str, b: str) -> bool:
    da, db = N[a]["props"].get("department"), N[b]["props"].get("department")
    return bool(da and db and da != db)


def agent_seed(session: Session, ext_id: str) -> Dict[str, Any]:
    """What the organisation already knows about one agent, as the starting point of its design. Names only; the design studio decides what to do with them."""
    N, edges = _graph(session)
    a = _system(N, ext_id, "agent")
    owner = a["props"].get("owner")
    humans: List[Dict[str, Any]] = []
    approvals: List[Dict[str, Any]] = []
    externals: List[Dict[str, Any]] = []
    delegates: List[Dict[str, Any]] = []
    inputs: List[Dict[str, Any]] = []
    data: List[Dict[str, Any]] = []
    goals: List[str] = []
    for e in edges:
        if e["kind"] == "works_with" and e["from"] == ext_id and e["to"] in N:
            t = N[e["to"]]
            if APPROVES.search(e["label"]):
                approvals.append({"name": f"Approval: {t['name']}", "person": t["name"], "label": e["label"]})
            elif e["to"] == owner:
                continue                                                 # the owner is the owner, not a user of the agent
            elif t["type"] == "external" and VENDOR.search(t["props"].get("title", "")):
                externals.append({"name": t["name"], "label": e["label"]})
            else:
                humans.append({"name": t["name"], "label": e["label"], "kind": t["type"]})
        elif e["kind"] == "task" and e["from"] == ext_id and e["to"] in N:
            t = N[e["to"]]
            delegates.append({"name": t["name"], "owner": N[t["props"]["owner"]]["name"] if t["props"].get("owner") in N else "", "department": _dept_name(N, e["to"]),
                              "task": e["label"], "data": e["props"].get("data") or [], "cross_department": _crosses(N, ext_id, e["to"])})
        elif e["kind"] == "task" and e["to"] == ext_id and e["from"] in N:
            s = N[e["from"]]
            inputs.append({"name": f"{s['name']}: {e['label']}" if e["label"] else s["name"], "from": s["name"], "department": _dept_name(N, e["from"]), "cross_department": _crosses(N, ext_id, e["from"])})
        elif e["kind"] == "access" and e["from"] == ext_id and e["to"] in N:
            data.append({"name": N[e["to"]]["name"], "write": bool(WRITES.search(e["label"]))})
        elif e["kind"] == "performs" and e["from"] == ext_id and e["to"] in N and N[e["to"]]["type"] == "operation":
            achieved = [N[x["to"]]["name"] for x in edges if x["kind"] == "achieves" and x["from"] == e["to"] and x["to"] in N]
            for g in achieved or [N[e["to"]]["name"]]:
                if g not in goals:
                    goals.append(g)
    return {"id": ext_id, "name": a["name"], "department": _dept_name(N, ext_id), "owner": N[owner]["name"] if owner in N else "", "purpose": a["props"].get("purpose", ""),
            "humans": humans, "approvals": approvals, "externals": externals, "delegates": delegates, "inputs": inputs, "data": data, "goals": goals[:3],
            "notes": ["Tools, MCP servers, memory and guardrails are not in the organisation: add them in the design studio."]}


def model_description(session: Session, ext_id: str) -> Dict[str, Any]:
    """A deployment description (the format the Model studio already imports) for one model: its departments, the people in each lifecycle role, and where it runs."""
    from compliance_schema import DeploymentDescription
    N, edges = _graph(session)
    m = _system(N, ext_id, "model")
    depts: Dict[str, str] = {}

    def add_dept(i: Optional[str]) -> Optional[str]:
        first, hops = None, 0
        while i and i in N and N[i]["type"] == "department" and hops < 10:
            first = first or f"dep-{i}"
            depts.setdefault(i, N[i]["name"])
            i, hops = N[i]["props"].get("parent"), hops + 1
        return first

    add_dept(m["props"].get("department"))
    actors: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for e in edges:
        if e["kind"] != "works_with" or e["from"] != ext_id or e["to"] not in N:
            continue
        t = N[e["to"]]
        sub = next((s for rx, s in MODEL_ROLES if rx.search(e["label"])), None)
        if sub is None:
            skipped.append(f"{t['name']} ({e['label'] or 'no role'}): the model studio has no place for this role")
            continue
        actors.append({"temp_id": f"act-{len(actors) + 1}", "subtype": sub, "identity": t["name"], "department_temp_id": add_dept(t["props"].get("department")) if t["type"] in PEOPLE else None})
    envs = [{"temp_id": f"env-{e['from']}", "name": N[e["from"]]["name"], "description": N[e["from"]]["props"].get("sub", "")} for e in edges if e["kind"] == "hosts" and e["to"] == ext_id and e["from"] in N]
    p = m["props"]
    risk = (p.get("risk_class") or "").lower()
    criticality = "SAFETY_CRITICAL" if re.search(r"safety|very high|unacceptable", risk) else "CRITICAL" if "high" in risk else "ADVISORY" if re.search(r"low|minimal", risk) else "OPERATIONAL"
    texts = [p.get("data_note", "")] + [N[e["to"]]["props"].get("sensitivity", "") for e in edges if e["kind"] == "access" and e["from"] == ext_id and e["to"] in N]
    sens = max((i for t in texts for i, (_, rx) in enumerate(SENSITIVITY) if rx.search(t or "")), default=1)
    origin = (p.get("origin") or "").lower()
    hosting = "TYPE_3_THIRDPARTY_API" if re.search(r"third|api|vendor|saas", origin) else "TYPE_2_FINETUNED" if "fine" in origin else "TYPE_1_INHOUSE"
    dep_list = [{"temp_id": f"dep-{i}", "name": n, "reports_to_temp_id": (f"dep-{N[i]['props']['parent']}" if N[i]["props"].get("parent") in depts else None)} for i, n in depts.items()]
    desc = {"schema_version": "1.0", "deployment_name": m["name"], "description": p.get("purpose", ""), "departments": dep_list, "actors": actors,
            "ai_models": [{"temp_id": "mdl-1", "name": m["name"], "model_type": "LLM", "ai_criticality": criticality, "data_sensitivity": SENSITIVITY[sens][0], "hosting_environment": hosting, "domain": p.get("purpose", "")[:120]}],
            "deployment_environments": envs}
    try:
        DeploymentDescription(**desc)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"The organisation's description of this model cannot be used as it is: {exc}")
    trained = [N[e["to"]]["name"] for e in edges if e["kind"] == "access" and e["from"] == ext_id and e["to"] in N and re.search(r"train", e["label"], re.I)]
    notes = ["Constraints and their status are not in the organisation: every constraint starts as not yet determined."]
    if trained:
        notes.append(f"Training data ({', '.join(trained)}) is not carried over; add it in the studio if the assessment needs it.")
    return {"id": ext_id, "name": m["name"], "description": desc, "skipped": skipped, "notes": notes, "datasets": trained}


@router.get("/systems/{ext_id}/agent-seed")
def get_agent_seed(ext_id: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    return agent_seed(session, ext_id)


@router.get("/systems/{ext_id}/deployment-description")
def get_deployment_description(ext_id: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    return model_description(session, ext_id)
