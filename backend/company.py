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
import json
import re
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
from agent_registry import agent_key as to_agent_key
from auth import AuthUser, current_user
from db.models import Agent, CompanyEdge, CompanyNode, Contract, RuntimeEvent
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
    return {"agents": agent_live, "tasks": task_live, "unmodelled": unmodelled, "unmapped_agents": unmapped}


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
    renamed = None
    name = p.get("company_name")
    if name and str(name).strip() and str(name).strip() != org.name and user.role == "admin":
        org.name = str(name).strip()[:120]
        renamed = org.name
    session.commit()
    return {"created": made, "updated": changed, "connections": links, "renamed": renamed}


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
    session.commit()
    return {"id": ext_id}


@router.delete("/nodes/{ext_id}")
def delete_node(ext_id: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    org = current_organisation(session)
    row = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id == ext_id))
    if row is None:
        raise HTTPException(status_code=404, detail="That item is not in the organisation.")
    others = list(session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id != ext_id)))
    users = [o for o in others if any(o.props.get(k) == ext_id for k in ("parent", "department", "lane"))]
    if row.type == "department" and users:
        raise HTTPException(status_code=409, detail=f"{row.name} still has {len(users)} item(s) in it ({', '.join(u.name for u in users[:3])}{'…' if len(users) > 3 else ''}). Move or delete them first.")
    for o in others:                                               # a deleted person is no longer anyone's owner, head or deputy
        gone = [k for k in REF_KEYS if o.props.get(k) == ext_id]
        if gone:
            o.props = {k: v for k, v in o.props.items() if k not in gone}
    session.execute(delete(CompanyEdge).where(CompanyEdge.organisation_id == org.id, (CompanyEdge.from_ext == ext_id) | (CompanyEdge.to_ext == ext_id)))
    session.delete(row)
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


class DraftDept(BaseModel):
    name: str
    reports_to: str = ""
    head: str = ""


class DraftPerson(BaseModel):
    name: str
    title: str = ""
    department: str = ""
    role_only: bool = False


class DraftSystem(BaseModel):
    name: str
    type: Literal["agent", "model"] = "agent"
    department: str = ""
    owner: str = ""


class DraftTask(BaseModel):
    from_agent: str
    to_agent: str
    task: str = ""


class DraftProposal(BaseModel):
    departments: List[DraftDept] = Field(default_factory=list)
    people: List[DraftPerson] = Field(default_factory=list)
    ai_systems: List[DraftSystem] = Field(default_factory=list)
    task_links: List[DraftTask] = Field(default_factory=list)


DRAFT_PROMPT = (
    "You turn a plain-English description of a company into a draft organisation. List only what the description says: departments (and which department each "
    "reports to), people with their title and department (role_only true for a group such as 'support agents'), AI agents or models with their department and "
    "owner, and tasks one AI agent hands to another. Use the exact names in the description. Never invent a person, surname, department or agent that the "
    "description does not mention. Leave a field empty rather than guess.")


def proposal_to_doc(prop: DraftProposal, existing: Dict[str, CompanyNode]) -> Dict[str, Any]:
    """Names become ids: an existing item with the same name is reused, a new one gets a generated id. Pure code, no model."""
    by_name = {n.name.strip().lower(): n for n in existing.values()}
    ids: Dict[str, str] = {}

    def ref(name: str, type_: str) -> Optional[str]:
        name = (name or "").strip()
        if not name:
            return None
        k = name.lower()
        if k in by_name:
            return by_name[k].ext_id
        if k not in ids:
            ids[k] = f"{PREFIX[type_]}-{slug(name)}"
        return ids[k]

    doc: Dict[str, Any] = {"departments": [], "people": [], "ai_systems": []}
    for d in prop.departments[:20]:
        if d.name.strip():
            i = ref(d.name, "department")
            doc["departments"].append({"id": i, "name": d.name.strip(), **({"reports_to": ref(d.reports_to, "department")} if d.reports_to.strip() else {}),
                                       **({"head": ref(d.head, "person")} if d.head.strip() else {})})
    for p in prop.people[:30]:
        if p.name.strip():
            doc["people"].append({"id": ref(p.name, "role" if p.role_only else "person"), "name": p.name.strip(), "title": p.title.strip(), "kind": "role" if p.role_only else "person",
                                  **({"department": ref(p.department, "department")} if p.department.strip() else {})})
    agents = {s.name.strip().lower(): s for s in prop.ai_systems}
    for s in prop.ai_systems[:20]:
        if s.name.strip():
            tasks = [{"agent": ref(t.to_agent, "agent"), "task": t.task.strip()} for t in prop.task_links if t.from_agent.strip().lower() == s.name.strip().lower() and t.to_agent.strip()]
            doc["ai_systems"].append({"id": ref(s.name, s.type), "type": s.type, "name": s.name.strip(), **({"department": ref(s.department, "department")} if s.department.strip() else {}),
                                      **({"owner": ref(s.owner, "person")} if s.owner.strip() else {}), **({"hands_tasks_to": tasks} if tasks else {})})
    for t in prop.task_links:                                           # a handoff to an agent the description only mentions in passing
        for n in (t.to_agent,):
            if n.strip() and n.strip().lower() not in agents and n.strip().lower() not in by_name:
                doc["ai_systems"].append({"id": ref(n, "agent"), "type": "agent", "name": n.strip()})
                agents[n.strip().lower()] = DraftSystem(name=n)
    return {k: v for k, v in doc.items() if v}


@router.post("/draft")
def draft(body: DraftIn, session: Session = Depends(get_session)) -> Dict[str, Any]:
    from ollama_client import chat_json
    raw = chat_json([{"role": "system", "content": DRAFT_PROMPT}, {"role": "user", "content": body.description}], DraftProposal.model_json_schema(), max_tokens=1200)
    try:
        prop = DraftProposal.model_validate(raw)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"The model returned a malformed proposal: {exc}")
    org, ns, es = load(session)
    doc = proposal_to_doc(prop, {n.ext_id: n for n in ns})
    return {"doc": doc, "plan": public_plan(plan(session, doc, [])) if doc else None}
