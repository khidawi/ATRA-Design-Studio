"""
Design findings: what is wrong with an AI model's design, and the step that fixes each thing.

Two kinds of finding are produced here, both from the Secure Tropos model the framework is built on (framework/tropos_model.py, tropos_catalogue.py):

  formal_findings()  the design is checked against the model itself: the five roles of the dependency chain (trainer, validator, deployer, operator, consumer) are named,
                     the people who check each other are different people, the veto constraints are met, personal data has a legal basis, and the model has the dataset it
                     was trained on and the environment it runs in. Nothing here depends on a regulation or an organisation policy.
  fix_for_rule()     a regulation or policy rule that is not met gets the step that would meet it, so the studio can offer the fix instead of only reporting the failure.

A fix is plain data the studio acts on ({"type": "constraint_evidence" | "add_element" | "edit_element" | "attestation" | "policy", ...}); nothing here changes a design.
"""
from typing import Any, Dict, List, Optional

from compliance_schema import Finding, RiskStatus
from schema import VETO_CLASS_CONSTRAINTS, is_placeholder_evidence

ROLES = [("trainer", "Trainer"), ("validator", "Validator"), ("deployer", "Deployer"), ("operator", "Operator"), ("consumer", "Consumer")]
CORE_ROLES = {"trainer", "validator", "deployer"}      # the chain the veto constraints and the role-concentration factor rest on
PERSONAL = {"SENSITIVE_PERSONAL", "SPECIAL_CATEGORY"}

# Checks that two roles are held by different people, with the constraint that states it and why it matters.
SEPARATION = [
    ("trainer", "validator", "SC-RCF-1", "The person who builds the model would also be the one who certifies it fit for purpose, so nobody independent has checked it."),
    ("validator", "deployer", "SC-RCF-2", "The person who certifies the model would also be the one who releases it, so the release has no independent sign-off."),
    ("trainer", "deployer", None, "The person who builds the model would also be the one who puts it into production."),
]


def _catalogue() -> Dict[str, Any]:
    from framework.tropos_catalogue import CANONICAL_CONSTRAINTS
    return {c.constraint_id: c for c in CANONICAL_CONSTRAINTS}


def _imposer_role(c) -> Optional[str]:
    """The role on the canvas that imposes the constraint: the one the catalogue names as imposing it ("Trainer", "Validator", ...). When the catalogue names a body that is not
    a role (a Data Protection Officer, the AI Governance Board) there is no such actor to draw, so it is the role that depends on the other in the dependency it constrains."""
    for role in ("TRAINER", "VALIDATOR", "DEPLOYER", "OPERATOR", "CONSUMER"):
        if (c.imposed_by or "").upper().startswith(role):
            return role
    return c.on_dependency[0].value if c.on_dependency else None


def constraint_info(constraint_id: str) -> Optional[Dict[str, Any]]:
    """What a security constraint is, who imposes it and what meets it, from the catalogue the framework scores with."""
    c = _catalogue().get(constraint_id)
    if c is None:
        return None
    return {
        "id": c.constraint_id, "name": c.name, "description": c.description, "requirement": c.condition, "imposed_by": c.imposed_by,
        "because": c.because, "standard_refs": list(c.standard_refs), "veto": constraint_id in VETO_CLASS_CONSTRAINTS,
        "imposer_role": _imposer_role(c),
    }


def _constraint_fix(constraint_id: str, constraint_node_ids: Dict[str, str]) -> Dict[str, Any]:
    info = constraint_info(constraint_id)
    name = info["name"] if info else constraint_id
    extra = (" The score also needs the fairness metric named (AI Models · Governance): until it is, the scoring engine still counts this constraint as open."
             if constraint_id == "SC-MAP-1" else "")
    return {
        "type": "constraint_evidence", "constraint_id": constraint_id, "node_id": constraint_node_ids.get(constraint_id), "constraint": info,
        "instruction": f"Record how “{name}” is met (a document, a decision or a link), then mark it Satisfied with that evidence." + extra,
    }


# ── regulation and policy rules ─────────────────────────────────────────────

def _selector_to_element(config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """For a rule that says "the design must include N of these", the element to add, when it is simple enough to add for the user."""
    cond = config.get("satisfied_if") or {}
    if "exists" in cond:
        sel = cond["exists"]
    elif "count" in cond and (cond["count"].get("op") == ">" or (cond["count"].get("op") == ">=" and cond["count"].get("value", 1) >= 1)):
        sel = cond["count"].get("select")
    else:
        return None
    if not isinstance(sel, dict) or not sel.get("type"):
        return None
    data: Dict[str, Any] = {}
    for key, want in (sel.get("where") or {}).items():
        if isinstance(want, dict):
            if set(want) == {"eq"}:
                data[key] = want["eq"]
            elif set(want) == {"truthy"}:
                data[key] = True
            else:
                return None            # a condition we cannot turn into a value: the person has to decide
        else:
            data[key] = want
    return {"kind": sel["type"], "data": data}


def _selector_text(sel: Dict[str, Any]) -> str:
    where = " and ".join(f"{k} is {list(v.values())[0] if isinstance(v, dict) and len(v) == 1 else v}" for k, v in (sel.get("where") or {}).items())
    return f"{sel.get('type', 'element')}" + (f" where {where}" if where else "")


def _plain_fix(cfg: Dict[str, Any], flagged: int) -> str:
    """What to do about a rule that looks at the design's structure, in words, when nobody wrote a description of it."""
    cond = cfg.get("satisfied_if") or {}
    count = cond.get("count") or {}
    if count.get("op") == "==" and count.get("value") == 0 and isinstance(count.get("select"), dict):
        return f"Remove or change {'the flagged element' if flagged == 1 else 'each flagged element'} so that no {_selector_text(count['select'])} is left in the design."
    if "exists" in cond and isinstance(cond["exists"], dict):
        return f"Add a {_selector_text(cond['exists'])} to the design."
    if "edge_exists" in cond:
        return f"Add the missing “{cond['edge_exists'].get('label')}” relationship between the elements."
    if "not" in cond and "edge_exists" in (cond["not"] or {}):
        return f"Remove the “{cond['not']['edge_exists'].get('label')}” relationship."
    return ""


def fix_for_rule(rule, verdict, constraint_node_ids: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """The step that would make this rule pass; None when it already does."""
    if verdict.status == RiskStatus.GREEN:
        return None
    if rule.check_type == "CONSTRAINT" and rule.maps_to_constraint_id:
        return _constraint_fix(rule.maps_to_constraint_id, constraint_node_ids)
    if rule.check_type == "ATTESTATION":
        return {
            "type": "attestation", "instrument": rule.instrument, "clause": rule.citation, "node_id": verdict.node_id,
            "instruction": f"Add a Regulatory requirement for {rule.instrument} {rule.citation} and record the evidence that you meet it.",
        }
    cfg = rule.check_config or {}
    label = cfg.get("fix_label")
    add = _selector_to_element(cfg)
    if add:
        return {"type": "add_element", "kind": add["kind"], "data": add["data"], "label": label,
                "instruction": (rule.description or rule.title or verdict.reason or "").strip() or f"Add the missing {add['kind']}."}
    flagged = list(verdict.flagged_node_ids or [])
    return {"type": "policy", "label": label, "flagged": flagged,
            "instruction": ((rule.description or "").strip() or _plain_fix(cfg, len(flagged)) or rule.title or verdict.reason or "").strip()}


# ── the design itself, against the Secure Tropos model ──────────────────────

def _norm(text: Optional[str]) -> str:
    return " ".join((text or "").split()).lower()


def _name(n) -> str:
    p = n.props or {}
    if n.type == "CONSTRAINT":
        return f"Constraint {p.get('constraintId') or ''}".strip()
    if n.type == "ACTOR":
        return f"{str(p.get('subtype') or 'Actor').title()} {p.get('identity') or ''}".strip()
    if n.type == "REGULATORY_REQ":
        return f"Requirement {p.get('instrument') or ''} {p.get('clause') or ''}".strip()
    return str(p.get("name") or n.type.replace("_", " ").capitalize())


ROLE_EDGE = {"TRAINER": "TRAINS", "VALIDATOR": "VALIDATES", "DEPLOYER": "DEPLOYS", "OPERATOR": "OPERATES", "CONSUMER": "CONSUMED_BY"}


def _connection_findings(nodes, edges, models) -> List[Finding]:
    """Only a relationship the model defines counts as a connection (trains, validates, deploys, operates, consumed_by, trained_on, runs_in, covered_by, imposed_by, requires).
    A line between two elements that the model has no relationship for (on_dependency) connects nothing, and is reported as such."""
    types = {n.id: n.type for n in nodes}
    actors = [n for n in nodes if n.type == "ACTOR"]
    out: List[Finding] = []

    def joined(a_id: str, b_id: str, label: str) -> bool:
        return any(e.label.upper() == label and {e.from_id, e.to_id} == {a_id, b_id} for e in edges)

    def report(n, needs, fix, severity="error"):
        out.append(Finding(
            finding_id=f"unconnected-{n.id}", severity=severity, title=f"{_name(n)} is not connected", detail=f"It is drawn on its own: nothing connects it to {needs}.",
            why="In the Secure Tropos model an element means something only through its relationships (who trains, validates, deploys and operates the model, who imposes a constraint, what the model is trained on and runs in). An element on its own is not part of the design.",
            blocks=["compile"] if severity == "error" else [], node_id=n.id, fix=fix))

    for n in nodes:
        if n.type == "CONSTRAINT":
            if any((e.label.upper() == "IMPOSED_BY" and e.from_id == n.id and types.get(e.to_id) == "ACTOR")
                   or (e.label.upper() == "REQUIRES" and e.to_id == n.id and types.get(e.from_id) == "REGULATORY_REQ") for e in edges):
                continue
            role = (constraint_info((n.props or {}).get("constraintId") or "") or {}).get("imposer_role")
            who = next((a for a in actors if str((a.props or {}).get("subtype", "")).upper() == role), None)
            report(n, "the role that imposes it",
                   {"type": "connect", "a": n.id, "b": who.id, "instruction": f"Connect it to the {role.lower()} who imposes it ({_name(who)})."} if who
                   else {"type": "info", "instruction": f"Add the {(role or 'responsible role').lower()} who imposes it, then connect them."})
        elif n.type == "ACTOR" and models:
            role = str((n.props or {}).get("subtype", "")).upper()
            if role not in ROLE_EDGE or any(joined(n.id, m.id, ROLE_EDGE[role]) for m in models):
                continue
            report(n, "the AI model", {"type": "connect", "a": n.id, "b": models[0].id, "instruction": f"Connect the {role.lower()} to the AI model ({_name(models[0])}): the {ROLE_EDGE[role].lower()} relationship."})
        elif n.type in ("TRAINING_DATASET", "DEPLOYMENT_ENV", "REGULATORY_REQ") and models:
            label = {"TRAINING_DATASET": "TRAINED_ON", "DEPLOYMENT_ENV": "RUNS_IN", "REGULATORY_REQ": "COVERED_BY"}[n.type]
            if any(joined(n.id, m.id, label) for m in models):
                continue
            report(n, "the AI model", {"type": "connect", "a": n.id, "b": models[0].id, "instruction": f"Connect it to the AI model ({_name(models[0])}): the {label.lower()} relationship."})
        elif n.type == "CONSENT_RECORD":
            bases = [b for b in nodes if b.type == "LEGAL_BASIS"]
            if any(joined(n.id, b.id, "COVERED_BY") for b in bases):
                continue
            report(n, "a legal basis", {"type": "connect", "a": n.id, "b": bases[0].id, "instruction": f"Connect it to {_name(bases[0])}."} if bases
                   else {"type": "info", "instruction": "Add the legal basis the consent rests on, then connect them."})

    for e in edges:
        if e.label.upper() == "ON_DEPENDENCY" and e.from_id in types and e.to_id in types:
            a, b = next(n for n in nodes if n.id == e.from_id), next(n for n in nodes if n.id == e.to_id)
            out.append(Finding(
                finding_id=f"edge-{e.from_id}-{e.to_id}", severity="warning", title=f"{_name(a)} \u2014 {_name(b)}: a line the model gives no meaning to",
                detail="The model defines no relationship between these two elements, so this line says nothing about the design and does not connect either of them.",
                why="A line should be one of the model's relationships: trains, validates, deploys, operates, consumed_by, trained_on, runs_in, covered_by, imposed_by or requires.",
                node_id=a.id, fix={"type": "unlink", "a": e.from_id, "b": e.to_id, "instruction": "Remove the line, or draw the relationship the model does define."}))
    return out


# Constraints that are not vetoes but still raise the score while they are open (framework/rule_engine.py: SC-TRAIN-1 raises W_h, SC-MC-1 raises the uncertainty term).
SCORE_CONSTRAINTS = ("SC-TRAIN-1", "SC-MC-1")


# What a declaration alone cannot supply: the scoring engine reads a fact the person has to state.
NEEDS_MORE = {"SC-MAP-1": "the fairness metric the model is assessed on, named under AI Models · Governance"}


def _pcs_instruction(open_veto: List[str], drivers: List[str], registry) -> str:
    declared = [d.split(" ")[0] for d in drivers if (registry.governance_state.constraints_declared.get(d.split(" ")[0]) is not None
                and registry.governance_state.constraints_declared[d.split(" ")[0]].status.value == "SATISFIED")]
    parts = []
    if open_veto:
        parts.append("Meet the open veto constraints listed above.")
    for cid in declared:
        parts.append(f"{cid} is marked Satisfied, but the score also needs {NEEDS_MORE.get(cid, 'a fact stated on the Lifecycle pages')}.")
    if not parts:
        parts.append("Meet the constraints that raise the score, listed above.")
    return " ".join(parts) + " The score is recomputed as you do; the platform never marks a constraint met for you."


def formal_findings(registry, constraint_node_ids: Optional[Dict[str, str]], graph) -> List[Finding]:
    constraint_node_ids = constraint_node_ids or {}
    nodes = list(graph.nodes) if graph is not None else []
    by_type = lambda t: [n for n in nodes if n.type == t]            # noqa: E731
    actor_node = {str((n.props or {}).get("subtype", "")).lower(): n.id for n in by_type("ACTOR")}
    out: List[Finding] = []

    if graph is not None and not by_type("AI_MODEL"):
        out.append(Finding(
            finding_id="model-missing", severity="error", title="No AI model is drawn",
            detail="The design has no AI model, so there is nothing to score or to sign a contract for.",
            why="Every role, constraint and requirement in the model is about one AI model in one deployment.", blocks=["compile"],
            fix={"type": "add_element", "kind": "AI_MODEL", "data": {}, "instruction": "Add the AI model this design is about."},
        ))

    # 0. Every element is connected the way the Secure Tropos model draws it: a role to the model it trains, validates, deploys or operates; a constraint to the actor
    #    who imposes it; the dataset, the environment and each regulatory requirement to the model. An element on its own is not part of the model.
    if graph is not None:
        out.extend(_connection_findings(nodes, list(graph.edges), by_type("AI_MODEL")))

    # 1. The dependency chain: every role is held by someone who is named.
    for key, label in ROLES:
        if _norm(getattr(registry.actors, key).identity):
            continue
        core = key in CORE_ROLES
        out.append(Finding(
            finding_id=f"role-{key}", severity="error" if core else "warning", title=f"No {label.lower()} is named",
            detail=f"Nobody is named as the {label.lower()}, so the trust between this role and its neighbours in the chain cannot be traced to a person.",
            why="In Secure Tropos every dependency needs a named actor: trust that no one holds is trust by good faith only (fail-open)." + (
                " The veto constraints and the role-concentration score rest on the trainer, validator and deployer being known." if core else ""),
            blocks=["compile", "score"] if core else [],
            fix={"type": "add_element", "kind": "ACTOR", "data": {"subtype": key.upper()}, "instruction": f"Add the {label.lower()} (a person, team or supplier) and give it a name."},
        ))

    # 2. People who check each other's work are different people.
    for a, b, cid, why in SEPARATION:
        ia, ib = _norm(getattr(registry.actors, a).identity), _norm(getattr(registry.actors, b).identity)
        if not ia or ia != ib:
            continue
        info = constraint_info(cid) if cid else None
        target = actor_node.get(b)
        out.append(Finding(
            finding_id=f"same-{a}-{b}", severity="error", title=f"The {a} and the {b} are the same actor",
            detail=f"“{getattr(registry.actors, a).identity}” is named as both the {a} and the {b}.",
            why=why + " The dependency between them is then fail-open and the role-concentration factor raises the PCS."
                + (f" Constraint {cid}: {info['name']}." if info else ""),
            blocks=["compile", "score"], node_id=target,
            fix={"type": "edit_element", "node_id": target, "field": "identity",
                 "instruction": f"Name a different person, team or organisation as the {b}. If it really cannot be different, record a compensating control instead of hiding it."},
        ))

    # 3. Personal data has a lawful basis in the design.
    ctx = registry.deployment_context
    personal = ctx.data_sensitivity in PERSONAL or any(getattr(c, "sensitivity", None) in PERSONAL for c in registry.data_categories)
    if personal and graph is not None and not by_type("LEGAL_BASIS") and not registry.consent_records and not by_type("CONSENT_RECORD"):
        out.append(Finding(
            finding_id="legal-basis", severity="error", title="Personal data has no legal basis or consent record",
            detail="The model uses personal data, but the design shows no legal basis and no consent record for it.",
            why="Processing personal data needs a lawful basis (UK GDPR Art. 6; Art. 9 for special-category data); the design must show which one.",
            blocks=["compile"],
            fix={"type": "add_element", "kind": "LEGAL_BASIS", "data": {}, "instruction": "Add the legal basis you rely on (for example public task or consent) and link it to the data."},
        ))

    # 4. The model has the data it was trained on and the place it runs.
    if graph is not None and by_type("AI_MODEL"):
        for kind, label, why in (("TRAINING_DATASET", "training dataset", "The data a model learns from decides what it can get wrong, so it has to be on the record."),
                                 ("DEPLOYMENT_ENV", "deployment environment", "Where the model runs decides who can reach it and what it can reach.")):
            if not by_type(kind):
                out.append(Finding(
                    finding_id=f"missing-{kind.lower()}", severity="warning", title=f"No {label} is drawn", detail=f"The design does not show the {label}.", why=why,
                    fix={"type": "add_element", "kind": kind, "data": {}, "instruction": f"Add the {label} and link it to the model."},
                ))

    # 5. The veto constraints: while any is not met, the gate is BLOCKED.
    for cid in sorted(VETO_CLASS_CONSTRAINTS):
        decl = registry.governance_state.constraints_declared.get(cid)
        if decl is not None and decl.status.value == "SATISFIED" and not is_placeholder_evidence(decl.evidence):
            continue
        info = constraint_info(cid) or {"name": cid, "because": ""}
        state = ("marked Unmet" if decl is not None and decl.status.value == "UNMET"
                 else f"marked Satisfied, but its evidence ({(decl.evidence or '').strip()!r}) is a placeholder, not a record" if decl is not None and decl.status.value == "SATISFIED"
                 else "not yet shown to be met")
        out.append(Finding(
            finding_id=f"veto-{cid}", severity="error", title=f"{cid} · {info['name']}",
            detail=f"This veto constraint is {state}.",
            why="A veto constraint is a condition no score can outweigh: while any one is open the gate is BLOCKED and no contract can be signed.",
            blocks=["gate", "compile"], node_id=constraint_node_ids.get(cid), fix=_constraint_fix(cid, constraint_node_ids),
        ))

    # 6. Constraints that are not vetoes but raise the PCS while they are open.
    for cid in SCORE_CONSTRAINTS:
        decl = registry.governance_state.constraints_declared.get(cid)
        if decl is not None and decl.status.value == "SATISFIED" and not is_placeholder_evidence(decl.evidence):
            continue
        info = constraint_info(cid) or {"name": cid}
        out.append(Finding(
            finding_id=f"score-{cid}", severity="warning", title=f"{cid} \u00b7 {info['name']}",
            detail="This constraint is not yet shown to be met, so the score is higher than it would be.",
            why="It does not block the gate on its own: it raises the PCS, and a PCS of 60 or more blocks the gate.",
            blocks=["score"], node_id=constraint_node_ids.get(cid), fix=_constraint_fix(cid, constraint_node_ids),
        ))

    # 6b. Any other constraint declared Satisfied on a placeholder instead of a record.
    seen = {f.finding_id for f in out}
    for cid, decl in sorted(registry.governance_state.constraints_declared.items()):
        if decl.status.value == "SATISFIED" and is_placeholder_evidence(decl.evidence) and f"veto-{cid}" not in seen and f"score-{cid}" not in seen:
            info = constraint_info(cid) or {"name": cid}
            out.append(Finding(
                finding_id=f"evidence-{cid}", severity="error", title=f"{cid} \u00b7 {info['name']}",
                detail=f"It is marked Satisfied, but its evidence ({(decl.evidence or '').strip()!r}) is a placeholder, not a record of how it is met.",
                why="The platform cannot judge whether evidence is good, but a word like \u201ctest\u201d is not evidence, and the contract would attest to it.",
                blocks=["compile"], node_id=constraint_node_ids.get(cid), fix=_constraint_fix(cid, constraint_node_ids)))

    # 7. What the PCS says about the design as a whole.
    try:
        from scoring_bridge import score_registry
        pcs, _ = score_registry(registry)
    except Exception:       # a registry too incomplete to score is reported by the checks above
        return out
    if pcs.gate == "BLOCKED":
        raw = pcs.raw_breakdown or {}
        tiers = (raw.get("risk_vector") or {}).get("tiers") or {}
        high = [f"{k} {v.lower()}" for k, v in tiers.items() if k != "composite" and v in ("HIGH", "CRITICAL")]
        open_veto = [f.finding_id[5:] for f in out if f.finding_id.startswith("veto-")]
        drivers = [b.split(" — ")[0].lstrip("\u274c ").strip() for b in (raw.get("blockers") or []) if b.startswith("\u274c SC-")]
        out.append(Finding(
            finding_id="pcs-gate", severity="error", title=f"PCS {pcs.pcs_final:.0f} / 100 \u00b7 {pcs.tier} \u00b7 the gate is BLOCKED",
            detail=("The score is driven by " + ("; ".join(high) if high else "the open constraints") + ". "
                    + (f"The scoring engine still counts {', '.join(drivers)} as unmet." if drivers else "")).strip(),
            why="The PCS is the socio-technical risk of deploying this model, computed from the design, its constraints and its context. At 60 or more the gate is blocked whatever else is met, and no contract is signed.",
            blocks=["compile"],
            fix={"type": "info", "instruction": _pcs_instruction(open_veto, drivers, registry)},
        ))
    return out
