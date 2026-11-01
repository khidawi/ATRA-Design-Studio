"""
Rule checks: a small, safe, data-driven language for rules that look at the
design itself (Task 3).

A GRAPH rule stores a JSON `check_config` instead of code, so an organisation
can write policies (Task 4) and regulations can be ingested (Task 5) without
anyone shipping Python. There is no eval and no user-supplied code: every
operator below is a fixed function in this module, and a malformed config can
only produce a CheckConfigError, never arbitrary behaviour.

Shape of a config (all keys optional except `satisfied_if`):

    {
      "code": "ASI01",                              # short label shown on flagged elements
      "applies_if":   <condition>,                  # absent = the rule always applies
      "satisfied_if": <condition>,
      "unsatisfied_status": "AMBER",                # default: RED if the rule is REQUIRED, else AMBER
      "flag_nodes": [<selector>, ...],              # elements to flag when unsatisfied
      "vars": {"n": {"count": <selector>}},         # values usable as {n} in messages
      "messages": {"not_applicable": "...", "satisfied": "...", "unsatisfied": "..."},
      "inapplicable": [{"when": <condition>, "status": "GREEN", "message": "..."}],
      "fix_label": "Add injection filter"           # UI hint only
    }

A selector picks elements:  {"type": "tool", "primary": true, "where": {"write": true}}
`where` values: a literal (booleans compare truthiness) or one operator:
{"eq": x} {"ne": x} {"in": [..]} {"nonempty": true} {"empty": true} {"truthy": true} {"falsy": true}

Conditions (exactly one key each):
    {"always": true}  {"never": true}
    {"all": [..]}  {"any": [..]}  {"not": <condition>}
    {"exists": <selector>}
    {"count": {"select": <selector>, "op": ">=", "value": 1}}
    {"edge_exists": {"label": "delegates"}}
    {"edge_count": {"label": "delegates", "op": ">=", "value": 1}}
    {"no_unguarded_path": {"from": <selector>, "to": <selector>, "along": ["uses", ...],
                           "guard": {"type": "approval", "label": "gates"}}}

A route is a chain of relationships the design draws, followed in the direction they are drawn and only along the labels in `along`. A guard is an element with a `label` line to a
node: the node is guarded, and no route goes through it. `no_unguarded_path` holds when no `to` element can be reached from a `from` element without passing a guarded node. That is
the difference between "an approval step exists" and "an approval lies on every route to the write action". A `from` element that is itself guarded blocks all of its routes.
"""
import operator
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_COMPARE = {
    "==": operator.eq, "!=": operator.ne, ">=": operator.ge,
    ">": operator.gt, "<=": operator.le, "<": operator.lt,
}
_VALUE_OPS = {"eq", "ne", "in", "nonempty", "empty", "truthy", "falsy"}
_COND_OPS = {"always", "never", "all", "any", "not", "exists", "count", "edge_exists", "edge_count", "no_unguarded_path"}
_STATUSES = {"GREEN", "AMBER", "RED"}
MAX_DEPTH = 12


class CheckConfigError(ValueError):
    """The rule's check_config is not valid."""


@dataclass(frozen=True)
class GNode:
    id: str
    type: str
    props: Dict[str, Any] = field(default_factory=dict)
    primary: bool = False


@dataclass(frozen=True)
class GEdge:
    from_id: str
    to_id: str
    label: str


@dataclass
class DesignGraph:
    nodes: List[GNode] = field(default_factory=list)
    edges: List[GEdge] = field(default_factory=list)


@dataclass
class GraphOutcome:
    status: str  # GREEN | AMBER | RED | NOT_APPLICABLE
    message: str
    flagged: List[str] = field(default_factory=list)


# ── selectors ───────────────────────────────────────────────────────────────

def _match_value(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        if len(expected) != 1:
            raise CheckConfigError(f"a `where` operator takes exactly one key, got {sorted(expected)}")
        (op, arg), = expected.items()
        if op == "eq":
            return actual == arg
        if op == "ne":
            return actual != arg
        if op == "in":
            if not isinstance(arg, list):
                raise CheckConfigError("`in` needs a list")
            return actual in arg
        if op == "nonempty":
            return actual is not None and bool(str(actual).strip())
        if op == "empty":
            return actual is None or not str(actual).strip()
        if op == "truthy":
            return bool(actual)
        if op == "falsy":
            return not actual
        raise CheckConfigError(f"unknown `where` operator {op!r}")
    if isinstance(expected, bool):
        return bool(actual) == expected
    return actual == expected


def select(graph: DesignGraph, selector: Dict[str, Any]) -> List[GNode]:
    if not isinstance(selector, dict):
        raise CheckConfigError("a selector must be an object")
    types = selector.get("type")
    if isinstance(types, str):
        types = [types]
    where = selector.get("where") or {}
    out = []
    for node in graph.nodes:
        if types is not None and node.type not in types:
            continue
        if "primary" in selector and node.primary != bool(selector["primary"]):
            continue
        if all(_match_value(node.props.get(k), v) for k, v in where.items()):
            out.append(node)
    return out


# ── conditions ──────────────────────────────────────────────────────────────

def _compare(n: int, spec: Dict[str, Any]) -> bool:
    op = spec.get("op", ">=")
    if op not in _COMPARE:
        raise CheckConfigError(f"unknown comparison {op!r}")
    value = spec.get("value", 1)
    if not isinstance(value, int) or isinstance(value, bool):
        raise CheckConfigError("`value` must be an integer")
    return _COMPARE[op](n, value)


def holds(graph: DesignGraph, cond: Dict[str, Any], _depth: int = 0) -> bool:
    if _depth > MAX_DEPTH:
        raise CheckConfigError("condition is nested too deeply")
    if not isinstance(cond, dict) or len(cond) != 1:
        raise CheckConfigError("a condition is an object with exactly one operator")
    (op, arg), = cond.items()
    if op == "always":
        return True
    if op == "never":
        return False
    if op == "all":
        return all(holds(graph, c, _depth + 1) for c in _as_list(arg, "all"))
    if op == "any":
        return any(holds(graph, c, _depth + 1) for c in _as_list(arg, "any"))
    if op == "not":
        return not holds(graph, arg, _depth + 1)
    if op == "exists":
        return len(select(graph, arg)) >= 1
    if op == "count":
        return _compare(len(select(graph, arg.get("select", {}))), arg)
    if op == "edge_exists":
        return any(e.label == arg.get("label") for e in graph.edges)
    if op == "edge_count":
        return _compare(sum(1 for e in graph.edges if e.label == arg.get("label")), arg)
    if op == "no_unguarded_path":
        return not unguarded_routes(graph, arg)
    raise CheckConfigError(f"unknown condition operator {op!r}")


def unguarded_routes(graph: DesignGraph, spec: Dict[str, Any]) -> List[Tuple[GNode, List[GNode]]]:
    """Every `to` element reachable from a `from` element without passing a guarded node, each with one route to it (the shortest)."""
    if not isinstance(spec, dict):
        raise CheckConfigError("no_unguarded_path needs an object")
    along = spec.get("along")
    if not isinstance(along, list) or not along or not all(isinstance(x, str) for x in along):
        raise CheckConfigError("no_unguarded_path needs `along`: a list of relationship labels")
    guard = spec.get("guard")
    if not isinstance(guard, dict) or not isinstance(guard.get("label"), str):
        raise CheckConfigError("no_unguarded_path needs `guard`: a selector with the `label` of the line that guards")
    guard_ids = {n.id for n in select(graph, {k: v for k, v in guard.items() if k in ("type", "where", "primary")})}
    guarded = {e.to_id for e in graph.edges if e.label == guard["label"] and e.from_id in guard_ids}
    by_id = {n.id: n for n in graph.nodes}
    adjacent: Dict[str, List[str]] = {}
    for e in graph.edges:
        if e.label in along:
            adjacent.setdefault(e.from_id, []).append(e.to_id)
    targets = {n.id for n in select(graph, spec.get("to") or {})}
    found: Dict[str, List[GNode]] = {}
    for start in select(graph, spec.get("from") or {}):
        if start.id in guarded:
            continue
        parent: Dict[str, Optional[str]] = {start.id: None}
        queue = [start.id]
        while queue:
            here = queue.pop(0)
            for nxt in adjacent.get(here, []):
                if nxt in parent or nxt in guarded or nxt not in by_id:
                    continue
                parent[nxt] = here
                queue.append(nxt)
        for tid in targets:
            if tid in parent and tid != start.id and tid not in found:
                path, cur = [], tid
                while cur is not None:
                    path.append(by_id[cur])
                    cur = parent[cur]
                found[tid] = list(reversed(path))
    return [(by_id[t], p) for t, p in found.items()]


def _route_text(path: List[GNode]) -> str:
    return " → ".join(str(n.props.get("name") or n.id) for n in path)


def _as_list(arg: Any, op: str) -> List[Any]:
    if not isinstance(arg, list):
        raise CheckConfigError(f"`{op}` needs a list of conditions")
    return arg


# ── messages ────────────────────────────────────────────────────────────────

def _variables(graph: DesignGraph, spec: Dict[str, Any]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for name, expr in (spec or {}).items():
        if not isinstance(expr, dict) or len(expr) != 1:
            raise CheckConfigError(f"variable {name!r} needs exactly one expression")
        (kind, arg), = expr.items()
        if kind == "count":
            values[name] = str(len(select(graph, arg)))
        elif kind == "edge_count":
            values[name] = str(sum(1 for e in graph.edges if e.label == arg.get("label")))
        elif kind == "unguarded":
            values[name] = str(len(unguarded_routes(graph, arg)))
        elif kind == "route":
            routes = unguarded_routes(graph, arg)
            values[name] = _route_text(routes[0][1]) if routes else ""
        elif kind == "prop":
            nodes = select(graph, arg.get("select", {}))
            value = nodes[0].props.get(arg.get("name")) if nodes else None
            values[name] = "" if value is None else str(value)
        else:
            raise CheckConfigError(f"unknown variable expression {kind!r}")
    return values


def _render(template: str, values: Dict[str, str]) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), ""), template or "")


# ── the rule ────────────────────────────────────────────────────────────────

def evaluate_graph_rule(graph: DesignGraph, config: Dict[str, Any], default_unsatisfied: str = "RED") -> GraphOutcome:
    if not isinstance(config, dict) or "satisfied_if" not in config:
        raise CheckConfigError("a GRAPH rule needs `satisfied_if`")
    messages = config.get("messages") or {}
    values = _variables(graph, config.get("vars"))

    def say(key: str) -> str:
        return _render(messages.get(key, ""), values)

    applies_if = config.get("applies_if")
    if applies_if is not None and not holds(graph, applies_if):
        for override in config.get("inapplicable") or []:
            if holds(graph, override.get("when", {"never": True})):
                status = override.get("status", "GREEN")
                if status not in _STATUSES:
                    raise CheckConfigError(f"unknown status {status!r}")
                return GraphOutcome(status, _render(override.get("message", ""), values))
        return GraphOutcome("NOT_APPLICABLE", say("not_applicable"))

    if holds(graph, config["satisfied_if"]):
        return GraphOutcome("GREEN", say("satisfied"))

    status = config.get("unsatisfied_status") or default_unsatisfied
    if status not in _STATUSES:
        raise CheckConfigError(f"unknown status {status!r}")
    flagged: List[str] = []
    if config.get("flag_unguarded"):
        for target, _ in unguarded_routes(graph, config["flag_unguarded"]):
            if target.id not in flagged:
                flagged.append(target.id)
    for selector in config.get("flag_nodes") or []:
        for node in select(graph, selector):
            if node.id not in flagged:
                flagged.append(node.id)
    return GraphOutcome(status, say("unsatisfied"), flagged)


# ── static validation (for authoring, Task 4) ───────────────────────────────

def validate_config(config: Any) -> List[str]:
    """Every problem with a GRAPH rule's config, without running it."""
    errors: List[str] = []
    if not isinstance(config, dict):
        return ["check_config must be an object"]
    if "satisfied_if" not in config:
        errors.append("missing `satisfied_if`")

    def check_selector(sel: Any, where: str) -> None:
        if not isinstance(sel, dict):
            errors.append(f"{where}: selector must be an object")
            return
        for key in sel:
            if key not in {"type", "primary", "where"}:
                errors.append(f"{where}: unknown selector key {key!r}")
        for k, v in (sel.get("where") or {}).items():
            if isinstance(v, dict) and (len(v) != 1 or next(iter(v)) not in _VALUE_OPS):
                errors.append(f"{where}: bad `where` operator on {k!r}")

    def check_cond(cond: Any, where: str, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            errors.append(f"{where}: nested too deeply")
            return
        if not isinstance(cond, dict) or len(cond) != 1:
            errors.append(f"{where}: a condition has exactly one operator")
            return
        (op, arg), = cond.items()
        if op not in _COND_OPS:
            errors.append(f"{where}: unknown operator {op!r}")
        elif op in ("all", "any"):
            if not isinstance(arg, list):
                errors.append(f"{where}: `{op}` needs a list")
            else:
                for i, c in enumerate(arg):
                    check_cond(c, f"{where}.{op}[{i}]", depth + 1)
        elif op == "not":
            check_cond(arg, f"{where}.not", depth + 1)
        elif op == "no_unguarded_path":
            if not isinstance(arg, dict):
                errors.append(f"{where}: no_unguarded_path needs an object")
            else:
                check_selector(arg.get("from"), f"{where}.from")
                check_selector(arg.get("to"), f"{where}.to")
                if not isinstance(arg.get("along"), list) or not arg.get("along"):
                    errors.append(f"{where}: `along` needs a list of relationship labels")
                if not isinstance(arg.get("guard"), dict) or not isinstance((arg.get("guard") or {}).get("label"), str):
                    errors.append(f"{where}: `guard` needs a selector and the `label` of the guarding line")
        elif op == "exists":
            check_selector(arg, f"{where}.exists")
        elif op == "count":
            check_selector((arg or {}).get("select"), f"{where}.count.select")
            if (arg or {}).get("op", ">=") not in _COMPARE:
                errors.append(f"{where}: unknown comparison")
        elif op == "edge_count" and (arg or {}).get("op", ">=") not in _COMPARE:
            errors.append(f"{where}: unknown comparison")

    for key in ("applies_if", "satisfied_if"):
        if key in config and config[key] is not None:
            check_cond(config[key], key)
    for i, sel in enumerate(config.get("flag_nodes") or []):
        check_selector(sel, f"flag_nodes[{i}]")
    if config.get("unsatisfied_status") not in (None, *_STATUSES):
        errors.append("unsatisfied_status must be GREEN, AMBER or RED")
    for i, o in enumerate(config.get("inapplicable") or []):
        check_cond(o.get("when"), f"inapplicable[{i}].when")
    return errors
