"""
Events and the conformity predicate (paper sections 3.4 and 3.5).

An event is a dict: {"kind", "agent", "t", ...attributes}. Each kind has required attributes. conforms() returns one of
    CONFORMS     the event is inside the contract
    DIVERGES     a deterministic class (policy or cryptographic basis) holds; the classes are listed
    UNVERIFIED   a required attribute is missing or the agent is unknown: it can never be read as conforming
    PENDING      a semantic class was judged to hold; a person adjudicates
    ADVISORY     the baseline score reached its threshold; tighten-only evidence

apply_event() turns the outcome into adverse evidence on the control the class protects. Severity decides the level: High and Critical give VIO, Medium gives UNV;
UNVERIFIED, PENDING and ADVISORY give UNV.
"""
from typing import Any, Dict, List, Tuple

from .classes import CLASSES, EVENT_CONTROL, SEVERITY_LEVEL
from .estate import Estate
from .statuses import State, adverse

REQUIRED: Dict[str, List[str]] = {
    "goal_set": ["goal", "source"], "tool_call": ["tool"], "exec": ["sandboxed"], "res_access": ["resource", "mode"],
    "mem_write": ["validated", "provenance"], "deleg_out": ["target", "mode"], "deleg_in": ["source"],
    "msg": ["verified"], "id": ["claimed"], "life": ["now_t"], "spawn": ["child", "inventoried"],
    "component": ["name", "signed", "in_aibom"],
}
KINDS = tuple(REQUIRED) + ("score",)


def _result(outcome: str, classes: List[str], missing: List[str]) -> Dict[str, Any]:
    return dict(outcome=outcome, classes=classes, missing=missing)


def conforms(E: Estate, ev: Dict[str, Any], hist: Tuple[Dict[str, Any], ...] = ()) -> Dict[str, Any]:
    kind = ev["kind"]
    a = E.agents.get(ev.get("agent"))
    if a is None:
        return _result("UNVERIFIED", [], ["agent"])
    missing = [k for k in REQUIRED.get(kind, []) if k not in ev]
    if kind == "tool_call" and ev.get("tool") in a.tools and a.tools[ev["tool"]] and "params" not in ev:
        missing.append("params")
    if kind == "tool_call" and ev.get("tool") in a.hitl_tools:
        if "confirmed" not in ev:
            missing.append("confirmed")
        elif ev["confirmed"]:
            missing += [k for k in ("presented_hash", "executed_hash") if k not in ev]
    if missing:
        return _result("UNVERIFIED", [], missing)
    v: List[str] = []
    if kind == "goal_set":
        sem = ev.get("semantic")                    # the judgement of a classifier or a person; the model never decides it
        if sem == "out_of_scope":
            v.append("DVG-GOAL-01")
        elif sem == "integrity":
            v.append("DVG-GOAL-02")
    elif kind == "tool_call":
        t = ev["tool"]
        if t not in a.tools:
            v.append("DVG-TOOL-01")
        else:
            for p, val in (ev.get("params") or {}).items():
                if p in a.tools[t]:
                    lo, hi = a.tools[t][p]
                    if val < lo or val > hi:
                        v.append("DVG-TOOL-02")
                        break
        if ev.get("prev_tool") and (ev["prev_tool"], t) in a.prohibited_chains:
            v.append("DVG-TOOL-03")
        if t in a.write_tools:
            if a.autonomy == "suggest":
                v.append("DVG-AUT-01")
            elif t in a.hitl_tools:
                if not ev.get("confirmed"):
                    v.append("DVG-AUT-02")
                elif ev.get("presented_hash") != ev.get("executed_hash"):
                    v.append("DVG-AUT-03")
    elif kind == "exec":
        if (a.sandbox and not ev["sandboxed"]) or (ev.get("host") is not None and ev["host"] not in a.egress):
            v.append("DVG-EXEC-01")
    elif kind == "res_access":
        r, m = ev["resource"], ev["mode"]
        if r not in a.resources or (m == "write" and a.resources[r] != "write"):
            v.append("DVG-RES-01")
    elif kind == "mem_write":
        if (a.validated_memory and not ev["validated"]) or (ev.get("scope") == "long_term" and not a.long_term_memory):
            v.append("DVG-MEM-01")
        if a.provenance_required and not ev["provenance"]:
            v.append("DVG-MEM-02")
    elif kind == "deleg_out":
        if ev["target"] not in a.may_delegate_to or ev.get("depth", 1) > a.max_depth:
            v.append("DVG-DEL-01")
        if ev["mode"] != a.deleg_mode:
            v.append("DVG-DEL-03")
    elif kind == "deleg_in":
        if ev["source"] not in a.accepts_from:
            v.append("DVG-DEL-02")
    elif kind == "msg":
        if a.auth_required and not ev["verified"]:
            v.append("DVG-COMM-01")
    elif kind == "id":
        if ev["claimed"] != a.identity:
            v.append("DVG-ID-01")
    elif kind == "life":
        if ev["now_t"] > a.expires or a.status != "production":
            v.append("DVG-LIFE-01")
    elif kind == "spawn":
        if ev["child"] not in a.may_spawn or not ev["inventoried"]:
            v.append("DVG-SPAWN-01")
    elif kind == "component":
        if not ev["signed"] and a.components.get(ev["name"], True):       # a signature is required unless the inventory says otherwise
            v.append("DVG-SUP-01")
        if not ev["in_aibom"]:
            v.append("DVG-SUP-02")
    elif kind == "score":
        if ev.get("score", 0) >= ev.get("theta", 1.0):
            return _result("ADVISORY", ["DVG-BASE-01"], [])
        return _result("CONFORMS", [], [])
    else:
        raise ValueError(f"unknown event kind {kind!r}; expected one of {', '.join(KINDS)}")
    if not v:
        return _result("CONFORMS", [], [])
    sem = [c for c in v if CLASSES[c].basis == "semantic"]
    if sem:
        return _result("PENDING", sem, [])
    return _result("DIVERGES", sorted(v), [])


def apply_event(E: Estate, S: State, ev: Dict[str, Any], hist: Tuple[Dict[str, Any], ...] = ()) -> Dict[str, Any]:
    """Check one event and record the outcome as adverse evidence on the controls it concerns. Returns the outcome."""
    res = conforms(E, ev, hist)
    ag = ev.get("agent")
    if res["outcome"] == "DIVERGES":
        for c in res["classes"]:
            adverse(S, (CLASSES[c].control, ag), SEVERITY_LEVEL[CLASSES[c].severity])
    elif res["outcome"] == "UNVERIFIED":
        adverse(S, (EVENT_CONTROL.get(ev["kind"], "least"), ag), "UNV")
    elif res["outcome"] == "PENDING":
        adverse(S, ("iso", ag), "UNV")                       # stays UNV until a person adjudicates (supportive evidence "human")
    elif res["outcome"] == "ADVISORY":
        adverse(S, ("base", ag), "UNV")
    return res
