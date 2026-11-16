"""
ASTRA Probe (reference): scenario generation with an expected-outcome oracle.

A scenario is (estate, violating event, benign event, expected outcome). The expected outcome is taken from the class table
(detection basis), NOT from the reconciler under test:
    policy / cryptographic class  -> DIVERGES exactly that class
    semantic class                -> PENDING (a person adjudicates)
    baseline class                -> ADVISORY (tighten-only evidence)
and the benign counterpart (a boundary value that is allowed) must give CONFORMS.
"""
import copy
from typing import Any, Dict, List

from . import model as M


def demo_estate() -> M.Estate:
    support = M.Agent(
        "support", "Customer", autonomy="approve", expires=100,
        tools={"search": {}, "refund": {"amount": (0, 100)}, "read_db": {}, "send_email": {}},
        write_tools={"refund", "send_email"}, hitl_tools={"refund"}, prohibited_chains={("read_db", "send_email")},
        resources={"crm": "read", "mem_support": "write"}, may_delegate_to={"payments"}, accepts_from={"orchestrator"},
        inputs={"email"}, components={"mcp://docs": True}, may_spawn={"helper"}, egress={"api.corp"}, runs_code=True)
    payments = M.Agent(
        "payments", "Finance", tools={"pay": {"amount": (0, 1000)}}, write_tools={"pay"}, hitl_tools={"pay"},
        resources={"ledger": "write"}, accepts_from={"support", "orchestrator"})
    hr = M.Agent("hr", "HR", tools={"hris": {}}, resources={"hr_db": "read"}, inputs={"cv"}, accepts_from={"orchestrator"})
    res = {"crm": ("Customer", 2, "data"), "mem_support": ("Customer", 1, "memory"), "ledger": ("Finance", 4, "data"), "hr_db": ("HR", 3, "data")}
    return M.Estate({"support": support, "payments": payments, "hr": hr}, res, {"Customer": 2, "Finance": 2, "HR": 2})


def _ev(kind: str, **kw) -> Dict[str, Any]:
    d = dict(kind=kind, agent="support", t=1)
    d.update(kw)
    return d


_H = dict(confirmed=True, presented_hash="h1", executed_hash="h1")


def scenarios(E: M.Estate) -> List[Dict[str, Any]]:
    """One scenario per class of the specification (22)."""
    s: List[Dict[str, Any]] = []

    def add(cls, bad, good, estate=None):
        basis = M.CLASSES[cls][1]
        exp = ("PENDING", [cls]) if basis == "semantic" else ("ADVISORY", [cls]) if basis == "baseline" else ("DIVERGES", [cls])
        s.append(dict(cls=cls, estate=estate or E, bad=bad, good=good, expected=exp))

    add("DVG-GOAL-01", _ev("goal_set", goal="g1", source="email", semantic="out_of_scope"), _ev("goal_set", goal="g1", source="email"))
    add("DVG-GOAL-02", _ev("goal_set", goal="g1", source="email", semantic="integrity"), _ev("goal_set", goal="g1", source="principal"))
    add("DVG-TOOL-01", _ev("tool_call", tool="shell.exec"), _ev("tool_call", tool="search"))
    add("DVG-TOOL-02", _ev("tool_call", tool="refund", params={"amount": 101}, **_H), _ev("tool_call", tool="refund", params={"amount": 100}, **_H))
    add("DVG-TOOL-03", _ev("tool_call", tool="send_email", prev_tool="read_db"), _ev("tool_call", tool="send_email", prev_tool="search"))
    add("DVG-EXEC-01", _ev("exec", sandboxed=False, host="api.corp"), _ev("exec", sandboxed=True, host="api.corp"))
    add("DVG-RES-01", _ev("res_access", resource="ledger", mode="read"), _ev("res_access", resource="crm", mode="read"))
    add("DVG-MEM-01", _ev("mem_write", validated=False, provenance=True), _ev("mem_write", validated=True, provenance=True))
    add("DVG-MEM-02", _ev("mem_write", validated=True, provenance=False), _ev("mem_write", validated=True, provenance=True))
    add("DVG-DEL-01", _ev("deleg_out", target="hr", mode="execution"), _ev("deleg_out", target="payments", mode="execution"))
    add("DVG-DEL-02", _ev("deleg_in", source="hr"), _ev("deleg_in", source="orchestrator"))
    add("DVG-DEL-03", _ev("deleg_out", target="payments", mode="permission"), _ev("deleg_out", target="payments", mode="execution"))
    add("DVG-COMM-01", _ev("msg", verified=False), _ev("msg", verified=True))
    E2 = copy.deepcopy(E)
    E2.agents["support"].autonomy = "suggest"
    add("DVG-AUT-01", _ev("tool_call", tool="send_email"), _ev("tool_call", tool="search"), estate=E2)
    add("DVG-AUT-02", _ev("tool_call", tool="refund", params={"amount": 50}, confirmed=False), _ev("tool_call", tool="refund", params={"amount": 50}, **_H))
    add("DVG-AUT-03", _ev("tool_call", tool="refund", params={"amount": 50}, confirmed=True, presented_hash="h1", executed_hash="h2"),
        _ev("tool_call", tool="refund", params={"amount": 50}, **_H))
    add("DVG-ID-01", _ev("id", claimed="someone-else"), _ev("id", claimed="support"))
    add("DVG-LIFE-01", _ev("life", now_t=101), _ev("life", now_t=100))
    add("DVG-BASE-01", _ev("score", detector="baseline", score=0.9, theta=0.8), _ev("score", detector="baseline", score=0.5, theta=0.8))
    add("DVG-SPAWN-01", _ev("spawn", child="rogue", inventoried=False), _ev("spawn", child="helper", inventoried=True))
    add("DVG-SUP-01", _ev("component", name="mcp://docs", signed=False, in_aibom=True), _ev("component", name="mcp://docs", signed=True, in_aibom=True))
    add("DVG-SUP-02", _ev("component", name="mcp://unknown", signed=True, in_aibom=False), _ev("component", name="mcp://docs", signed=True, in_aibom=True))
    return s


def run_scenario(sc: Dict[str, Any]) -> Dict[str, Any]:
    """Run one scenario against the reconciler as currently implemented (defects may be switched on)."""
    bad = M.conforms(sc["estate"], sc["bad"])
    good = M.conforms(sc["estate"], sc["good"])
    exp_out, exp_cls = sc["expected"]
    ok_bad = bad["outcome"] == exp_out and bad["classes"] == exp_cls
    ok_good = good["outcome"] == "CONFORMS"
    return dict(cls=sc["cls"], bad=bad, good=good, ok_bad=ok_bad, ok_good=ok_good)


def run_suite(E: M.Estate) -> List[Dict[str, Any]]:
    return [run_scenario(sc) for sc in scenarios(E)]


def oracle_suite(E: M.Estate) -> List[Dict[str, Any]]:
    """Run with every defect switched off (the oracle must never come from the implementation under test)."""
    saved = set(M.DEFECTS)
    M.DEFECTS.clear()
    try:
        return run_suite(E)
    finally:
        M.DEFECTS.update(saved)


# -------- the existing prototype's reconciler (backend/divergence.py), for the gap measurement --------
def prototype_view(E: M.Estate, agent: str) -> Dict[str, Any]:
    a = E.agents[agent]
    return dict(tools=[dict(name=t, write=t in a.write_tools) for t in sorted(a.tools)],
                mcp_servers=[dict(name=n, signed=req) for n, req in sorted(a.components.items())],
                memory=[dict(name="mem", long_term=a.long_term_memory)],
                data=sorted(a.resources), delegates_to=sorted(a.may_delegate_to))


# class -> (violating prototype event, benign prototype event); a class absent here has no event type in the prototype
PROTOTYPE_EVENTS = {
    "DVG-TOOL-01": ({"type": "tool_call", "name": "shell.exec", "write": False}, {"type": "tool_call", "name": "search", "write": False}),
    "DVG-DEL-01": ({"type": "delegation", "name": "hr"}, {"type": "delegation", "name": "payments"}),
    "DVG-SUP-01": ({"type": "mcp_connect", "name": "mcp://docs", "signed": False}, {"type": "mcp_connect", "name": "mcp://docs", "signed": True}),
    "DVG-SUP-02": ({"type": "mcp_connect", "name": "mcp://unknown", "signed": True}, {"type": "mcp_connect", "name": "mcp://docs", "signed": True}),
    "DVG-MEM-01": ({"type": "memory_write", "scope": "long_term"}, {"type": "memory_write", "scope": "session"}),
    "DVG-RES-01": ({"type": "data_access", "name": "ledger"}, {"type": "data_access", "name": "crm"}),
}
