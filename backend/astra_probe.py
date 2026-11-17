"""
ASTRA Probe (phase 8): scenarios generated from a behavioural contract, replayed against the reconciler, results folded into evidence.

For every divergence class (all 22, the behavioural baseline included) the Probe builds a pair of events from the contract: a planted defect that must be
caught, and a boundary case that must be left alone. The pair is replayed through exactly what the runtime uses (astra_runtime.to_event and the conformity predicate), in memory, against
a copy of the contract document. What counts as the right answer is read from the class table (the detection basis of the class), never from the reconciler under test:

    policy or cryptographic class   the defect DIVERGES with exactly that class
    semantic class                  the defect is PENDING (a person adjudicates) with exactly that class
    baseline class                  a score at its threshold is ADVISORY (tighten-only evidence); a score below it CONFORMS
    the boundary case               CONFORMS

A scenario passes when both hold. A class the contract gives nothing to test (no parameter bounds declared, no delegate to spell a boundary with) is reported as not applicable, with
the reason, and never counted as a pass.

Safety rules of the phase, kept by what this module cannot do: it holds no credentials, it never writes to a database or to a collector, it replays events it made itself against a copy of a
document, and the only thing that leaves it is a result (latest_evidence below only reads stored results). Scenarios come from templates; no language model writes or rephrases anything here.

Evidence (fold): for each control, a miss on any of its classes is adverse evidence (VIOLATED). When every applicable scenario of a control passed, that is supportive evidence with a
lifetime (PROBE_TTL_DAYS), but only for a control the design does not already show to be missing, and never for a semantic class: a person's judgement is not something a replay can
vouch for. A miss counts for semantic classes too.
"""
import base64
import copy
import hashlib
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import astra_runtime as AR
from astra_model.classes import CLASSES

PROBE_TTL_DAYS = 30
CLASS_IDS = list(CLASSES)
EXPECTED_BY_BASIS = {"policy": "DIVERGES", "cryptographic": "DIVERGES", "semantic": "PENDING", "baseline": "ADVISORY"}
UNDECLARED = "probe-undeclared"


def expected(cid: str) -> Dict[str, Any]:
    """The outcome the class table demands for a planted defect of this class."""
    return {"outcome": EXPECTED_BY_BASIS[CLASSES[cid].basis], "classes": [cid]}


# ── generation ─────────────────────────────────────────────────────────────────────────────────────────────────

def _good_call(a, tool: str, **extra: Any) -> Dict[str, Any]:
    """A call of a declared tool that satisfies everything the contract asks of it (parameters at their lower bounds, a confirmation where a person is needed)."""
    ev: Dict[str, Any] = {"type": "tool_call", "name": tool}
    if a.tools.get(tool):
        ev["params"] = {p: lo for p, (lo, _hi) in a.tools[tool].items()}
    if tool in a.hitl_tools:
        ev.update(confirmed=True, presented_hash="probe-h", executed_hash="probe-h")
    ev.update(extra)
    return ev


def _na(cid: str, why: str) -> Dict[str, Any]:
    return {"class": cid, "bad": None, "good": None, "na": why}


def generate(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One scenario per class, from the contract document. Deterministic: the same document gives the same scenarios."""
    a = AR.agent_from_contract(doc)
    sc: List[Dict[str, Any]] = []

    def add(cid: str, bad: Dict[str, Any], good: Optional[Dict[str, Any]], **meta: Any) -> None:
        sc.append({"class": cid, "bad": bad, "good": good, "na": None, **meta})

    tools = sorted(a.tools)
    plain = [t for t in tools if t not in a.suggest_only_tools]
    add("DVG-GOAL-01", {"type": "goal_set", "name": "probe-goal", "source": "probe", "semantic": "out_of_scope"}, {"type": "goal_set", "name": "probe-goal", "source": "principal"})
    add("DVG-GOAL-02", {"type": "goal_set", "name": "probe-goal", "source": "probe", "semantic": "integrity"}, {"type": "goal_set", "name": "probe-goal", "source": "principal"})
    add("DVG-TOOL-01", {"type": "tool_call", "name": f"{UNDECLARED}-tool"}, _good_call(a, plain[0]) if plain else None)
    bounded = next(((t, p, b) for t in tools for p, b in sorted(a.tools[t].items())), None)
    if bounded:
        t, p, (lo, hi) = bounded
        bad = _good_call(a, t)
        bad["params"] = {**bad.get("params", {}), p: hi + 1}
        good = _good_call(a, t)
        good["params"] = {**good.get("params", {}), p: hi}
        add("DVG-TOOL-02", bad, good)
    else:
        sc.append(_na("DVG-TOOL-02", "the contract declares no parameter bounds"))
    chain = next(((x, y) for x, y in sorted(a.prohibited_chains) if y in a.tools), None)
    if chain:
        add("DVG-TOOL-03", _good_call(a, chain[1], prev_tool=chain[0]), _good_call(a, chain[1], prev_tool=f"{UNDECLARED}-previous"))
    else:
        sc.append(_na("DVG-TOOL-03", "the contract declares no prohibited chain"))
    if a.suggest_only_tools:
        add("DVG-AUT-01", _good_call(a, sorted(a.suggest_only_tools)[0]), _good_call(a, plain[0]) if plain else None)
    else:
        sc.append(_na("DVG-AUT-01", "every write tool may run unattended or with a confirmation"))
    hw = sorted(a.hitl_tools & a.write_tools & set(a.tools))
    if hw:
        h = hw[0]
        for cid, over in (("DVG-AUT-02", {"confirmed": False}), ("DVG-AUT-03", {"confirmed": True, "presented_hash": "probe-h1", "executed_hash": "probe-h2"})):
            add(cid, {**_good_call(a, h), **over}, _good_call(a, h))
    else:
        sc.append(_na("DVG-AUT-02", "no write tool needs a person's confirmation"))
        sc.append(_na("DVG-AUT-03", "no write tool needs a person's confirmation"))
    add("DVG-BASE-01", {"type": "score", "score": 0.9, "theta": 0.8}, {"type": "score", "score": 0.5, "theta": 0.8})
    add("DVG-EXEC-01", {"type": "exec", "sandboxed": False}, {"type": "exec", "sandboxed": True})
    res = sorted(a.resources)
    add("DVG-RES-01", {"type": "data_access", "name": f"{UNDECLARED}-resource"}, {"type": "data_access", "name": res[0]} if res else None)
    if a.validated_memory:
        add("DVG-MEM-01", {"type": "memory_write", "validated": False, "provenance": True}, {"type": "memory_write", "validated": True, "provenance": True})
    elif not a.long_term_memory:
        add("DVG-MEM-01", {"type": "memory_write", "validated": True, "provenance": True, "scope": "long_term"}, {"type": "memory_write", "validated": True, "provenance": True, "scope": "session"})
    else:
        sc.append(_na("DVG-MEM-01", "memory writes are unrestricted and long-term memory is allowed"))
    if a.provenance_required:
        add("DVG-MEM-02", {"type": "memory_write", "validated": True, "provenance": False}, {"type": "memory_write", "validated": True, "provenance": True})
    else:
        sc.append(_na("DVG-MEM-02", "the contract does not require provenance on memory writes"))
    dl = sorted(a.may_delegate_to)
    add("DVG-DEL-01", {"type": "delegation", "name": f"{UNDECLARED}-agent", "mode": a.deleg_mode}, {"type": "delegation", "name": dl[0], "mode": a.deleg_mode, "depth": 1} if dl else None)
    ac = sorted(a.accepts_from)
    add("DVG-DEL-02", {"type": "delegation_in", "name": f"{UNDECLARED}-agent"}, {"type": "delegation_in", "name": ac[0]} if ac else None)
    if dl:
        add("DVG-DEL-03", {"type": "delegation", "name": dl[0], "mode": f"{UNDECLARED}-mode"}, {"type": "delegation", "name": dl[0], "mode": a.deleg_mode})
    else:
        sc.append(_na("DVG-DEL-03", "the contract allows no delegation, so there is no allowed target to test the mode with"))
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"astra-probe-message-key").digest())          # a fixed throwaway key: scenarios are reproducible and it signs nothing real
    pub = base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode().rstrip("=")
    sig = key.sign(b"probe-message").hex()
    add("DVG-COMM-01", {"type": "msg", "name": "probe-peer", "payload": "probe-message-tampered", "signature": sig}, {"type": "msg", "name": "probe-peer", "payload": "probe-message", "signature": sig}, _peer=pub)
    add("DVG-ID-01", {"type": "id", "name": f"{UNDECLARED}-identity"}, {"type": "id", "name": a.identity})
    if a.status == "production":
        add("DVG-LIFE-01", {"type": "life", "_day": "after_expiry"}, {"type": "life", "_day": "on_expiry"})
    else:
        sc.append(_na("DVG-LIFE-01", f"the contract's lifecycle status is {a.status}, so every life event diverges and there is no boundary to test"))
    sp = sorted(a.may_spawn)
    add("DVG-SPAWN-01", {"type": "spawn", "name": f"{UNDECLARED}-child", "_registered": True}, {"type": "spawn", "name": sp[0], "_registered": True} if sp else None)
    add("DVG-SUP-01", {"type": "component", "name": "probe-component", "signed": False, "in_aibom": True}, {"type": "component", "name": "probe-component", "signed": True, "in_aibom": True})
    add("DVG-SUP-02", {"type": "component", "name": "probe-component", "signed": True, "in_aibom": False}, {"type": "component", "name": "probe-component", "signed": True, "in_aibom": True})
    order = {c: i for i, c in enumerate(CLASS_IDS)}
    sc.sort(key=lambda s: order[s["class"]])
    return sc


# ── replay ────────────────────────────────────────────────────────────────────────────────────────────────────

def observe(doc: Dict[str, Any], wire: Dict[str, Any], scenario: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """What the reconciler says about one event, replayed in memory against a copy of the contract document."""
    a = AR.agent_from_contract(copy.deepcopy(doc))
    sc = scenario or {}
    data = {k: v for k, v in wire.items() if k != "type" and not k.startswith("_")}
    today = date.today().toordinal()
    if wire.get("_day") == "after_expiry":
        today = a.expires + 1
    elif wire.get("_day") == "on_expiry":
        today = a.expires
    peer = None
    if sc.get("_peer"):
        peer = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(sc["_peer"] + "=" * (-len(sc["_peer"]) % 4)))
    ev = AR.to_event(a.name, wire["type"], data, [], today, registered=bool(wire.get("_registered")), peer=peer)
    res = AR.conforms(AR.estate_of(a), ev)                                  # looked up at call time: the very function the runtime judges with
    return {"outcome": res["outcome"], "classes": list(res["classes"]), "missing": list(res["missing"])}


def run_scenario(doc: Dict[str, Any], sc: Dict[str, Any]) -> Dict[str, Any]:
    cid = sc["class"]
    out: Dict[str, Any] = {"class": cid, "control": CLASSES[cid].control, "basis": CLASSES[cid].basis, "source": sc.get("source", "template"), "scenario_id": sc.get("scenario_id"),
                           "applicable": sc["bad"] is not None, "reason": sc.get("na"), "expected": expected(cid), "bad_event": sc["bad"], "good_event": sc["good"],
                           "bad": None, "good": None, "bad_ok": None, "good_ok": None, "passed": None}
    if sc["bad"] is None:
        return out
    out["bad"] = observe(doc, sc["bad"], sc)
    out["bad_ok"] = out["bad"]["outcome"] == out["expected"]["outcome"] and out["bad"]["classes"] == out["expected"]["classes"]
    if sc["good"] is not None:
        out["good"] = observe(doc, sc["good"], sc)
        out["good_ok"] = out["good"]["outcome"] == "CONFORMS"
    out["passed"] = bool(out["bad_ok"]) and out["good_ok"] is not False
    return out


def run(doc: Dict[str, Any], incidents: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Every generated scenario, then every standing incident scenario (each a planted defect that must still be caught: a regression suite)."""
    results = [run_scenario(doc, sc) for sc in generate(doc)]
    for inc in incidents or []:
        results.append(run_scenario(doc, {"class": inc["class"], "bad": inc["bad"], "good": None, "na": None, "source": "incident", "scenario_id": inc.get("id")}))
    return results


# ── evidence ──────────────────────────────────────────────────────────────────────────────────────────────────

def fold(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """control kind -> {"ok": bool, "classes": [...], "missed": [...], "supports": bool}. A control with no applicable scenario is absent: the Probe says nothing about it."""
    by: Dict[str, Dict[str, Any]] = {}
    for r in results:
        if not r["applicable"]:
            continue
        e = by.setdefault(r["control"], {"ok": True, "classes": [], "missed": [], "supports": False})
        e["classes"].append(r["class"])
        if not r["passed"]:
            e["ok"] = False
            e["missed"].append(r["class"])
        elif r["basis"] != "semantic":
            e["supports"] = True
    return by


def summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    app = [r for r in results if r["applicable"]]
    return {"scenarios": len(results), "applicable": len(app), "not_applicable": len(results) - len(app), "passed": sum(1 for r in app if r["passed"]),
            "missed": sum(1 for r in app if not r["passed"]), "caught": sum(1 for r in app if r["bad_ok"]), "boundary_ok": sum(1 for r in app if r["good_ok"]),
            "incidents": sum(1 for r in results if r["source"] == "incident")}


def latest_evidence(session: Any, org_id: Any, design_key: str, design_hash: str, today: int) -> Dict[str, Tuple[bool, Optional[int]]]:
    """What the newest Probe run of this design says about each control, for the estate builder: kind -> (ok, the day number until which a pass counts). Only a run of this exact
    version of the design counts (a changed design needs a new run); a pass lapses PROBE_TTL_DAYS after the run, a miss stays until the next run."""
    from sqlalchemy import select
    from db.models import ProbeResult, ProbeRun
    run = session.scalar(select(ProbeRun).where(ProbeRun.organisation_id == org_id, ProbeRun.design_key == design_key).order_by(ProbeRun.created_at.desc()).limit(1))
    if run is None or run.design_hash != design_hash:
        return {}
    rows = [{"class": r.class_code, "control": r.control, "basis": r.basis, "applicable": r.applicable, "passed": r.passed}
            for r in session.scalars(select(ProbeResult).where(ProbeResult.run_id == run.id))]
    out: Dict[str, Tuple[bool, Optional[int]]] = {}
    for kind, e in fold(rows).items():
        if not e["ok"]:
            out[kind] = (False, None)
        elif e["supports"]:
            out[kind] = (True, run.created_at.date().toordinal() + PROBE_TTL_DAYS)
    return out
