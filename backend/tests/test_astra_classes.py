"""
Tests for the divergence classes checked against a signed contract (ASTRA phase 6): astra_runtime.py, runtime ingest and astra_runtime_api.py.

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_astra_classes        # see tests/_guard.py

Part one is pure: for every class one planted defect and one boundary case that conforms, on a contract in the Appendix A format. Part two goes through the real API on a scratch
database: a signed contract, the typed findings, a revoked or tampered contract, bindings, peer keys, adjudication and the classes screen.
"""
import copy
import os
import sys
from datetime import date, datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import astra_runtime as AR
import astra_schema
import astra_signing as SG
from astra_model.classes import CLASSES
from astra_model.events import conforms

PRIV, PUB = SG.generate("zz-classes-key")
TODAY = date.today().toordinal()
AGENT = "zz-rt-agent"

DOC = {
    "schema_version": "0.1",
    "agent": {"id": AGENT, "owner": "owner.zz@example.test", "lifecycle": {"status": "production", "expires": "2099-12-31"}, "model_version": "1.0.0"},
    "permitted_goals": [{"id": "G1", "statement": "Handle refunds"}],
    "permitted_tasks": [
        {"id": "T1", "tool": "lookup", "scope": {"amount": [0, 100]}},
        {"id": "T2", "tool": "refund", "scope": {"access": "write"}},
        {"id": "T3", "tool": "export", "scope": {}},
        {"id": "T4", "tool": "notify", "scope": {}, "prohibited_chains": ["export -> notify"]},
    ],
    "resource_scopes": {"memory": {"writes": "validated", "default_context": "ephemeral"}, "data": [{"resource": "ledger", "access": "read"}, {"resource": "books", "access": "read-write"}]},
    "delegation": {"may_delegate_to": ["zz-peer-agent"], "accepts_delegation_from": ["zz-orchestrator"], "mode": "execution_only"},
    "autonomy": {"unattended_actions": ["T1", "T3", "T4"], "human_in_the_loop": [{"action": "refund over limit", "require": "forced_confirmation"}]},
    "constraints": [], "regulatory_mappings": [],
}
assert astra_schema.validate(DOC) == [], astra_schema.validate(DOC)


def agent(doc=None):
    return AR.agent_from_contract(doc or DOC)


def judge(wire, today=TODAY, registered=False, peer=None, doc=None, **data):
    a = agent(doc)
    ev = AR.to_event(a.name, wire, data, [], today, registered=registered, peer=peer)
    return conforms(AR.estate_of(a), ev)


def diverges(cls, wire, **kw):
    r = judge(wire, **kw)
    want = "PENDING" if CLASSES[cls].basis == "semantic" else "DIVERGES"
    assert r["outcome"] == want and cls in r["classes"], (cls, r)


def conform(wire, **kw):
    r = judge(wire, **kw)
    assert r["outcome"] == "CONFORMS", (wire, kw, r)


# ── part one: every class, a planted defect and a boundary ──────────────────────────────────────────────────────

def test_tool_classes():
    diverges("DVG-TOOL-01", "tool_call", name="shell")
    conform("tool_call", name="lookup", params={"amount": 100})
    diverges("DVG-TOOL-02", "tool_call", name="lookup", params={"amount": 101})
    conform("tool_call", name="lookup", params={"amount": 0})
    diverges("DVG-TOOL-02", "tool_call", name="lookup", params={"amount": -1})
    diverges("DVG-TOOL-03", "tool_call", name="notify", prev_tool="export")
    conform("tool_call", name="notify", prev_tool="lookup")


def test_autonomy_classes():
    diverges("DVG-AUT-02", "tool_call", name="refund", confirmed=False)
    diverges("DVG-AUT-03", "tool_call", name="refund", confirmed=True, presented_hash="a" * 8, executed_hash="b" * 8)
    conform("tool_call", name="refund", confirmed=True, presented_hash="a" * 8, executed_hash="a" * 8)
    d = copy.deepcopy(DOC)                                          # a write tool that may neither run unattended nor with a person: the agent may only suggest
    d["permitted_tasks"].append({"id": "T5", "tool": "wipe", "scope": {"access": "write"}})
    assert agent(d).suggest_only_tools == {"wipe"} and agent().suggest_only_tools == set() and agent().autonomy == "approve"
    diverges("DVG-AUT-01", "tool_call", doc=d, name="wipe")
    d["autonomy"]["unattended_actions"].append("T5")              # the same tool allowed unattended: no breach
    assert agent(d).suggest_only_tools == set()
    conform("tool_call", doc=d, name="wipe")


def test_exec_and_resource_and_memory_classes():
    diverges("DVG-EXEC-01", "exec", sandboxed=False)
    conform("exec", sandboxed=True)
    diverges("DVG-EXEC-01", "exec", sandboxed=True, host="evil.example")
    diverges("DVG-RES-01", "data_access", name="payroll")
    conform("data_access", name="ledger")
    diverges("DVG-RES-01", "data_access", name="ledger", write=True)
    conform("data_access", name="books", write=True)
    diverges("DVG-MEM-01", "memory_write", validated=False, provenance=True)
    conform("memory_write", validated=True, provenance=True)
    diverges("DVG-MEM-01", "memory_write", validated=True, provenance=True, scope="long_term")
    diverges("DVG-MEM-02", "memory_write", validated=True, provenance=False)


def test_delegation_classes():
    diverges("DVG-DEL-01", "delegation", name="zz-evil", mode="execution_only")
    conform("delegation", name="zz-peer-agent", mode="execution_only")
    diverges("DVG-DEL-01", "delegation", name="zz-peer-agent", mode="execution_only", depth=3)
    diverges("DVG-DEL-03", "delegation", name="zz-peer-agent", mode="execution_and_permission")
    diverges("DVG-DEL-02", "delegation_in", name="zz-intruder")
    conform("delegation_in", name="zz-orchestrator")


def test_identity_lifecycle_and_spawn_classes():
    diverges("DVG-ID-01", "id", name="someone-else")
    conform("id", name=AGENT)
    diverges("DVG-LIFE-01", "life", today=date(2100, 1, 1).toordinal())
    conform("life")
    d = copy.deepcopy(DOC)
    d["agent"]["lifecycle"]["status"] = "staging"
    diverges("DVG-LIFE-01", "life", doc=d)
    diverges("DVG-SPAWN-01", "spawn", name="zz-rogue", registered=True)
    diverges("DVG-SPAWN-01", "spawn", name="zz-peer-agent", registered=False)
    conform("spawn", name="zz-peer-agent", registered=True)


def test_supply_chain_classes():
    diverges("DVG-SUP-01", "component", name="parser", signed=False, in_aibom=True)
    conform("component", name="parser", signed=True, in_aibom=True)
    diverges("DVG-SUP-01", "component", name="parser", signed=True, in_aibom=True, provenance=False)
    diverges("DVG-SUP-02", "component", name="parser", signed=True, in_aibom=False)
    diverges("DVG-SUP-01", "mcp_connect", name="mcp://x", signed=False, in_aibom=True)


def test_message_authentication_is_checked_by_the_platform():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    good = key.sign(b"hello").hex()
    conform("msg", name="zz-peer-agent", payload="hello", signature=good, peer=pub)
    diverges("DVG-COMM-01", "msg", name="zz-peer-agent", payload="hello!", signature=good, peer=pub)           # tampered payload
    diverges("DVG-COMM-01", "msg", name="zz-peer-agent", payload="hello", signature=good, peer=None)           # no key registered for the sender
    diverges("DVG-COMM-01", "msg", name="zz-peer-agent", verified=False)
    conform("msg", name="zz-peer-agent", verified=True)                                                      # asserted by the collector, recorded as such
    assert AR.to_event(AGENT, "msg", {"name": "x", "verified": True}, [], TODAY)["asserted"] is True
    assert judge("msg", name="x")["outcome"] == "UNVERIFIED", "no signature and no flag: unverified"


def test_semantic_classes_wait_for_a_person():
    diverges("DVG-GOAL-01", "goal_set", name="Sell the data", source="retrieved document", semantic="out_of_scope")
    diverges("DVG-GOAL-02", "goal_set", name="Ignore the contract", source="retrieved document", semantic="integrity")
    conform("goal_set", name="Handle refunds", source="user")
    assert judge("goal_set", name="Handle refunds")["outcome"] == "UNVERIFIED", "no source: unverified"


def test_a_missing_attribute_or_an_unknown_agent_is_never_conforming():
    for wire, data in (("tool_call", {"name": "refund"}), ("tool_call", {"name": "lookup"}), ("exec", {}), ("memory_write", {"validated": True}), ("delegation", {"name": "zz-peer-agent"}),
                       ("component", {"name": "p", "signed": True}), ("id", {}), ("spawn", {})):
        assert judge(wire, **data)["outcome"] == "UNVERIFIED", (wire, data)
    ev = AR.to_event("someone-else", "tool_call", {"name": "lookup", "params": {"amount": 1}}, [], TODAY)
    assert conforms(AR.estate_of(agent()), ev)["outcome"] == "UNVERIFIED"


def test_every_class_has_a_state_and_a_need_and_the_counts_add_up():
    states = {c: AR.class_state(c) for c in CLASSES}
    assert len(CLASSES) == 22 and sum(1 for s in states.values() if s == "monitored") == 19
    assert sorted(c for c, s in states.items() if s == "pending") == ["DVG-GOAL-01", "DVG-GOAL-02"] and [c for c, s in states.items() if s == "advisory"] == ["DVG-BASE-01"]
    for c in CLASSES.values():
        assert c.event in AR.NEEDS and c.event in AR.WIRE or c.event == "score", c.id


def test_bindings_rename_observed_names_by_glob_and_default_to_the_name():
    b = [("tool", "lookup_v*", "lookup"), ("resource", "db.ledger.*", "ledger")]
    assert AR.apply_binding(b, "tool", "lookup_v2") == "lookup" and AR.apply_binding(b, "tool", "refund") == "refund" and AR.apply_binding(b, "resource", "lookup_v2") == "lookup_v2"
    ev = AR.to_event(AGENT, "tool_call", {"name": "lookup_v2", "params": {"amount": 5}}, b, TODAY)
    assert conforms(AR.estate_of(agent()), ev)["outcome"] == "CONFORMS"


# ── part two: through the API on a scratch database ─────────────────────────────────────────────────────────────

def _db():
    from sqlalchemy import select
    from db.bootstrap import DEFAULT_ORG_SLUG
    from db.models import (Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent)
    from db.session import SessionLocal
    return select, DEFAULT_ORG_SLUG, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal


FMT = "%Y-%m-%dT%H:%M:%SZ"
PEER = "zz-peer-agent"


def reset():
    select, _, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal = _db()
    with SessionLocal() as s:
        for M in (RuntimeEvent, Finding):
            s.query(M).filter(M.agent_key.in_((AGENT, PEER))).delete(synchronize_session=False)
        s.query(AstraSignedContract).filter(AstraSignedContract.design_key == "zz-classes").delete(synchronize_session=False)
        s.query(AstraBaseline).filter(AstraBaseline.design_key == "zz-classes").delete(synchronize_session=False)
        s.query(AstraAssessment).filter(AstraAssessment.design_key == "zz-classes").delete(synchronize_session=False)
        s.query(AstraBinding).filter(AstraBinding.agent_key == AGENT).delete(synchronize_session=False)
        s.query(AstraPeerKey).filter(AstraPeerKey.key_id.like("zz-%")).delete(synchronize_session=False)
        s.query(Agent).filter(Agent.agent_key.in_((AGENT, PEER, "zz-spawn-child"))).delete(synchronize_session=False)
        s.commit()


def sign_into_db(doc=None, status="ACTIVE", not_before=None, expires=None, tamper=None):
    select, slug, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal = _db()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    nb, exp = (not_before or now - timedelta(hours=1)).strftime(FMT), (expires or now + timedelta(days=1)).strftime(FMT)
    kid, key = SG.load_signer({"ASTRA_SIGNING_KEY": PRIV})
    signed = SG.sign(doc or DOC, kid, key, nb, exp)
    document = signed["document"]
    if tamper:
        document = copy.deepcopy(document)
        tamper(document)
    with SessionLocal() as s:
        org = s.scalar(select(Organisation).where(Organisation.slug == slug))
        a = AstraAssessment(organisation_id=org.id, design_key="zz-classes", design_version=1, design_hash="0" * 64, verdict="APPROVED", departments=[], result={}, created_by="Zz Recorder")
        s.add(a)
        s.flush()
        b = AstraBaseline(organisation_id=org.id, design_key="zz-classes", design_hash="0" * 64, assessment_id=a.id, accepted_by="Zz Acceptor", accepted_by_id=a.id)
        s.add(b)
        s.flush()
        row = AstraSignedContract(organisation_id=org.id, agent_key=AGENT, design_key="zz-classes", design_hash="0" * 64, baseline_id=b.id, version="1.0.0", document=document,
                                  contract_hash=signed["contract_hash"], key_id=kid, signature=signed["signature"], not_before=nb, expires_at=exp, status=status, signed_by="Zz Acceptor")
        s.add(row)
        s.commit()


_ready = []


def _migrated():
    """The application brings the scratch database up to date when it starts; start it once before the first reset."""
    if not _ready:
        from fastapi.testclient import TestClient
        from main import app
        with TestClient(app):
            pass
        _ready.append(1)


def with_key(fn):
    def run():
        from tests._auth import authed_client  # noqa: F401  (imports the scratch guard before anything touches a database)
        _migrated()
        old = {k: os.environ.get(k) for k in ("ASTRA_SIGNING_KEY", "ASTRA_SIGNING_PUBLIC_KEYS")}
        os.environ["ASTRA_SIGNING_KEY"] = PRIV
        os.environ.pop("ASTRA_SIGNING_PUBLIC_KEYS", None)
        reset()
        try:
            fn()
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            reset()
    run.__name__ = fn.__name__
    return run


def send(c, wire, agent_name=AGENT, **data):
    r = c.post("/api/runtime/events", json={"agent": agent_name, "events": [{"type": wire, **data}]})
    assert r.status_code == 202, r.text
    return r.json()["results"][0], r.json()


def finding(key):
    select, _, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal = _db()
    with SessionLocal() as s:
        return s.scalar(select(Finding).where(Finding.seq == int(key.removeprefix("F-"))))


@with_key
def test_a_divergence_becomes_a_typed_finding_and_a_conforming_event_none():
    from tests._auth import authed_client
    with authed_client("engineer", "Eli Engineer") as c:
        sign_into_db()
        r, _ = send(c, "tool_call", name="lookup", params={"amount": 5})
        assert r["verdict"] == "CONFORMING" and r["finding_key"] is None
        r, body = send(c, "tool_call", name="shell")
        assert r["verdict"] == "DIVERGENT" and r["finding_key"] and body["contract_version"] == "1.0.0"
        f = finding(r["finding_key"])
        assert f.class_code == "DVG-TOOL-01" and f.detection_basis == "policy" and f.asi_signal == ["ASI02"] and f.contract_element == "permitted_tasks" and f.construct == "Task/plan"
        assert f.severity == "High" and f.class_severity == "High" and f.threat.startswith("ASI02") and f.adjudication is None
        r, _ = send(c, "tool_call", name="refund", confirmed=False)
        f = finding(r["finding_key"])
        assert f.class_code == "DVG-AUT-02" and f.class_severity == "Critical" and f.severity == "High", "a Critical class keeps the three-level severity of the existing screens"


@with_key
def test_an_event_that_cannot_be_judged_is_unverified_and_raises_no_finding():
    from tests._auth import authed_client
    select, _, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal = _db()
    with authed_client("engineer", "Eli Engineer") as c:
        sign_into_db()
        r, _ = send(c, "tool_call", name="refund")                       # a write tool that needs a person, with no word on whether one confirmed
        assert r["verdict"] == "UNVERIFIED" and r["finding_key"] is None
        with SessionLocal() as s:
            ev = s.scalar(select(RuntimeEvent).where(RuntimeEvent.agent_key == AGENT).order_by(RuntimeEvent.seq.desc()))
            assert ev.verdict == "UNVERIFIED" and "confirmed" in ev.attrs["missing"]
            assert s.query(Finding).filter(Finding.agent_key == AGENT).count() == 0


@with_key
def test_a_revoked_expired_or_tampered_contract_means_unverified_never_the_legacy_check():
    from tests._auth import authed_client
    select, _, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal = _db()
    with authed_client("engineer", "Eli Engineer") as c:
        for label, kw in (("revoked", {"status": "REVOKED"}), ("expired", {"not_before": datetime.now(timezone.utc) - timedelta(days=3), "expires": datetime.now(timezone.utc) - timedelta(days=1)}),
                          ("tampered", {"tamper": lambda d: d["permitted_tasks"].append({"id": "T9", "tool": "shell", "scope": {}})})):
            reset()
            sign_into_db(**kw)
            r, _ = send(c, "tool_call", name="lookup", params={"amount": 5})
            assert r["verdict"] == "UNVERIFIED" and r["finding_key"] is None, (label, r)
            with SessionLocal() as s:
                ev = s.scalar(select(RuntimeEvent).where(RuntimeEvent.agent_key == AGENT).order_by(RuntimeEvent.seq.desc()))
                assert any("contract" in m for m in ev.attrs["missing"]), (label, ev.attrs)
        reset()
        sign_into_db()
        os.environ["ASTRA_SIGNING_KEY"] = SG.generate("zz-other-key")[0]            # the key that signed it is no longer known
        r, _ = send(c, "tool_call", name="lookup", params={"amount": 5})
        assert r["verdict"] == "UNVERIFIED"


@with_key
def test_an_agent_without_a_signed_contract_keeps_the_legacy_behaviour():
    from tests._auth import authed_client
    with authed_client("engineer", "Eli Engineer") as c:
        r, body = send(c, "tool_call", name="anything")                  # discovered, no contract at all
        assert r["verdict"] == "UNKNOWN_AGENT" and body["discovered"]
        r, _ = send(c, "exec", sandboxed=False)                           # a new kind cannot be judged without a signed contract
        assert r["verdict"] == "NO_CONTRACT"
        r, _ = send(c, "heartbeat")
        assert r["verdict"] == "CONFORMING"


@with_key
def test_the_same_divergence_is_one_finding_within_ten_minutes():
    from tests._auth import authed_client
    with authed_client("engineer", "Eli Engineer") as c:
        sign_into_db()
        a, _ = send(c, "data_access", name="payroll")
        b, _ = send(c, "data_access", name="payroll")
        assert a["finding_key"] == b["finding_key"]


@with_key
def test_bindings_are_signoff_only_and_decide_what_a_name_stands_for():
    from tests._auth import authed_client
    with authed_client("engineer", "Eli Engineer") as eng, authed_client("compliance", "Rhea One") as comp:
        sign_into_db()
        body = {"agent": AGENT, "element": "tool", "selector": "lookup_v*", "contract_name": "lookup"}
        assert eng.post("/api/astra/bindings", json=body).status_code == 403, "an engineer cannot decide what a name may be"
        assert send(eng, "tool_call", name="lookup_v2", params={"amount": 5})[0]["verdict"] == "DIVERGENT"
        made = comp.post("/api/astra/bindings", json=body)
        assert made.status_code == 201, made.text
        assert comp.post("/api/astra/bindings", json=body).status_code == 409
        assert send(eng, "tool_call", name="lookup_v2", params={"amount": 5})[0]["verdict"] == "CONFORMING"
        assert [b["selector"] for b in eng.get(f"/api/astra/bindings?agent={AGENT}").json()] == ["lookup_v*"]
        assert eng.delete(f"/api/astra/bindings/{made.json()['id']}").status_code == 403
        assert comp.delete(f"/api/astra/bindings/{made.json()['id']}").status_code == 200
        assert send(eng, "tool_call", name="lookup_v2", params={"amount": 5})[0]["verdict"] == "DIVERGENT"


@with_key
def test_a_message_is_authenticated_against_the_key_registered_for_its_sender():
    from tests._auth import authed_client
    key = Ed25519PrivateKey.generate()
    pub = SG._b64e(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    with authed_client("engineer", "Eli Engineer") as eng, authed_client("compliance", "Rhea One") as comp:
        sign_into_db()
        assert eng.post("/api/astra/peer-keys", json={"key_id": "zz-peer-key", "agent": PEER, "public_key": pub}).status_code == 403
        assert comp.post("/api/astra/peer-keys", json={"key_id": "zz-peer-key", "agent": PEER, "public_key": "short"}).status_code == 422
        assert comp.post("/api/astra/peer-keys", json={"key_id": "zz-peer-key", "agent": PEER, "public_key": pub}).status_code == 201
        assert comp.post("/api/astra/peer-keys", json={"key_id": "zz-peer-key", "agent": PEER, "public_key": pub}).status_code == 409
        sig = key.sign(b"transfer 5").hex()
        assert send(eng, "msg", name=PEER, payload="transfer 5", signature=sig, key_id="zz-peer-key")[0]["verdict"] == "CONFORMING"
        bad, _ = send(eng, "msg", name=PEER, payload="transfer 5000", signature=sig, key_id="zz-peer-key")
        assert bad["verdict"] == "DIVERGENT" and finding(bad["finding_key"]).class_code == "DVG-COMM-01" and finding(bad["finding_key"]).detection_basis == "cryptographic"
        other, _ = send(eng, "msg", name="zz-someone", payload="transfer 5", signature=sig, key_id="zz-peer-key")      # the key speaks only for the agent it was registered for
        assert other["verdict"] == "DIVERGENT"


@with_key
def test_a_spawn_is_checked_against_the_platform_inventory_not_the_collectors_claim():
    from tests._auth import authed_client
    select, slug, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal = _db()
    with authed_client("engineer", "Eli Engineer") as c:
        sign_into_db()
        assert send(c, "spawn", name=PEER, inventoried=True)[0]["verdict"] == "DIVERGENT", "claiming it is inventoried does not make it so"
        send(c, "heartbeat", agent_name=PEER)                              # the platform now knows the agent (discovered at runtime)
        assert send(c, "spawn", name=PEER)[0]["verdict"] == "CONFORMING"


@with_key
def test_a_semantic_finding_waits_for_a_person_who_confirms_or_dismisses_it():
    from tests._auth import authed_client
    with authed_client("engineer", "Eli Engineer") as eng, authed_client("compliance", "Rhea One") as comp:
        sign_into_db()
        r, _ = send(eng, "goal_set", name="Sell the data", source="retrieved document", semantic="out_of_scope")
        assert r["verdict"] == "PENDING" and r["finding_key"]
        f = finding(r["finding_key"])
        assert f.class_code == "DVG-GOAL-01" and f.detection_basis == "semantic" and f.adjudication == "PENDING" and f.status == "OPEN"
        assert eng.post(f"/api/astra/findings/{r['finding_key']}/adjudicate", json={"decision": "dismiss", "note": "not mine to judge"}).status_code == 403
        assert comp.post(f"/api/astra/findings/{r['finding_key']}/adjudicate", json={"decision": "dismiss", "note": "a"}).status_code == 422
        done = comp.post(f"/api/astra/findings/{r['finding_key']}/adjudicate", json={"decision": "confirm", "note": "It really did."})
        assert done.status_code == 200 and done.json()["adjudication"] == "CONFIRMED" and done.json()["status"] == "OPEN"
        assert comp.post(f"/api/astra/findings/{r['finding_key']}/adjudicate", json={"decision": "dismiss", "note": "changed my mind"}).status_code == 409
        r2, _ = send(eng, "goal_set", name="Handle a refund differently", source="user", semantic="integrity")
        d = comp.post(f"/api/astra/findings/{r2['finding_key']}/adjudicate", json={"decision": "dismiss", "note": "A normal request."})
        assert d.json()["status"] == "ACKNOWLEDGED" and d.json()["adjudication"] == "DISMISSED"


@with_key
def test_the_classes_screen_counts_what_is_monitored_and_asks_for_collector_events():
    from tests._auth import authed_client
    select, _, Agent, AstraAssessment, AstraBaseline, AstraBinding, AstraPeerKey, AstraSignedContract, Finding, Organisation, RuntimeEvent, SessionLocal = _db()
    with authed_client("engineer", "Eli Engineer") as c:
        with SessionLocal() as s:                                           # earlier suites leave events behind; the counts below are about this test's own
            s.query(RuntimeEvent).delete()
            s.query(Finding).filter(Finding.class_code.like("DVG-%-%")).delete(synchronize_session=False)
            s.commit()
        before = c.get("/api/astra/classes").json()
        n = before["counts"]
        assert n["total"] == 22 and n["monitored"] == 22 and n["deterministic"] == 19 and n["pending"] == 2 and n["advisory"] == 1
        by = {r["id"]: r for r in before["classes"]}
        assert by["DVG-BASE-01"]["state"] == "advisory" and "never block on its own" in by["DVG-BASE-01"]["note"]
        assert by["DVG-EXEC-01"]["state"] == "monitored" and by["DVG-EXEC-01"]["events"] == 0 and "exec event" in by["DVG-EXEC-01"]["needs"], "no collector event: say so instead of claiming coverage"
        sign_into_db()
        send(c, "tool_call", name="shell")
        after = c.get("/api/astra/classes").json()
        by2 = {r["id"]: r for r in after["classes"]}
        assert by2["DVG-TOOL-01"]["events"] >= 1 and by2["DVG-TOOL-01"]["needs"] is None and by2["DVG-TOOL-01"]["open_findings"] >= 1
        assert after["counts"]["receiving_events"] > before["counts"]["receiving_events"] and by2["DVG-EXEC-01"]["needs"]


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}  {exc!r}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
