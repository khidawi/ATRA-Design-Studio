"""
End-to-end script (Task 9, extended in ASTRA phase 13): drives the whole platform over HTTP, as five different people, from sign-in to evidence packs, and then the whole ASTRA loop:
describe an agent, assess it, add controls, ratify the risk layer, accept the baseline, sign a contract, run it, see a divergence and the verdict, Probe it, cover it, generate a pack.

    docker compose exec backend python -m tests.e2e                 # everything that needs no language model
    docker compose exec backend python -m tests.e2e --with-ollama   # also drafts an agent with the local model (minutes on a CPU)
    docker compose exec backend python -m tests.e2e --base http://localhost:8765

It talks to the running backend (default http://localhost:8765) with real sign-ins, so it exercises the same path a browser
does: cookies, the CSRF header, role checks and the audit log. It needs a database with no agent designs, agents, findings or packs
of its own, because it asserts exact counts. Everything it creates is removed at the end (users, sessions, designs, agents, contracts,
findings, drift, packs, coverage assignments and the audit events it caused), whether or not a step failed.
"""
import argparse
import csv
import io
import sys
import time
import uuid

import httpx

from auth import CSRF_HEADER, hash_password
from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import (Agent, AuditEvent, Contract, CoverageAssignment, Design, DriftItem, EvidencePack, Finding, Organisation, User, UserSession)
from db.session import SessionLocal
from tests._guard import require_scratch_database

PASSWORD = "e2e-Password-" + uuid.uuid4().hex[:8]
RUN = uuid.uuid4().hex[:6]
PEOPLE = {"admin": "Ada Admin", "compliance": "Cora Compliance", "engineer": "Eli Engineer", "auditor": "Ava Auditor", "security": "Sam Security"}
STEPS = []


def step(title):
    def wrap(fn):
        STEPS.append((title, fn))
        return fn
    return wrap


class Client:
    def __init__(self, base):
        self.http = httpx.Client(base_url=base, timeout=300, headers={CSRF_HEADER: "1"})

    def __getattr__(self, name):
        return getattr(self.http, name)


def person(base, role):
    c = Client(base)
    r = c.post("/api/auth/login", json={"email": f"e2e-{role}-{RUN}@example.test", "password": PASSWORD})
    assert r.status_code == 200, (role, r.status_code, r.text)
    return c


def design_doc(name, extra=None, req=None):
    doc = {
        "nodes": [
            {"id": "h1", "type": "human", "name": "Clinician", "p": {}},
            {"id": "g1", "type": "goal", "name": "Summarise patient records", "p": {}},
            {"id": "a1", "type": "agent", "name": name, "p": {"owner": "Platform team", "auto": "approval"}, "primary": True},
            {"id": "t1", "type": "tool", "name": "ehr.records.read", "p": {"write": False}},
            {"id": "t2", "type": "tool", "name": "email.send.external", "p": {"write": True}},
        ],
        "edges": [{"from": "h1", "to": "a1", "label": "requests"}, {"from": "a1", "to": "g1", "label": "pursues"},
                  {"from": "a1", "to": "t1", "label": "uses"}, {"from": "a1", "to": "t2", "label": "uses"}],
        "n": 100, "profile": "healthcare", "req": req or {}, "policy": "block",
    }
    if extra:
        doc["nodes"].append(extra)
        doc["edges"].append({"from": "a1", "to": extra["id"], "label": "uses"})
    return doc


S = {}   # what one step hands to the next


def ratify_reviewing(client, design_key, **extra):
    """Ratify an agent design. A design whose gate says REVIEW needs a recorded review by someone who is not its owner first (the Fix tab); record one if the platform asks for it."""
    r = client.post("/api/agents/ratify", json={"design_key": design_key, **extra})
    if r.status_code == 422 and "gate says REVIEW" in r.text:
        rv = client.post(f"/api/agents/designs/{design_key}/review", json={"decision": "APPROVED", "note": "e2e: reviewed against the Fix tab."})
        assert rv.status_code == 201, rv.text
        r = client.post("/api/agents/ratify", json={"design_key": design_key, **extra})
    return r
AGENT = f"e2e-patient-agent-{RUN}"


def pdf(r, what):
    assert r.status_code == 200 and r.content.startswith(b"%PDF-") and len(r.content) > 1500, (what, r.status_code)


# ── 1. Getting in ───────────────────────────────────────────────────────────

@step("The platform is up and nothing is open without signing in")
def s_open(base):
    anon = Client(base)
    assert anon.get("/health").status_code == 200
    for path in ("/api/agents", "/api/designs", "/api/packs", "/api/audit", "/api/overview"):
        assert anon.get(path).status_code == 401, path
    assert anon.post("/api/auth/login", json={"email": f"e2e-admin-{RUN}@example.test", "password": "wrong"}).status_code == 401


@step("Each role signs in and sees its own permissions")
def s_roles(base):
    expect = {"admin": {"admin", "audit", "read", "signoff", "write", "ingest"}, "compliance": {"audit", "read", "signoff", "write", "ingest"}, "engineer": {"read", "write", "ingest"}, "auditor": {"audit", "read"},
              "security": {"audit", "read", "write"}}
    for role in PEOPLE:
        S[role] = person(base, role)
        me = S[role].get("/api/auth/me").json()
        assert me["user"]["role"] == role and set(me["permissions"]) == expect[role], role


@step("An administrator manages users; nobody else can")
def s_users(base):
    r = S["admin"].post("/api/users", json={"email": f"e2e-extra-{RUN}@example.test", "full_name": "Extra Person", "role": "engineer", "password": "another-long-pw-1"})
    assert r.status_code == 201
    assert S["engineer"].get("/api/users").status_code == 403 and S["compliance"].post("/api/users", json={}).status_code == 403
    assert S["admin"].patch(f"/api/users/{r.json()['id']}", json={"active": False}).json()["active"] is False


# ── 2. Rules, regulations and organisation policies ─────────────────────────

@step("Regulations, rules and domains come from the database")
def s_regs(base):
    regs = {r["instrument"]: r for r in S["engineer"].get("/api/regulations").json()}
    assert {"GDPR", "EU AI Act", "OWASP"} <= set(regs) and regs["GDPR"]["approved_rules"] >= 1
    assert len(S["engineer"].get("/api/rules?status=APPROVED").json()) >= 20
    assert any(d["domain_id"] == "OWASP_AGENTIC" for d in S["engineer"].get("/api/domains?subject=AGENT").json())
    assert any(d["domain_id"] == "HEALTHCARE" for d in S["engineer"].get("/api/domains").json())


@step("An organisation policy is added by compliance and flags agent designs")
def s_policy(base):
    vocab = S["compliance"].get("/api/policies/vocabulary").json()
    body = {"title": f"E2E no external email {RUN}", "description": "e2e", "message": "No tool may send email outside the organisation", "severity": "REQUIRED", "subject": "AGENT",
            "applies_to_all": True, "domains": [], "status": "APPROVED",
            "spec": {"rule": "FORBID", "element": "tool", "where": [{"property": "name", "op": "is", "value": "email.send.external"}]}}
    assert vocab["subjects"]["AGENT"]["elements"]
    assert S["engineer"].post("/api/policies", json=body).status_code == 403
    r = S["compliance"].post("/api/policies", json=body)
    assert r.status_code in (200, 201), r.text
    S["policy_key"] = r.json()["policy_key"]
    graph = {"nodes": [{"id": "a1", "type": "agent", "props": {"name": "x"}, "primary": True}, {"id": "t1", "type": "tool", "props": {"name": "email.send.external", "write": True}}],
             "edges": [{"from": "a1", "to": "t1", "label": "uses"}]}
    rows = S["engineer"].post("/api/agents/analyse", json={"graph": graph}).json()["rows"]
    assert any(row["status"] == "Gap" and "E2E no external email" in row["name"] for row in rows), [r["name"] for r in rows]


# ── 3. The model studio ─────────────────────────────────────────────────────

@step("A model deployment is imported, saved, reopened and listed")
def s_model(base):
    desc = {"deployment_name": f"E2E clinical triage {RUN}", "assessment_domain": "HEALTHCARE",
            "departments": [{"temp_id": "d1", "name": "Clinical AI"}],
            "actors": [{"temp_id": "a1", "subtype": "TRAINER", "identity": "Data scientist", "department_temp_id": "d1"}],
            "ai_models": [{"temp_id": "m1", "name": "Triage LLM", "model_type": "LLM", "ai_criticality": "OPERATIONAL", "data_sensitivity": "SENSITIVE_PERSONAL", "hosting_environment": "TYPE_1_INHOUSE", "domain": "healthcare"}],
            "deployment_environments": []}
    r = S["engineer"].post("/api/designs/import", json=desc)
    assert r.status_code == 200, r.text
    nodes = r.json()["departments"] + r.json()["actors"] + r.json()["ai_models"]
    assert len(nodes) >= 3
    d = S["engineer"].post("/api/designs", json={"name": desc["deployment_name"], "domain": "HEALTHCARE", "document": {"nodes": nodes, "edges": r.json()["edges"], "n": 10}}).json()
    S["model_design"] = d["design_key"]
    again = S["compliance"].get(f"/api/designs/{d['design_key']}").json()
    assert len(again["document"]["nodes"]) == len(nodes) and again["domain"] == "HEALTHCARE"
    assert any(x["design_key"] == d["design_key"] for x in S["auditor"].get("/api/designs").json())
    assert S["auditor"].put(f"/api/designs/{d['design_key']}", json={"name": "x", "domain": "GENERAL", "document": {"nodes": [], "edges": [], "n": 1}, "version": 1}).status_code == 403


# ── 4. An agent from design to ratified contract ────────────────────────────

@step("An engineer designs an agent; the risk score is Blocked until a veto requirement is signed off")
def s_design(base):
    req = {"dpia": {"status": "Gap", "evidence": "", "signed_off_by": ""}}
    d = S["engineer"].post("/api/designs", json={"name": AGENT, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": design_doc(AGENT, req=req)}).json()
    S["agent_design"], S["version"] = d["design_key"], d["version"]
    graph = {"nodes": [{"id": n["id"], "type": n["type"], "props": {"name": n["name"], **n["p"]}, "primary": bool(n.get("primary"))} for n in d["document"]["nodes"]],
             "edges": d["document"]["edges"]}
    r = S["engineer"].post("/api/rcr/score", json={"profile": "healthcare", "graph": graph, "declarations": req}).json()
    assert r["gate"] == "BLOCK" and r["band"] == "blocked" and r["score"] >= 80, r["score"]
    assert S["engineer"].post("/api/agents/ratify", json={"design_key": S["agent_design"]}).status_code == 403          # an engineer cannot ratify
    blocked = S["compliance"].post("/api/agents/ratify", json={"design_key": S["agent_design"]})
    assert blocked.status_code == 422 and "Blocked" in blocked.json()["detail"]


@step("Only the person signed in can sign off, and only compliance can")
def s_signoff(base):
    def save(who, signer):
        cur = S[who].get(f"/api/designs/{S['agent_design']}").json()
        req = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": signer}}
        return S[who].put(f"/api/designs/{S['agent_design']}", json={"name": AGENT, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": design_doc(AGENT, req=req), "version": cur["version"]})
    assert save("engineer", PEOPLE["compliance"]).status_code == 403
    assert save("compliance", "Someone Else").status_code == 403
    assert save("compliance", PEOPLE["compliance"]).status_code == 200


@step("Compliance ratifies; the contract is issued in their name and its hash verifies")
def s_ratify(base):
    r = ratify_reviewing(S["compliance"], S["agent_design"], reviewer="Spoofed Name")
    assert r.status_code == 200, r.text
    c = r.json()["contract"]
    S["contract"] = c
    assert c["issued_by"] == PEOPLE["compliance"] and c["version"] == "1.0.0" and c["object_type"] == "AGENT" and r.json()["agent"]["status"] == "DESIGNED"
    assert c["design_snapshot"]["rcr"]["gate"] in ("REVIEW", "APPROVE")
    assert S["auditor"].get(f"/api/contracts/{c['contract_id']}/verify").json()["ok"] is True
    assert any(x["agent_key"] == AGENT for x in S["auditor"].get("/api/agents").json())


# ── 5. Inventory and findings ───────────────────────────────────────────────

@step("An unowned agent is registered and counts against ASI10")
def s_inventory(base):
    r = S["engineer"].post("/api/agents/register", json={"name": f"e2e-sandbox-{RUN}", "framework": "MCP only", "tools_count": 3})
    assert r.status_code == 201 and r.json()["status"] == "UNOWNED"
    cov = {x["code"]: x for x in S["auditor"].get("/api/coverage").json()["rows"]}
    assert cov["ASI10"]["status"] == "Gap" and any(b["agent"] == f"e2e-sandbox-{RUN}" for b in cov["ASI10"]["breakdown"])
    assert S["engineer"].patch(f"/api/agents/e2e-sandbox-{RUN}", json={"owner": "Platform"}).json()["status"] == "TO_RATIFY"


@step("A definition file becomes a draft agent model; nothing in it is trusted blindly")
def s_import(base):
    name = f"e2e-import-{RUN}"
    text = "\n".join([f"agent: {name}", 'owner: Payments eng', 'tools:', '  - name: stripe.payouts.create', '    access: write', '  - list_orders', 'mcp_servers:', '  - name: mcp://erp', '    signed: true', 'api_key: never-read']) + "\n"
    pv = S["auditor"].post("/api/agents/import/preview", json={"content": text, "filename": "agent.model.yaml"})
    assert pv.status_code == 200 and pv.json()["existing"]["will"] == "create" and any("api_key" in x for x in pv.json()["ignored"])
    assert S["auditor"].post("/api/agents/import", json={"content": text}).status_code == 403
    assert S["engineer"].post("/api/agents/import", json={"content": "not: an agent"}).status_code == 422
    r = S["engineer"].post("/api/agents/import", json={"content": text, "filename": "agent.model.yaml"})
    assert r.status_code == 201 and r.json()["outcome"] == "created" and r.json()["agent"]["status"] == "TO_RATIFY"
    doc = S["engineer"].get(f"/api/designs/{r.json()['design_key']}").json()["document"]
    assert doc["provenance"]["imported_by"] == PEOPLE["engineer"] and "never-read" not in str(doc)
    assert [n["p"] for n in doc["nodes"] if n["type"] == "mcp"] == [{"signed": True}]


@step("Observed events become findings only when they diverge from the contract")
def s_findings(base):
    ok = S["engineer"].post("/api/findings/ingest", json={"agent": AGENT, "event": {"type": "tool_call", "name": "ehr.records.read"}}).json()
    assert ok["finding"] is None and ok["checked_against"] == "1.0.0"
    bad = S["engineer"].post("/api/findings/ingest", json={"agent": AGENT, "event": {"type": "tool_call", "name": "shell.exec", "write": True}}).json()["finding"]
    assert bad["severity"] == "High" and bad["class_code"] == "DVG-TOOL" and bad["source"] == "COLLECTED"
    S["finding"] = bad["finding_key"]
    assert S["engineer"].post(f"/api/findings/{S['finding']}/acknowledge", json={}).status_code == 403
    ack = S["compliance"].post(f"/api/findings/{S['finding']}/acknowledge", json={}).json()
    assert ack["status"] == "ACKNOWLEDGED" and ack["acknowledged_by"] == PEOPLE["compliance"]
    assert "DVG-TOOL must not recur" in S["engineer"].post(f"/api/findings/{S['finding']}/test").json()["test_spec"]
    assert S["compliance"].post(f"/api/findings/{S['finding']}/halt", json={}).json()["halt_requested_by"] == PEOPLE["compliance"]


# ── 6. Drift, contract versions and revocation ──────────────────────────────

@step("A widening design change goes to review, is approved, and supersedes the contract")
def s_drift(base):
    req = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": PEOPLE["compliance"]}}
    cur = S["engineer"].get(f"/api/designs/{S['agent_design']}").json()
    wider = design_doc(AGENT, {"id": "t9", "type": "tool", "name": "ehr.records.write", "p": {"write": True}}, req)
    assert S["engineer"].put(f"/api/designs/{S['agent_design']}", json={"name": AGENT, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": wider, "version": cur["version"]}).status_code == 200
    item = S["engineer"].post("/api/drift/propose", json={"design_key": S["agent_design"]}).json()
    assert item["kind"] == "Widening" and item["status"] == "OPEN" and item["source"] == "DESIGN"
    assert S["engineer"].post(f"/api/drift/{item['id']}/decide", json={"decision": "approve"}).status_code == 403
    done = S["compliance"].post(f"/api/drift/{item['id']}/decide", json={"decision": "approve"}).json()
    assert done["status"] == "APPROVED" and done["decided_by"] == PEOPLE["compliance"] and done["new_contract_id"]
    recs = {r["contract"]["contract_id"]: r for r in S["auditor"].get(f"/api/contract-records?object_type=AGENT&deployment={AGENT}").json()}
    assert recs[S["contract"]["contract_id"]]["status"] == "SUPERSEDED" and recs[done["new_contract_id"]]["status"] == "ACTIVE"
    v2 = recs[done["new_contract_id"]]["contract"]
    assert v2["version"] == "2.0.0" and v2["design_snapshot"]["change"]["widens"] is True
    S["v2"] = v2


@step("A simulated change can be declined and leaves the contract alone")
def s_decline(base):
    d = S["engineer"].post("/api/drift/simulate", json={"agent": AGENT, "scenario": "add_unsigned_mcp"}).json()
    assert d["source"] == "SIMULATED" and any("mcp://" in c["text"] for c in d["changes"])
    r = S["compliance"].post(f"/api/drift/{d['id']}/decide", json={"decision": "decline", "note": "not needed"}).json()
    assert r["status"] == "DECLINED"
    active = [x for x in S["auditor"].get(f"/api/contract-records?object_type=AGENT&deployment={AGENT}").json() if x["status"] == "ACTIVE"]
    assert [x["contract"]["version"] for x in active] == ["2.0.0"]


# ── 7. Coverage, evidence packs, documents ──────────────────────────────────

@step("Coverage is computed from the active contract and owners can be assigned")
def s_coverage(base):
    cov = S["auditor"].get("/api/coverage").json()
    assert cov["agents_in_scope"] == 1 and cov["agents_without_contract"] >= 1
    row = S["engineer"].put("/api/coverage/ASI08", json={"owner": "Platform lead"})
    assert row.status_code == 403
    row = S["compliance"].put("/api/coverage/ASI08", json={"owner": "Platform lead", "due": "2026-01-01"}).json()
    assert row["owner"] == "Platform lead" and row["due_label"].startswith("Overdue") or row["status"] == "Covered"


@step("Trust and Assurance packs are generated, chained, and verify; a trust report names no agent")
def s_packs(base):
    assert S["engineer"].post("/api/packs", json={"template": "TRUST"}).status_code == 403
    a = S["compliance"].post("/api/packs", json={"template": "ASSURANCE", "period": "30d"}).json()
    t = S["compliance"].post("/api/packs", json={"template": "TRUST", "period": "all", "frameworks": ["OWASP_AGENTIC"]}).json()
    assert a["generated_by"] == PEOPLE["compliance"] and t["previous_pack_hash"] == a["pack_hash"]
    assert AGENT not in str(t["content"]) and any(AGENT in str(x) for x in a["content"]["agents"])
    assert any("simulated" in l for l in a["content"]["limits"]) and a["gaps"] >= 1
    for p in (a, t):
        v = S["auditor"].get(f"/api/packs/{p['pack_key']}/verify").json()
        assert v["ok"] and v["chain_ok"] and v["contracts_checked"] == 1
    S["packs"] = (a["pack_key"], t["pack_key"])


@step("Every document can be downloaded: PDF, JSON, CSV and YAML")
def s_documents(base):
    a, t = S["packs"]
    c = S["v2"]["contract_id"]
    pdf(S["auditor"].get(f"/api/export/packs/{a}.pdf"), "assurance pack")
    pdf(S["auditor"].get(f"/api/export/packs/{t}.pdf"), "trust report")
    assert S["auditor"].get(f"/api/export/packs/{a}.json").json()["pack_hash"]
    pdf(S["auditor"].get(f"/api/export/contracts/{c}.pdf"), "agent contract")
    assert S["auditor"].get(f"/api/export/contracts/{c}.json").json()["contract_hash"] == S["v2"]["contract_hash"]
    assert f"agent: {AGENT}" in S["auditor"].get(f"/api/export/contracts/{c}.yaml").text
    pdf(S["auditor"].get("/api/export/coverage.pdf"), "coverage")
    assert S["auditor"].get("/api/export/coverage.json").json()["agents_in_scope"] == 1
    pdf(S["auditor"].get("/api/export/findings.pdf"), "findings")
    rows = list(csv.reader(io.StringIO(S["auditor"].get("/api/export/findings.csv").text)))
    assert rows[0][0] == "finding" and any(r[0] == S["finding"] for r in rows[1:])
    drift = S["auditor"].get("/api/drift").json()[0]
    pdf(S["auditor"].get(f"/api/export/drift/{drift['id']}.pdf"), "drift")
    pdf(S["auditor"].get("/api/export/audit.pdf"), "audit")
    assert S["auditor"].get("/api/export/audit.csv").status_code == 200 and S["engineer"].get("/api/export/audit.csv").status_code == 403


@step("Revoking the only active contract takes the agent back to To ratify and the hash still verifies")
def s_revoke(base):
    assert S["engineer"].post(f"/api/contracts/{S['v2']['contract_id']}/revoke", json={"reason": "e2e"}).status_code == 403
    r = S["compliance"].post(f"/api/contracts/{S['v2']['contract_id']}/revoke", json={"reason": "End of the end-to-end run"}).json()
    assert r["status"] == "REVOKED" and r["status_by"] == PEOPLE["compliance"]
    assert S["auditor"].get(f"/api/contracts/{S['v2']['contract_id']}/verify").json()["ok"] is True
    assert [a for a in S["auditor"].get("/api/agents").json() if a["agent_key"] == AGENT][0]["status"] == "TO_RATIFY"
    assert S["auditor"].get(f"/api/packs/{S['packs'][0]}/verify").json()["notes"]                                            # the pack notes the revocation
    assert S["auditor"].get("/api/coverage").json()["agents_in_scope"] == 0


# ── 8. Overview, workspace and the audit trail ──────────────────────────────

@step("The overview and workspace reflect all of it")
def s_overview(base):
    o = S["auditor"].get("/api/overview").json()
    assert o["findings"]["open"] == 0 and o["agents_total"] >= 2 and o["agents_with_contract"] == 0, o     # the one finding was acknowledged
    assert any("contract" in a["text"].lower() for a in o["activity"]) and any("Finding raised" in a["text"] for a in o["activity"]), [a["text"] for a in o["activity"]]
    w = S["auditor"].get("/api/workspace").json()
    assert w["auditor"]["packs"] and all(p["ok"] for p in w["auditor"]["packs"]) and PEOPLE["compliance"] in w["auditor"]["approvers"], w["auditor"]


@step("The audit log recorded who did what, refused actions too, and its chain is intact")
def s_audit(base):
    assert S["engineer"].get("/api/audit").status_code == 403
    events = S["auditor"].get("/api/audit?limit=500").json()
    seen = {(e["actor"], e["action"], e["outcome"]) for e in events}
    for who, action, outcome in ((PEOPLE["compliance"], "POST /api/agents/ratify", "ok"), (PEOPLE["compliance"], "POST /api/agents/ratify", "failed"),   # the Blocked attempt
                                 (PEOPLE["engineer"], "POST /api/agents/ratify", "denied"), (PEOPLE["compliance"], "POST /api/packs", "ok"),     # the engineer's refused attempt
                                 (PEOPLE["admin"], "POST /api/users", "ok")):
        assert (who, action, outcome) in seen, (who, action, outcome, sorted(seen)[:12])
    assert all("password" not in str(e["detail"]).lower() for e in events)
    v = S["auditor"].get("/api/audit/verify").json()
    assert v["ok"] and v["events"] >= len(events) and v["head_hash"]


@step("The runtime SDK reports a running agent: conforming events pass, a new capability becomes a finding and runtime drift, an unknown agent is discovered")
def s_runtime(base):
    try:
        import astra_runtime
        from astra_runtime.client import Client
    except ImportError:
        raise Skip("the SDK is not importable (copy sdk/python into the container and set PYTHONPATH)")
    name = f"e2e-runtime-{RUN}"
    req = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": PEOPLE["compliance"]}}
    d = S["engineer"].post("/api/designs", json={"name": name, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": design_doc(name, req={"dpia": {**req["dpia"], "signed_off_by": ""}})}).json()
    cur = S["compliance"].get(f"/api/designs/{d['design_key']}").json()
    assert S["compliance"].put(f"/api/designs/{d['design_key']}", json={"name": name, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": design_doc(name, req=req), "version": cur["version"]}).status_code == 200
    assert ratify_reviewing(S["compliance"], d["design_key"]).status_code == 200
    key = S["admin"].post("/api/keys", json={"name": f"e2e collector {RUN}", "role": "collector"}).json()
    c = Client(base, key["key"], name, flush_interval=0.05)
    try:
        assert c.check() == {"ok": True, "key": f"API key: e2e collector {RUN}", "role": "collector"}
        c.tool_call("ehr.records.read", write=False)                                   # allowed by the contract
        c.heartbeat()
        c.tool_call("payments.transfer.create", write=True)                            # not in the contract
        with c.as_agent(f"e2e-ghost-{RUN}"):
            c.tool_call("shell.exec", write=True)                                      # an agent the platform has never seen
        assert c.flush(5)
        for _ in range(40):
            if S["auditor"].get(f"/api/runtime/overview?agent={name}").json()["events"] and len(S["auditor"].get(f"/api/runtime/overview?agent={name}").json()["events"]) >= 3:
                break
            time.sleep(0.1)
    finally:
        c.close()
    ov = S["auditor"].get("/api/runtime/overview").json()
    live = {a["agent_key"]: a for a in ov["agents"]}
    mine = live[name]
    assert mine["status"] == "live" and mine["divergent_1h"] == 1 and mine["open_findings"] == 1 and mine["open_drift"] and mine["contract_version"] == "1.0.0"
    ghost = live[f"e2e-ghost-{RUN}"]
    assert ghost["origin"] == "DISCOVERED" and ghost["status"] == "live" and ghost["owner"] is None
    item = [x for x in S["auditor"].get("/api/drift").json() if x["id"] == mine["open_drift"]][0]
    assert item["source"] == "RUNTIME" and item["kind"] == "Widening" and any("payments.transfer.create" in ch["text"] for ch in item["changes"])
    verdicts = [e["verdict"] for e in S["auditor"].get(f"/api/runtime/overview?agent={name}").json()["events"]]
    assert verdicts.count("DIVERGENT") == 1 and "CONFORMING" in verdicts
    assert [a for a in S["auditor"].get("/api/agents").json() if a["agent_key"] == f"e2e-ghost-{RUN}"][0]["status"] == "UNOWNED"
    assert S["compliance"].post(f"/api/drift/{item['id']}/decide", json={"decision": "decline", "note": "e2e"}).json()["status"] == "DECLINED"


@step("(optional) The local model drafts an agent from plain English")
def s_ollama(base):
    if not ARGS.with_ollama:
        raise Skip("run with --with-ollama")
    t = time.time()
    r = S["engineer"].post("/api/agents/draft", json={"description": "An agent that reads refund requests from our support inbox, checks the order in the CRM and issues refunds through Stripe."})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["nodes"] and any(n.get("primary") for n in d["nodes"]), d
    print(f"        drafted {len(d['nodes'])} elements in {round(time.time() - t)} s")


class Skip(Exception):
    pass


# ── 9. The ASTRA loop (phases 1 to 12) ──────────────────────────────────────

ASTRA_AGENT = f"e2e-astra-agent-{RUN}"
DEPT, STORE, AG_NODE = f"E2E-D-{RUN}", f"E2E-DS-{RUN}", f"E2E-AG-{RUN}"


def need(key):
    if key not in S:
        raise Skip(f"needs the step before it ({key})")


def astra_doc(guarded):
    doc = {"nodes": [{"id": "a1", "type": "agent", "name": ASTRA_AGENT, "p": {"owner": f"e2e-owner-{RUN}@example.test", "auto": "approval"}, "primary": True},
                     {"id": "g1", "type": "goal", "name": "Refund small claims", "p": {}},
                     {"id": "i1", "type": "input", "name": "customer email", "p": {"untrusted": True}},
                     {"id": "t1", "type": "tool", "name": "refund", "p": {"write": True}},
                     {"id": "t2", "type": "tool", "name": "lookup", "p": {"write": False}},
                     {"id": "d1", "type": "data", "name": f"E2E Ledger {RUN}", "p": {}}],
           "edges": [{"from": "a1", "to": "g1", "label": "pursues"}, {"from": "i1", "to": "a1", "label": "feeds"}, {"from": "a1", "to": "t1", "label": "uses"}, {"from": "a1", "to": "t2", "label": "uses"},
                     {"from": "a1", "to": "d1", "label": "reads"}], "n": 100, "profile": None, "req": {}, "policy": "block"}
    if guarded:
        doc["nodes"] += [{"id": "ap1", "type": "approval", "name": "manager approval", "p": {}}, {"id": "gr1", "type": "guardrail", "name": "injection filter", "p": {"kind": "injection"}}]
        doc["edges"] += [{"from": "ap1", "to": "t1", "label": "gates"}, {"from": "gr1", "to": "a1", "label": "limits"}]
    return doc


def astra_controls(base):
    a = S["engineer"].get(f"/api/agents/designs/{S['astra_design']}/assessment")
    assert a.status_code == 200, a.text
    return a.json()


@step("ASTRA: the organisation has a department and a data store, and an engineer describes an agent in it that reads untrusted input")
def s_astra_describe(base):
    from db.models import CompanyNode
    with SessionLocal() as s:
        org = s.query(Organisation).filter_by(slug=DEFAULT_ORG_SLUG).one()
        s.add(CompanyNode(organisation_id=org.id, ext_id=DEPT, type="department", name=f"E2E Finance {RUN}", props={}))
        s.add(CompanyNode(organisation_id=org.id, ext_id=STORE, type="data_store", name=f"E2E Ledger {RUN}", props={"department": DEPT}))
        s.add(CompanyNode(organisation_id=org.id, ext_id=AG_NODE, type="agent", name=ASTRA_AGENT, props={"department": DEPT, "agent_key": ASTRA_AGENT}))
        s.commit()
    d = S["engineer"].post("/api/designs", json={"name": ASTRA_AGENT, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": astra_doc(False)})
    assert d.status_code == 201, d.text
    S["astra_design"], S["astra_version"] = d.json()["design_key"], d.json()["version"]


@step("ASTRA: the gate blocks the unguarded design, names what to fix, and adding the controls moves it to review")
def s_astra_assess(base):
    need("astra_design")
    a = astra_controls(base)
    assert a["verdict"] == "BLOCKED" and a["paths"] and a["paths"][0]["department"] == f"E2E Finance {RUN}", a["verdict"]
    assert {s["kind"] for s in a["suggestions"]} >= {"iso", "hitl"} and all(s["why"] for s in a["suggestions"])
    r = S["engineer"].put(f"/api/designs/{S['astra_design']}", json={"name": ASTRA_AGENT, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": astra_doc(True), "version": S["astra_version"]})
    assert r.status_code == 200, r.text
    after = astra_controls(base)
    assert after["verdict"] == "REQUIRES_REVIEW" and {c["status"] for c in after["paths"][0]["controls"]} <= {"UNV", "NA"}, after["verdict"]
    assert S["auditor"].get(f"/api/agents/designs/{S['astra_design']}/assessment").status_code == 200, "anyone who can read can read the assessment"


@step("ASTRA: impact and tolerance are declared by one person and ratified by another; the gate then approves")
def s_astra_risk(base):
    need("astra_design")
    for kind, path, body in (("tolerance", "/api/risk/tolerances", {"department_ext": DEPT, "tolerance": 4, "rationale": "e2e: the department accepts up to tier 4."}),
                             ("asset", "/api/risk/assets", {"asset_ext": STORE, "tier": 2, "rationale": "e2e: a low-impact store."})):
        made = S["compliance"].post(path, json=body)
        assert made.status_code == 201, made.text
        assert S["compliance"].post(f"/api/risk/proposals/{kind}/{made.json()['id']}/ratify", json={}).status_code in (403, 409, 422), "the proposer cannot ratify their own declaration"
        assert S["engineer"].post(f"/api/risk/proposals/{kind}/{made.json()['id']}/ratify", json={}).status_code == 403, "an engineer cannot ratify"
        done = S["admin"].post(f"/api/risk/proposals/{kind}/{made.json()['id']}/ratify", json={})
        assert done.status_code == 200, done.text
    assert astra_controls(base)["verdict"] == "APPROVED"


@step("ASTRA: the assessment is recorded, a different person accepts the baseline, and the contract is signed (Ed25519, a key separate from the platform's secret)")
def s_astra_sign(base):
    need("astra_design")
    st = S["admin"].get("/api/astra/signing").json()
    if not st["configured"]:
        raise Skip("ASTRA_SIGNING_KEY is not set on the backend, so nothing can be signed (docker compose run --rm backend python astra_signing.py generate <key_id>)")
    assert set(st) <= {"configured", "key_id", "retired", "error"}, "the signing status carries ids and a flag, never key material"
    rec = S["compliance"].post(f"/api/agents/designs/{S['astra_design']}/assessments")
    assert rec.status_code == 201 and rec.json()["verdict"] == "APPROVED", rec.text
    assert S["compliance"].post(f"/api/agents/designs/{S['astra_design']}/baseline", json={}).status_code == 403, "the person who recorded the assessment cannot accept it"
    assert S["engineer"].post(f"/api/agents/designs/{S['astra_design']}/baseline", json={}).status_code == 403
    assert S["admin"].post(f"/api/agents/designs/{S['astra_design']}/sign", json={}).status_code == 409, "nothing is signed without an accepted baseline"
    assert S["admin"].post(f"/api/agents/designs/{S['astra_design']}/baseline", json={"note": "e2e"}).status_code == 201
    assert S["engineer"].post(f"/api/agents/designs/{S['astra_design']}/sign", json={}).status_code == 403
    signed = S["compliance"].post(f"/api/agents/designs/{S['astra_design']}/sign", json={})
    assert signed.status_code == 201, signed.text
    c = signed.json()
    assert c["status"] == "ACTIVE" and c["signed_by"] == PEOPLE["compliance"] and c["document"]["agent"]["signature"].startswith("ed25519:") and c["probe"].get("run"), c.get("probe")
    S["signed"] = c
    v = S["auditor"].get(f"/api/astra/contracts/{c['id']}/verify").json()
    assert v["valid"] and v["reasons"] == [], v


@step("ASTRA: a collector key reports a running agent; the verdict is conforming, then a divergence from the signed contract lowers it, and what cannot be judged is never read as fine")
def s_astra_run(base):
    need("signed")
    key = S["admin"].post("/api/keys", json={"name": f"e2e collector {RUN} astra", "role": "collector"}).json()
    col = httpx.Client(base_url=base, timeout=60, headers={"Authorization": f"Bearer {key['key']}"})
    def send(**ev):
        r = col.post("/api/runtime/events", json={"agent": ASTRA_AGENT, "events": [ev]})
        assert r.status_code == 202, r.text
        return r.json()["results"][0]
    def verdict():
        return S["auditor"].get(f"/api/runtime/verdicts?agent={ASTRA_AGENT}").json()["agents"][0]
    assert verdict()["verdict"] == "APPROVED" and verdict()["contract"]["valid"]
    assert send(type="tool_call", name="lookup")["verdict"] == "CONFORMING"
    assert send(type="tool_call", name="refund")["verdict"] == "UNVERIFIED", "a write tool that needs a person, with no word on a confirmation"
    div = send(type="tool_call", name="shell")
    assert div["verdict"] == "DIVERGENT" and div["finding_key"]
    v = verdict()
    assert v["verdict"] == "REQUIRES_REVIEW" and any(m["kind"] == "least" and m["to"] == "VIO" for m in v["controls_moved"]), v
    assert v["posture"]["recommended"] in ("observe", "flag", "block", "halt") and v["findings"]["open"] == 1
    f = [x for x in S["auditor"].get("/api/findings").json() if x["finding_key"] == div["finding_key"]][0]
    assert f["class_code"] == "DVG-TOOL-01" and f["detection_basis"] == "policy" and f["asi_signal"] == ["ASI02"]
    assert col.get("/api/agents").status_code == 403 and col.post("/api/astra/probe/run", json={"design_key": S["astra_design"]}).status_code == 403, "a collector key can do nothing but report"
    col.close()
    S["divergence"] = div["finding_key"]


@step("ASTRA: the Probe plants a defect for every class, the checks catch them, and the admission check admits this version of the design")
def s_astra_probe(base):
    need("signed")
    run = S["security"].post("/api/astra/probe/run", json={"design_key": S["astra_design"]})
    assert run.status_code == 201, run.text
    r = run.json()
    assert r["summary"]["scenarios"] == 22 and r["summary"]["missed"] == 0 and r["current"], r["summary"]
    adm = S["auditor"].get(f"/api/astra/probe/admission?design_key={S['astra_design']}").json()
    assert adm["admit"] is True, adm
    prop = S["engineer"].post(f"/api/astra/probe/scenarios/from-finding/{S['divergence']}")
    assert prop.status_code == 201 and prop.json()["status"] == "PROPOSED"
    assert S["engineer"].post(f"/api/astra/probe/scenarios/{prop.json()['id']}/approve", json={}).status_code == 403, "an incident joins the standing suite only by a person's approval"
    assert S["security"].post(f"/api/astra/probe/scenarios/{prop.json()['id']}/approve", json={}).status_code == 403, "the security role does not sign off either"
    assert S["admin"].post(f"/api/astra/probe/scenarios/{prop.json()['id']}/approve", json={}).status_code == 200


@step("ASTRA: coverage is per OWASP row from the contract, the Probe and real events; the dossier resolves every claim; the security view lists what is wrong")
def s_astra_assurance(base):
    need("signed")
    cov = S["auditor"].get("/api/astra/coverage").json()
    assert cov["agents_in_scope"] >= 1 and len(cov["rows"]) == 10 and next(r for r in cov["rows"] if r["code"] == "ASI08")["classes"] == []
    d = S["auditor"].get(f"/api/astra/assurance/agent/{ASTRA_AGENT}").json()
    assert d["contract"]["id"] == S["signed"]["id"] and d["contract"]["valid_now"] and [c["row"] for c in d["claims"]] == [f"ASI{i:02d}" for i in range(1, 11)]
    assert d["unmapped_rows"] and d["gaps"] and d["limits"] and d["probe"]["current"]
    sec = S["security"].get("/api/astra/security")
    assert sec.status_code == 200 and sec.json()["findings"]["open"] >= 1 and sec.json()["contracts"]["signed_agents"] >= 1
    assert S["security"].post("/api/astra/regwatch/review", json={"clause": "EU-AI-Act:Art.14", "note": "e2e review."}).status_code == 403
    assert S["engineer"].get("/api/astra/learned/detectors").status_code == 200


@step("ASTRA: the evidence pack carries the ASTRA section, and the signed contract, the Probe run and the findings it names are the ones on record")
def s_astra_pack(base):
    need("signed")
    p = S["compliance"].post("/api/packs", json={"template": "ASSURANCE", "period": "30d"})
    assert p.status_code == 201, p.text
    pk = p.json()
    sec = pk["content"]["astra"]
    assert sec["agents_with_signed_contract"] >= 1 and sec["divergence_classes"]["total"] == 22 and sec["limits"] and sec["rows_detail"]
    mine = next(a for a in sec["agents"] if a["agent"] == ASTRA_AGENT)
    assert mine["contract"]["id"] == S["signed"]["id"] and mine["contract"]["hash"] == S["signed"]["contract_hash"] and mine["probe"]["current"] and mine["assessments"] >= 1
    short = S["compliance"].post("/api/packs", json={"template": "TRUST", "period": "all", "frameworks": ["OWASP_AGENTIC"]}).json()
    assert ASTRA_AGENT not in str(short["content"]), "the short form names no agent"
    for x in (pk, short):
        v = S["auditor"].get(f"/api/packs/{x['pack_key']}/verify").json()
        assert v["ok"] and v["chain_ok"], v


@step("ASTRA: the audit log names who recorded, accepted, signed, probed and approved, and refused the attempts that were not allowed")
def s_astra_audit(base):
    need("signed")
    events = S["auditor"].get("/api/audit?limit=1000").json()
    seen = {(e["actor"], e["action"], e["outcome"]) for e in events}
    d = S["astra_design"]
    tpl = "POST /api/agents/designs/{design_key}"                           # an allowed request is logged by its route, a refused one by the path it asked for
    for who, action, outcome in ((PEOPLE["compliance"], tpl + "/assessments", "ok"), (PEOPLE["admin"], tpl + "/baseline", "ok"), (PEOPLE["compliance"], tpl + "/sign", "ok"),
                                 (PEOPLE["engineer"], f"POST /api/agents/designs/{d}/sign", "denied"), (PEOPLE["security"], "POST /api/astra/probe/run", "ok"),
                                 (PEOPLE["compliance"], tpl + "/baseline", "denied")):
        assert (who, action, outcome) in seen, (who, action, outcome)
    explicit = {e["action"] for e in events}
    assert {"astra.assess", "astra.baseline", "astra.sign", "astra.probe"} <= explicit, explicit
    assert all(S["signed"]["signature"] not in str(e["detail"]) for e in events), "a signature is not copied into the audit log"
    assert all("ASTRA_SIGNING_KEY" not in str(e["detail"]) for e in events)
    v = S["auditor"].get("/api/audit/verify").json()
    assert v["ok"] and v["head_hash"]

# ── Running it ──────────────────────────────────────────────────────────────

def setup():
    with SessionLocal() as s:
        org = s.query(Organisation).filter_by(slug=DEFAULT_ORG_SLUG).one()
        S["start_seq"] = s.query(AuditEvent.seq).order_by(AuditEvent.seq.desc()).limit(1).scalar() or 0
        for role, name in PEOPLE.items():
            s.add(User(organisation_id=org.id, email=f"e2e-{role}-{RUN}@example.test", full_name=name, role=role, password_hash=hash_password(PASSWORD)))
        s.commit()


def teardown():
    with SessionLocal() as s:
        for model in (EvidencePack, DriftItem, Finding, CoverageAssignment):
            for x in s.query(model).all():
                s.delete(x)
        s.commit()
        for c in s.query(Contract).filter(Contract.deployment_id == AGENT).all():
            s.delete(c)
        for c in s.query(Contract).filter(Contract.deployment_id.like(f"%{RUN}")).all():
            s.delete(c)
        from db.models import (ApiKey, AstraAssessment, AstraBaseline, AstraSignedContract, CompanyNode, ProbeResult, ProbeRun, ProbeScenario, RegulationReview, RiskAssetTier,
                               RiskDepartmentTolerance, RiskPosture, RuntimeEvent)
        s.query(RuntimeEvent).filter(RuntimeEvent.agent_key.like(f"%{RUN}")).delete(synchronize_session=False)
        s.query(ApiKey).filter(ApiKey.name.like(f"e2e collector {RUN}%")).delete(synchronize_session=False)
        s.query(ProbeScenario).filter(ProbeScenario.agent_key == ASTRA_AGENT).delete(synchronize_session=False)
        for r in s.query(ProbeRun).filter(ProbeRun.agent_key == ASTRA_AGENT).all():
            s.query(ProbeResult).filter(ProbeResult.run_id == r.id).delete(synchronize_session=False)
            s.delete(r)
        s.query(AstraSignedContract).filter(AstraSignedContract.agent_key == ASTRA_AGENT).delete(synchronize_session=False)
        s.query(AstraBaseline).filter(AstraBaseline.design_key == S.get("astra_design", "-")).delete(synchronize_session=False)
        s.query(AstraAssessment).filter(AstraAssessment.design_key == S.get("astra_design", "-")).delete(synchronize_session=False)
        s.query(RegulationReview).filter(RegulationReview.reviewed_by.in_(list(PEOPLE.values()))).delete(synchronize_session=False)
        for m in (RiskAssetTier, RiskDepartmentTolerance, RiskPosture):
            s.query(m).delete()
        s.query(CompanyNode).filter(CompanyNode.ext_id.in_((DEPT, STORE, AG_NODE))).delete(synchronize_session=False)
        for a in s.query(Agent).filter(Agent.agent_key.like(f"%{RUN}")).all():
            s.delete(a)
        for a in s.query(Agent).filter(Agent.agent_key == AGENT).all():
            s.delete(a)
        for d in s.query(Design).filter(Design.name.like(f"%{RUN}%")).all():
            s.delete(d)
        for d in s.query(Design).filter(Design.name.in_((AGENT, ASTRA_AGENT))).all():
            s.delete(d)
        from db.models import Rule, DomainRule
        for r in s.query(Rule).filter(Rule.title.like(f"E2E no external email {RUN}%")).all():
            s.query(DomainRule).filter(DomainRule.rule_id == r.id).delete()
            s.delete(r)
        ids = [u.id for u in s.query(User).filter(User.email.like(f"e2e-%-{RUN}@example.test")).all()]
        s.query(UserSession).filter(UserSession.user_id.in_(ids)).delete(synchronize_session=False)
        s.query(User).filter(User.id.in_(ids)).delete(synchronize_session=False)
        s.query(AuditEvent).filter(AuditEvent.seq > S.get("start_seq", 0)).delete()
        s.commit()


def main():
    global ARGS
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://localhost:8765")
    p.add_argument("--with-ollama", action="store_true")
    ARGS = p.parse_args()
    require_scratch_database()
    setup()
    failed = skipped = 0
    started = time.time()
    try:
        for i, (title, fn) in enumerate(STEPS, 1):
            t = time.time()
            try:
                fn(ARGS.base)
                print(f"PASS  {i:2}. {title}  ({time.time() - t:.1f}s)")
            except Skip as why:
                skipped += 1
                print(f"SKIP  {i:2}. {title}  ({why})")
            except Exception as exc:                                  # a failed step leaves later ones without their inputs
                failed += 1
                print(f"FAIL  {i:2}. {title}\n        {type(exc).__name__}: {exc}")
                if isinstance(exc, (KeyError, httpx.HTTPError)) or title.startswith("Each role"):
                    break
    finally:
        teardown()
    print(f"\n{len(STEPS) - failed - skipped} passed, {failed} failed, {skipped} skipped in {time.time() - started:.0f}s; test data removed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
