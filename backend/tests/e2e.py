"""
End-to-end script (Task 9): drives the whole platform over HTTP, as four different people, from sign-in to evidence packs.

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

PASSWORD = "e2e-Password-" + uuid.uuid4().hex[:8]
RUN = uuid.uuid4().hex[:6]
PEOPLE = {"admin": "Ada Admin", "compliance": "Cora Compliance", "engineer": "Eli Engineer", "auditor": "Ava Auditor"}
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
            {"id": "a1", "type": "agent", "name": name, "p": {"owner": "Compliance lead", "auto": "approval"}, "primary": True},
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
    expect = {"admin": {"admin", "audit", "read", "signoff", "write"}, "compliance": {"audit", "read", "signoff", "write"}, "engineer": {"read", "write"}, "auditor": {"audit", "read"}}
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
    r = S["compliance"].post("/api/agents/ratify", json={"design_key": S["agent_design"], "reviewer": "Spoofed Name"})
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
        for a in s.query(Agent).filter(Agent.agent_key.like(f"%{RUN}")).all():
            s.delete(a)
        for a in s.query(Agent).filter(Agent.agent_key == AGENT).all():
            s.delete(a)
        for d in s.query(Design).filter(Design.name.like(f"%{RUN}%")).all():
            s.delete(d)
        for d in s.query(Design).filter(Design.name == AGENT).all():
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
