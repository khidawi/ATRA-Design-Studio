"""
Tests for agent_import.py (Task 10): a JSON or YAML definition file becomes a proposed Secure Tropos model.

    docker compose exec backend python -m tests.test_agent_import
"""
import json
import sys

import agent_import as ai
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

NL = chr(10)
NAME = "zz-test-import-agent"
MANIFEST = f"""agent: {NAME}
owner: Payments eng
framework: LangGraph
autonomy: acts_with_approval
goal: Pay approved supplier invoices
inputs:
  - name: supplier-invoices
    untrusted: true
tools:
  - name: erp.invoices.read
    access: read
  - name: stripe.payouts.create
    access: write
mcp_servers:
  - name: mcp://erp
memory:
  - name: case-memory
data:
  - billing-store
delegates_to:
  - notify-agent
human_approval:
  - finance-approval
guardrails:
  - name: prompt-injection-filter
constraints:
  - name: retention-30d
api_key: should-never-be-read
"""


def by_type(c, t):
    return [n for n in c.nodes if n["type"] == t]


def test_manifest_becomes_the_studio_model():
    c = ai.convert(MANIFEST)
    assert c.format == "astra" and c.agent_name == NAME and c.owner == "Payments eng" and c.autonomy == "approval"
    primary = [n for n in c.nodes if n["primary"]]
    assert len(primary) == 1 and primary[0]["p"] == {"owner": "Payments eng", "auto": "approval"}
    tools = {n["name"]: n["p"]["write"] for n in by_type(c, "tool")}
    assert tools == {"erp.invoices.read": False, "stripe.payouts.create": True}
    assert by_type(c, "mcp")[0]["p"] == {"signed": False}                                    # a file can never attest a signature
    assert by_type(c, "input")[0]["p"] == {"untrusted": True} and by_type(c, "memory")[0]["p"] == {"long": False}
    assert by_type(c, "guardrail")[0]["p"] == {"kind": "injection"} and by_type(c, "constraint")[0]["p"] == {"kind": "retention"}
    rel = {(e["label"]) for e in c.edges}
    assert {"uses", "feeds", "pursues", "connects", "stores", "reads", "delegates", "gates", "limits", "restricts"} <= rel
    ids = {n["id"] for n in c.nodes}
    assert all(e["from"] in ids and e["to"] in ids for e in c.edges) and len(ids) == len(c.nodes)
    gate = [e for e in c.edges if e["label"] == "gates"][0]
    assert [n for n in c.nodes if n["id"] == gate["to"]][0]["name"] == "stripe.payouts.create"      # the approval gates the write tool
    restrict = [e for e in c.edges if e["label"] == "restricts"][0]
    assert [n for n in c.nodes if n["id"] == restrict["to"]][0]["type"] == "memory"                  # a retention limit restricts memory
    assert any("api_key" in x and "secret" in x for x in c.ignored)
    assert "should-never-be-read" not in json.dumps(c.model_dump())


def test_inference_is_reported_not_hidden():
    c = ai.convert("agent: x-agent\ntools:\n  - send_email\n  - list_orders\ninputs:\n  - support-inbox\n")
    tools = {n["name"]: n["p"]["write"] for n in by_type(c, "tool")}
    assert tools == {"send_email": True, "list_orders": False}
    assert any("send_email" in x and "write-capable" in x for x in c.inferred) and any("support-inbox" in x and "untrusted" in x for x in c.inferred)
    assert any("autonomy" in x for x in c.inferred) and c.autonomy == "approval"
    odd = ai.convert("agent: x-agent\nguardrails:\n  - mystery-control\n")
    assert by_type(odd, "guardrail")[0]["p"]["kind"] == "other" and any("mystery-control" in w for w in odd.warnings)


def test_other_formats():
    mcp = ai.convert(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["x"], "env": {"TOKEN": "s3cret"}}, "gh": {"url": "https://x.test", "headers": {"Authorization": "Bearer abc"}}}}))
    assert mcp.format == "mcp-config" and [n["name"] for n in by_type(mcp, "mcp")] == ["mcp://fs", "mcp://gh"] and all(not n["p"]["signed"] for n in by_type(mcp, "mcp"))
    assert "s3cret" not in json.dumps(mcp.model_dump()) and "abc" not in json.dumps(mcp.model_dump()) and any("never read" in x for x in mcp.ignored)
    crew = ai.convert(ai.EXAMPLES["crewai"][1])
    assert crew.format == "crewai" and crew.agent_name == "researcher" and crew.agents_found == ["researcher", "writer"]
    assert [n["name"] for n in by_type(crew, "agent")] == ["researcher", "writer"] and any(e["label"] == "delegates" for e in crew.edges)
    assert {n["name"]: n["p"]["write"] for n in by_type(crew, "tool")} == {"web_search": False, "read_file": False}
    writer = ai.convert(ai.EXAMPLES["crewai"][1], primary="writer")
    assert writer.agent_name == "writer" and by_type(writer, "tool")[0]["p"]["write"] is True and any("separate agents" in x for x in writer.ignored)
    card = ai.convert(ai.EXAMPLES["agent-card"][1])
    assert card.format == "agent-card" and card.agent_name == "invoice-agent" and card.owner == "Finance ops eng" and len(by_type(card, "tool")) == 2
    lg = ai.convert(ai.EXAMPLES["langgraph"][1])
    assert lg.format == "langgraph" and lg.agent_name == "refund_agent" and any("not their tools" in w for w in lg.warnings) and not any(".env" in x and "read)" not in x for x in lg.ignored)
    for fmt, (_, text) in ai.EXAMPLES.items():
        assert ai.convert(text, fmt).format == fmt                                              # every shipped example converts


def test_openai_agents_sdk_definition():
    c = ai.convert(ai.EXAMPLES["openai-agents"][1])
    assert c.format == "openai-agents" and c.agent_name == "Refund agent" and c.framework == "OpenAI Agents SDK" and c.owner == "Payments eng"
    tools = {n["name"]: n["p"]["write"] for n in by_type(c, "tool")}
    assert tools == {"lookup_order": False, "issue_refund": True, "web_search": False, "file_search": False}
    web = [n for n in by_type(c, "input") if n["name"] == "web-search-results"]
    assert web and web[0]["p"] == {"untrusted": True}                                                  # web results are untrusted input
    assert [n["name"] for n in by_type(c, "data")] == ["vector-store:vs_policy_docs"]
    mcp = by_type(c, "mcp")
    assert [n["name"] for n in mcp] == ["mcp://orders"] and mcp[0]["p"] == {"signed": False}
    assert [n["name"] for n in by_type(c, "approval")] == ["orders-tool-approval"]                       # require_approval: always
    assert [n["name"] for n in by_type(c, "agent") if not n["primary"]] == ["Notification agent"] and any(e["label"] == "delegates" for e in c.edges)
    assert {n["name"]: n["p"]["kind"] for n in by_type(c, "guardrail")} == {"prompt_injection_check": "injection", "pii_redaction": "other"}
    assert c.goal if hasattr(c, "goal") else True
    primary = [n for n in c.nodes if n["primary"]][0]
    assert primary["p"]["auto"] == "approval"
    dump = json.dumps(c.model_dump())
    assert "never-read" not in dump and "example.test" not in dump and "Check the order first" not in dump          # no key, no address, no prompt text
    assert any("api_key" in x and "secret" in x for x in c.ignored) and any("prompt" in x for x in c.inferred)
    # a hosted tool nobody asked for, and a code tool
    risky = ai.convert(NL.join(["name: Coder", "instructions: Write code.", "tools:", "  - type: code_interpreter", "  - type: teleport"]) + NL)
    assert {n["name"]: n["p"]["write"] for n in by_type(risky, "tool")} == {"code_interpreter": True} and any("teleport" in w for w in risky.warnings)
    # JSON works too, a list of agents lets you choose, and the Chat Completions tool shape is read
    many = json.dumps({"agents": [{"name": "Triage", "instructions": "Route requests.", "handoffs": ["Billing"], "tools": [{"type": "function", "function": {"name": "send_email"}}]},
                                  {"name": "Billing", "instructions": "Handle billing."}]})
    t = ai.convert(many)
    assert t.format == "openai-agents" and t.agents_found == ["Triage", "Billing"] and {n["name"]: n["p"]["write"] for n in by_type(t, "tool")} == {"send_email": True}
    assert ai.convert(many, primary="Billing").agent_name == "Billing"
    assert ai.detect({"name": "x-agent", "tools": []}) == "astra"                                      # no instructions: not an SDK agent


def test_bad_files_are_refused_with_a_reason():
    cases = [("", "empty"), ("{not json", "JSON could not be read"), ("a: [1, 2", "YAML could not be read"), ("- 1\n- 2\n", "object"), ("hello: world\n", "not in a format"),
             ("a: &x 1\nagent: *x\n", "anchors"), ("x" * 600_000, "larger than"), ("agent: ' '\n", "needs a name"), ("agent: '!!'\n", "letters or digits"),
             ("agent: a-agent\ntools:\n" + "".join(f"  - t{i}\n" for i in range(70)), "at most 60")]
    for text, why in cases:
        try:
            ai.convert(text)
        except ai.ImportProblem as exc:
            assert why.lower() in str(exc).lower(), (why, str(exc))
            continue
        raise AssertionError(f"expected a refusal: {why}")
    try:
        ai.convert("agent: x-agent\n", "crewai")
    except ai.ImportProblem as exc:
        assert "does not match" in str(exc) or "object" in str(exc) or "name" in str(exc)


def test_preview_writes_nothing_and_import_creates_a_draft():
    with authed_client("engineer", "Eli Engineer") as eng, authed_client("auditor", "Ada Auditor") as aud, authed_client("compliance", "Cora Compliance") as comp:
        formats = aud.get("/api/agents/import/formats").json()
        assert {f["id"] for f in formats} == set(ai.FORMATS) and all(f["example"] for f in formats)
        try:
            p = aud.post("/api/agents/import/preview", json={"content": MANIFEST, "filename": "agent.model.yaml"})
            assert p.status_code == 200, p.text                                             # a computation: an auditor may preview
            body = p.json()
            assert body["agent_name"] == NAME and body["existing"]["will"] == "create" and body["analysis"]["rows"] and body["sha256"]
            assert eng.get("/api/agents").json() == [] or NAME not in [a["agent_key"] for a in eng.get("/api/agents").json()]
            assert aud.post("/api/agents/import", json={"content": MANIFEST}).status_code == 403
            assert eng.post("/api/agents/import", json={"content": "nope: 1"}).status_code == 422

            r = eng.post("/api/agents/import", json={"content": MANIFEST, "filename": "agent.model.yaml"})
            assert r.status_code == 201, r.text
            out = r.json()
            assert out["outcome"] == "created" and out["agent"]["status"] == "TO_RATIFY" and out["agent"]["owner"] == "Payments eng" and out["agent"]["tools_count"] == 3
            design = eng.get(f"/api/designs/{out['design_key']}").json()
            prov = design["document"]["provenance"]
            assert design["subject"] == "AGENT" and prov["format"] == "astra" and prov["imported_by"] == "Eli Engineer" and prov["sha256"] == body["sha256"]
            assert "content" not in prov and "should-never-be-read" not in json.dumps(design)           # only the hash is kept, never the file
            assert any(n["primary"] and n["name"] == NAME for n in design["document"]["nodes"])

            again = eng.post("/api/agents/import", json={"content": MANIFEST.replace("Pay approved", "Pay all approved"), "filename": "agent.model.yaml"}).json()
            assert again["outcome"] == "updated" and again["design_key"] == out["design_key"]
            assert eng.get(f"/api/designs/{out['design_key']}").json()["version"] == design["version"] + 1

            # Ratified, a new file never overwrites: it waits for review as drift.
            req = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Cora Compliance"}}
            cur = comp.get(f"/api/designs/{out['design_key']}").json()
            doc = {**cur["document"], "profile": "healthcare", "req": req}
            assert comp.put(f"/api/designs/{out['design_key']}", json={"name": NAME, "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc, "version": cur["version"]}).status_code == 200
            rat = comp.post("/api/agents/ratify", json={"design_key": out["design_key"]})
            assert rat.status_code == 200, rat.text
            wider = MANIFEST + "  - name: ehr.records.write\n    access: write\n"
            wider = MANIFEST.replace("mcp_servers:", "  - name: payments.transfer.create\n    access: write\nmcp_servers:")
            pv = eng.post("/api/agents/import/preview", json={"content": wider}).json()
            assert pv["existing"]["will"] == "drift" and pv["existing"]["contract_version"] == "1.0.0"
            d = eng.post("/api/agents/import", json={"content": wider, "filename": "agent.model.yaml"}).json()
            assert d["outcome"] == "drift" and d["drift_id"]
            item = [x for x in eng.get("/api/drift").json() if x["id"] == d["drift_id"]][0]
            assert item["source"] == "IMPORT" and item["kind"] == "Widening" and "agent.model.yaml" in item["source_label"] and any("payments.transfer.create" in c["text"] for c in item["changes"])
            assert [r["status"] for r in eng.get(f"/api/contract-records?object_type=AGENT&deployment={NAME}").json()] == ["ACTIVE"]      # nothing was overwritten
            ok = comp.post(f"/api/drift/{d['drift_id']}/decide", json={"decision": "approve"})
            assert ok.status_code == 200 and ok.json()["new_contract_id"]
        finally:
            from db.models import DriftItem
            from db.session import SessionLocal
            with SessionLocal() as s:
                for x in s.query(DriftItem).all():
                    s.delete(x)
                s.commit()
            cleanup(NAME)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for n, f in tests:
        try:
            f()
            print("PASS ", n)
        except Exception as exc:
            failed += 1
            print("FAIL ", n, repr(exc))
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
