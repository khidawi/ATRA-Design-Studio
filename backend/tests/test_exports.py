"""
Tests for exports.py: every document the platform offers is produced, correctly typed, and permission-checked.

    docker compose exec backend python -m tests.test_exports
"""
import csv
import io
import sys

import exports
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc

KEY = "zz-test-patient-agent"
REQ = {"dpia": {"status": "Covered", "evidence": "DPIA report DOC-9", "signed_off_by": "Compliance lead"}}


def is_pdf(r, name_part):
    assert r.status_code == 200, (r.status_code, r.text[:200])
    assert r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF-") and r.content.rstrip().endswith(b"%%EOF") and len(r.content) > 1500
    assert "attachment" in r.headers["content-disposition"] and name_part in r.headers["content-disposition"]


def test_text_cleaning_never_prints_boxes():
    assert exports.clean("a → b — c ‘d’ φ ✓") == "a -> b - c 'd' phi ok"
    assert exports.clean("café · x") == "café · x"                       # Latin-1 characters are kept
    assert exports.clean("中") == "?" and exports.clean(None) == ""
    assert exports.esc("<b>&") == "&lt;b&gt;&amp;"
    assert exports.safe_name("My agent / v1!") == "My-agent-v1"


def test_every_document_is_produced():
    with authed_client() as api:
        d = api.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=REQ)}).json()
        c = api.post("/api/agents/ratify", json={"design_key": d["design_key"]}).json()["contract"]
        api.post("/api/agents/register", json={"name": "zz-test-sandbox"})
        f = api.post("/api/findings/simulate", json={"agent": KEY, "scenario": "write_tool_outside"}).json()["finding"]
        api.post(f"/api/findings/{f['finding_key']}/test")
        drift = api.post("/api/drift/simulate", json={"agent": KEY, "scenario": "add_unsigned_mcp"}).json()
        pack = api.post("/api/packs", json={"template": "ASSURANCE", "period": "30d"}).json()
        trust = api.post("/api/packs", json={"template": "TRUST", "period": "all", "frameworks": ["OWASP_AGENTIC"]}).json()
        try:
            is_pdf(api.get(f"/api/export/packs/{pack['pack_key']}.pdf"), "assurance-pack")
            is_pdf(api.get(f"/api/export/packs/{trust['pack_key']}.pdf"), "trust-report")
            pj = api.get(f"/api/export/packs/{pack['pack_key']}.json")
            assert pj.status_code == 200 and "attachment" in pj.headers["content-disposition"]
            body = pj.json()
            assert body["pack_hash"] == pack["pack_hash"] and body["content"]["schema"] == "astra.pack/1"

            is_pdf(api.get(f"/api/export/contracts/{c['contract_id']}.pdf"), "agent-contract")
            cj = api.get(f"/api/export/contracts/{c['contract_id']}.json")
            assert cj.json()["contract_hash"] == c["contract_hash"] and "contract-zz-test-patient-agent-v1.0.0.json" in cj.headers["content-disposition"]
            y = api.get(f"/api/export/contracts/{c['contract_id']}.yaml")
            assert y.status_code == 200 and y.text.startswith("# agent.contract.yaml") and "agent: zz-test-patient-agent" in y.text and "text/yaml" in y.headers["content-type"]

            is_pdf(api.get("/api/export/coverage.pdf"), "coverage-scorecard")
            assert api.get("/api/export/coverage.json").json()["agents_in_scope"] == 1
            is_pdf(api.get("/api/export/findings.pdf"), "findings-report")
            fc = api.get("/api/export/findings.csv")
            rows = list(csv.reader(io.StringIO(fc.text)))
            assert rows[0][0] == "finding" and rows[1][0] == f["finding_key"] and rows[1][4] == "High" and "text/csv" in fc.headers["content-type"]
            is_pdf(api.get(f"/api/export/drift/{drift['id']}.pdf"), "drift-zz-test-patient-agent")
            is_pdf(api.get("/api/export/audit.pdf"), "audit-log")
            ac = list(csv.reader(io.StringIO(api.get("/api/export/audit.csv").text)))
            assert ac[0][:3] == ["seq", "at", "actor"] and any(r[4] == "POST /api/agents/ratify" for r in ac[1:])
            assert api.get("/api/export/audit.json").json()["events"][-1]["payload"]["actor"] == "Compliance lead"

            for path in ("/api/export/packs/P-1.pdf", "/api/export/packs/nope.pdf", "/api/export/contracts/nope.pdf", "/api/export/contracts/nope.yaml", "/api/export/drift/not-a-uuid.pdf"):
                assert api.get(path).status_code == 404, path
        finally:
            from db.models import DriftItem, EvidencePack, Finding
            from db.session import SessionLocal
            with SessionLocal() as s:
                for model in (EvidencePack, DriftItem, Finding):
                    for x in s.query(model).all():
                        s.delete(x)
                s.commit()
            cleanup(KEY, "zz-test-sandbox")


def test_model_contract_pdf_and_permissions():
    from db.models import Contract
    from db.session import SessionLocal
    from tests.test_design_store import contract
    with authed_client() as admin, authed_client("auditor", "Ada Auditor") as aud, authed_client("engineer", "Eli Engineer") as eng:
        m = contract("d-zz-model")
        assert admin.post("/api/contracts/import", json=m.model_dump(mode="json")).status_code == 201
        try:
            is_pdf(admin.get(f"/api/export/contracts/{m.contract_id}.pdf"), "model-contract")
            assert admin.get(f"/api/export/contracts/{m.contract_id}.yaml").status_code == 409                            # models have no agent yaml
            is_pdf(aud.get(f"/api/export/contracts/{m.contract_id}.pdf"), "model-contract")                                # an auditor may export
            assert aud.get("/api/export/audit.csv").status_code == 200 and aud.get("/api/export/audit.pdf").status_code == 200
            assert eng.get("/api/export/audit.csv").status_code == 403 and eng.get("/api/export/audit.json").status_code == 403   # engineers cannot export the audit log
            assert eng.get("/api/export/coverage.pdf").status_code == 200
        finally:
            with SessionLocal() as s:
                s.query(Contract).filter(Contract.contract_id == m.contract_id).delete()
                s.commit()


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
