"""
Tests for design_store.py through the real API and database.

    docker compose exec backend python -m tests.test_design_store
"""
import sys
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from compliance_schema import CompiledContract, DesignRiskAssessment, compute_contract_hash
from main import app
from tests._auth import authed_client

DOC = {"nodes": [{"id": "n1", "kind": "AI_MODEL", "x": 10, "y": 20, "name": "Triage model"}], "edges": [], "n": 2}


def contract(deployment_id="d-test"):
    c = CompiledContract(contract_id=str(uuid.uuid4()), deployment_id=deployment_id, domain="GENERAL", design_snapshot={"nodes": []},
                         risk_assessment=DesignRiskAssessment(deployment_id=deployment_id, domain="GENERAL"),
                         issued_at=datetime.now(timezone.utc), issued_by="test")
    c.contract_hash = compute_contract_hash(c)
    return c


def test_design_lifecycle_and_version_conflict():
    with authed_client() as api:
        r = api.post("/api/designs", json={"name": "  Test design  ", "domain": "GENERAL", "document": DOC})
        assert r.status_code == 201, r.text
        d = r.json()
        key = d["design_key"]
        try:
            assert d["name"] == "Test design" and d["version"] == 1 and d["document"]["nodes"][0]["name"] == "Triage model"
            assert any(x["design_key"] == key and x["node_count"] == 1 for x in api.get("/api/designs").json())
            saved = api.put(f"/api/designs/{key}", json={"name": "Renamed", "domain": "HEALTHCARE", "document": {**DOC, "n": 3}, "version": 1})
            assert saved.status_code == 200 and saved.json()["version"] == 2 and saved.json()["domain"] == "HEALTHCARE"
            stale = api.put(f"/api/designs/{key}", json={"name": "Other tab", "domain": "GENERAL", "document": DOC, "version": 1})
            assert stale.status_code == 409 and "changed elsewhere" in stale.json()["detail"]
            assert api.get(f"/api/designs/{key}").json()["name"] == "Renamed"           # the stale save changed nothing
            assert api.post("/api/designs", json={"name": "x", "domain": "OWASP_AGENTIC", "document": DOC}).status_code == 422   # an agent domain
            assert api.post("/api/designs", json={"name": "  ", "domain": "GENERAL", "document": DOC}).status_code == 422
            assert api.post("/api/designs", json={"name": "x", "domain": "NOPE", "document": DOC}).status_code == 422
        finally:
            assert api.delete(f"/api/designs/{key}").status_code == 204
        assert api.get(f"/api/designs/{key}").status_code == 404


def test_contract_import_verify_and_survives_design_deletion():
    with authed_client() as api:
        d = api.post("/api/designs", json={"name": "With contract", "domain": "GENERAL", "document": DOC}).json()
        c = contract(d["design_key"])
        r = api.post(f"/api/contracts/import?design={d['design_key']}", json=c.model_dump(mode="json"))
        assert r.status_code == 201, r.text
        try:
            assert api.post("/api/contracts/import", json=c.model_dump(mode="json")).status_code == 409           # no duplicates
            v = api.get(f"/api/contracts/{c.contract_id}/verify").json()
            assert v["ok"] and v["origin"] == "IMPORTED"
            assert any(x["contract_id"] == c.contract_id for x in api.get(f"/api/contracts?design={d['design_key']}").json())
            assert [x["contract_count"] for x in api.get("/api/designs").json() if x["design_key"] == d["design_key"]] == [1]
            api.delete(f"/api/designs/{d['design_key']}")
            assert any(x["contract_id"] == c.contract_id for x in api.get("/api/contracts").json())               # outlives its design
        finally:
            from db.models import Contract
            from db.session import SessionLocal
            with SessionLocal() as s:
                s.delete(s.query(Contract).filter_by(contract_id=c.contract_id).one())
                s.commit()


def test_tampered_contract_is_not_imported_and_a_stored_one_fails_verification():
    with authed_client() as api:
        bad = contract().model_dump(mode="json")
        bad["domain"] = "HEALTHCARE"                                                                            # content changed after hashing
        r = api.post("/api/contracts/import", json=bad)
        assert r.status_code == 422 and "hash" in r.json()["detail"]

        good = contract()
        assert api.post("/api/contracts/import", json=good.model_dump(mode="json")).status_code == 201
        from db.models import Contract
        from db.session import SessionLocal
        try:
            with SessionLocal() as s:
                row = s.query(Contract).filter_by(contract_id=good.contract_id).one()
                row.document = {**row.document, "issued_by": "someone else"}                                    # tampering in the database
                s.commit()
            assert api.get(f"/api/contracts/{good.contract_id}/verify").json()["ok"] is False
        finally:
            with SessionLocal() as s:
                s.delete(s.query(Contract).filter_by(contract_id=good.contract_id).one())
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
