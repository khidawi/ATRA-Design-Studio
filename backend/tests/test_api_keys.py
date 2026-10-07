"""
Tests for API keys (Task 11): a pipeline calls the platform with a key, with limited power and a clear audit trail.

    docker compose exec backend python -m tests.test_api_keys
"""
import sys
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import auth
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup

NAME = "zz-test-key-agent"
MANIFEST = f"agent: {NAME}\nowner: Payments eng\ntools:\n  - name: stripe.payouts.create\n    access: write\n  - crm.orders.read\napi_key: never-read\n"


def keyed(key):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {key}"          # no cookie and no CSRF header: this is how a pipeline calls
    return c


def drop_keys():
    from db.models import ApiKey
    from db.session import SessionLocal
    with SessionLocal() as s:
        s.query(ApiKey).filter(ApiKey.name.like("zz-test%")).delete(synchronize_session=False)
        s.commit()


def test_no_keys_exist_until_an_admin_makes_one():
    from db.models import ApiKey
    from db.session import SessionLocal
    with SessionLocal() as s:
        assert s.query(ApiKey).filter(~ApiKey.name.like("zz-test%")).count() == 0           # nothing is seeded


def test_keys_are_created_shown_once_and_only_hashed():
    with authed_client("admin", "Alice Admin") as admin, authed_client("compliance", "Cora Compliance") as comp:
        try:
            assert comp.post("/api/keys", json={"name": "zz-test-no"}).status_code == 403 and comp.get("/api/keys").status_code == 403       # admin only
            r = admin.post("/api/keys", json={"name": "zz-test-ci pipeline", "role": "engineer", "expires_in_days": 90})
            assert r.status_code == 201, r.text
            made = r.json()
            assert made["key"].startswith("astra_" + made["prefix"] + "_") and len(made["key"]) > 40 and made["status"] == "active" and made["expires_at"]
            listed = admin.get("/api/keys").json()
            assert any(k["id"] == made["id"] for k in listed) and made["key"] not in str(listed) and all("key" not in k for k in listed)
            from db.models import ApiKey
            from db.session import SessionLocal
            with SessionLocal() as s:
                row = s.query(ApiKey).filter(ApiKey.id == made["id"]).one()
                assert row.key_hash == auth._token_hash(made["key"]) and made["key"] not in (row.key_hash, row.name, row.prefix)
            for bad in ({"name": "zz-test-x", "role": "compliance"}, {"name": "zz-test-x", "role": "admin"}, {"name": "ab"}, {"name": "zz-test-x", "expires_in_days": 0}):
                assert admin.post("/api/keys", json=bad).status_code == 422, bad
        finally:
            drop_keys()


def test_a_key_authenticates_with_limited_power_and_is_audited():
    with authed_client("admin", "Alice Admin") as admin:
        eng = admin.post("/api/keys", json={"name": "zz-test-eng key", "role": "engineer"}).json()
        aud = admin.post("/api/keys", json={"name": "zz-test-aud key", "role": "auditor"}).json()
        try:
            pipeline, reader = keyed(eng["key"]), keyed(aud["key"])
            me = pipeline.get("/api/auth/me").json()
            assert me["user"]["full_name"] == "API key: zz-test-eng key" and me["user"]["role"] == "engineer" and set(me["permissions"]) == {"read", "write"}
            assert pipeline.get("/api/agents").status_code == 200

            r = pipeline.post("/api/agents/register", json={"name": NAME})                     # a write works without a cookie or CSRF header
            assert r.status_code == 201, r.text
            assert pipeline.post("/api/agents/ratify", json={"design_key": "x"}).status_code == 403                    # a key cannot sign off
            for path in ("/api/users", "/api/keys", "/api/audit"):
                assert pipeline.get(path).status_code == 403, path
            assert pipeline.post("/api/keys", json={"name": "zz-test-escalate"}).status_code == 403                    # a key cannot mint keys

            assert reader.get("/api/agents").status_code == 200 and reader.get("/api/audit").status_code == 200
            assert reader.post("/api/agents/register", json={"name": "zz-test-key-2"}).status_code == 403

            events = admin.get("/api/audit?limit=50").json()
            assert any(e["actor"] == "API key: zz-test-eng key" and e["action"] == "POST /api/agents/register" and e["outcome"] == "ok" for e in events)
            assert any(e["actor"] == "API key: zz-test-eng key" and e["action"] == "POST /api/agents/ratify" and e["outcome"] == "denied" for e in events)
            assert all(eng["key"] not in str(e) for e in events)                                                          # the key is never logged
            used = [k for k in admin.get("/api/keys").json() if k["id"] == eng["id"]][0]
            assert used["last_used_at"] is not None
            x = TestClient(app)
            x.headers["X-API-Key"] = eng["key"]                                                                           # the other accepted header
            assert x.get("/api/agents").status_code == 200
        finally:
            drop_keys()
            cleanup(NAME, "zz-test-key-2")


def test_bad_revoked_and_expired_keys_are_refused():
    with authed_client("admin", "Alice Admin") as admin:
        k = admin.post("/api/keys", json={"name": "zz-test-short life"}).json()
        try:
            assert keyed("astra_deadbeef_not-a-real-key").get("/api/agents").status_code == 401
            assert keyed("not-even-prefixed").get("/api/agents").status_code == 401
            assert "not valid" in keyed("astra_deadbeef_x").get("/api/agents").json()["detail"]
            assert keyed(k["key"]).get("/api/agents").status_code == 200
            assert admin.post(f"/api/keys/{k['id']}/revoke").json()["status"] == "revoked"
            assert keyed(k["key"]).get("/api/agents").status_code == 401 and admin.post(f"/api/keys/{k['id']}/revoke").status_code == 200   # idempotent
            e = admin.post("/api/keys", json={"name": "zz-test-expiring", "expires_in_days": 1}).json()
            from db.models import ApiKey
            from db.session import SessionLocal
            with SessionLocal() as s:
                s.query(ApiKey).filter(ApiKey.id == e["id"]).one().expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
                s.commit()
            assert keyed(e["key"]).get("/api/agents").status_code == 401
            assert [x["status"] for x in admin.get("/api/keys").json() if x["id"] == e["id"]] == ["expired"]
            assert admin.post("/api/keys/00000000-0000-0000-0000-000000000000/revoke").status_code == 404
        finally:
            drop_keys()


def test_a_pipeline_imports_a_raw_file():
    with authed_client("admin", "Alice Admin") as admin:
        k = admin.post("/api/keys", json={"name": "zz-test-import key"}).json()
        try:
            ci = keyed(k["key"])
            pv = ci.post("/api/agents/import/file-preview?filename=agent.model.yaml", content=MANIFEST, headers={"Content-Type": "application/yaml"})
            assert pv.status_code == 200 and pv.json()["agent_name"] == NAME and pv.json()["existing"]["will"] == "create"
            assert any("api_key" in x for x in pv.json()["ignored"])
            assert ci.get("/api/agents").json() == [] or NAME not in [a["agent_key"] for a in ci.get("/api/agents").json()]       # a preview writes nothing
            r = ci.post("/api/agents/import/file?filename=agent.model.yaml", content=MANIFEST, headers={"Content-Type": "application/yaml"})
            assert r.status_code == 201, r.text
            assert r.json()["outcome"] == "created" and r.json()["agent"]["status"] == "TO_RATIFY"
            doc = ci.get(f"/api/designs/{r.json()['design_key']}").json()["document"]
            assert doc["provenance"]["imported_by"] == "API key: zz-test-import key" and "never-read" not in str(doc)
            assert ci.post("/api/agents/import/file", content="", headers={"Content-Type": "text/plain"}).status_code == 422
            assert ci.post("/api/agents/import/file", content=b"\xff\xfe\x00bad", headers={"Content-Type": "text/plain"}).status_code == 422
            assert ci.post("/api/agents/import/file", content="hello: world").status_code == 422
        finally:
            from db.models import DriftItem
            from db.session import SessionLocal
            with SessionLocal() as s:
                for x in s.query(DriftItem).all():
                    s.delete(x)
                s.commit()
            drop_keys()
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
