"""
Tests for auth.py and audit.py (Task 8): sign-in, roles, sign-offs that are the signed-in person's, and the audit chain.

    docker compose exec backend python -m tests.test_auth
"""
import sys

from fastapi.testclient import TestClient

import auth
from main import app
from tests._auth import authed_client
from tests.test_agent_registry import cleanup, doc


def test_password_hashing():
    h = auth.hash_password("correct horse battery")
    assert h.startswith("scrypt$") and "correct" not in h
    assert auth.verify_password("correct horse battery", h) and not auth.verify_password("wrong", h)
    assert auth.hash_password("correct horse battery") != h                                   # a fresh salt each time
    assert not auth.verify_password("x", "garbage")


def test_permission_table_defaults_to_protected():
    rp = auth.required_permission
    assert rp("GET", "/api/agents") == "read" and rp("GET", "/api/users") == "admin" and rp("GET", "/api/audit") == "audit"
    assert rp("POST", "/api/agents/register") == "write" and rp("POST", "/api/designs") == "write" and rp("PUT", "/api/designs/d-1") == "write"
    assert rp("POST", "/api/agents/ratify") == "signoff" and rp("POST", "/api/drift/abc/decide") == "signoff"
    assert rp("POST", "/api/contracts/abc/revoke") == "signoff" and rp("POST", "/api/designs/x/compile") == "signoff"
    assert rp("POST", "/api/packs") == "signoff" and rp("PUT", "/api/coverage/ASI08") == "signoff" and rp("POST", "/api/policies") == "signoff"
    assert rp("POST", "/api/ingestion/candidates/1/approve") == "signoff" and rp("PATCH", "/api/rules/R") == "signoff"
    assert rp("POST", "/api/users") == "admin" and rp("PATCH", "/api/organisation") == "admin"
    assert rp("POST", "/api/rcr/score") == "read" and rp("POST", "/api/designs/x/assess") == "read" and rp("POST", "/api/policies/test") == "read"
    assert rp("POST", "/api/some/new/endpoint") == "write"                                    # a new endpoint is protected by default
    assert auth.has("admin", "admin") and not auth.has("compliance", "admin") and auth.has("compliance", "signoff")
    assert not auth.has("engineer", "signoff") and not auth.has("auditor", "write") and auth.has("auditor", "audit") and not auth.has("engineer", "audit")


def test_core_endpoints_the_studio_calls_exist():
    # The agent drafting route once went missing and every draft failed with "Method Not Allowed".
    paths = app.openapi()["paths"]
    for method, path in (("post", "/api/agents/draft"), ("post", "/chat"), ("post", "/api/agents/analyse"), ("post", "/api/rcr/score"),
                         ("post", "/api/designs/import"), ("post", "/api/designs/{design_id}/assess"), ("post", "/api/designs/{design_id}/compile"),
                         ("post", "/api/agents/ratify"), ("get", "/api/agents"), ("post", "/api/findings/ingest"), ("post", "/api/packs"),
                         ("get", "/api/coverage"), ("get", "/api/overview"), ("get", "/api/audit/verify"), ("post", "/api/auth/login")):
        assert method in paths.get(path, {}), f"{method.upper()} {path} is missing"


def test_nothing_is_open_without_signing_in():
    with TestClient(app) as api:
        assert api.get("/health").status_code == 200
        for method, path in (("get", "/api/agents"), ("get", "/api/designs"), ("get", "/api/audit"), ("post", "/score"), ("get", "/api/packs"), ("get", "/api/users")):
            r = getattr(api, method)(path)
            assert r.status_code == 401, (path, r.status_code)
        assert api.get("/api/auth/me").status_code == 401
        assert isinstance(api.get("/api/auth/status").json()["needs_bootstrap"], bool)


def test_bootstrap_only_while_no_user_exists():
    with authed_client() as api:
        r = TestClient(app).post("/api/auth/bootstrap", json={"email": "x@example.test", "full_name": "Nobody", "password": "a-long-enough-password"})
        assert r.status_code == 409 and "already exists" in r.json()["detail"]
        assert api.get("/api/auth/status").json()["needs_bootstrap"] is False


def test_login_logout_and_lockout():
    with authed_client(password="a-good-password-1") as admin:
        email = admin.test_user["email"]
        anon = TestClient(app)
        bad = anon.post("/api/auth/login", json={"email": email, "password": "nope"})
        assert bad.status_code == 401 and "do not match" in bad.json()["detail"]
        assert anon.post("/api/auth/login", json={"email": "nobody@example.test", "password": "nope"}).status_code == 401      # same message
        ok = anon.post("/api/auth/login", json={"email": email.upper(), "password": "a-good-password-1"})
        assert ok.status_code == 200 and ok.json()["user"]["role"] == "admin" and "signoff" in ok.json()["permissions"]
        assert "httponly" in ok.headers["set-cookie"].lower() and "samesite=lax" in ok.headers["set-cookie"].lower()
        assert "a-good-password-1" not in str(ok.json())
        anon.headers[auth.CSRF_HEADER] = "1"
        assert anon.get("/api/auth/me").json()["user"]["email"] == email
        assert anon.get("/api/agents").status_code == 200
        assert anon.post("/api/auth/logout").status_code == 204
        assert anon.get("/api/agents").status_code == 401                                         # the session is dead, not just the cookie
        for _ in range(auth.MAX_FAILURES):
            anon.post("/api/auth/login", json={"email": email, "password": "wrong"})
        locked = anon.post("/api/auth/login", json={"email": email, "password": "a-good-password-1"})
        assert locked.status_code == 429 and "Too many" in locked.json()["detail"]                # even the right password waits


def test_csrf_header_is_required_for_writes():
    with authed_client() as api:
        del api.headers[auth.CSRF_HEADER]
        r = api.post("/api/agents/register", json={"name": "zz-test-csrf"})
        assert r.status_code == 403 and "request header" in r.json()["detail"]
        assert api.get("/api/agents").status_code == 200                                          # reads need no header


def test_roles_are_enforced():
    with authed_client("auditor", "Ada Auditor") as aud, authed_client("engineer", "Eli Engineer") as eng, authed_client("compliance", "Cora Compliance") as comp:
        assert aud.get("/api/agents").status_code == 200 and aud.get("/api/audit").status_code == 200
        r = aud.post("/api/agents/register", json={"name": "zz-test-aud"})
        assert r.status_code == 403 and "auditor" in r.json()["detail"]
        assert aud.post("/api/rcr/score", json={"profile": "payments", "graph": {"nodes": [], "edges": []}}).status_code == 200      # a computation, not a change
        assert aud.get("/api/users").status_code == 403

        assert eng.get("/api/audit").status_code == 403
        ok = eng.post("/api/agents/register", json={"name": "zz-test-eng"})
        assert ok.status_code == 201
        try:
            assert eng.post("/api/agents/ratify", json={"design_key": "d-none"}).status_code == 403                                   # cannot sign off
            assert eng.post("/api/packs", json={"template": "TRUST"}).status_code == 403
            assert comp.post("/api/agents/ratify", json={"design_key": "d-none"}).status_code == 404                                  # allowed in, then not found
            assert comp.get("/api/users").status_code == 403 and comp.post("/api/users", json={}).status_code == 403
        finally:
            cleanup("zz-test-eng")


def test_sign_offs_are_the_signed_in_persons_own():
    req = {"dpia": {"status": "Covered", "evidence": "DPIA report", "signed_off_by": ""}}
    with authed_client("engineer", "Eli Engineer") as eng, authed_client("compliance", "Cora Compliance") as comp:
        d = eng.post("/api/designs", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc(req=req)}).json()
        key = d["design_key"]
        try:
            def save(client, signer):
                cur = client.get(f"/api/designs/{key}").json()
                body = doc(req={"dpia": {**req["dpia"], "signed_off_by": signer}})
                return client.put(f"/api/designs/{key}", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": body, "version": cur["version"]})
            forged = save(eng, "Cora Compliance")
            assert forged.status_code == 403 and "Only compliance can sign off" in forged.json()["detail"]
            impersonated = save(comp, "Someone Else")
            assert impersonated.status_code == 403 and "cannot sign for" in impersonated.json()["detail"]
            assert save(comp, "Cora Compliance").status_code == 200                                                                   # their own name
            assert eng.put(f"/api/designs/{key}", json={"name": "zz-test design", "domain": "OWASP_AGENTIC", "subject": "AGENT",
                           "document": doc(req={"dpia": {**req["dpia"], "evidence": "edited by engineer", "signed_off_by": "Cora Compliance"}}),
                           "version": eng.get(f"/api/designs/{key}").json()["version"]}).status_code == 200                              # unchanged sign-off is fine
            removed = save(eng, "")
            assert removed.status_code == 403                                                                                         # an engineer cannot drop it
            assert comp.post("/api/agents/ratify", json={"design_key": key, "reviewer": "Spoofed Name"}).json()["contract"]["issued_by"] == "Cora Compliance"
        finally:
            cleanup("zz-test-patient-agent")


def test_user_management_and_the_last_admin():
    with authed_client("admin", "Alice Admin") as admin:
        created = admin.post("/api/users", json={"email": "ZZ-New@Example.test", "full_name": "New Person", "role": "engineer", "password": "a-long-password-1"})
        assert created.status_code == 201 and created.json()["email"] == "zz-new@example.test" and "password" not in str(created.json())
        uid = created.json()["id"]
        try:
            assert admin.post("/api/users", json={"email": "zz-new@example.test", "full_name": "Dup", "role": "auditor", "password": "a-long-password-1"}).status_code == 409
            assert admin.post("/api/users", json={"email": "zz-b@example.test", "full_name": "Bad Role", "role": "king", "password": "a-long-password-1"}).status_code == 422
            assert admin.post("/api/users", json={"email": "zz-c@example.test", "full_name": "Short Pw", "role": "auditor", "password": "short"}).status_code == 422
            anon = TestClient(app)
            assert anon.post("/api/auth/login", json={"email": "zz-new@example.test", "password": "a-long-password-1"}).status_code == 200
            anon.headers[auth.CSRF_HEADER] = "1"
            assert anon.post("/api/agents/ratify", json={"design_key": "x"}).status_code == 403                                       # engineer
            assert admin.patch(f"/api/users/{uid}", json={"role": "compliance"}).json()["role"] == "compliance"
            assert anon.get("/api/agents").status_code == 401                                                                         # a changed role ends their sessions
            assert admin.patch(f"/api/users/{uid}", json={"active": False}).json()["active"] is False
            assert TestClient(app).post("/api/auth/login", json={"email": "zz-new@example.test", "password": "a-long-password-1"}).status_code == 401
            assert admin.post(f"/api/users/{uid}/reset-password", json={"password": "another-long-one-2"}).status_code == 204
            assert admin.patch(f"/api/users/{uid}", json={"active": True}).status_code == 200
            assert TestClient(app).post("/api/auth/login", json={"email": "zz-new@example.test", "password": "another-long-one-2"}).status_code == 200

            from sqlalchemy import select
            from db.models import User
            from db.session import SessionLocal
            with SessionLocal() as s:
                others = s.query(User).filter(User.role == "admin", User.active.is_(True), User.id != admin.test_user["id"]).count()
            if others == 0:                                                                                                          # then the test admin is the only one
                r = admin.patch(f"/api/users/{admin.test_user['id']}", json={"active": False})
                assert r.status_code == 409 and "only active administrator" in r.json()["detail"]
        finally:
            from db.models import User, UserSession
            from db.session import SessionLocal
            with SessionLocal() as s:
                s.query(UserSession).filter(UserSession.user_id == uid).delete()
                s.query(User).filter(User.id == uid).delete()
                s.commit()


def test_change_password_ends_other_sessions():
    with authed_client(password="a-good-password-1") as a:
        other = TestClient(app)
        assert other.post("/api/auth/login", json={"email": a.test_user["email"], "password": "a-good-password-1"}).status_code == 200
        other.headers[auth.CSRF_HEADER] = "1"
        assert a.post("/api/auth/change-password", json={"current_password": "wrong", "new_password": "a-new-long-password"}).status_code == 403
        assert a.post("/api/auth/change-password", json={"current_password": "a-good-password-1", "new_password": "short"}).status_code == 422
        assert a.post("/api/auth/change-password", json={"current_password": "a-good-password-1", "new_password": "a-new-long-password"}).status_code == 204
        assert other.get("/api/agents").status_code == 401 and a.get("/api/agents").status_code == 200


def test_audit_log_records_and_detects_tampering():
    with authed_client("admin", "Alice Admin") as admin:
        for n in ("zz-test-audit", "zz-test-audit-2", "zz-test-audit-3"):
            admin.post("/api/agents/register", json={"name": n})
        try:
            admin.post("/api/agents/register", json={"name": "zz-test-audit"})                                                        # a refused one is logged too
            events = admin.get("/api/audit?limit=20").json()
            acts = [(e["action"], e["outcome"], e["actor"]) for e in events]
            assert ("POST /api/agents/register", "ok", "Alice Admin") in acts and ("POST /api/agents/register", "failed", "Alice Admin") in acts
            assert all("zz-test-audit" not in str(e["detail"]) or "path" in e["detail"] for e in events)                             # no request bodies
            assert admin.get("/api/audit/verify").json()["ok"] is True

            from db.models import AuditEvent
            from db.session import SessionLocal
            with SessionLocal() as s:
                row = s.query(AuditEvent).filter(AuditEvent.action == "POST /api/agents/register", AuditEvent.outcome == "ok").order_by(AuditEvent.seq.desc()).first()
                seq, original = row.seq, dict(row.payload)
                row.payload = {**original, "actor": "Someone Else"}
                s.commit()
            v = admin.get("/api/audit/verify").json()
            assert not v["ok"] and v["broken_at"] == seq and "no longer matches" in v["problem"]
            with SessionLocal() as s:
                s.query(AuditEvent).filter(AuditEvent.seq == seq).one().payload = original
                s.commit()
            assert admin.get("/api/audit/verify").json()["ok"] is True

            with SessionLocal() as s:                                                                                                  # an event taken out of the middle
                victim = s.query(AuditEvent).filter(AuditEvent.seq < seq).order_by(AuditEvent.seq.desc()).offset(1).first()
                saved = (victim.seq, victim.at, victim.actor_name, victim.actor_role, victim.action, victim.outcome, dict(victim.payload), victim.prev_hash, victim.event_hash)
                s.delete(victim)
                s.commit()
            gap = admin.get("/api/audit/verify").json()
            assert not gap["ok"] and "removed or inserted" in gap["problem"]
            with SessionLocal() as s:
                s.add(AuditEvent(seq=saved[0], at=saved[1], actor_name=saved[2], actor_role=saved[3], action=saved[4], outcome=saved[5], payload=saved[6], prev_hash=saved[7], event_hash=saved[8]))
                s.commit()
            assert admin.get("/api/audit/verify").json()["ok"] is True
        finally:
            cleanup("zz-test-audit", "zz-test-audit-2", "zz-test-audit-3")


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
