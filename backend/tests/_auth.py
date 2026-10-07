"""
A signed-in test client. Creates a throwaway user and session straight in the database (no password hashing per test),
and on exit removes them and any audit events the test wrote. The audit log is append-only, so those events can only be
dropped as a suffix; that is safe here because nothing else writes while a test runs.
"""
import hashlib
import secrets
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from auth import COOKIE, CSRF_HEADER, hash_password
from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import AuditEvent, Organisation, User, UserSession
from db.session import SessionLocal
from main import app
from tests._guard import require_scratch_database

require_scratch_database()


@contextmanager
def authed_client(role: str = "admin", name: str = "Compliance lead", password: str = None):
    with TestClient(app) as api:
        with SessionLocal() as s:
            start_seq = s.scalar(select(func.coalesce(func.max(AuditEvent.seq), 0)))
            org = s.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
            email = f"zz-test-{role}-{uuid.uuid4().hex[:8]}@example.test"
            user = User(organisation_id=org.id, email=email, full_name=name, role=role, password_hash=hash_password(password or "a-long-test-password"))
            s.add(user)
            s.flush()
            token = secrets.token_urlsafe(32)
            s.add(UserSession(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
            s.commit()
            user_id = user.id
        api.cookies.set(COOKIE, token)
        api.headers[CSRF_HEADER] = "1"
        api.test_user = {"id": str(user_id), "email": email, "name": name, "role": role}
        try:
            yield api
        finally:
            with SessionLocal() as s:
                for e in s.query(AuditEvent).filter(AuditEvent.seq > start_seq).all():
                    s.delete(e)
                s.query(UserSession).filter(UserSession.user_id == user_id).delete()
                s.query(User).filter(User.id == user_id).delete()
                s.commit()
