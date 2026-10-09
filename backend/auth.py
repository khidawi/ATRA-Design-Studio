"""
Users, roles and sign-in (Task 8).

Local accounts. A password is stored only as a scrypt hash. A sign-in creates a server-side session whose random token is
sent in an HttpOnly, SameSite cookie and stored only as a hash. State-changing requests must also carry a custom header
(X-ASTRA-CSRF), which a page on another site cannot add without a CORS preflight that this API refuses.

Roles (a person has one):
    admin       everything, including managing users
    compliance  design, sign off (ratify, decide drift, revoke, acknowledge, generate packs, approve rules and policies)
    engineer    design and propose; cannot sign anything off
    auditor     read-only, plus the audit log

Every request except the public ones is authenticated and checked against `required_permission` by the middleware, so a
new endpoint is protected by default: a write needs the "write" permission unless it is listed as a sign-off or a pure
computation. The names recorded on contracts, decisions, findings and packs are the signed-in person's, never typed.
"""
import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

import audit
from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import ApiKey, AuditEvent, Organisation, User, UserSession
from db.session import SessionLocal, get_session

COOKIE = "astra_session"
CSRF_HEADER = "x-astra-csrf"
SESSION_HOURS = 12
MAX_FAILURES, FAILURE_WINDOW_MINUTES = 5, 15
MIN_PASSWORD = 10
ROLES = ("admin", "compliance", "engineer", "auditor")
PERMISSIONS = {
    "admin": {"read", "write", "signoff", "admin", "audit", "ingest"},
    "compliance": {"read", "write", "signoff", "audit", "ingest"},
    "engineer": {"read", "write", "ingest"},
    "auditor": {"read", "audit"},
    "collector": {"ingest"},           # only a key can be a collector: it sends runtime events and reads the contract summary it needs
}
SAFE = {"GET", "HEAD", "OPTIONS"}


def has(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())


# ── Passwords ───────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        got = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(digest) // 2)
        return secrets.compare_digest(got.hex(), digest)
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password("not-a-real-password")      # so an unknown email costs the same time as a wrong password


def check_password_rules(password: str, email: str = "") -> None:
    if len(password) < MIN_PASSWORD:
        raise HTTPException(status_code=422, detail=f"The password needs at least {MIN_PASSWORD} characters.")
    if email and password.lower() == email.lower():
        raise HTTPException(status_code=422, detail="The password cannot be the email address.")


# ── What each request needs ─────────────────────────────────────────────────

PUBLIC = [("GET", r"^/health$"), ("GET", r"^/docs"), ("GET", r"^/redoc"), ("GET", r"^/openapi\.json$"),
          ("GET", r"^/api/auth/(status|me)$"), ("POST", r"^/api/auth/(login|bootstrap|logout)$")]
PURE = [r"^/score$", r"^/document/validate$", r"^/api/rcr/score$", r"^/api/agents/analyse$", r"^/api/policies/test$", r"^/api/designs/[^/]+/assess$", r"^/api/agents/import/(preview|file-preview)$"]
SIGNOFF = [r"^/api/agents/ratify$", r"^/api/drift/[^/]+/decide$", r"^/api/contracts/", r"^/api/designs/[^/]+/compile$",
           r"^/api/findings/[^/]+/(acknowledge|halt)$", r"^/api/coverage/", r"^/api/packs$", r"^/api/ingestion/candidates/",
           r"^/api/policies", r"^/api/rules/"]


def is_public(method: str, path: str) -> bool:
    return any(method == m and re.search(p, path) for m, p in PUBLIC)


def required_permission(method: str, path: str) -> str:
    if (method == "POST" and path == "/api/runtime/events") or (method == "GET" and path.startswith("/api/runtime/contract/")):
        return "ingest"
    if method in SAFE:
        if path.startswith(("/api/users", "/api/keys")):
            return "admin"
        return "audit" if path.startswith(("/api/audit", "/api/export/audit")) else "read"
    if path.startswith(("/api/users", "/api/keys")) or path == "/api/organisation" or (method == "DELETE" and path == "/api/company"):
        return "admin"
    if any(re.search(p, path) for p in PURE):
        return "read"
    if any(re.search(p, path) for p in SIGNOFF):
        return "signoff"
    return "write"


# ── Who is asking ───────────────────────────────────────────────────────────

@dataclass
class AuthUser:
    id: uuid.UUID
    email: str
    name: str
    role: str


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def authenticate(token: Optional[str]) -> Optional[AuthUser]:
    if not token:
        return None
    with SessionLocal() as s:
        row = s.execute(select(UserSession, User).join(User, User.id == UserSession.user_id).where(
            UserSession.token_hash == _token_hash(token), UserSession.revoked.is_(False),
            UserSession.expires_at > datetime.now(timezone.utc), User.active.is_(True))).first()
        if row is None:
            return None
        return AuthUser(id=row[1].id, email=row[1].email, name=row[1].full_name, role=row[1].role)


KEY_PREFIX = "astra_"
KEY_ROLES = ("engineer", "auditor", "collector")      # a key never signs anything off, so it can never be compliance or admin


def bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return request.headers.get("x-api-key") or None


def authenticate_key(token: Optional[str]) -> Optional[AuthUser]:
    if not token or not token.startswith(KEY_PREFIX):
        return None
    now = datetime.now(timezone.utc)
    with SessionLocal() as s:
        row = s.scalar(select(ApiKey).where(ApiKey.key_hash == _token_hash(token), ApiKey.revoked.is_(False)))
        if row is None or (row.expires_at is not None and row.expires_at <= now):
            return None
        if row.last_used_at is None or now - row.last_used_at > timedelta(minutes=1):      # not a write on every request
            row.last_used_at = now
            s.commit()
        return AuthUser(id=row.id, email=f"api-key:{row.prefix}", name=f"API key: {row.name}", role=row.role)


def current_user(request: Request) -> AuthUser:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return user


def _log_request(user: AuthUser, request: Request, status: int) -> None:
    route = request.scope.get("route")
    template = getattr(route, "path", request.url.path)
    audit.record(user.name, user.role, f"{request.method} {template}", "ok" if status < 400 else ("denied" if status == 403 else "failed"),
                 {"path": request.url.path, "status": status})


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method, path = request.method, request.url.path
        if method == "OPTIONS" or is_public(method, path):
            return await call_next(request)
        token = bearer_token(request)
        via_key = token is not None
        if via_key:
            user = await run_in_threadpool(authenticate_key, token)
            if user is None:
                return JSONResponse({"detail": "The API key is not valid, has expired or was revoked."}, status_code=401)
        else:
            user = await run_in_threadpool(authenticate, request.cookies.get(COOKIE))
            if user is None:
                return JSONResponse({"detail": "Sign in to continue."}, status_code=401)
        need = required_permission(method, path)
        if not has(user.role, need):
            await run_in_threadpool(audit.record, user.name, user.role, f"{method} {path}", "denied", {"needs": need, "status": 403})
            return JSONResponse({"detail": f"Your role ({user.role}) cannot do this. It needs the {need} permission."}, status_code=403)
        if method not in SAFE and not via_key and request.headers.get(CSRF_HEADER) != "1":     # a key is not sent by the browser on its own, so there is nothing to forge
            return JSONResponse({"detail": "Missing the request header that proves this came from the studio."}, status_code=403)
        request.state.user = user
        response = await call_next(request)
        if method not in SAFE:
            await run_in_threadpool(_log_request, user, request, response.status_code)
        return response


# ── Sign-in API ─────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/auth", tags=["auth"])
users_router = APIRouter(prefix="/api/users", tags=["users"])


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    active: bool
    created_at: datetime
    last_login_at: Optional[datetime]


def _user_out(u: User) -> UserOut:
    return UserOut(id=str(u.id), email=u.email, full_name=u.full_name, role=u.role, active=u.active, created_at=u.created_at, last_login_at=u.last_login_at)


class StatusOut(BaseModel):
    needs_bootstrap: bool


@router.get("/status", response_model=StatusOut)
def status(session: Session = Depends(get_session)) -> StatusOut:
    return StatusOut(needs_bootstrap=not session.scalar(select(func.count()).select_from(User)))


class MeOut(BaseModel):
    user: UserOut
    permissions: List[str]


@router.get("/me", response_model=MeOut)
def me(request: Request, session: Session = Depends(get_session)) -> MeOut:
    token = bearer_token(request)
    if token is not None:
        key_user = authenticate_key(token)
        if key_user is None:
            raise HTTPException(status_code=401, detail="The API key is not valid, has expired or was revoked.")
        row = session.get(ApiKey, key_user.id)
        return MeOut(user=UserOut(id=str(row.id), email=key_user.email, full_name=key_user.name, role=row.role, active=True, created_at=row.created_at, last_login_at=row.last_used_at),
                     permissions=sorted(PERMISSIONS[row.role]))
    user = authenticate(request.cookies.get(COOKIE))
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return MeOut(user=_user_out(session.get(User, user.id)), permissions=sorted(PERMISSIONS[user.role]))


def _start_session(session: Session, user: User, request: Request, response: Response) -> None:
    token = secrets.token_urlsafe(32)
    session.add(UserSession(user_id=user.id, token_hash=_token_hash(token), expires_at=datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)))
    user.last_login_at = func.now()
    session.commit()
    response.set_cookie(COOKIE, token, max_age=SESSION_HOURS * 3600, httponly=True, samesite="lax", secure=request.url.scheme == "https", path="/")


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=1, max_length=200)

    @field_validator("email", mode="before")
    @classmethod
    def lower(cls, v):
        return v.strip().lower() if isinstance(v, str) else v


@router.post("/login", response_model=MeOut)
def login(body: Credentials, request: Request, response: Response, session: Session = Depends(get_session)) -> MeOut:
    since = datetime.now(timezone.utc) - timedelta(minutes=FAILURE_WINDOW_MINUTES)
    failures = session.scalar(select(func.count()).select_from(AuditEvent).where(
        AuditEvent.action == "login", AuditEvent.outcome == "failed", AuditEvent.actor_name == body.email, AuditEvent.at > since)) or 0
    if failures >= MAX_FAILURES:
        audit.record(body.email, None, "login", "denied", {"reason": "too many failed attempts"})
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Try again in {FAILURE_WINDOW_MINUTES} minutes.")
    user = session.scalar(select(User).where(User.email == body.email))
    good = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if not (user and good and user.active):
        audit.record(body.email, None, "login", "failed", {})
        raise HTTPException(status_code=401, detail="That email and password do not match an active account.")
    _start_session(session, user, request, response)
    audit.record(user.full_name, user.role, "login", "ok", {})
    return MeOut(user=_user_out(user), permissions=sorted(PERMISSIONS[user.role]))


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, session: Session = Depends(get_session)) -> None:
    token = request.cookies.get(COOKIE)
    user = authenticate(token)
    if token:
        row = session.scalar(select(UserSession).where(UserSession.token_hash == _token_hash(token)))
        if row is not None:
            row.revoked = True
            session.commit()
    response.delete_cookie(COOKIE, path="/")
    if user:
        audit.record(user.name, user.role, "logout", "ok", {})


class UserIn(BaseModel):
    email: str = Field(min_length=3, max_length=200, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=1, max_length=200)

    @field_validator("email", "full_name", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


@router.post("/bootstrap", response_model=MeOut, status_code=201)
def bootstrap(body: UserIn, request: Request, response: Response, session: Session = Depends(get_session)) -> MeOut:
    """Creates the first administrator. Only possible while no user exists."""
    session.execute(select(func.pg_advisory_xact_lock(7003)))
    if session.scalar(select(func.count()).select_from(User)):
        raise HTTPException(status_code=409, detail="An administrator already exists. Ask them to create your account.")
    check_password_rules(body.password, body.email)
    org = session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
    user = User(organisation_id=org.id, email=body.email.lower(), full_name=body.full_name, role="admin", password_hash=hash_password(body.password))
    session.add(user)
    session.flush()
    _start_session(session, user, request, response)
    audit.record(user.full_name, "admin", "bootstrap", "ok", {"email": user.email})
    return MeOut(user=_user_out(user), permissions=sorted(PERMISSIONS["admin"]))


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


@router.post("/change-password", status_code=204)
def change_password(body: PasswordChange, request: Request, response: Response, who: AuthUser = Depends(current_user), session: Session = Depends(get_session)) -> None:
    user = session.get(User, who.id)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=403, detail="The current password is not right.")
    check_password_rules(body.new_password, user.email)
    user.password_hash = hash_password(body.new_password)
    token = request.cookies.get(COOKIE)
    for row in session.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked.is_(False))):
        if row.token_hash != _token_hash(token or ""):
            row.revoked = True                                  # every other sign-in is ended
    session.commit()


# ── User management (admin) ─────────────────────────────────────────────────

@users_router.get("", response_model=List[UserOut])
def list_users(session: Session = Depends(get_session)) -> List[UserOut]:
    return [_user_out(u) for u in session.scalars(select(User).order_by(User.created_at))]


class NewUser(UserIn):
    role: str


@users_router.post("", response_model=UserOut, status_code=201)
def create_user(body: NewUser, session: Session = Depends(get_session)) -> UserOut:
    if body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"The role must be one of {', '.join(ROLES)}.")
    check_password_rules(body.password, body.email)
    if session.scalar(select(User.id).where(User.email == body.email.lower())):
        raise HTTPException(status_code=409, detail="A user with this email already exists.")
    org = session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
    u = User(organisation_id=org.id, email=body.email.lower(), full_name=body.full_name, role=body.role, password_hash=hash_password(body.password))
    session.add(u)
    session.commit()
    return _user_out(u)


class UserUpdate(BaseModel):
    role: Optional[str] = None
    active: Optional[bool] = None
    full_name: Optional[str] = Field(None, min_length=2, max_length=120)


def _other_admins(session: Session, user: User) -> int:
    return session.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active.is_(True), User.id != user.id)) or 0


@users_router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: uuid.UUID, body: UserUpdate, session: Session = Depends(get_session)) -> UserOut:
    u = session.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="No such user.")
    if body.role is not None and body.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"The role must be one of {', '.join(ROLES)}.")
    losing_admin = u.role == "admin" and u.active and ((body.role is not None and body.role != "admin") or body.active is False)
    if losing_admin and not _other_admins(session, u):
        raise HTTPException(status_code=409, detail="This is the only active administrator; promote another user first.")
    if body.role is not None:
        u.role = body.role
    if body.full_name is not None:
        u.full_name = body.full_name.strip()
    if body.active is not None:
        u.active = body.active
    if body.active is False or body.role is not None:
        for row in session.scalars(select(UserSession).where(UserSession.user_id == u.id, UserSession.revoked.is_(False))):
            row.revoked = True                                  # a changed role or disabled account signs the person out
    session.commit()
    return _user_out(u)


class PasswordReset(BaseModel):
    password: str = Field(min_length=1, max_length=200)


@users_router.post("/{user_id}/reset-password", status_code=204)
def reset_password(user_id: uuid.UUID, body: PasswordReset, session: Session = Depends(get_session)) -> None:
    u = session.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="No such user.")
    check_password_rules(body.password, u.email)
    u.password_hash = hash_password(body.password)
    for row in session.scalars(select(UserSession).where(UserSession.user_id == u.id, UserSession.revoked.is_(False))):
        row.revoked = True
    session.commit()


# ── API keys (admin, signed in) ─────────────────────────────────────────────

keys_router = APIRouter(prefix="/api/keys", tags=["api-keys"])


class KeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    role: str
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    revoked: bool
    revoked_by: Optional[str]
    revoked_at: Optional[datetime]
    status: str                       # active | expired | revoked


def _key_out(k: ApiKey) -> KeyOut:
    expired = k.expires_at is not None and k.expires_at <= datetime.now(timezone.utc)
    return KeyOut(id=str(k.id), name=k.name, prefix=k.prefix, role=k.role, created_by=k.created_by, created_at=k.created_at, expires_at=k.expires_at,
                  last_used_at=k.last_used_at, revoked=k.revoked, revoked_by=k.revoked_by, revoked_at=k.revoked_at,
                  status="revoked" if k.revoked else ("expired" if expired else "active"))


@keys_router.get("", response_model=List[KeyOut])
def list_keys(session: Session = Depends(get_session)) -> List[KeyOut]:
    return [_key_out(k) for k in session.scalars(select(ApiKey).order_by(ApiKey.created_at.desc()))]


class NewKey(BaseModel):
    name: str = Field(min_length=3, max_length=60)
    role: str = "engineer"
    expires_in_days: Optional[int] = Field(None, ge=1, le=730)

    @field_validator("name", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


class CreatedKey(KeyOut):
    key: str                          # shown once; only its hash is kept


@keys_router.post("", response_model=CreatedKey, status_code=201)
def create_key(body: NewKey, who: AuthUser = Depends(current_user), session: Session = Depends(get_session)) -> CreatedKey:
    if body.role not in KEY_ROLES:
        raise HTTPException(status_code=422, detail=f"A key's role must be one of {', '.join(KEY_ROLES)}: sign-offs belong to people, so a key cannot be compliance or admin.")
    org = session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
    prefix = secrets.token_hex(4)
    key = f"{KEY_PREFIX}{prefix}_{secrets.token_urlsafe(32)}"
    row = ApiKey(organisation_id=org.id, name=body.name, prefix=prefix, key_hash=_token_hash(key), role=body.role, created_by=who.name,
                 expires_at=datetime.now(timezone.utc) + timedelta(days=body.expires_in_days) if body.expires_in_days else None)
    session.add(row)
    session.commit()
    session.refresh(row)
    return CreatedKey(**_key_out(row).model_dump(), key=key)


@keys_router.post("/{key_id}/revoke", response_model=KeyOut)
def revoke_key(key_id: uuid.UUID, who: AuthUser = Depends(current_user), session: Session = Depends(get_session)) -> KeyOut:
    row = session.get(ApiKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such key.")
    if not row.revoked:
        row.revoked, row.revoked_by, row.revoked_at = True, who.name, datetime.now(timezone.utc)
        session.commit()
    return _key_out(row)
