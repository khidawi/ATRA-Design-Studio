"""
Repository connectors: connect a source repository, find the AI agents defined in it (LangGraph, the OpenAI Agents SDK, CrewAI, MCP
configurations) and keep them in step with the platform.

  POST   /api/repos                     connect a repository (checks it can be read)
  GET    /api/repos                     the connected repositories
  GET    /api/repos/capabilities        what this deployment allows (is token storage set up, are private hosts allowed)
  PATCH  /api/repos/{id}                rename, change branch or folder, rotate or clear the token, switch auto-sync
  DELETE /api/repos/{id}                disconnect (agents already imported stay)
  POST   /api/repos/{id}/scan           read the repository now and list what is in it
  GET    /api/repos/{id}/scan           the latest scan, with each agent marked new / changed / unchanged
  GET    /api/repos/{id}/agents/{key}   the model one agent would become, with its threat analysis
  POST   /api/repos/{id}/import         turn selected agents into draft designs, or into drift items when they have an active contract
  POST   /api/repos/{id}/webhook-secret make (or replace) the secret that signs push webhooks
  POST   /api/repos/webhook/{id}        the push webhook (GitHub or GitLab), authenticated by its signature

What this is careful about, because it reads a company's source code:
  * Nothing from the repository is ever executed or imported. Python is parsed to a syntax tree; configuration is parsed as data (repo_scan.py).
  * Files that usually hold secrets (.env, keys, certificates, credential files) are never opened. Only source and known configuration files are read.
  * The access token and the webhook secret are encrypted at rest with ASTRA_SECRET_KEY (several keys may be listed, comma separated, to
    rotate: the first one encrypts, all of them decrypt). They are never returned by the API and never written to a log or an error message.
    Without the key the platform still reads public repositories; it refuses to store a token it cannot protect.
  * The token travels to git in the process environment, scoped to the repository's own host, not on the command line.
  * Only https addresses are accepted (file:// only when ASTRA_REPO_ALLOW_FILE=1, for tests). A host that resolves to a private, loopback or
    link-local address is refused unless ASTRA_REPO_ALLOW_PRIVATE_HOSTS=1 (a self-hosted GitLab inside the company network).
  * A scan is a shallow clone into a temporary folder that is removed afterwards, with a time limit and a size limit, git hooks and
    submodules off, and symbolic links ignored.
  * A scan only proposes. Whatever it imports starts as a draft, or as a drift item for compliance to decide when the agent already has an
    active contract, exactly like a file import. The imported model says it came from a static scan and was not verified against running code.
"""
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import os
import posixpath
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

import audit
from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_import import ImportOut, _active, _clean, apply_converted, finish
from agent_registry import AGENT_DOMAIN, _graph, agent_key
from auth import AuthUser, current_user
from db.models import Agent, RepoConnection, RepoImport, RepoScan
from db.session import SessionLocal, get_session
from organisation import current_organisation
from repo_scan import scan_files, MAX_CONFIG_BYTES, MAX_PY_BYTES, MCP_FILES

router = APIRouter(prefix="/api/repos", tags=["repositories"])

CLONE_SECONDS = 120
MAX_REPO_BYTES = 300 * 1024 * 1024
MAX_FILES_READ = 6000
MAX_BYTES_READ = 60 * 1024 * 1024
KEEP_SCANS = 20
WEBHOOK_DEBOUNCE_SECONDS = 10
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "site-packages", "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor", ".next", ".idea", "target"}
KEEP_DOT_DIRS = {".cursor", ".vscode", ".claude", ".windsurf", ".well-known"}
TEST_DIRS = {"tests", "test", "testing", "__tests__", "e2e"}
NEVER_READ = re.compile(r"(^\.env|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|id_rsa|id_ed25519|credential|secret|\.tfstate|\.npmrc$|\.pypirc$|\.netrc$)", re.I)
CONFIG_NAMES = {"langgraph.json", "agents.yaml", "agents.yml", "agent-card.json", "agent.json"} | MCP_FILES
PROVIDER_USER = {"github": "x-access-token", "gitlab": "oauth2", "bitbucket": "x-token-auth", "azure": "", "git": "x-access-token"}
BRANCH_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$")


class RepoError(Exception):
    """Something about reaching or reading the repository went wrong; the message is safe to show and says what to do."""


def allow_private() -> bool:
    return os.environ.get("ASTRA_REPO_ALLOW_PRIVATE_HOSTS") == "1"


def allow_file() -> bool:
    return os.environ.get("ASTRA_REPO_ALLOW_FILE") == "1"


# ── Encryption of the token and the webhook secret ──────────────────────────

def _fernet() -> Optional[MultiFernet]:
    keys = [k.strip() for k in os.environ.get("ASTRA_SECRET_KEY", "").split(",") if k.strip()]
    if not keys:
        return None
    try:
        return MultiFernet([Fernet(k.encode("ascii")) for k in keys])
    except (ValueError, TypeError):
        return None


def secrets_ready() -> bool:
    return _fernet() is not None


def seal(value: str) -> str:
    f = _fernet()
    if f is None:
        raise HTTPException(status_code=422, detail="This deployment has no ASTRA_SECRET_KEY, so it cannot store an access token or a webhook secret safely. "
                                                    "Set one (generate it with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"), restart, and try again. Public repositories can be read without one.")
    return f.encrypt(value.encode("utf-8")).decode("ascii")


def unseal(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    f = _fernet()
    if f is None:
        return None
    try:
        return f.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


# ── The address ─────────────────────────────────────────────────────────────

def provider_of(host: str) -> str:
    h = host.lower()
    if h == "github.com" or h.endswith(".github.com") or h.startswith("github."):
        return "github"
    if h == "gitlab.com" or h.startswith("gitlab."):
        return "gitlab"
    if h == "bitbucket.org":
        return "bitbucket"
    if h == "dev.azure.com" or h.endswith(".visualstudio.com"):
        return "azure"
    return "git"


def check_url(url: str) -> Tuple[str, str]:
    """The cleaned address and the provider, or a RepoError saying what is wrong with it."""
    url = (url or "").strip()
    if not url or len(url) > 500 or re.search(r"\s", url):
        raise RepoError("Enter the repository's https address, for example https://github.com/your-org/your-repo.")
    p = urlparse(url)
    if p.scheme == "file":
        if not allow_file():
            raise RepoError("Only https addresses are accepted.")
        if not os.path.isdir(p.path):
            raise RepoError("That folder does not exist.")
        return url, "git"
    if p.scheme != "https":
        raise RepoError("Only https addresses are accepted (not http, ssh or a local path).")
    if p.username or p.password:
        raise RepoError("Do not put a user name or token in the address: use the access token field, which is stored encrypted.")
    if not p.hostname:
        raise RepoError("The address has no host name.")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise RepoError(f"The host {p.hostname} could not be found.")
    if not allow_private():
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                raise RepoError(f"{p.hostname} points at a private or internal address, which this deployment does not allow "
                                f"(an administrator can permit it with ASTRA_REPO_ALLOW_PRIVATE_HOSTS=1 for a self-hosted server).")
    path = p.path.rstrip("/")
    prov = provider_of(p.hostname)
    if prov in ("github", "gitlab") and path and not path.endswith(".git"):
        path += ".git"
    if not path or path == "/":
        raise RepoError("The address needs the repository's path, for example https://github.com/your-org/your-repo.")
    return f"https://{p.netloc}{path}", prov


def check_branch(branch: str) -> str:
    branch = (branch or "").strip()
    if branch and not BRANCH_RX.match(branch):
        raise RepoError("That branch name is not valid.")
    return branch


def check_subpath(path: str) -> str:
    path = posixpath.normpath((path or "").strip().strip("/")) if (path or "").strip().strip("/") else ""
    if path in (".", ""):
        return ""
    if path.startswith("..") or path.startswith("/") or "\\" in path or len(path) > 200:
        raise RepoError("The folder must be a path inside the repository, such as services/agents.")
    return path


# ── Git ─────────────────────────────────────────────────────────────────────

def _git(args: List[str], home: str, token: Optional[str] = None, provider: str = "git", url: str = "", cwd: Optional[str] = None, timeout: int = CLONE_SECONDS) -> str:
    cfg = [("core.hooksPath", os.devnull), ("core.fsmonitor", "false"), ("credential.helper", ""), ("core.symlinks", "false"), ("submodule.recurse", "false"),
           ("protocol.file.allow", "always" if allow_file() else "never"), ("http.followRedirects", "initial"), ("advice.detachedHead", "false")]
    if token and urlparse(url).scheme == "https":
        p = urlparse(url)
        basic = base64.b64encode(f"{PROVIDER_USER.get(provider, 'x-access-token')}:{token}".encode("utf-8")).decode("ascii")
        cfg.append((f"http.{p.scheme}://{p.netloc}/.extraHeader", f"Authorization: Basic {basic}"))     # sent only to this repository's own host
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https:file" if allow_file() else "https",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_LFS_SKIP_SMUDGE": "1", "LC_ALL": "C", "GIT_CONFIG_COUNT": str(len(cfg))}
    for i, (k, v) in enumerate(cfg):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    try:
        r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise RepoError(f"Reading the repository took longer than {timeout} seconds, so it was stopped.")
    except FileNotFoundError:
        raise RepoError("git is not installed in the backend image.")
    if r.returncode != 0:
        raise RepoError(_explain(r.stderr, token))
    return r.stdout


def _explain(stderr: str, token: Optional[str]) -> str:
    text = (stderr or "").strip()
    if token:
        text = text.replace(token, "***")
    low = text.lower()
    if "authentication failed" in low or "could not read username" in low or "invalid username or password" in low or "http 401" in low or "returned error: 401" in low:
        return "The repository refused the access token (or it needs one). Check that the token is valid and can read this repository."
    if "returned error: 403" in low or "permission denied" in low:
        return "The token is valid but may not read this repository. Give it read access to the code (contents)."
    if "not found" in low and "remote branch" in low:
        return "That branch does not exist in the repository."
    if "not found" in low or "returned error: 404" in low:
        return "The repository was not found, or the token cannot see it. Check the address and the token."
    if "could not resolve host" in low or "unable to access" in low:
        return "The repository's host could not be reached from the platform."
    if "ssl" in low or "certificate" in low:
        return "The repository's TLS certificate was not accepted."
    return "git could not read the repository: " + re.sub(r"\s+", " ", text)[:200]


def check_access(url: str, provider: str, token: Optional[str], branch: str) -> None:
    home = tempfile.mkdtemp(prefix="astra-git-home-")
    try:
        out = _git(["ls-remote", "--heads", "--", url] + ([f"refs/heads/{branch}"] if branch else []), home, token, provider, url, timeout=45)
        if branch and not out.strip():
            raise RepoError("That branch does not exist in the repository.")
        if not out.strip():
            raise RepoError("The repository has no branches yet.")
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _tree_bytes(root: str) -> int:
    total = 0
    for base, dirs, names in os.walk(root):
        if os.path.basename(base) == ".git":
            dirs[:] = []
            continue
        for n in names:
            try:
                total += os.lstat(os.path.join(base, n)).st_size
            except OSError:
                pass
        if total > MAX_REPO_BYTES:
            break
    return total


def collect(root: str, subpath: str, include_tests: bool) -> Tuple[Dict[str, str], List[str]]:
    """The files worth reading, keyed by path inside the repository. Never follows symbolic links, never opens a file that usually holds a secret."""
    files: Dict[str, str] = {}
    notes: List[str] = []
    start = os.path.join(root, subpath) if subpath else root
    if not os.path.isdir(start):
        raise RepoError(f"The folder {subpath} does not exist in the repository.")
    read_bytes = 0
    for base, dirs, names in os.walk(start, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and (not d.startswith(".") or d in KEEP_DOT_DIRS) and not os.path.islink(os.path.join(base, d))
                         and (include_tests or d.lower() not in TEST_DIRS))
        for n in sorted(names):
            path = os.path.join(base, n)
            low = n.lower()
            is_py = low.endswith(".py")
            if os.path.islink(path) or NEVER_READ.search(low) and low not in CONFIG_NAMES:
                continue
            if not (is_py or low in CONFIG_NAMES):
                continue
            if is_py and not include_tests and (low.startswith("test_") or low.endswith("_test.py") or low == "conftest.py"):
                continue
            size = os.lstat(path).st_size
            if size > (MAX_PY_BYTES if is_py else MAX_CONFIG_BYTES):
                notes.append(f"{posixpath.relpath(path.replace(os.sep, '/'), root.replace(os.sep, '/'))}: larger than the scan limit, skipped")
                continue
            if len(files) >= MAX_FILES_READ or read_bytes + size > MAX_BYTES_READ:
                notes.append("The repository is larger than the scan limit; only part of it was read. Narrow it with the folder field.")
                return files, notes
            with open(path, "rb") as fh:
                data = fh.read()
            if b"\x00" in data:
                continue
            read_bytes += len(data)
            files[posixpath.relpath(path.replace(os.sep, "/"), root.replace(os.sep, "/"))] = data.decode("utf-8", errors="replace")
    return files, notes


_SCANNING: set = set()
_SCANNING_LOCK = threading.Lock()


def _read_repository(conn: RepoConnection) -> Tuple[str, Dict[str, Any]]:
    """Clones the repository into a temporary folder, reads it, removes it. Returns the commit and the scan result."""
    token = unseal(conn.token_enc) if conn.token_enc else None
    if conn.token_enc and token is None:
        raise RepoError("The stored access token cannot be decrypted (the secret key was changed or removed). Enter the token again.")
    tmp = tempfile.mkdtemp(prefix="astra-repo-")
    try:
        dest = os.path.join(tmp, "src")
        args = ["clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules", "--quiet"] + (["--branch", conn.branch] if conn.branch else []) + ["--", conn.url, dest]
        _git(args, tmp, token, conn.provider, conn.url)
        sha = _git(["rev-parse", "HEAD"], tmp, cwd=dest, timeout=20).strip()
        if _tree_bytes(dest) > MAX_REPO_BYTES:
            raise RepoError(f"The repository is larger than {MAX_REPO_BYTES // (1024 * 1024)} MB. Connect a smaller one, or one folder of it.")
        files, notes = collect(dest, conn.subpath, conn.include_tests)
        label = agent_key(conn.name) or agent_key(posixpath.basename(urlparse(conn.url).path).removesuffix(".git")) or "repository"
        result = scan_files(files, label)
        result["notes"] = notes + result["notes"]
        return sha, result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── Reading what a scan found against what the platform already holds ────────

def _annotate(session: Session, conn: RepoConnection, result: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(result)
    imports = {i.agent_key: i for i in session.scalars(select(RepoImport).where(RepoImport.connection_id == conn.id))}
    keys = [a["key"] for a in result["agents"]]
    existing = {a.agent_key: a for a in session.scalars(select(Agent).where(Agent.agent_key.in_(keys)))} if keys else {}
    for a in result["agents"]:
        imp, ex = imports.get(a["key"]), existing.get(a["key"])
        a["status"] = ("unchanged" if imp.fingerprint == a["fingerprint"] else "changed") if imp else ("exists" if ex else "new")
        a["imported_commit"] = imp.commit_sha[:7] if imp else None
        a["has_contract"] = bool(ex is not None and _active(session, a["key"]) is not None)
    found = set(keys)
    result["removed"] = sorted(k for k in imports if k not in found)
    return result


class RepoOut(BaseModel):
    id: str
    name: str
    provider: str
    url: str
    branch: str
    subpath: str
    has_token: bool
    webhook_enabled: bool
    auto_sync: bool
    include_tests: bool
    status: str
    last_scan_at: Optional[datetime]
    last_commit: Optional[str]
    last_error: Optional[str]
    created_by: str
    imported_agents: int


def _out(session: Session, c: RepoConnection) -> RepoOut:
    n = len(list(session.scalars(select(RepoImport.id).where(RepoImport.connection_id == c.id))))
    return RepoOut(id=str(c.id), name=c.name, provider=c.provider, url=c.url, branch=c.branch, subpath=c.subpath, has_token=bool(c.token_enc), webhook_enabled=bool(c.webhook_secret_enc),
                   auto_sync=c.auto_sync, include_tests=c.include_tests, status=c.status, last_scan_at=c.last_scan_at, last_commit=c.last_commit, last_error=c.last_error,
                   created_by=c.created_by, imported_agents=n)


def _get(session: Session, conn_id: str) -> RepoConnection:
    try:
        cid = uuid.UUID(conn_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="No such repository connection.")
    c = session.scalar(select(RepoConnection).where(RepoConnection.id == cid, RepoConnection.organisation_id == current_organisation(session).id))
    if c is None:
        raise HTTPException(status_code=404, detail="No such repository connection.")
    return c


def _scan_row(session: Session, conn: RepoConnection) -> Optional[RepoScan]:
    return session.scalar(select(RepoScan).where(RepoScan.connection_id == conn.id).order_by(RepoScan.created_at.desc()).limit(1))


class ScanOut(BaseModel):
    scan_id: str
    commit: str
    scanned_at: datetime
    trigger: str
    agents: List[Dict[str, Any]]
    mcp_servers: List[Dict[str, Any]]
    notes: List[str]
    stats: Dict[str, Any]
    removed: List[str]


def _scan_out(session: Session, conn: RepoConnection, row: RepoScan) -> ScanOut:
    r = _annotate(session, conn, row.result)
    for a in r["agents"]:
        m = a.pop("manifest", None) or {}                                   # the full manifest stays on the server; the list shows what a person decides on
        a["inferred"], a["warnings"], a["ignored"] = m.get("inferred", []), m.get("warnings", []), m.get("ignored", [])
    return ScanOut(scan_id=str(row.id), commit=row.commit_sha, scanned_at=row.created_at, trigger=row.trigger, agents=r["agents"], mcp_servers=r["mcp_servers"], notes=r["notes"], stats=r["stats"], removed=r["removed"])


def run_scan(session: Session, conn: RepoConnection, trigger: str, actor: str) -> RepoScan:
    with _SCANNING_LOCK:
        if conn.id in _SCANNING:
            raise HTTPException(status_code=409, detail="This repository is already being scanned. Try again in a moment.")
        _SCANNING.add(conn.id)
    try:
        try:
            sha, result = _read_repository(conn)
        except RepoError as exc:
            conn.status, conn.last_error, conn.last_scan_at = "ERROR", str(exc)[:400], datetime.now(timezone.utc)
            session.commit()
            raise HTTPException(status_code=502, detail=str(exc))
        row = RepoScan(connection_id=conn.id, commit_sha=sha, trigger=trigger, result=result, created_by=actor)
        session.add(row)
        conn.status, conn.last_error, conn.last_commit, conn.last_scan_at = "OK", None, sha, datetime.now(timezone.utc)
        session.flush()
        old = list(session.scalars(select(RepoScan.id).where(RepoScan.connection_id == conn.id).order_by(RepoScan.created_at.desc()).offset(KEEP_SCANS)))
        for oid in old:
            session.delete(session.get(RepoScan, oid))
        session.commit()
        session.refresh(row)
        return row
    finally:
        with _SCANNING_LOCK:
            _SCANNING.discard(conn.id)


# ── Importing ───────────────────────────────────────────────────────────────

def import_agents(session: Session, conn: RepoConnection, row: RepoScan, keys: List[str], actor: str, profile: Optional[str]) -> List[Dict[str, Any]]:
    by_key = {a["key"]: a for a in row.result["agents"]}
    results = []
    for key in keys:
        a = by_key.get(key)
        if a is None:
            results.append({"key": key, "ok": False, "error": "It is not in the latest scan. Scan again."})
            continue
        m = copy.deepcopy(a["manifest"])
        c = finish(m, "repository", [a["name"]], a["fingerprint"])
        ref = f"{conn.name} {a['path']}:{a['line']} @{row.commit_sha[:7]}"
        prov = {"source": "repository", "format": "repository", "repository": conn.url, "connection": conn.name, "commit": row.commit_sha, "path": a["path"], "line": a["line"],
                "confidence": a["confidence"], "sha256": a["fingerprint"], "imported_by": actor, "imported_at": datetime.now(timezone.utc).isoformat(),
                "note": "Generated from a static scan of the source; nothing here is verified against the running agent.",
                "label": f"Imported from {ref} (static scan), not verified against code"}
        try:
            out: ImportOut = apply_converted(session, actor, c, prov, profile)
        except HTTPException as exc:
            session.rollback()
            results.append({"key": key, "ok": False, "error": str(exc.detail)})
            continue
        imp = session.scalar(select(RepoImport).where(RepoImport.connection_id == conn.id, RepoImport.agent_key == key))
        if imp is None:
            imp = RepoImport(connection_id=conn.id, agent_key=key, path=a["path"][:300], line=a["line"], fingerprint=a["fingerprint"], commit_sha=row.commit_sha, outcome=out.outcome)
            session.add(imp)
        else:
            imp.path, imp.line, imp.fingerprint, imp.commit_sha, imp.outcome, imp.imported_at = a["path"][:300], a["line"], a["fingerprint"], row.commit_sha, out.outcome, datetime.now(timezone.utc)
        session.commit()
        results.append({"key": key, "ok": True, "outcome": out.outcome, "summary": out.summary, "drift_id": out.drift_id, "design_key": out.design_key})
    return results


# ── The API ─────────────────────────────────────────────────────────────────

class Capabilities(BaseModel):
    secrets_ready: bool
    allow_private_hosts: bool
    frameworks: List[str]
    limits: Dict[str, Any]


@router.get("/capabilities", response_model=Capabilities)
def capabilities() -> Capabilities:
    return Capabilities(secrets_ready=secrets_ready(), allow_private_hosts=allow_private(),
                        frameworks=["LangGraph", "OpenAI Agents SDK", "CrewAI", "MCP configuration", "A2A agent card"],
                        limits={"clone_seconds": CLONE_SECONDS, "max_repository_mb": MAX_REPO_BYTES // (1024 * 1024), "max_files_read": MAX_FILES_READ, "max_python_kb": MAX_PY_BYTES // 1000})


class ConnectBody(BaseModel):
    name: Optional[str] = Field(None, max_length=120)
    url: str = Field(max_length=500)
    branch: str = Field("", max_length=120)
    subpath: str = Field("", max_length=200)
    token: Optional[str] = Field(None, max_length=600)
    auto_sync: bool = False
    include_tests: bool = False
    webhook: bool = False


class Connected(RepoOut):
    webhook_secret: Optional[str] = None          # shown once, here only
    webhook_path: Optional[str] = None


@router.get("", response_model=List[RepoOut])
def list_connections(session: Session = Depends(get_session)) -> List[RepoOut]:
    org = current_organisation(session)
    return [_out(session, c) for c in session.scalars(select(RepoConnection).where(RepoConnection.organisation_id == org.id).order_by(RepoConnection.created_at))]


@router.post("", response_model=Connected, status_code=201)
def connect(body: ConnectBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Connected:
    org = current_organisation(session)
    try:
        url, provider = check_url(body.url)
        branch, subpath = check_branch(body.branch), check_subpath(body.subpath)
    except RepoError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    token = (body.token or "").strip() or None
    sealed = seal(token) if token else None
    secret = secrets.token_urlsafe(32) if body.webhook else None
    sealed_secret = seal(secret) if secret else None
    if session.scalar(select(RepoConnection.id).where(RepoConnection.organisation_id == org.id, RepoConnection.url == url, RepoConnection.branch == branch, RepoConnection.subpath == subpath)):
        raise HTTPException(status_code=409, detail="This repository, branch and folder are already connected.")
    try:
        check_access(url, provider, token, branch)
    except RepoError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    name = _clean(body.name or posixpath.basename(urlparse(url).path).removesuffix(".git") or "repository", 120)
    c = RepoConnection(organisation_id=org.id, name=name, provider=provider, url=url, branch=branch, subpath=subpath, token_enc=sealed, webhook_secret_enc=sealed_secret,
                       auto_sync=body.auto_sync and bool(sealed_secret), include_tests=body.include_tests, created_by=user.name)
    session.add(c)
    session.commit()
    session.refresh(c)
    return Connected(**_out(session, c).model_dump(), webhook_secret=secret, webhook_path=f"/api/repos/webhook/{c.id}" if secret else None)


@router.get("/{conn_id}", response_model=RepoOut)
def get_connection(conn_id: str, session: Session = Depends(get_session)) -> RepoOut:
    return _out(session, _get(session, conn_id))


class PatchBody(BaseModel):
    name: Optional[str] = Field(None, max_length=120)
    branch: Optional[str] = Field(None, max_length=120)
    subpath: Optional[str] = Field(None, max_length=200)
    token: Optional[str] = Field(None, max_length=600)         # a new token replaces the old one; an empty string removes it
    auto_sync: Optional[bool] = None
    include_tests: Optional[bool] = None


@router.patch("/{conn_id}", response_model=RepoOut)
def update_connection(conn_id: str, body: PatchBody, session: Session = Depends(get_session)) -> RepoOut:
    c = _get(session, conn_id)
    try:
        if body.branch is not None:
            c.branch = check_branch(body.branch)
        if body.subpath is not None:
            c.subpath = check_subpath(body.subpath)
    except RepoError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if body.name is not None and body.name.strip():
        c.name = _clean(body.name, 120)
    if body.token is not None:
        c.token_enc = seal(body.token.strip()) if body.token.strip() else None
    if body.auto_sync is not None:
        if body.auto_sync and not c.webhook_secret_enc:
            raise HTTPException(status_code=422, detail="Auto-sync is driven by the push webhook. Create the webhook secret first.")
        c.auto_sync = body.auto_sync
    if body.include_tests is not None:
        c.include_tests = body.include_tests
    session.commit()
    return _out(session, c)


@router.delete("/{conn_id}", status_code=204)
def disconnect(conn_id: str, session: Session = Depends(get_session)) -> None:
    c = _get(session, conn_id)
    session.delete(c)
    session.commit()


@router.post("/{conn_id}/scan", response_model=ScanOut)
def scan(conn_id: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ScanOut:
    c = _get(session, conn_id)
    row = run_scan(session, c, "manual", user.name)
    return _scan_out(session, c, row)


@router.get("/{conn_id}/scan", response_model=Optional[ScanOut])
def latest_scan(conn_id: str, session: Session = Depends(get_session)) -> Optional[ScanOut]:
    c = _get(session, conn_id)
    row = _scan_row(session, c)
    return _scan_out(session, c, row) if row else None


def _found(session: Session, c: RepoConnection, key: str) -> Tuple[RepoScan, Dict[str, Any]]:
    row = _scan_row(session, c)
    a = next((x for x in row.result["agents"] if x["key"] == key), None) if row else None
    if a is None:
        raise HTTPException(status_code=404, detail="That agent is not in the latest scan.")
    return row, a


@router.get("/{conn_id}/agents/{key}")
def preview_agent(conn_id: str, key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """The model this agent would become and its threat analysis, before anything is imported."""
    c = _get(session, conn_id)
    row, a = _found(session, c, key)
    conv = finish(copy.deepcopy(a["manifest"]), "repository", [a["name"]], a["fingerprint"])
    analysis = analyse_agent(AgentAnalyseRequest(graph=_graph({"nodes": conv.nodes, "edges": conv.edges}), domain=AGENT_DOMAIN), session)
    ex = session.scalar(select(Agent).where(Agent.agent_key == key))
    contract = _active(session, key) if ex else None
    will = "drift" if contract else ("update" if ex and ex.design_id else "create")
    return {**conv.model_dump(), "analysis": analysis.model_dump(mode="json"), "source": {"path": a["path"], "line": a["line"], "commit": row.commit_sha, "confidence": a["confidence"]},
            "existing": {"agent_exists": ex is not None, "has_active_contract": contract is not None, "will": will, "contract_version": contract.document["version"] if contract else None}}


class ImportBody(BaseModel):
    agents: List[str] = Field(min_length=1, max_length=100)
    profile: Optional[str] = Field(None, max_length=64)


@router.post("/{conn_id}/import")
def import_selected(conn_id: str, body: ImportBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    c = _get(session, conn_id)
    row = _scan_row(session, c)
    if row is None:
        raise HTTPException(status_code=409, detail="Scan the repository first.")
    return {"commit": row.commit_sha, "results": import_agents(session, c, row, body.agents, user.name, body.profile)}


class SecretOut(BaseModel):
    webhook_secret: str
    webhook_path: str


@router.post("/{conn_id}/webhook-secret", response_model=SecretOut)
def new_webhook_secret(conn_id: str, session: Session = Depends(get_session)) -> SecretOut:
    c = _get(session, conn_id)
    secret = secrets.token_urlsafe(32)
    c.webhook_secret_enc = seal(secret)
    session.commit()
    return SecretOut(webhook_secret=secret, webhook_path=f"/api/repos/webhook/{c.id}")


# ── The push webhook ────────────────────────────────────────────────────────

def _verified(secret: str, headers: Any, raw: bytes) -> bool:
    sig = headers.get("x-hub-signature-256")
    if sig:
        want = "sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, want)
    tok = headers.get("x-gitlab-token")
    return bool(tok) and hmac.compare_digest(tok, secret)


def _scan_from_webhook(conn_id: uuid.UUID) -> None:
    actor = "repository webhook"
    with SessionLocal() as s:
        c = s.get(RepoConnection, conn_id)
        if c is None:
            return
        try:
            row = run_scan(s, c, "webhook", actor)
        except HTTPException as exc:
            audit.record(actor, None, "repo.webhook.scan", "failed", {"repository": c.name, "reason": str(exc.detail)[:200]})
            return
        synced = []
        if c.auto_sync:
            r = _annotate(s, c, row.result)
            changed = [a["key"] for a in r["agents"] if a["status"] == "changed"]
            if changed:
                synced = [x for x in import_agents(s, c, row, changed, actor, None)]
        audit.record(actor, None, "repo.webhook.scan", "ok", {"repository": c.name, "commit": row.commit_sha[:12], "auto_imported": [x["key"] for x in synced if x.get("ok")]})


@router.post("/webhook/{conn_id}", status_code=202)
async def webhook(conn_id: str, request: Request, background: BackgroundTasks) -> Dict[str, Any]:
    """A push to the connected branch triggers a scan. Authenticated by the signature, not by a session."""
    raw = await request.body()
    if len(raw) > 5_000_000:
        raise HTTPException(status_code=413, detail="Too large.")
    c: Optional[RepoConnection] = None
    try:
        with SessionLocal() as s:
            c = s.get(RepoConnection, uuid.UUID(conn_id))
            secret = unseal(c.webhook_secret_enc) if c is not None else None
            branch, last, name, cid = (c.branch, c.last_scan_at, c.name, c.id) if c is not None else ("", None, "", None)
    except ValueError:
        c = None
    if c is None or not secret:
        raise HTTPException(status_code=404, detail="Not found.")                 # the same answer whether the connection exists or has no secret
    if not _verified(secret, request.headers, raw):
        audit.record("repository webhook", None, "repo.webhook", "denied", {"repository": name, "reason": "bad signature"})
        raise HTTPException(status_code=401, detail="The signature does not match.")
    event = request.headers.get("x-github-event") or request.headers.get("x-gitlab-event") or ""
    if event.lower() == "ping":
        return {"ok": True, "event": "ping"}
    try:
        ref = (json.loads(raw.decode("utf-8") or "{}") or {}).get("ref", "")
    except (ValueError, UnicodeDecodeError, AttributeError):
        ref = ""
    if branch and ref and ref != f"refs/heads/{branch}":
        return {"ok": True, "ignored": "a push to another branch"}
    if last is not None and datetime.now(timezone.utc) - last < timedelta(seconds=WEBHOOK_DEBOUNCE_SECONDS):
        return {"ok": True, "ignored": "scanned a moment ago"}
    background.add_task(_scan_from_webhook, cid)
    return {"ok": True, "scanning": True}
