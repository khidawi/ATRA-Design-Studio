"""
Identity-provider connectors: start from the service accounts and OAuth clients that an identity provider holds for AI agents.

  GET    /api/idps/capabilities        the providers (Microsoft Entra ID, Okta, Auth0, Keycloak), what each needs, how agents are tagged in each
  POST   /api/idps                     connect one (signs in with the credentials to prove they work)
  GET    /api/idps                     the connections
  PATCH  /api/idps/{id}                rename, change the tag rule, rotate the secret
  DELETE /api/idps/{id}                disconnect (agents already imported stay)
  POST   /api/idps/{id}/scan           read the tagged identities now
  GET    /api/idps/{id}/scan           the latest scan, each identity marked new / changed / unchanged / already in the inventory
  GET    /api/idps/{id}/agents/{key}   the model one identity would become, with its threat analysis
  POST   /api/idps/{id}/import         bring selected identities in as agents

An identity tells ASTRA what an agent may do (its permissions become the agent's tools), who owns it, and whether its credentials are looked after.
It does not tell ASTRA how the agent is built, so each import is a proposal that starts as a draft design, or as a drift item when the agent
already has an active contract. When the agent is already in the inventory (from a repository, say) the identity's permissions are merged into its
design rather than replacing it, so a repository and an identity provider together give a fuller picture than either alone.

Protections: the credential used to read the provider (a client secret or API token) is encrypted at rest with ASTRA_SECRET_KEY, never returned,
never logged; the connector only issues read requests, with a time limit, a size limit, no redirects and no credentials in any error message
(idp_providers.py); the address of an Okta or Keycloak server or an Auth0 domain is checked like a repository's: https only, and a private or
internal address is refused unless ASTRA_REPO_ALLOW_PRIVATE_HOSTS=1. A changed permission is the event that matters most: a later scan marks the agent
Changed, and importing it sends it to Drift review when the agent has a contract.
"""
import copy
import ipaddress
import socket
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_import import MAX_NODES, ImportOut, _active, _clean, apply_converted, finish
from agent_registry import AGENT_DOMAIN, _graph, agent_key
from auth import AuthUser, current_user
from db.models import Agent, Design, IdpConnection, IdpImport, IdpScan
from db.session import get_session
from idp_manifest import to_agent
from idp_providers import MAX_IDENTITIES, PROVIDERS, IdpError, Provider, describe
from organisation import current_organisation
from repo_connect import allow_private, seal, secrets_ready, unseal

router = APIRouter(prefix="/api/idps", tags=["identity-providers"])
KEEP_SCANS = 20
SOURCE_NOTE = "Generated from the identity provider's record of this identity; nothing here is verified against the running agent."


def _check_host(host: str) -> None:
    """The host must resolve to a public address (unless private hosts are allowed). Tests replace this."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise IdpError(f"The host {host} could not be found.")
    if not allow_private():
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise IdpError(f"{host} points at a private or internal address, which this deployment does not allow "
                               f"(an administrator can permit it with ASTRA_REPO_ALLOW_PRIVATE_HOSTS=1 for a server inside the company network).")


HOST_CHECK: Callable[[str], None] = _check_host


def _hosts_of(provider: str, cfg: Dict[str, str]) -> List[str]:
    if provider == "okta":
        return [urlparse(cfg["domain"]).hostname or ""]
    if provider == "auth0":
        return [cfg["domain"]]
    if provider == "keycloak":
        return [urlparse(cfg["base_url"]).hostname or ""]
    return []                                                    # Entra uses Microsoft's own fixed addresses


class IdpOut(BaseModel):
    id: str
    name: str
    provider: str
    provider_label: str
    account: str
    config: Dict[str, str]
    rule: Dict[str, str]
    status: str
    last_scan_at: Optional[datetime]
    last_error: Optional[str]
    created_by: str
    imported_agents: int


def _out(session: Session, c: IdpConnection) -> IdpOut:
    n = len(list(session.scalars(select(IdpImport.id).where(IdpImport.connection_id == c.id))))
    return IdpOut(id=str(c.id), name=c.name, provider=c.provider, provider_label=PROVIDERS[c.provider].label, account=c.account, config=c.config, rule=c.rule, status=c.status,
                  last_scan_at=c.last_scan_at, last_error=c.last_error, created_by=c.created_by, imported_agents=n)


def _get(session: Session, conn_id: str) -> IdpConnection:
    try:
        cid = uuid.UUID(conn_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="No such identity provider connection.")
    c = session.scalar(select(IdpConnection).where(IdpConnection.id == cid, IdpConnection.organisation_id == current_organisation(session).id))
    if c is None:
        raise HTTPException(status_code=404, detail="No such identity provider connection.")
    return c


def _provider(c: IdpConnection) -> Provider:
    secret = unseal(c.secret_enc)
    if secret is None:
        raise IdpError("The stored credential cannot be decrypted (the secret key was changed or removed). Enter it again in Settings.")
    return PROVIDERS[c.provider](c.config, secret)


def _check_rule(provider: str, rule: Dict[str, Any]) -> Dict[str, str]:
    modes = {m["id"]: m for m in PROVIDERS[provider].modes}
    mode, value = str(rule.get("mode") or ""), str(rule.get("value") or "").strip()
    if mode not in modes:
        raise HTTPException(status_code=422, detail="Choose how this provider marks an identity as an agent.")
    if modes[mode]["value"] and not value:
        raise HTTPException(status_code=422, detail=f"Say what to look for ({modes[mode]['label'].lower()}).")
    return {"mode": mode, "value": value if modes[mode]["value"] else ""}


class Capabilities(BaseModel):
    secrets_ready: bool
    providers: List[Dict[str, Any]]
    limits: Dict[str, Any]


@router.get("/capabilities", response_model=Capabilities)
def capabilities() -> Capabilities:
    return Capabilities(secrets_ready=secrets_ready(), providers=describe(), limits={"max_identities": MAX_IDENTITIES})


class ConnectBody(BaseModel):
    provider: str
    name: Optional[str] = Field(None, max_length=120)
    config: Dict[str, str] = Field(default_factory=dict)
    secret: str = Field(min_length=1, max_length=2000)
    rule: Dict[str, str]


@router.get("", response_model=List[IdpOut])
def list_connections(session: Session = Depends(get_session)) -> List[IdpOut]:
    org = current_organisation(session)
    return [_out(session, c) for c in session.scalars(select(IdpConnection).where(IdpConnection.organisation_id == org.id).order_by(IdpConnection.created_at))]


@router.post("", response_model=IdpOut, status_code=201)
def connect(body: ConnectBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> IdpOut:
    if body.provider not in PROVIDERS:
        raise HTTPException(status_code=422, detail="Choose an identity provider.")
    cls = PROVIDERS[body.provider]
    org = current_organisation(session)
    sealed = seal(body.secret.strip())                                     # refuses, with instructions, when no ASTRA_SECRET_KEY is set
    rule = _check_rule(body.provider, body.rule)
    try:
        cfg = cls.check_config(body.config)
        for h in _hosts_of(body.provider, cfg):
            HOST_CHECK(h)
        account = cls(cfg, body.secret.strip()).verify()
    except IdpError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    name = _clean(body.name or f"{cls.label} · {account}", 120)
    if session.scalar(select(IdpConnection.id).where(IdpConnection.organisation_id == org.id, IdpConnection.name == name)):
        raise HTTPException(status_code=409, detail="A connection with that name already exists.")
    c = IdpConnection(organisation_id=org.id, name=name, provider=body.provider, account=_clean(account, 200), config=cfg, secret_enc=sealed, rule=rule, created_by=user.name)
    session.add(c)
    session.commit()
    session.refresh(c)
    return _out(session, c)


@router.get("/{conn_id}", response_model=IdpOut)
def get_connection(conn_id: str, session: Session = Depends(get_session)) -> IdpOut:
    return _out(session, _get(session, conn_id))


class PatchBody(BaseModel):
    name: Optional[str] = Field(None, max_length=120)
    rule: Optional[Dict[str, str]] = None
    secret: Optional[str] = Field(None, max_length=2000)       # a new secret replaces the old one


@router.patch("/{conn_id}", response_model=IdpOut)
def update_connection(conn_id: str, body: PatchBody, session: Session = Depends(get_session)) -> IdpOut:
    c = _get(session, conn_id)
    if body.name is not None and body.name.strip():
        c.name = _clean(body.name, 120)
    if body.rule is not None:
        c.rule = _check_rule(c.provider, body.rule)
    if body.secret is not None and body.secret.strip():
        try:
            PROVIDERS[c.provider](c.config, body.secret.strip()).verify()
        except IdpError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        c.secret_enc = seal(body.secret.strip())
    session.commit()
    return _out(session, c)


@router.delete("/{conn_id}", status_code=204)
def disconnect(conn_id: str, session: Session = Depends(get_session)) -> None:
    session.delete(_get(session, conn_id))
    session.commit()


# ── Scanning ────────────────────────────────────────────────────────────────

_SCANNING: set = set()
_LOCK = threading.Lock()


def _annotate(session: Session, c: IdpConnection, result: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(result)
    imports = {i.agent_key: i for i in session.scalars(select(IdpImport).where(IdpImport.connection_id == c.id))}
    keys = [a["key"] for a in result["agents"]]
    existing = {a.agent_key: a for a in session.scalars(select(Agent).where(Agent.agent_key.in_(keys)))} if keys else {}
    for a in result["agents"]:
        imp, ex = imports.get(a["key"]), existing.get(a["key"])
        a["status"] = ("unchanged" if imp.fingerprint == a["fingerprint"] else "changed") if imp else ("exists" if ex else "new")
        a["has_contract"] = bool(ex is not None and _active(session, a["key"]) is not None)
    result["removed"] = sorted(k for k in imports if k not in set(keys))
    return result


class ScanOut(BaseModel):
    scan_id: str
    scanned_at: datetime
    agents: List[Dict[str, Any]]
    notes: List[str]
    stats: Dict[str, Any]
    removed: List[str]


def _scan_out(session: Session, c: IdpConnection, row: IdpScan) -> ScanOut:
    r = _annotate(session, c, row.result)
    for a in r["agents"]:
        m = a.pop("manifest", None) or {}
        a["warnings"], a["inferred"] = m.get("warnings", []), m.get("inferred", [])
    return ScanOut(scan_id=str(row.id), scanned_at=row.created_at, agents=r["agents"], notes=r["notes"], stats=r["stats"], removed=r["removed"])


def _latest(session: Session, c: IdpConnection) -> Optional[IdpScan]:
    return session.scalar(select(IdpScan).where(IdpScan.connection_id == c.id).order_by(IdpScan.created_at.desc()).limit(1))


@router.post("/{conn_id}/scan", response_model=ScanOut)
def scan(conn_id: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> ScanOut:
    c = _get(session, conn_id)
    with _LOCK:
        if c.id in _SCANNING:
            raise HTTPException(status_code=409, detail="This connection is already being read. Try again in a moment.")
        _SCANNING.add(c.id)
    try:
        try:
            records, notes = _provider(c).list_identities(c.rule)
        except IdpError as exc:
            c.status, c.last_error, c.last_scan_at = "ERROR", str(exc)[:400], datetime.now(timezone.utc)
            session.commit()
            raise HTTPException(status_code=502, detail=str(exc))
        agents = [a for a in (to_agent(r) for r in records) if a]
        unique, taken, dup = [], set(), set()
        for a in agents:
            if a["key"] in taken:
                dup.add(a["key"])
                continue
            taken.add(a["key"])
            unique.append(a)
        if dup:
            notes.append("Two identities have the same name (" + ", ".join(sorted(dup)) + "); only the first of each can be imported until one is renamed in the identity provider.")
        agents = unique
        row = IdpScan(connection_id=c.id, result={"agents": agents, "notes": notes, "stats": {"identities": len(records), "agents": len(agents), "with_privileged": sum(1 for a in agents if a["privileged"]),
                                                                                              "with_hygiene_issues": sum(1 for a in agents if a["hygiene"])}}, created_by=user.name)
        session.add(row)
        c.status, c.last_error, c.last_scan_at = "OK", None, datetime.now(timezone.utc)
        session.flush()
        for oid in list(session.scalars(select(IdpScan.id).where(IdpScan.connection_id == c.id).order_by(IdpScan.created_at.desc()).offset(KEEP_SCANS))):
            session.delete(session.get(IdpScan, oid))
        session.commit()
        session.refresh(row)
        return _scan_out(session, c, row)
    finally:
        with _LOCK:
            _SCANNING.discard(c.id)


@router.get("/{conn_id}/scan", response_model=Optional[ScanOut])
def latest_scan(conn_id: str, session: Session = Depends(get_session)) -> Optional[ScanOut]:
    c = _get(session, conn_id)
    row = _latest(session, c)
    return _scan_out(session, c, row) if row else None


def _found(session: Session, c: IdpConnection, key: str) -> Dict[str, Any]:
    row = _latest(session, c)
    a = next((x for x in row.result["agents"] if x["key"] == key), None) if row else None
    if a is None:
        raise HTTPException(status_code=404, detail="That identity is not in the latest scan.")
    return a


# ── Merging into an agent that is already known ─────────────────────────────

EDGE_LABEL = {"tool": "uses", "mcp": "connects", "data": "reads", "agent": "delegates", "memory": "stores"}


def _merged(session: Session, key: str, conv, types: Tuple[str, ...] = ("tool",)):
    """When the agent already has a design, add what the new source found (the identity's permissions, what telemetry observed) to it instead of replacing it."""
    agent = session.scalar(select(Agent).where(Agent.agent_key == key))
    design = session.get(Design, agent.design_id) if agent is not None and agent.design_id else None
    if design is None:
        return conv, False
    doc = design.document
    nodes, edges = copy.deepcopy(doc.get("nodes", [])), copy.deepcopy(doc.get("edges", []))
    primary = next((n for n in nodes if n.get("primary")), None)
    if primary is None:
        return conv, False
    have = {(n["type"], n["name"]) for n in nodes}
    taken = {n["id"] for n in nodes}
    added = 0
    for n in conv.nodes:
        if n["type"] not in types or n.get("primary") or (n["type"], n["name"]) in have:
            continue
        nid, i = f"idp{added + 1}", added + 1
        while nid in taken:
            i += 1
            nid = f"idp{i}"
        taken.add(nid)
        nodes.append({"id": nid, "type": n["type"], "name": n["name"], "p": n["p"], "primary": False})
        edges.append({"from": primary["id"], "to": nid, "label": EDGE_LABEL.get(n["type"], "uses")})
        have.add((n["type"], n["name"]))
        added += 1
    if len(nodes) > MAX_NODES:
        raise HTTPException(status_code=422, detail="Merging the identity's permissions would make the design larger than an agent model can hold.")
    merged = conv.model_copy(update={"nodes": nodes, "edges": edges})
    merged.recognised = list(conv.recognised) + [f"merged into the existing design: {added} element(s) added, nothing else changed"]
    return merged, True


class ImportBody(BaseModel):
    agents: List[str] = Field(min_length=1, max_length=100)
    profile: Optional[str] = Field(None, max_length=64)


def _convert(c: IdpConnection, a: Dict[str, Any]):
    return finish(copy.deepcopy(a["manifest"]), "identity-provider", [a["name"]], a["fingerprint"])


@router.get("/{conn_id}/agents/{key}")
def preview_agent(conn_id: str, key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    c = _get(session, conn_id)
    a = _found(session, c, key)
    conv, merged = _merged(session, key, _convert(c, a))
    analysis = analyse_agent(AgentAnalyseRequest(graph=_graph({"nodes": conv.nodes, "edges": conv.edges}), domain=AGENT_DOMAIN), session)
    ex = session.scalar(select(Agent).where(Agent.agent_key == key))
    contract = _active(session, key) if ex else None
    will = "drift" if contract else ("update" if ex and ex.design_id else "create")
    return {**conv.model_dump(), "analysis": analysis.model_dump(mode="json"), "source": {"provider": PROVIDERS[c.provider].label, "identity": a["kind"], "external_id": a["external_id"], "merged": merged},
            "existing": {"agent_exists": ex is not None, "has_active_contract": contract is not None, "will": will, "contract_version": contract.document["version"] if contract else None, "merges": merged}}


@router.post("/{conn_id}/import")
def import_selected(conn_id: str, body: ImportBody, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    c = _get(session, conn_id)
    row = _latest(session, c)
    if row is None:
        raise HTTPException(status_code=409, detail="Read the identity provider first.")
    label = PROVIDERS[c.provider].label
    results = []
    for key in body.agents:
        a = next((x for x in row.result["agents"] if x["key"] == key), None)
        if a is None:
            results.append({"key": key, "ok": False, "error": "It is not in the latest scan. Scan again."})
            continue
        try:
            conv, merged = _merged(session, key, _convert(c, a))
            prov = {"source": "identity-provider", "format": "identity-provider", "provider": label, "connection": c.name, "identity": a["kind"], "external_id": a["external_id"], "sha256": a["fingerprint"],
                    "imported_by": user.name, "imported_at": datetime.now(timezone.utc).isoformat(), "note": SOURCE_NOTE, "merged": merged,
                    "label": f"Imported from {label} ({a['kind'].replace('-', ' ')} {a['name']}), not verified against code"}
            out: ImportOut = apply_converted(session, user.name, conv, prov, body.profile)
        except HTTPException as exc:
            session.rollback()
            results.append({"key": key, "ok": False, "error": str(exc.detail)})
            continue
        imp = session.scalar(select(IdpImport).where(IdpImport.connection_id == c.id, IdpImport.agent_key == key))
        if imp is None:
            session.add(IdpImport(connection_id=c.id, agent_key=key, external_id=a["external_id"], fingerprint=a["fingerprint"], outcome=out.outcome))
        else:
            imp.external_id, imp.fingerprint, imp.outcome, imp.imported_at = a["external_id"], a["fingerprint"], out.outcome, datetime.now(timezone.utc)
        session.commit()
        results.append({"key": key, "ok": True, "outcome": out.outcome, "summary": out.summary, "drift_id": out.drift_id, "design_key": out.design_key, "merged": merged})
    return {"results": results}
