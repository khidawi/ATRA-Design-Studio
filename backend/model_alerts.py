"""
Telling people when production monitoring finds something: alert channels.

  GET    /api/model-monitor/alerts/channels              the channels (the address is never returned, only its host)
  POST   /api/model-monitor/alerts/channels              add a webhook (an administrator)
  PATCH  /api/model-monitor/alerts/channels/{id}         pause or resume, change the minimum severity or the name
  DELETE /api/model-monitor/alerts/channels/{id}
  POST   /api/model-monitor/alerts/channels/{id}/test    send a test message and say what came back

When a monitor opens a new incident (a model version changed and behaves differently, review is not catching wrong outputs, a credential in a prompt, a
canary that stopped passing, drift, bias), every active channel whose minimum severity it reaches gets one message. The message says what was found and that
ASTRA only advises: nothing was stopped. Nothing else is sent: not records, not prompts, not replies.

The body is JSON with a `text` field (Slack, Mattermost and Teams "incoming webhook" style accept it) and an `astra` object with the fields, for a tool that
wants to parse it. The address is stored encrypted (it often carries a secret) and shown only as its host. It must be https, must have no user name in it, and
is refused if it points at a private or internal address unless an administrator has set ASTRA_REPO_ALLOW_PRIVATE_HOSTS=1; the check is repeated at every
delivery, redirects are not followed, and a failure is retried twice and then recorded on the channel ("last status"), never raised into the work that found the
incident. Delivery happens after the incident is saved, on a background thread, so a slow or broken channel cannot hold up the ingestion of records.

Not built: re-alerting while an incident stays unattended, quiet hours, e-mail and paging services (a webhook to them works).
"""
import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from auth import AuthUser, current_user
from db.models import AlertChannel
from db.session import SessionLocal, get_session
from organisation import current_organisation
from repo_connect import allow_private, seal, unseal

router = APIRouter(prefix="/api/model-monitor/alerts", tags=["model-monitor"])

SEVERITY_WORD = {1: "Low", 2: "Moderate", 3: "High", 4: "Severe", 5: "Critical"}
KIND_WORD = {"DRIFT_DETECTION": "Drift", "BIAS_BREACH": "Bias breach", "MODEL_FAILURE": "Model failure", "SUPPLY_CHAIN": "Model version changed", "HUMAN_OVERRIDE_FAILED": "Human review failing",
             "DATA_BREACH": "Data leaving the organisation", "SECURITY_EVENT": "Unsafe output"}
MAX_CHANNELS = 10
TIMEOUT_SECONDS = 6
PENDING: List[threading.Thread] = []                 # the delivery threads still running; tests join them


def _check_host(host: str) -> None:
    """The host must resolve to a public address (unless private hosts are allowed). Tests replace this."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"The host {host} could not be found.")
    if not allow_private():
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise ValueError(f"{host} points at a private or internal address, which this deployment does not allow (an administrator can permit it with ASTRA_REPO_ALLOW_PRIVATE_HOSTS=1).")


HOST_CHECK: Callable[[str], None] = _check_host


def check_address(url: str) -> str:
    """The cleaned address and its host, or a ValueError saying what is wrong."""
    url = (url or "").strip()
    if not url or len(url) > 1000 or any(c.isspace() for c in url):
        raise ValueError("Enter the webhook address, for example https://hooks.slack.com/services/...")
    p = urlparse(url)
    if p.scheme != "https" and not (p.scheme == "http" and allow_private()):
        raise ValueError("Only https addresses are accepted.")
    if p.username or p.password:
        raise ValueError("Do not put a user name or password in the address.")
    if not p.hostname:
        raise ValueError("The address has no host name.")
    HOST_CHECK(p.hostname)
    return p.hostname


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _post(url: str, payload: Dict[str, Any]) -> str:
    """One delivery. Returns a short status for the channel; never raises."""
    try:
        host = urlparse(url).hostname or ""
        HOST_CHECK(host)
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={"Content-Type": "application/json", "User-Agent": "astra-alerts/1"})
        opener = urllib.request.build_opener(_NoRedirect)
        for attempt in range(3):
            try:
                with opener.open(req, timeout=TIMEOUT_SECONDS) as r:
                    return f"delivered (HTTP {r.status})"
            except urllib.error.HTTPError as e:
                if e.code < 500 or attempt == 2:
                    return f"refused by the channel (HTTP {e.code})"
            except Exception as e:                                      # unreachable, timed out
                if attempt == 2:
                    return "could not reach the channel: " + str(e)[:150]
            time.sleep(1 + attempt * 2)
        return "failed"
    except Exception as e:
        return "not sent: " + str(e)[:150]


def message(alert: Dict[str, Any]) -> Dict[str, Any]:
    sev = SEVERITY_WORD.get(alert["severity"], str(alert["severity"]))
    kind = KIND_WORD.get(alert["kind"], alert["kind"])
    return {"text": f"ASTRA · {sev} · {kind} · {alert['monitor']}\n{alert['title']}\nAdvice only: nothing was stopped or rerouted. Open AI Models → Runtime to see the evidence and decide.",
            "astra": {"incident": alert["id"], "monitor": alert["monitor"], "kind": alert["kind"], "severity": alert["severity"], "detected_at": alert["detected_at"], "title": alert["title"]}}


def _deliver(org_id: uuid.UUID, alerts: List[Dict[str, Any]]) -> None:
    try:
        with SessionLocal() as s:
            channels = list(s.scalars(select(AlertChannel).where(AlertChannel.organisation_id == org_id, AlertChannel.active.is_(True))))
            for ch in channels:
                url = unseal(ch.url_sealed)
                status = None
                for a in alerts:
                    if a["severity"] < ch.min_severity:
                        continue
                    status = _post(url, message(a)) if url else "the stored address could not be decrypted (is ASTRA_SECRET_KEY the same as when it was saved?)"
                if status:
                    ch.last_status, ch.last_at = status, datetime.now(timezone.utc)
            s.commit()
    except Exception:                                                  # an alert must never break anything
        pass


def queue(session: Session, org_id: uuid.UUID, alert: Dict[str, Any]) -> None:
    """Remember an alert on the session; it is delivered only if and when the session commits."""
    session.info.setdefault("astra_alerts", []).append((org_id, alert))


@event.listens_for(Session, "after_commit")
def _after_commit(session: Session) -> None:
    items = session.info.pop("astra_alerts", None)
    if not items:
        return
    by_org: Dict[uuid.UUID, List[Dict[str, Any]]] = {}
    for org_id, a in items:
        by_org.setdefault(org_id, []).append(a)
    for org_id, alerts in by_org.items():
        t = threading.Thread(target=_deliver, args=(org_id, alerts), daemon=True, name="astra-alert")
        PENDING[:] = [x for x in PENDING if x.is_alive()] + [t]
        t.start()


@event.listens_for(Session, "after_rollback")
def _after_rollback(session: Session) -> None:
    session.info.pop("astra_alerts", None)


# ── Managing channels ───────────────────────────────────────────────────────

class ChannelIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    url: str = Field(max_length=1000)
    min_severity: int = Field(3, ge=1, le=5)


class ChannelPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=120)
    min_severity: Optional[int] = Field(None, ge=1, le=5)
    active: Optional[bool] = None


def _out(c: AlertChannel) -> Dict[str, Any]:
    return {"id": str(c.id), "name": c.name, "host": c.host, "min_severity": c.min_severity, "min_severity_word": SEVERITY_WORD.get(c.min_severity), "active": c.active,
            "last_status": c.last_status, "last_at": c.last_at, "created_by": c.created_by}


def _channel(session: Session, cid: str) -> AlertChannel:
    try:
        key = uuid.UUID(cid)
    except ValueError:
        raise HTTPException(status_code=404, detail="No such channel.")
    c = session.scalar(select(AlertChannel).where(AlertChannel.id == key, AlertChannel.organisation_id == current_organisation(session).id))
    if c is None:
        raise HTTPException(status_code=404, detail="No such channel.")
    return c


@router.get("/channels")
def list_channels(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    return [_out(c) for c in session.scalars(select(AlertChannel).where(AlertChannel.organisation_id == current_organisation(session).id).order_by(AlertChannel.created_at))]


@router.post("/channels", status_code=201)
def add_channel(body: ChannelIn, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    org = current_organisation(session)
    if session.query(AlertChannel).filter(AlertChannel.organisation_id == org.id).count() >= MAX_CHANNELS:
        raise HTTPException(status_code=409, detail=f"At most {MAX_CHANNELS} channels.")
    try:
        host = check_address(body.url)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    c = AlertChannel(organisation_id=org.id, name=body.name.strip(), url_sealed=seal(body.url.strip()), host=host[:200], min_severity=body.min_severity, created_by=user.name)
    session.add(c)
    session.commit()
    return _out(c)


@router.patch("/channels/{cid}")
def patch_channel(cid: str, body: ChannelPatch, session: Session = Depends(get_session)) -> Dict[str, Any]:
    c = _channel(session, cid)
    if body.name:
        c.name = body.name.strip()
    if body.min_severity:
        c.min_severity = body.min_severity
    if body.active is not None:
        c.active = body.active
    session.commit()
    return _out(c)


@router.delete("/channels/{cid}", status_code=204)
def delete_channel(cid: str, session: Session = Depends(get_session)) -> None:
    session.delete(_channel(session, cid))
    session.commit()


@router.post("/channels/{cid}/test")
def test_channel(cid: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    c = _channel(session, cid)
    url = unseal(c.url_sealed)
    if not url:
        raise HTTPException(status_code=422, detail="The stored address could not be decrypted. Is ASTRA_SECRET_KEY the one it was saved with? Remove the channel and add it again.")
    status = _post(url, message({"id": "TEST", "monitor": "a test message", "kind": "DRIFT_DETECTION", "severity": 3, "title": "This is a test from ASTRA. If you can read it, alerts will reach this channel.", "detected_at": datetime.now(timezone.utc).isoformat()}))
    c.last_status, c.last_at = status, datetime.now(timezone.utc)
    session.commit()
    return {"ok": status.startswith("delivered"), "status": status}
