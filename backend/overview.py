"""
Overview and Compliance workspace (Task 7f). Nothing here is stored: both screens are computed on request from what the
other screens already keep (agents, contracts, findings, drift, coverage assignments, packs).

Demo agents and their sample findings and drift are never counted. The roles on the workspace (compliance, engineering,
auditor) are three views of the same data, not permissions: there is no sign-in yet (Task 8).
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from coverage_scorecard import coverage
from db.models import Agent, Contract, Design, DriftItem, EvidencePack, Finding
from db.session import get_session
from organisation import current_organisation
from packs import verify as verify_pack

router = APIRouter(prefix="/api", tags=["overview"])


class AttentionItem(BaseModel):
    title: str
    detail: str
    label: str
    tone: str          # bad | warn | muted | ok
    link: str


class ActivityItem(BaseModel):
    at: datetime
    text: str
    detail: str
    link: str


class OverviewOut(BaseModel):
    organisation: str
    demo_agents: int
    agents_total: int
    agents_with_contract: int
    agents_unowned: int
    agents_to_ratify: int
    coverage: Dict[str, int]
    findings: Dict[str, int]
    drift: Dict[str, int]
    attention: List[AttentionItem]
    activity: List[ActivityItem]


def _real_agents(session: Session) -> List[Agent]:
    return list(session.scalars(select(Agent).where(Agent.origin != "DEMO").order_by(Agent.created_at)))


def _active(session: Session) -> Dict[str, Contract]:
    return {c.deployment_id: c for c in session.scalars(select(Contract).where(
        Contract.object_type == "AGENT", Contract.status == "ACTIVE").order_by(Contract.issued_at))}


def _open_drift(session: Session) -> List[DriftItem]:
    return list(session.scalars(select(DriftItem).where(DriftItem.status == "OPEN", DriftItem.source != "DEMO").order_by(DriftItem.created_at.desc())))


def _open_findings(session: Session) -> List[Finding]:
    return list(session.scalars(select(Finding).where(Finding.status == "OPEN", Finding.source != "DEMO").order_by(Finding.created_at.desc())))


@router.get("/overview", response_model=OverviewOut)
def overview(session: Session = Depends(get_session)) -> OverviewOut:
    agents, active = _real_agents(session), _active(session)
    cov = coverage(session)
    drift, findings = _open_drift(session), _open_findings(session)
    sev = lambda s: sum(1 for f in findings if f.severity == s)

    attention: List[AttentionItem] = []
    for d in drift:
        attention.append(AttentionItem(
            title=f"{d.agent_key}: proposed change {('widens' if d.kind == 'Widening' else 'differs from')} the ratified contract",
            detail=f"{d.title} · {'simulated' if d.source == 'SIMULATED' else 'from the design studio'} · policy {d.policy}"
                   + (" · the proposed design is Blocked" if d.gate_after == "BLOCK" else ""),
            label="Drift", tone="bad" if d.gate_after == "BLOCK" or d.kind == "Widening" else "warn", link="drift"))
    for f in [f for f in findings if f.severity == "High"][:3]:
        attention.append(AttentionItem(title=f.title, detail=f"F-{f.seq} · {f.agent_key} · {f.class_code} · {f.source.lower()}", label="High", tone="bad", link="findings"))
    for r in [r for r in cov.rows if r.group == "OWASP" and r.status == "Gap"]:
        attention.append(AttentionItem(title=f"{r.code} {r.name} has a gap", detail=f"{r.summary} Owner: {r.owner or 'not assigned'} · {r.due_label}",
                                       label="Gap", tone="warn", link="coverage"))
    for a in [a for a in agents if a.status == "UNOWNED"]:
        attention.append(AttentionItem(title=f"{a.name} has no owner", detail=f"{a.framework} · {a.tools_count} tools · counts against ASI10", label="Unowned", tone="muted", link="agents"))
    for a in [a for a in agents if a.status == "TO_RATIFY"]:
        attention.append(AttentionItem(title=f"{a.name} is waiting for a ratified design", detail=f"Owner {a.owner or 'none'}", label="To ratify", tone="warn", link="agents"))

    events: List[ActivityItem] = []
    for c in session.scalars(select(Contract).where(Contract.origin == "COMPILED").order_by(Contract.issued_at.desc()).limit(12)):
        doc = c.document
        kind = "Agent contract" if c.object_type == "AGENT" else "Model contract"
        events.append(ActivityItem(at=c.issued_at, text=f"{kind} issued for {c.deployment_id} v{doc['version']}", detail=f"sha256:{c.contract_hash[:12]}… · by {doc.get('issued_by') or 'unknown'}",
                                   link="contract?agent=" + c.deployment_id if c.object_type == "AGENT" else "model/contracts"))
        if c.status == "REVOKED" and c.status_at:
            events.append(ActivityItem(at=c.status_at, text=f"Contract for {c.deployment_id} v{doc['version']} revoked", detail=f"{c.status_by}: {c.status_reason}", link="contract?agent=" + c.deployment_id))
    for f in session.scalars(select(Finding).where(Finding.source != "DEMO").order_by(Finding.created_at.desc()).limit(12)):
        events.append(ActivityItem(at=f.created_at, text=f"Finding raised on {f.agent_key}", detail=f"{f.class_code} · F-{f.seq} · {f.source.lower()}", link="findings"))
    for d in session.scalars(select(DriftItem).where(DriftItem.source != "DEMO").order_by(DriftItem.created_at.desc()).limit(12)):
        events.append(ActivityItem(at=d.created_at, text=f"Change proposed for {d.agent_key} ({d.kind.lower()})", detail=d.source_label.split(" · ")[0], link="drift"))
        if d.decided_at:
            events.append(ActivityItem(at=d.decided_at, text=f"Change for {d.agent_key} {d.status.lower()}", detail=f"by {d.decided_by}", link="drift"))
    for p in session.scalars(select(EvidencePack).order_by(EvidencePack.seq.desc()).limit(6)):
        events.append(ActivityItem(at=p.generated_at, text=f"{'Trust report' if p.template == 'TRUST' else 'Assurance Pack'} P-{p.seq} generated", detail=f"{p.claims} claims · {p.gaps} gaps stated", link="pack?key=P-" + str(p.seq)))
    events.sort(key=lambda e: e.at, reverse=True)

    owner_count = lambda s: sum(1 for a in agents if a.status == s)
    return OverviewOut(
        organisation=current_organisation(session).name,
        demo_agents=session.scalar(select(func.count()).select_from(Agent).where(Agent.origin == "DEMO")) or 0,
        agents_total=len(agents), agents_with_contract=sum(1 for a in agents if a.agent_key in active),
        agents_unowned=owner_count("UNOWNED"), agents_to_ratify=owner_count("TO_RATIFY"),
        coverage={"covered": cov.covered, "partial": cov.partial, "gap": cov.gap, "no_data": cov.no_data, "total": cov.covered + cov.partial + cov.gap + cov.no_data},
        findings={"open": len(findings), "high": sev("High"), "medium": sev("Medium"), "low": sev("Low")},
        drift={"open": len(drift), "from_design": sum(1 for d in drift if d.source == "DESIGN"), "simulated": sum(1 for d in drift if d.source == "SIMULATED")},
        attention=attention[:8], activity=events[:10])


# ── Compliance workspace ────────────────────────────────────────────────────

class WorkspaceOut(BaseModel):
    compliance: Dict[str, Any]
    engineering: Dict[str, Any]
    auditor: Dict[str, Any]


@router.get("/workspace", response_model=WorkspaceOut)
def workspace(session: Session = Depends(get_session)) -> WorkspaceOut:
    agents, active = _real_agents(session), _active(session)
    drift, cov = _open_drift(session), coverage(session)

    policy_of: Dict[str, List[str]] = {}
    for a in agents:
        c = active.get(a.agent_key)
        if c is not None:
            policy_of.setdefault(c.document["design_snapshot"].get("drift_policy") or "block", []).append(a.name)
    recent_packs = list(session.scalars(select(EvidencePack).order_by(EvidencePack.seq.desc()).limit(3)))

    compliance = {
        "queue": [{"agent": d.agent_key, "from_version": d.from_version, "kind": d.kind, "title": d.title,
                   "source": "Simulated" if d.source == "SIMULATED" else "Design studio", "gate_after": d.gate_after, "policy": d.policy} for d in drift],
        "gap_owners": [{"code": r.code, "name": r.name, "status": r.status, "owner": r.owner, "due": r.due_label, "note": r.note}
                       for r in cov.rows if r.group == "OWASP" and r.status in ("Gap", "Partial")],
        "policies": [{"policy": p, "agents": names} for p, names in sorted(policy_of.items())],
        "packs": [{"pack_key": f"P-{p.seq}", "template": p.template, "generated_at": p.generated_at, "period": p.period_label} for p in recent_packs],
    }

    waiting: List[Dict[str, Any]] = [{"type": "drift", "title": d.agent_key, "detail": f"{d.title} · policy {d.policy}" + (" · proposed design Blocked" if d.gate_after == "BLOCK" else ""), "link": "drift"} for d in drift]
    waiting += [{"type": "owner", "title": a.name, "detail": "No owner assigned", "link": "agents"} for a in agents if a.status == "UNOWNED"]
    live_designs = {a.design_id for a in agents if a.agent_key in active}
    for d in session.scalars(select(Design).where(Design.subject == "AGENT").order_by(Design.updated_at.desc())):
        if d.id not in live_designs:
            waiting.append({"type": "design", "title": d.name, "detail": "Saved design that is not ratified", "link": "studio", "design_key": d.design_key})
    findings = list(session.scalars(select(Finding).where(Finding.source != "DEMO").order_by(Finding.created_at.desc()).limit(10)))
    engineering = {"waiting": waiting, "tests": [{"finding_key": f"F-{f.seq}", "agent": f.agent_key, "class": f.class_code, "title": f.title, "drafted": f.test_spec is not None} for f in findings]}

    packs_out = []
    for p in session.scalars(select(EvidencePack).order_by(EvidencePack.seq.desc()).limit(10)):
        v = verify_pack(f"P-{p.seq}", session)
        packs_out.append({"pack_key": f"P-{p.seq}", "template": p.template, "generated_at": p.generated_at, "ok": v.ok, "contracts_ok": v.contracts_ok,
                          "contracts_checked": v.contracts_checked, "problems": v.problems, "notes": v.notes})
    decided = list(session.scalars(select(DriftItem).where(DriftItem.decided_at.is_not(None), DriftItem.source != "DEMO").order_by(DriftItem.decided_at.desc())))
    versions = session.scalar(select(func.count()).select_from(Contract).where(Contract.object_type == "AGENT")) or 0
    auditor = {"packs": packs_out, "contract_versions": versions,
               "decisions": [{"agent": d.agent_key, "status": d.status, "by": d.decided_by, "at": d.decided_at, "kind": d.kind} for d in decided[:10]],
               "approvers": sorted({d.decided_by for d in decided if d.decided_by})}
    return WorkspaceOut(compliance=compliance, engineering=engineering, auditor=auditor)
