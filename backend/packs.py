"""
Trust reports and Assurance Packs (Task 7e): immutable, hash-chained snapshots of what the platform can evidence.

A pack is built from real data at the moment it is generated: the agents that have an active contract, the coverage
scorecard, findings and drift decisions in the period, and each agent's design-time risk score. It is stored exactly as
hashed. Each pack's hash covers its content and the previous pack's hash, so removing or editing an earlier pack breaks
every later one, and verifying a pack re-checks that chain and re-hashes every contract it cites.

What a pack does NOT claim is part of it. It states, in its own words, that nothing was observed from a running agent
unless a finding's source says COLLECTED, how many findings came from the simulator, that sign-off is a typed name,
and that the risk weights are uncalibrated. Gaps (checks that fail, partly pass or could not be assessed, agents without
a contract, agents without an owner) are listed with their owner and due date, never hidden.

TRUST is the short, shareable form: no agent names, owners, finding details or per-agent results.
ASSURANCE is the full form for an auditor. Both carry the same hashes.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from auth import AuthUser, current_user
from compliance_schema import CompiledContract, compute_contract_hash
from coverage_scorecard import coverage
from db.models import Agent, Contract, DriftItem, EvidencePack, Finding, RemovedContract
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/packs", tags=["packs"])

GENESIS = "GENESIS"
FRAMEWORKS = {"OWASP_AGENTIC": "OWASP Top 10 for Agentic Applications", "RCR": "Design-time regulatory risk"}
PERIODS = {"30d": ("Last 30 days", 30), "90d": ("Last 90 days", 90), "all": ("All time", None)}


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def pack_hash(previous: str, content_hash: str) -> str:
    return hashlib.sha256(f"{previous}:{content_hash}".encode("utf-8")).hexdigest()


# ── Building the content ────────────────────────────────────────────────────

def _finding_record(f: Finding) -> Dict[str, Any]:
    return {"key": f"F-{f.seq}", "agent": f.agent_key, "severity": f.severity, "class": f.class_code, "title": f.title,
            "status": f.status, "source": f.source, "evidence": f.evidence, "contract_version": f.contract_version,
            "created_at": f.created_at.isoformat()}


def _drift_record(d: DriftItem) -> Dict[str, Any]:
    return {"id": str(d.id), "agent": d.agent_key, "kind": d.kind, "status": d.status, "source": d.source, "from_version": d.from_version,
            "decided_by": d.decided_by, "decided_at": d.decided_at.isoformat() if d.decided_at else None,
            "changes": [c["text"] for c in d.changes], "created_at": d.created_at.isoformat()}


def build_content(session: Session, template: str, period: str, frameworks: List[str], generated_by: str) -> Dict[str, Any]:
    trust = template == "TRUST"
    now = datetime.now(timezone.utc)
    label, days = PERIODS[period]
    start = now - timedelta(days=days) if days else None
    org = current_organisation(session)

    cov = coverage(session)
    if cov.agents_in_scope == 0:
        raise HTTPException(status_code=409, detail="No agent has an active contract, so there is nothing to attest. Ratify an agent design first.")

    agents = list(session.scalars(select(Agent).where(Agent.origin != "DEMO").order_by(Agent.created_at, Agent.name)))
    contracts = {c.deployment_id: c for c in session.scalars(select(Contract).where(
        Contract.object_type == "AGENT", Contract.status == "ACTIVE").order_by(Contract.issued_at))}
    in_scope = [a for a in agents if a.agent_key in contracts]
    label_of = {a.agent_key: f"Agent {i + 1}" for i, a in enumerate(in_scope)}
    name_of = (lambda a: label_of[a.agent_key]) if trust else (lambda a: a.name)

    evidence: List[Dict[str, Any]] = []
    agent_rows: List[Dict[str, Any]] = []
    for a in in_scope:
        c = contracts[a.agent_key]
        doc = c.document
        rcr = (doc["design_snapshot"].get("rcr") or {})
        row: Dict[str, Any] = {"agent": name_of(a), "status": a.status,
                               "contract": {"version": doc["version"], "issued_at": doc["issued_at"], "hash": c.contract_hash}}
        if not trust:
            row["owner"] = a.owner
            row["contract"].update(id=c.contract_id, issued_by=doc.get("issued_by"))
            row["risk"] = {"score": rcr.get("score"), "band": rcr.get("band"), "gate": rcr.get("gate"), "worst_regulation": rcr.get("worst_instrument")}
            if "RCR" in frameworks:
                row["requirements"] = [{"name": r["name"], "instrument": r["instrument"], "class": r["cls"], "counted": r["counted"],
                                        "signed_off_by": r.get("signed_off_by") or None} for r in rcr.get("rows", [])]
        agent_rows.append(row)
        evidence.append({"type": "contract", "ref": c.contract_id, "hash": c.contract_hash, "agent": name_of(a)})

    finding_q = select(Finding).where(Finding.source != "DEMO")
    drift_q = select(DriftItem).where(DriftItem.source != "DEMO")
    if start:
        finding_q, drift_q = finding_q.where(Finding.created_at >= start), drift_q.where(DriftItem.created_at >= start)
    findings = list(session.scalars(finding_q.order_by(Finding.created_at)))
    drift = [d for d in session.scalars(drift_q.order_by(DriftItem.created_at)) if d.status != "SUPERSEDED"]
    for f in findings:
        evidence.append({"type": "finding", "ref": f"F-{f.seq}", "hash": sha(_finding_record(f))})
    for d in drift:
        evidence.append({"type": "drift", "ref": str(d.id), "hash": sha(_drift_record(d))})

    simulated = sum(1 for f in findings if f.source == "SIMULATED")
    collected = sum(1 for f in findings if f.source == "COLLECTED")
    sev = lambda s: sum(1 for f in findings if f.severity == s)
    findings_block: Dict[str, Any] = {"counts": {"total": len(findings), "high": sev("High"), "medium": sev("Medium"), "low": sev("Low"),
                                                 "open": sum(1 for f in findings if f.status == "OPEN"),
                                                 "acknowledged": sum(1 for f in findings if f.status == "ACKNOWLEDGED"),
                                                 "from_simulated_events": simulated, "from_collected_events": collected}}
    drift_block: Dict[str, Any] = {"counts": {"total": len(drift), "open": sum(1 for d in drift if d.status == "OPEN"),
                                              "approved": sum(1 for d in drift if d.status == "APPROVED"),
                                              "declined": sum(1 for d in drift if d.status == "DECLINED")}}
    if not trust:
        findings_block["items"] = [_finding_record(f) for f in findings]
        drift_block["items"] = [_drift_record(d) for d in drift]

    coverage_rows: List[Dict[str, Any]] = []
    if "OWASP_AGENTIC" in frameworks:
        for r in cov.rows:
            item: Dict[str, Any] = {"code": r.code, "name": r.name, "status": r.status, "agents_met": r.agents_covered,
                                    "agents_applicable": r.agents_applicable, "open_findings": r.open_findings,
                                    "owner": r.owner, "due": r.due_label, "summary": r.summary if not trust else None}
            if not trust:
                item["breakdown"] = [{"agent": b.agent, "contract": b.version, "status": b.status, "why": b.why} for b in r.breakdown]
            coverage_rows.append(item)

    claims: List[Dict[str, Any]] = []
    for r in coverage_rows:
        if r["status"] == "No data":
            continue
        claims.append({"id": f"C-{len(claims) + 1}", "text": f"{r['code']} {r['name']}: {r['status']} across {r['agents_applicable']} agent(s)",
                       "status": "evidenced" if r["status"] == "Covered" else "gap_stated", "evidence": [e["ref"] for e in evidence if e["type"] == "contract"]})
    for e in [e for e in evidence if e["type"] == "contract"]:
        row = next(x for x in agent_rows if x["agent"] == e["agent"])
        claims.append({"id": f"C-{len(claims) + 1}", "text": f"{row['agent']} operates under ratified contract v{row['contract']['version']}",
                       "status": "evidenced", "evidence": [e["ref"]]})
    claims.append({"id": f"C-{len(claims) + 1}", "status": "evidenced", "evidence": [e["ref"] for e in evidence if e["type"] == "finding"],
                   "text": f"{findings_block['counts']['open']} open and {findings_block['counts']['acknowledged']} acknowledged findings in the period "
                           f"({simulated} from simulated events, {collected} from collected events)"})

    gaps: List[Dict[str, Any]] = []
    for r in coverage_rows:
        if r["status"] in ("Gap", "Partial", "No data"):
            if r["status"] == "No data":
                text_ = f"{r['code']} {r['name']}: not assessable, no agent in scope"
            else:
                text_ = f"{r['code']} {r['name']}: {r['status']}" + (f". {r['summary']}" if r["summary"] else "")
            gaps.append({"id": f"G-{len(gaps) + 1}", "check": r["code"], "text": text_, "status": r["status"], "owner": r["owner"], "due": r["due"]})
    without = [a for a in agents if a.agent_key not in contracts]
    if without:
        gaps.append({"id": f"G-{len(gaps) + 1}", "check": None, "status": "Gap", "owner": None, "due": None,
                     "text": f"{len(without)} agent(s) in the inventory have no active contract" + ("" if trust else ": " + ", ".join(a.name for a in without))})
    unowned = [a for a in agents if a.status == "UNOWNED"]
    if unowned:
        gaps.append({"id": f"G-{len(gaps) + 1}", "check": "ASI10", "status": "Gap", "owner": None, "due": None,
                     "text": f"{len(unowned)} agent(s) have no owner" + ("" if trust else ": " + ", ".join(a.name for a in unowned))})

    limits = [
        "Nothing in this pack was observed from a running agent unless a finding below has the source COLLECTED. No collector reads code, telemetry or an identity provider yet.",
        f"{simulated} of the {len(findings)} findings in the period come from simulated events and are disclosed as such.",
        "Each approval is recorded against the signed-in person who made it (local accounts with a password); there is no second factor and no second approver.",
        "Risk scores use weights and floors that are judgement values and have not been calibrated. A Clear result does not certify compliance.",
        "Coverage is the worst result across agents, re-checked against the rules in force at generation time.",
    ]
    if "RCR" not in frameworks and not trust:
        limits.append("Design-time regulatory requirements (GDPR, EU AI Act and similar) were not included in this pack.")

    return {
        "schema": "astra.pack/1", "template": template, "organisation": org.name, "generated_at": now.isoformat(), "generated_by": generated_by,
        "period": {"label": label, "from": start.isoformat() if start else None, "to": now.isoformat()},
        "frameworks": [FRAMEWORKS[f] for f in frameworks],
        "approval_mode": "Single signed-in reviewer per action; recorded in the audit log",
        "limits": limits,
        "scope": {"agents_in_scope": len(in_scope), "agents_without_contract": len(without), "unowned_agents": len(unowned)},
        "agents": agent_rows, "coverage": coverage_rows, "findings": findings_block, "drift": drift_block,
        "claims": claims, "gaps": gaps, "evidence": evidence,
    }


# ── API ─────────────────────────────────────────────────────────────────────

class PackSummary(BaseModel):
    pack_key: str
    template: str
    period_label: str
    generated_by: str
    generated_at: datetime
    claims: int
    evidenced: int
    gaps: int
    evidence_count: int
    content_hash: str
    previous_pack_hash: str
    pack_hash: str


class PackOut(PackSummary):
    content: Dict[str, Any]


def _summary(p: EvidencePack) -> Dict[str, Any]:
    return dict(pack_key=f"P-{p.seq}", template=p.template, period_label=p.period_label, generated_by=p.generated_by, generated_at=p.generated_at,
                claims=p.claims, evidenced=p.evidenced, gaps=p.gaps, evidence_count=p.evidence_count, content_hash=p.content_hash,
                previous_pack_hash=p.previous_pack_hash, pack_hash=p.pack_hash)


def _get(session: Session, key: str) -> EvidencePack:
    try:
        seq = int(key.removeprefix("P-"))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such pack.")
    p = session.scalar(select(EvidencePack).where(EvidencePack.seq == seq))
    if p is None:
        raise HTTPException(status_code=404, detail="No such pack.")
    return p


class GenerateRequest(BaseModel):
    template: Literal["TRUST", "ASSURANCE"]
    period: Literal["30d", "90d", "all"] = "30d"
    frameworks: List[Literal["OWASP_AGENTIC", "RCR"]] = Field(default_factory=lambda: ["OWASP_AGENTIC", "RCR"])
    generated_by: str = Field("", max_length=120)      # ignored: the signed-in person is recorded

    @field_validator("generated_by", mode="before")
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


@router.post("", response_model=PackOut, status_code=201)
def generate(body: GenerateRequest, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> PackOut:
    if not body.frameworks:
        raise HTTPException(status_code=422, detail="Choose at least one framework.")
    session.execute(text("SELECT pg_advisory_xact_lock(7001)"))              # one pack at a time, so the chain has no fork
    content = build_content(session, body.template, body.period, body.frameworks, user.name)
    previous = session.scalar(select(EvidencePack.pack_hash).order_by(EvidencePack.seq.desc()).limit(1)) or GENESIS
    ch = sha(content)
    claims = len(content["claims"])
    p = EvidencePack(organisation_id=current_organisation(session).id, template=body.template, period_label=PERIODS[body.period][0],
                     generated_by=user.name, content=content, content_hash=ch, previous_pack_hash=previous, pack_hash=pack_hash(previous, ch),
                     claims=claims, evidenced=sum(1 for c in content["claims"] if c["status"] == "evidenced"),
                     gaps=len(content["gaps"]), evidence_count=len(content["evidence"]))
    session.add(p)
    session.commit()
    session.refresh(p)
    return PackOut(**_summary(p), content=p.content)


@router.get("", response_model=List[PackSummary])
def list_packs(session: Session = Depends(get_session)) -> List[PackSummary]:
    return [PackSummary(**_summary(p)) for p in session.scalars(select(EvidencePack).order_by(EvidencePack.seq.desc()))]


@router.get("/{key}", response_model=PackOut)
def get_pack(key: str, session: Session = Depends(get_session)) -> PackOut:
    p = _get(session, key)
    return PackOut(**_summary(p), content=p.content)


class VerifyOut(BaseModel):
    pack_key: str
    ok: bool
    content_ok: bool
    chain_ok: bool
    broken_at: Optional[str]
    contracts_checked: int
    contracts_ok: int
    problems: List[str]
    notes: List[str]


@router.get("/{key}/verify", response_model=VerifyOut)
def verify(key: str, session: Session = Depends(get_session)) -> VerifyOut:
    """Re-hashes this pack, walks the chain back to the first pack, and re-hashes every contract the pack cites."""
    pack = _get(session, key)
    problems: List[str] = []
    notes: List[str] = []
    content_ok = sha(pack.content) == pack.content_hash
    if not content_ok:
        problems.append(f"{key}: the stored content no longer matches its hash.")
    chain = list(session.scalars(select(EvidencePack).where(EvidencePack.seq <= pack.seq).order_by(EvidencePack.seq)))
    chain_ok, broken, expected_prev = True, None, GENESIS
    for p in chain:
        ok = (p.previous_pack_hash == expected_prev and pack_hash(p.previous_pack_hash, p.content_hash) == p.pack_hash and sha(p.content) == p.content_hash)
        if not ok:
            chain_ok, broken = False, f"P-{p.seq}"
            problems.append(f"The chain is broken at P-{p.seq}.")
            break
        expected_prev = p.pack_hash
    checked = good = 0
    for e in pack.content.get("evidence", []):
        if e["type"] != "contract":
            continue
        checked += 1
        row = session.scalar(select(Contract).where(Contract.contract_id == e["ref"]))
        gone = session.scalar(select(RemovedContract).where(RemovedContract.contract_id == e["ref"])) if row is None else None
        if gone is not None:                 # removed together with its agent or model: the pack stays valid, and says so
            checked -= 1
            notes.append(f"Contract {e['ref']} was removed on {gone.removed_at:%d %b %Y} by {gone.removed_by} ({gone.reason}); its hash is kept: {gone.contract_hash[:16]}.")
        elif row is None:
            problems.append(f"Contract {e['ref']} is no longer stored.")
        elif compute_contract_hash(CompiledContract(**row.document)) != e["hash"]:
            problems.append(f"Contract {e['ref']} no longer matches the hash recorded in this pack.")
        else:
            good += 1
            if row.status != "ACTIVE":
                notes.append(f"Contract {e['ref']} was active when this pack was generated and is now {row.status.lower()}.")
    return VerifyOut(pack_key=key, ok=not problems, content_ok=content_ok, chain_ok=chain_ok, broken_at=broken,
                     contracts_checked=checked, contracts_ok=good, problems=problems, notes=notes)
