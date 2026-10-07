"""
Documents the platform produces on request (PDF, JSON, CSV, YAML), all built on the server from what is stored.

Every export is a GET, so it needs only the read permission (the audit log needs the audit permission), and the file
arrives with a Content-Disposition header so the browser saves it under a sensible name. A PDF states what it was made
from and, where there is one, the hash that identifies the stored record, so the printed copy can be checked against the
platform. Nothing in an export is computed by a page.
"""
import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

import agent_contract
from audit import canonical
from coverage_scorecard import coverage
from db.models import AuditEvent, Contract, DriftItem, EvidencePack, Finding
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/export", tags=["export"])

# ── A small PDF writer ──────────────────────────────────────────────────────

_REPLACE = {"→": "->", "←": "<-", "—": "-", "–": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
            "…": "...", "−": "-", "✓": "ok", "φ": "phi", "≥": ">=", "≤": "<=", " ": " "}


def clean(text: Any) -> str:
    """Text the built-in PDF fonts can draw: anything outside Latin-1 is replaced rather than printed as a box."""
    s = "" if text is None else str(text)
    for k, v in _REPLACE.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "replace").decode("latin-1")


def esc(text: Any) -> str:
    return clean(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_STY = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=_STY["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13, alignment=TA_LEFT)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=10.5, textColor=colors.HexColor("#4A5563"))
H1 = ParagraphStyle("h1", parent=BODY, fontName="Helvetica-Bold", fontSize=18, leading=22, spaceAfter=2)
H2 = ParagraphStyle("h2", parent=BODY, fontName="Helvetica-Bold", fontSize=12, leading=15, spaceBefore=12, spaceAfter=4, textColor=colors.HexColor("#141A22"))
CELL = ParagraphStyle("cell", parent=BODY, fontSize=8.5, leading=11)
CODE = ParagraphStyle("code", parent=BODY, fontName="Courier", fontSize=7.8, leading=9.6, backColor=colors.HexColor("#F3F5F7"), borderPadding=5)

Block = Tuple[str, Any]
TONE = {"ok": "#1E7F4F", "bad": "#B42318", "warn": "#B45309", "muted": "#4A5563"}


def render_pdf(title: str, subtitle: str, blocks: Sequence[Block], footer: str) -> bytes:
    """blocks: ("h", text) ("p", text) ("small", text) ("kv", [(k, v)]) ("bullets", [text]) ("code", text)
    ("table", (header, rows, widths_in_percent))."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=20 * mm,
                            title=clean(title), author="ASTRA")
    width = A4[0] - 36 * mm
    story: List[Any] = [Paragraph(esc(title), H1), Paragraph(esc(subtitle), SMALL), Spacer(1, 4)]
    for kind, val in blocks:
        if kind == "h":
            story.append(Paragraph(esc(val), H2))
        elif kind == "p":
            story.append(Paragraph(esc(val), BODY))
            story.append(Spacer(1, 3))
        elif kind == "small":
            story.append(Paragraph(esc(val), SMALL))
        elif kind == "bullets":
            for item in val:
                story.append(Paragraph("&bull; " + esc(item), BODY))
            story.append(Spacer(1, 3))
        elif kind == "code":
            story.append(Preformatted(clean(val), CODE))
            story.append(Spacer(1, 4))
        elif kind == "kv":
            rows = [[Paragraph("<b>" + esc(k) + "</b>", CELL), Paragraph(esc(v), CELL)] for k, v in val]
            t = Table(rows, colWidths=[width * 0.28, width * 0.72])
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#DDE1E7")),
                                   ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
            story.append(t)
            story.append(Spacer(1, 4))
        elif kind == "table":
            header, rows, pct = val
            data = [[Paragraph("<b>" + esc(h) + "</b>", CELL) for h in header]] + [[Paragraph(esc(c), CELL) for c in r] for r in rows]
            t = Table(data, colWidths=[width * p / 100 for p in pct], repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EDF2")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#DDE1E7")),
                                   ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
            story.append(t)
            story.append(Spacer(1, 6))

    def page(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#4A5563"))
        canvas.drawString(18 * mm, 11 * mm, clean(footer)[:120])
        canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=page, onLaterPages=page)
    return buf.getvalue()


def cls_label(c: Any) -> str:
    return {"veto": "critical", "ordinary": "standard"}.get(str(c), str(c))


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def pdf_response(data: bytes, filename: str) -> Response:
    return Response(content=data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def file_response(text: str, media: str, filename: str) -> Response:
    return Response(content=text.encode("utf-8"), media_type=f"{media}; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "document"


def iso(value: Any) -> str:
    return value.strftime("%Y-%m-%d %H:%M") if hasattr(value, "strftime") else str(value or "")


# ── Packs ───────────────────────────────────────────────────────────────────

def _pack(session: Session, key: str) -> EvidencePack:
    try:
        seq = int(key.removeprefix("P-"))
    except ValueError:
        raise HTTPException(status_code=404, detail="No such pack.")
    p = session.scalar(select(EvidencePack).where(EvidencePack.seq == seq))
    if p is None:
        raise HTTPException(status_code=404, detail="No such pack.")
    return p


def pack_blocks(p: EvidencePack) -> List[Block]:
    x = p.content
    trust = x["template"] == "TRUST"
    c, d = x["findings"]["counts"], x["drift"]["counts"]
    blocks: List[Block] = [
        ("kv", [("Organisation", x["organisation"]), ("Period", x["period"]["label"]), ("Generated", f"{x['generated_at'][:16].replace('T', ' ')} UTC by {x['generated_by']}"),
                ("Frameworks", "; ".join(x["frameworks"])), ("Approval", x["approval_mode"]),
                ("Summary", f"{p.claims} claims, {p.evidenced} evidenced, {p.gaps} gaps stated, {p.evidence_count} evidence items")]),
        ("h", "What this pack does not claim"), ("bullets", x["limits"]),
        ("h", f"Agents in scope ({x['scope']['agents_in_scope']})"),
        ("table", (["Agent", "Contract", "Status"] + ([] if trust else ["Owner", "Design-time risk"]),
                   [[a["agent"], f"v{a['contract']['version']}  sha256:{a['contract']['hash'][:16]}...", a["status"]] +
                    ([] if trust else [a.get("owner") or "none", f"{a['risk']['score']} ({a['risk']['band']}, gate {a['risk']['gate']})" if a.get("risk") else ""]) for a in x["agents"]],
                   [30, 36, 12] if trust else [22, 30, 12, 14, 22])),
    ]
    if x["coverage"]:
        blocks += [("h", "Coverage"), ("table", (["Check", "Status", "Agents met", "Open findings", "Detail"],
                   [[f"{r['code']} {r['name']}", r["status"], f"{r['agents_met']} / {r['agents_applicable']}" if r["agents_applicable"] else "none in scope", r["open_findings"], r.get("summary") or ""] for r in x["coverage"]],
                   [24, 9, 12, 9, 46]))]
    for a in x["agents"]:
        if a.get("requirements"):
            blocks += [("h", f"Design-time regulatory requirements: {a['agent']}"), ("table", (["Requirement", "Instrument", "Class", "Counted as", "Signed off by"],
                       [[r["name"], r["instrument"], cls_label(r["class"]), r["counted"], r.get("signed_off_by") or ""] for r in a["requirements"]], [34, 16, 10, 14, 26]))]
    blocks += [("h", "Findings in the period"), ("p", f"{c['total']} in total: {c['high']} high, {c['medium']} medium, {c['low']} low; {c['open']} open, {c['acknowledged']} acknowledged; "
                                                  f"{c['from_simulated_events']} from simulated events, {c['from_collected_events']} from collected events.")]
    if x["findings"].get("items"):
        blocks.append(("table", (["Finding", "Agent", "Severity", "Source", "Evidence"], [[f"{f['key']} {f['title']}", f["agent"], f["severity"], f["source"].lower(), f["evidence"]] for f in x["findings"]["items"]], [36, 16, 9, 11, 28])))
    blocks += [("h", "Drift decisions in the period"), ("p", f"{d['total']} in total: {d['approved']} approved, {d['declined']} declined, {d['open']} still open.")]
    if x["drift"].get("items"):
        blocks.append(("table", (["Agent", "Kind", "Status", "Changes", "Decided by"], [[i["agent"], i["kind"], i["status"].lower(), "; ".join(i["changes"]), i.get("decided_by") or ""] for i in x["drift"]["items"]], [16, 10, 10, 46, 18])))
    blocks += [("h", f"Gaps stated ({len(x['gaps'])})"),
               ("table", (["Gap", "Owner", "Due"], [[g["text"], g.get("owner") or "no owner assigned", g.get("due") or ""] for g in x["gaps"]], [64, 20, 16])) if x["gaps"] else ("p", "No gaps."),
               ("h", f"Claims ({len(x['claims'])})"),
               ("table", (["Claim", "Status", "Evidence references"], [[k["text"], "evidenced" if k["status"] == "evidenced" else "gap stated", len(k["evidence"])] for k in x["claims"]], [66, 14, 20])),
               ("h", "Integrity"), ("code", f"pack     sha256:{p.pack_hash}\nprevious {p.previous_pack_hash}\ncontent  sha256:{p.content_hash}"),
               ("small", f"{p.evidence_count} evidence items are hashed (contracts, findings, drift decisions). Use Verify hash chain in the platform to re-check this pack, the packs before it and every contract it cites.")]
    return blocks


@router.get("/packs/{key}.pdf")
def pack_pdf(key: str, session: Session = Depends(get_session)) -> Response:
    p = _pack(session, key)
    name = "Trust report" if p.template == "TRUST" else "Assurance Pack"
    data = render_pdf(f"{name} {key}", f"{p.content['organisation']} - {p.period_label} - generated {iso(p.generated_at)} UTC by {p.generated_by}", pack_blocks(p),
                      f"{name} {key} - pack hash sha256:{p.pack_hash[:24]}...")
    return pdf_response(data, f"{safe_name(name.lower())}-{key}.pdf")


@router.get("/packs/{key}.json")
def pack_json(key: str, session: Session = Depends(get_session)) -> Response:
    p = _pack(session, key)
    doc = {"pack_key": key, "template": p.template, "period": p.period_label, "generated_by": p.generated_by, "generated_at": p.generated_at.isoformat(),
           "claims": p.claims, "evidenced": p.evidenced, "gaps": p.gaps, "evidence_count": p.evidence_count, "content_hash": p.content_hash,
           "previous_pack_hash": p.previous_pack_hash, "pack_hash": p.pack_hash, "content": p.content}
    return file_response(json.dumps(doc, indent=2), "application/json", f"{'trust-report' if p.template == 'TRUST' else 'assurance-pack'}-{key}.json")


# ── Contracts ───────────────────────────────────────────────────────────────

def _contract(session: Session, contract_id: str) -> Contract:
    c = session.scalar(select(Contract).where(Contract.contract_id == contract_id))
    if c is None:
        raise HTTPException(status_code=404, detail="No such contract.")
    return c


def _node_name(n: Dict[str, Any]) -> str:
    data = n.get("data") if isinstance(n.get("data"), dict) else {}
    for src in (n, data):
        for k in ("name", "title", "label", "identity"):
            if src.get(k):
                return str(src[k])
    return str(n.get("id", ""))


def _status_line(c: Contract) -> str:
    s = c.status.title()
    if c.status != "ACTIVE":
        s += f" {iso(c.status_at)}" + (f" by {c.status_by}" if c.status_by else "") + (f": {c.status_reason}" if c.status_reason else "")
    return s


def contract_blocks(c: Contract) -> List[Block]:
    doc = c.document
    snap = doc["design_snapshot"]
    head: List[Tuple[str, str]] = [("Contract id", doc["contract_id"]), ("Version", doc["version"]), ("Status now", _status_line(c)), ("Issued", f"{iso(c.issued_at)} UTC by {doc.get('issued_by') or 'unknown'}"),
                                   ("Domain", doc.get("domain", "")), ("Origin", c.origin.title())]
    blocks: List[Block] = [("kv", head)]
    if c.object_type == "AGENT":
        v = agent_contract.view(snap)
        rcr, ch = snap.get("rcr") or {}, snap.get("change") or {}
        blocks += [("h", "What this contract allows"), ("kv", [
            ("Owner", v["owner"] or "none"), ("Autonomy", v["autonomy"]), ("Goal", v["goal"] or "not stated"),
            ("Allowed tools", ", ".join(f"{t['name']} ({'write' if t['write'] else 'read'})" for t in v["tools"]) or "none"),
            ("MCP servers", ", ".join(f"{m['name']} ({'signed' if m['signed'] else 'unsigned'})" for m in v["mcp_servers"]) or "none"),
            ("Data and memory", ", ".join(v["data"] + [f"{m['name']} ({'long-term' if m['long_term'] else 'session'})" for m in v["memory"]]) or "none"),
            ("Inputs", ", ".join(i["name"] + (" (untrusted)" if i["untrusted"] else "") for i in v["inputs"]) or "none"),
            ("Delegation", ", ".join(v["delegates_to"]) or "none"), ("Human approval", ", ".join(v["approvals"]) or "none"),
            ("Guardrails and constraints", ", ".join(v["guardrails"] + v["constraints"]) or "none")])]
        blocks.append(("h", "Change from the previous version"))
        if ch.get("previous_version"):
            blocks.append(("p", f"Compared with version {ch['previous_version']}: " + ("widens what the agent can do; this version needs its own review." if ch.get("widens") else "does not widen what the agent can do.")))
            blocks.append(("bullets", [f"Widened: {x}" for x in ch.get("widened", [])] + [f"Narrowed: {x}" for x in ch.get("narrowed", [])] or ["No change to tools, data, delegation, autonomy or safeguards."]))
        else:
            blocks.append(("p", "First version of this contract."))
        analysis = (snap.get("analysis") or {}).get("rows", [])
        blocks += [("h", "Clause mappings at ratification"), ("table", (["Check", "Status", "Detail"], [[f"{r['id']} {r['name']}", r["status"], r["why"]] for r in analysis], [30, 12, 58]))]
        if rcr:
            blocks += [("h", "Design-time risk at ratification"),
                       ("p", f"Score {rcr.get('score')} - {rcr.get('band')} - gate {rcr.get('gate')}" + (f" - worst regulation {rcr['worst_instrument']}" if rcr.get("worst_instrument") else "") + ". Weights and floors are judgement values and have not been calibrated."),
                       ("table", (["Requirement", "Instrument", "Class", "Counted as", "Signed off by"], [[r["name"], r["instrument"], cls_label(r["cls"]), r["counted"], r.get("signed_off_by") or ""] for r in rcr.get("rows", [])], [34, 16, 10, 14, 26]))]
        blocks += [("h", "agent.contract.yaml"), ("code", v["yaml"])]
    else:
        graph = snap.get("graph") or {}
        names = {n.get("id"): _node_name(n) for n in graph.get("nodes", [])}
        ra = doc["risk_assessment"]
        blocks += [("kv", [("Deployment", graph.get("name") or doc["deployment_id"]), ("Overall status", ra["overall_status"])]), ("h", "Assessment by regulation"),
                   ("table", (["Regulation", "Status", "Passed", "Failed", "Undetermined"], [[b["category"], b["status"], b["passed"], b["failed"], b["unknown"]] for b in ra.get("score_breakdown", [])], [34, 16, 16, 16, 18])),
                   ("h", "Element verdicts"), ("table", (["Element", "Status", "Citation", "Reason"], [[names.get(v["node_id"], v["node_id"]), v["status"], v.get("citation") or "", v.get("reason", "")] for v in ra.get("element_verdicts", [])], [22, 10, 18, 50])),
                   ("p", f"The design held {len(graph.get('nodes', []))} elements and {len(graph.get('edges', []))} connections when it was compiled; the full design is in the JSON export.")]
    blocks += [("h", "Integrity"), ("code", f"contract sha256:{c.contract_hash}"),
               ("small", "The hash covers everything this contract was issued with. It does not cover the status above, which can change; verify it in the platform (Verify hash).")]
    return blocks


@router.get("/contracts/{contract_id}.pdf")
def contract_pdf(contract_id: str, session: Session = Depends(get_session)) -> Response:
    c = _contract(session, contract_id)
    doc = c.document
    snap = doc["design_snapshot"]
    label = (snap.get("name") if c.object_type == "AGENT" else (snap.get("graph") or {}).get("name")) or doc["deployment_id"]
    kind = "Agent contract" if c.object_type == "AGENT" else "Model contract"
    data = render_pdf(f"{kind}: {label}", f"Version {doc['version']} - issued {iso(c.issued_at)} UTC by {doc.get('issued_by') or 'unknown'}", contract_blocks(c),
                      f"{kind} {doc['contract_id']} - sha256:{c.contract_hash[:24]}...")
    return pdf_response(data, f"{safe_name(kind.lower())}-{safe_name(str(label))}-v{doc['version']}.pdf")


@router.get("/contracts/{contract_id}.json")
def contract_json(contract_id: str, session: Session = Depends(get_session)) -> Response:
    c = _contract(session, contract_id)
    return file_response(json.dumps(c.document, indent=2), "application/json", f"contract-{safe_name(c.deployment_id)}-v{c.document['version']}.json")


@router.get("/contracts/{contract_id}.yaml")
def contract_yaml(contract_id: str, session: Session = Depends(get_session)) -> Response:
    c = _contract(session, contract_id)
    if c.object_type != "AGENT":
        raise HTTPException(status_code=409, detail="Only agent contracts have an agent.contract.yaml.")
    v = agent_contract.view(c.document["design_snapshot"])
    header = f"# agent.contract.yaml - contract {c.document['contract_id']} v{c.document['version']} - sha256:{c.contract_hash}\n"
    return file_response(header + v["yaml"], "text/yaml", f"agent.contract-{safe_name(c.deployment_id)}-v{c.document['version']}.yaml")


# ── Coverage ────────────────────────────────────────────────────────────────

@router.get("/coverage.pdf")
def coverage_pdf(session: Session = Depends(get_session)) -> Response:
    cov = coverage(session)
    org = current_organisation(session).name
    blocks: List[Block] = [("kv", [("Organisation", org), ("Computed", stamp()), ("Agents in scope", f"{cov.agents_in_scope} with an active contract; {cov.agents_without_contract} without one; demo agents never counted"),
                                   ("Result", f"{cov.covered} covered, {cov.partial} partial, {cov.gap} gap, {cov.no_data} no data")]),
                           ("p", "A check's status is the worst across agents, re-checked now against the rules in force. Open findings come from the findings list."),
                           ("table", (["Check", "Status", "Agents met", "Open findings", "Owner", "Due"],
                                      [[f"{r.code} {r.name}", r.status, f"{r.agents_covered} / {r.agents_applicable}" if r.agents_applicable else "none", r.open_findings, r.owner or "not assigned", r.due_label] for r in cov.rows], [28, 9, 11, 10, 20, 22]))]
    for r in cov.rows:
        if r.breakdown:
            blocks += [("h", f"{r.code} {r.name}"), ("p", r.summary), ("table", (["Agent", "Contract", "Status", "Why"], [[b.agent, b.version or "none", b.status, b.why] for b in r.breakdown], [24, 10, 10, 56]))]
    return pdf_response(render_pdf("Coverage scorecard", f"{org} - OWASP Top 10 for Agentic Applications - {stamp()}", blocks, f"Coverage scorecard - {stamp()}"), "coverage-scorecard.pdf")


@router.get("/coverage.json")
def coverage_json(session: Session = Depends(get_session)) -> Response:
    return file_response(coverage(session).model_dump_json(indent=2), "application/json", "coverage-scorecard.json")


# ── Findings ────────────────────────────────────────────────────────────────

def _findings(session: Session) -> List[Finding]:
    return list(session.scalars(select(Finding).where(Finding.source != "DEMO").order_by(Finding.created_at.desc())))


@router.get("/findings.pdf")
def findings_pdf(session: Session = Depends(get_session)) -> Response:
    rows = _findings(session)
    org = current_organisation(session).name
    blocks: List[Block] = [("kv", [("Organisation", org), ("Generated", stamp()), ("Findings", f"{len(rows)} (demo findings are not included)"),
                                   ("Open", str(sum(1 for f in rows if f.status == "OPEN")))]),
                           ("p", "Each finding is a divergence between an observed event and the agent's active contract. Findings with the source SIMULATED came from the simulator, not from a running agent.")]
    for f in rows:
        blocks += [("h", f"F-{f.seq} {f.severity}: {f.title}"), ("kv", [("Agent", f"{f.agent_key} (contract v{f.contract_version or '?'})"), ("Class", f"{f.class_code} - {f.threat}"), ("Observed", f.observed),
                                                                        ("Permitted", f.permitted), ("Source", f.source.title()), ("Status", f.status.title() + (f" by {f.acknowledged_by}" if f.acknowledged_by else "")),
                                                                        ("Evidence", f.evidence), ("Raised", iso(f.created_at))])]
        if f.test_spec:
            blocks.append(("code", f.test_spec))
    if not rows:
        blocks.append(("p", "No findings."))
    return pdf_response(render_pdf("Findings report", f"{org} - {stamp()}", blocks, f"Findings report - {stamp()}"), "findings-report.pdf")


@router.get("/findings.csv")
def findings_csv(session: Session = Depends(get_session)) -> Response:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["finding", "raised_at", "agent", "contract_version", "severity", "class", "threat", "title", "observed", "permitted", "source", "status", "acknowledged_by", "evidence"])
    for f in _findings(session):
        w.writerow([f"F-{f.seq}", f.created_at.isoformat(), f.agent_key, f.contract_version, f.severity, f.class_code, f.threat, f.title, f.observed, f.permitted, f.source, f.status, f.acknowledged_by or "", f.evidence])
    return file_response(out.getvalue(), "text/csv", "findings.csv")


# ── Drift ───────────────────────────────────────────────────────────────────

@router.get("/drift/{item_id}.pdf")
def drift_pdf(item_id: str, session: Session = Depends(get_session)) -> Response:
    import uuid as _uuid
    try:
        d = session.get(DriftItem, _uuid.UUID(item_id))
    except ValueError:
        d = None
    if d is None:
        raise HTTPException(status_code=404, detail="No such drift item.")
    blocks: List[Block] = [("kv", [("Agent", d.agent_key), ("Compared with", f"contract {d.from_version}"), ("Source", d.source_label), ("Kind", d.kind), ("Drift policy", d.policy),
                                   ("Status", d.status.title() + (f" by {d.decided_by} on {iso(d.decided_at)}" if d.decided_by else "")), ("Decision note", d.decision_note or ""),
                                   ("New contract", d.new_contract_id or "none issued")]),
                           ("h", "Changes to the design"), ("table", (["", "Change", "Why it matters", "Class"], [[{"add": "+", "del": "-", "mod": "~"}[c["op"]], c["text"], c["note"], c["class"]] for c in d.changes], [5, 40, 40, 15])),
                           ("h", "Threat and risk impact if approved"), ("bullets", d.impact or ["No change to any threat check."])]
    return pdf_response(render_pdf(f"Drift review: {d.agent_key}", f"{d.title} - raised {iso(d.created_at)} UTC", blocks, f"Drift review {d.agent_key} - {stamp()}"), f"drift-{safe_name(d.agent_key)}-{str(d.id)[:8]}.pdf")


# ── Audit log ───────────────────────────────────────────────────────────────

def _audit(session: Session, limit: int) -> List[AuditEvent]:
    return list(session.scalars(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit)))


@router.get("/audit.csv")
def audit_csv(session: Session = Depends(get_session)) -> Response:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["seq", "at", "actor", "role", "action", "outcome", "path", "event_hash", "previous_hash"])
    for e in reversed(_audit(session, 100000)):
        w.writerow([e.seq, e.at.isoformat(), e.actor_name, e.actor_role or "", e.action, e.outcome, (e.payload.get("detail") or {}).get("path", ""), e.event_hash, e.prev_hash])
    return file_response(out.getvalue(), "text/csv", "audit-log.csv")


@router.get("/audit.json")
def audit_json(session: Session = Depends(get_session)) -> Response:
    events = [{"seq": e.seq, "prev_hash": e.prev_hash, "event_hash": e.event_hash, "payload": e.payload} for e in reversed(_audit(session, 100000))]
    return file_response(json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(), "events": events}, indent=2), "application/json", "audit-log.json")


@router.get("/audit.pdf")
def audit_pdf(session: Session = Depends(get_session)) -> Response:
    events = _audit(session, 500)
    head = events[0].event_hash if events else "none"
    blocks: List[Block] = [("kv", [("Exported", stamp()), ("Events shown", f"the newest {len(events)}"), ("Head hash", head)]),
                           ("p", "Each event's hash covers the one before it. The log holds who did what and when, never the content of a request."),
                           ("table", (["#", "When", "Who", "Action", "Outcome"], [[e.seq, iso(e.at), f"{e.actor_name}" + (f" ({e.actor_role})" if e.actor_role else ""), e.action, e.outcome] for e in events], [6, 17, 24, 41, 12]))]
    return pdf_response(render_pdf("Audit log", f"{current_organisation(session).name} - {stamp()}", blocks, f"Audit log - head sha256:{head[:24]}..."), "audit-log.pdf")
