"""
Compare agent designs side by side (Essex demo, Phase 1).

The same question asked of several designs for the same task: what does each one score, what is its gate, and exactly where do they differ? A council that is
choosing between a basic assistant and a bespoke, monitored tool does not need two reports to hold next to each other: it needs the one list of requirements and
checks where the answers differ.

Nothing is stored and nothing is changed. Each design is read from the design store and put through the same two engines that ratification uses (the OWASP
agentic checks and the design-time RCR score), against one profile so the comparison is like for like. The profile is the first design's own unless the request
names one.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_analysis import AgentAnalyseRequest, analyse_agent
from agent_registry import AGENT_DOMAIN, _graph
from db.models import Design
from db.session import get_session
from rcr import Declaration, RcrRequest, score_agent

router = APIRouter(prefix="/api/agents", tags=["agents"])

GATE_ORDER = {"APPROVE": 0, "REVIEW": 1, "BLOCK": 2}
GATE_WORDS = {"APPROVE": "Go", "REVIEW": "Conditional", "BLOCK": "No-go"}


class CompareRequest(BaseModel):
    design_keys: List[str] = Field(min_length=2, max_length=4)
    profile: Optional[str] = None


def assess_document(session: Session, doc: Dict[str, Any], profile: str) -> Dict[str, Any]:
    """One design's gate, score and the reasons behind them."""
    graph = _graph(doc)
    declarations = {k: Declaration(**v) for k, v in (doc.get("req") or {}).items()}
    rcr = score_agent(RcrRequest(profile=profile, graph=graph, declarations=declarations), session)
    analysis = analyse_agent(AgentAnalyseRequest(graph=graph, domain=AGENT_DOMAIN), session)
    primary = next((n for n in doc.get("nodes", []) if n.get("primary") and n.get("type") == "agent"), None)
    return {
        "name": (primary or {}).get("name") or "(no primary agent)",
        "profile": profile,
        "gate": rcr.gate, "verdict": GATE_WORDS[rcr.gate], "score": rcr.score, "band": rcr.band,
        "watch_line": rcr.watch_line, "blocked_line": rcr.blocked_line,
        "binding": rcr.binding, "floor": rcr.floor_name,
        "requirements": [{"key": r.key, "name": r.name, "cls": r.cls, "counted": r.counted, "reason": r.reason} for r in rcr.rows],
        "owasp": [{"id": r.id, "name": r.name, "status": r.status, "why": r.why} for r in analysis.rows],
        "owasp_covered": analysis.covered, "owasp_applicable": analysis.applicable,
    }


def _differences(options: List[Dict[str, Any]], section: str, key: str, label: str) -> List[Dict[str, Any]]:
    """Rows (requirements or OWASP checks) on which the options do not give the same answer."""
    status_field = "counted" if section == "requirements" else "status"
    out = []
    first = options[0][section]
    for row in first:
        values = []
        for o in options:
            match = next((r for r in o[section] if r[key] == row[key]), None)
            values.append({"status": match[status_field] if match else "n/a", "detail": (match.get("reason") or match.get("why")) if match else ""})
        if len({v["status"] for v in values}) > 1:
            out.append({"key": row[key], "name": row[label], "values": values})
    return out


@router.post("/compare")
def compare(body: CompareRequest, session: Session = Depends(get_session)) -> Dict[str, Any]:
    designs = []
    for k in body.design_keys:
        d = session.scalar(select(Design).where(Design.design_key == k))
        if d is None or d.subject != "AGENT":
            raise HTTPException(status_code=404, detail=f"No agent design {k!r}.")
        designs.append(d)
    profile = body.profile or designs[0].document.get("profile") or "payments"
    options = []
    for d in designs:
        o = assess_document(session, d.document, profile)
        o["design_key"] = d.design_key
        o["label"] = d.name
        options.append(o)
    best, worst = min(options, key=lambda o: (GATE_ORDER[o["gate"]], o["score"])), max(options, key=lambda o: (GATE_ORDER[o["gate"]], o["score"]))
    diffs_req = _differences(options, "requirements", "key", "name")
    diffs_owasp = _differences(options, "owasp", "id", "name")
    if len({o["gate"] for o in options}) == 1:
        headline = f"All {len(options)} designs get the same verdict ({options[0]['verdict']}); the differences are in the detail below."
    else:
        headline = (f"{best['label']} is {best['verdict']} (risk score {best['score']:g}); {worst['label']} is {worst['verdict']} (risk score {worst['score']:g}). "
                    f"{len(diffs_req)} requirement{'s' if len(diffs_req) != 1 else ''} and {len(diffs_owasp)} OWASP check{'s' if len(diffs_owasp) != 1 else ''} differ.")
    return {"profile": profile, "headline": headline, "options": options, "requirement_differences": diffs_req, "owasp_differences": diffs_owasp}
