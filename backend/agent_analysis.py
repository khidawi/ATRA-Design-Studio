"""
Agent design studio — live analysis against the OWASP Agentic Top 10 (Task 3).

This used to be hardcoded in the page (studioAnalysis in studio/index.html).
The ten checks are now GRAPH rules in the database (db/seed.py, domain
OWASP_AGENTIC), evaluated here by the same rule_checks.py engine the model
studio's rules use. The page sends the design it is editing and gets back the
rows, and the codes to badge on the flagged elements.

Statuses keep the studio's own vocabulary (Covered / Partial / Gap / Not
applicable) rather than the model studio's red/amber/green.
"""
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from compliance_engine import to_design_graph
from compliance_schema import DesignGraphIn, RuleSeverity
from db.session import get_session
from regulations import require_domain
from rule_checks import CheckConfigError, evaluate_graph_rule

router = APIRouter(prefix="/api/agents", tags=["agents"])

AgentStatus = Literal["Covered", "Partial", "Gap", "Not applicable"]
_STATUS = {"GREEN": "Covered", "AMBER": "Partial", "RED": "Gap", "NOT_APPLICABLE": "Not applicable"}


class AgentAnalyseRequest(BaseModel):
    graph: DesignGraphIn
    domain: str = "OWASP_AGENTIC"


class AnalysisRow(BaseModel):
    id: str
    name: str
    status: AgentStatus
    why: str
    fix_label: Optional[str] = None
    has_fix: bool = False


class AgentAnalysis(BaseModel):
    domain: str
    rows: List[AnalysisRow]
    # element id -> the rule codes that flag it, space separated (e.g. "ASI01 ASI08")
    flags: Dict[str, str]
    covered: int
    applicable: int


@router.post("/analyse", response_model=AgentAnalysis)
def analyse_agent(req: AgentAnalyseRequest, session: Session = Depends(get_session)) -> AgentAnalysis:
    domain = require_domain(session, req.domain, "AGENT")
    graph = to_design_graph(req.graph)

    rows: List[AnalysisRow] = []
    flags: Dict[str, str] = {}
    for rule in domain.rule_set:
        if rule.check_type != "GRAPH":
            continue  # an agent domain is made of design checks
        config = rule.check_config
        code = config.get("code") or rule.citation
        fix_label = config.get("fix_label")
        default = "RED" if rule.severity == RuleSeverity.REQUIRED else "AMBER"
        try:
            outcome = evaluate_graph_rule(graph, config, default)
        except CheckConfigError as exc:
            rows.append(AnalysisRow(id=code, name=rule.title, status="Partial",
                                    why=f"This check is invalid and could not be evaluated: {exc}"))
            continue
        for node_id in outcome.flagged:
            flags[node_id] = f"{flags[node_id]} {code}" if node_id in flags else code
        status = _STATUS[outcome.status]
        rows.append(AnalysisRow(
            id=code, name=rule.title, status=status, why=outcome.message,
            fix_label=fix_label, has_fix=bool(fix_label) and status in ("Gap", "Partial"),
        ))

    return AgentAnalysis(
        domain=domain.domain_id,
        rows=rows,
        flags=flags,
        covered=sum(1 for r in rows if r.status == "Covered"),
        applicable=sum(1 for r in rows if r.status != "Not applicable"),
    )
