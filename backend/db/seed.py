"""
Reference data seeded into PostgreSQL on first start (Task 2, extended in Task 3).

This is the registry that used to be hardcoded in compliance_schema.py, moved
here so the verdicts, breakdowns and contracts the platform produced before the
database existed are reproduced exactly (apart from the two attestation rules
described below), plus Sam's OWASP agent rules, which used to be hardcoded in
the Agent design studio's page.

Applied once per SEED_VERSION and then never again for rows that already
exist, so anything edited or retired through the API survives a restart.
Raise SEED_VERSION when this module gains new rules.
"""
import logging
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AppSetting, Domain, DomainRule, Regulation, Rule

log = logging.getLogger("stai.db")

SEED_VERSION = 2  # 2: check types, attestation rules, the OWASP agent rules (Task 3)
SEED_SETTING = "reference_data_seed_version"

# instrument is the label shown on a verdict and in the per-regulation breakdown.
REGULATIONS: List[Dict[str, Optional[str]]] = [
    dict(instrument="GDPR", kind="REGULATION", source_url="https://eur-lex.europa.eu/eli/reg/2016/679/oj",
         name="General Data Protection Regulation (EU) 2016/679"),
    dict(instrument="EU AI Act", kind="REGULATION", source_url="https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
         name="Artificial Intelligence Act (EU) 2024/1689"),
    dict(instrument="OWASP", kind="STANDARD", source_url="https://genai.owasp.org/",
         name="OWASP Top 10 for LLM Applications and for Agentic Applications"),
    dict(instrument="NIST AI RMF", kind="STANDARD", source_url="https://www.nist.gov/itl/ai-risk-management-framework",
         name="NIST AI Risk Management Framework 1.0"),
    dict(instrument="ISO/IEC 42001", kind="STANDARD", source_url="https://www.iso.org/standard/81230.html",
         name="ISO/IEC 42001:2023 Artificial intelligence management system"),
    dict(instrument="ORG_POLICY", kind="ORG_POLICY", source_url=None, name="Organisation policy"),
]


def _rule(key, instrument, citation, title, maps_to=None, severity="REQUIRED",
          check_type=None, config=None, description="", subject="MODEL"):
    return dict(rule_key=key, instrument=instrument, citation=citation, title=title,
                maps_to_constraint_id=maps_to, severity=severity, description=description, subject=subject,
                check_type=check_type or ("CONSTRAINT" if maps_to else "ATTESTATION"),
                check_config=config or {})


# GDPR + EU AI Act citations for the six veto-class constraints (from
# framework/crosswalk.py's BLOCK_REASON_CROSSWALK) plus two modulating ones.
BASE_RULES = [
    _rule("GDPR-ART35-DPIA", "GDPR", "Art. 35", "Data protection impact assessment", "SC-DPIA-1"),
    _rule("EUAI-ART27-FRIA", "EU AI Act", "Art. 27", "Fundamental rights impact assessment for high-risk AI", "SC-DPIA-1"),
    _rule("EUAI-ART14-HITL", "EU AI Act", "Art. 14", "Human oversight for high-risk AI", "SC-HITL-1"),
    _rule("EUAI-ART50-HALLU", "EU AI Act", "Art. 50", "Transparency obligations / disclosure of generated content", "SC-HALLU-1"),
    _rule("EUAI-ART15-MAP", "EU AI Act", "Art. 15(4)", "Accuracy levels relevant to intended purpose", "SC-MAP-1"),
    _rule("EUAI-ART86-CHALL", "EU AI Act", "Art. 86", "Right to explanation of individual decision-making", "SC-CHALL-1"),
    _rule("GDPR-ART22-CHALL", "GDPR", "Art. 22", "Automated individual decision-making, including profiling", "SC-CHALL-1"),
    _rule("EUAI-ART25-LIAB", "EU AI Act", "Art. 25", "Responsibilities along the AI value chain", "SC-LIAB-1"),
    _rule("GDPR-ART6-CONSENT", "GDPR", "Art. 6", "Lawfulness of processing", "SC-CONSENT-1"),
    _rule("ORG-RCF", "ORG_POLICY", "Internal Policy", "Role-concentration segregation of duties", "SC-RCF-1"),
]

# These two had no linked Security Constraint, so they could never be evaluated and kept
# their domains at amber for good. They are attested by a Regulatory requirement node.
HEALTHCARE_RULES = [
    _rule("GDPR-ART9-SPECIAL", "GDPR", "Art. 9", "Processing of special categories of personal data (health data)", "SC-CONSENT-1"),
    _rule("EUAI-ANNEXIII-HEALTH", "EU AI Act", "Annex III",
          "High-risk classification for AI used in healthcare/essential services", None, "RECOMMENDED",
          description="Attested by a Regulatory requirement node for EU AI Act, clause Annex III, marked "
                      "Satisfied with evidence of the classification assessment."),
]
FINANCIAL_RULES = [
    _rule("OWASP-LLM-TOP10", "OWASP", "LLM Top 10", "OWASP Top 10 for LLM Applications — security baseline", None, "RECOMMENDED",
          description="Attested by a Regulatory requirement node for OWASP, clause LLM Top 10, marked "
                      "Satisfied with evidence of the review."),
]


# ── OWASP Top 10 for Agentic Applications, as data (Task 3) ──────────────────
# Ported from the Agent design studio's in-browser analysis. Each rule is a GRAPH check
# (rule_checks.py) over the agent design: typed elements with properties, and relations.

def _sel(type=None, where=None, primary=None):
    out = {}
    if type is not None:
        out["type"] = type
    if primary is not None:
        out["primary"] = primary
    if where:
        out["where"] = where
    return out


_WRITE_TOOL = _sel("tool", {"write": True})
_UNTRUSTED_INPUT = _sel("input", {"untrusted": True})
_LONG_MEMORY = _sel("memory", {"long": True})
_UNSIGNED_MCP = _sel("mcp", {"signed": {"falsy": True}})


def _guardrail(kind):
    return {"exists": _sel("guardrail", {"kind": kind})}


ASI_RULES = [
    _rule("OWASP-ASI01", "OWASP", "ASI01", "Agent goal hijack", check_type="GRAPH", subject="AGENT",
          description="Applies when untrusted input can reach a write-capable tool. Satisfied by a prompt-injection guardrail.",
          config=dict(code="ASI01", fix_label="Add injection filter",
                      applies_if={"all": [{"exists": _UNTRUSTED_INPUT}, {"exists": _WRITE_TOOL}]},
                      satisfied_if=_guardrail("injection"),
                      flag_nodes=[_sel(primary=True), _UNTRUSTED_INPUT],
                      messages={"not_applicable": "No untrusted input with write tools",
                                "satisfied": "Injection filter on untrusted input",
                                "unsatisfied": "Untrusted input reaches a write-capable tool"})),
    _rule("OWASP-ASI02", "OWASP", "ASI02", "Tool misuse", check_type="GRAPH", subject="AGENT",
          description="Applies when the agent has a write-capable tool. Satisfied by a human approval step.",
          config=dict(code="ASI02", fix_label="Add approval step", unsatisfied_status="AMBER",
                      applies_if={"exists": _WRITE_TOOL},
                      satisfied_if={"exists": _sel("approval")},
                      flag_nodes=[_WRITE_TOOL],
                      inapplicable=[{"when": {"always": True}, "status": "GREEN", "message": "Read-only tools declared"}],
                      messages={"satisfied": "Write tools gated by human approval",
                                "unsatisfied": "Write tool has no approval step"})),
    _rule("OWASP-ASI03", "OWASP", "ASI03", "Identity and privilege abuse", check_type="GRAPH", subject="AGENT",
          description="Always satisfied: the design declares its tool scopes.",
          config=dict(code="ASI03", satisfied_if={"always": True},
                      messages={"satisfied": "Tool scopes declared in the design"})),
    _rule("OWASP-ASI04", "OWASP", "ASI04", "Agentic supply chain", check_type="GRAPH", subject="AGENT",
          description="Applies when the agent connects to MCP servers. Satisfied when every server is signed.",
          config=dict(code="ASI04", fix_label="Require signed MCP",
                      applies_if={"exists": _sel("mcp")},
                      satisfied_if={"count": {"select": _UNSIGNED_MCP, "op": "==", "value": 0}},
                      flag_nodes=[_UNSIGNED_MCP],
                      vars={"n": {"count": _UNSIGNED_MCP}},
                      messages={"not_applicable": "No MCP servers", "satisfied": "All MCP servers signed",
                                "unsatisfied": "{n} unsigned MCP server"})),
    _rule("OWASP-ASI05", "OWASP", "ASI05", "Unexpected code execution", check_type="GRAPH", subject="AGENT",
          description="Not applicable until the design can declare code-execution tools.",
          config=dict(code="ASI05", applies_if={"never": True}, satisfied_if={"always": True},
                      messages={"not_applicable": "No code-execution tools"})),
    _rule("OWASP-ASI06", "OWASP", "ASI06", "Memory and context poisoning", check_type="GRAPH", subject="AGENT",
          description="Applies when the agent has long-term memory. Satisfied by a retention constraint.",
          config=dict(code="ASI06", fix_label="Add retention limit",
                      applies_if={"exists": _LONG_MEMORY},
                      satisfied_if={"exists": _sel("constraint", {"kind": "retention"})},
                      flag_nodes=[_LONG_MEMORY],
                      inapplicable=[{"when": {"exists": _sel("memory")}, "status": "GREEN", "message": "Session memory only"}],
                      messages={"not_applicable": "No memory", "satisfied": "Retention constraint on memory",
                                "unsatisfied": "Long-term memory without retention limit"})),
    _rule("OWASP-ASI07", "OWASP", "ASI07", "Inter-agent communication", check_type="GRAPH", subject="AGENT",
          description="Applies when the agent delegates to other agents; the delegations are declared in the design.",
          config=dict(code="ASI07", applies_if={"edge_exists": {"label": "delegates"}}, satisfied_if={"always": True},
                      vars={"n": {"edge_count": {"label": "delegates"}}},
                      messages={"not_applicable": "No delegations", "satisfied": "{n} delegation declared in the design"})),
    _rule("OWASP-ASI08", "OWASP", "ASI08", "Cascading failures", check_type="GRAPH", subject="AGENT",
          description="Satisfied by a rate-limit guardrail.",
          config=dict(code="ASI08", fix_label="Add rate limit", satisfied_if=_guardrail("rate"),
                      flag_nodes=[_sel(primary=True)],
                      messages={"satisfied": "Rate limit declared", "unsatisfied": "No rate limit between agents"})),
    _rule("OWASP-ASI09", "OWASP", "ASI09", "Human-agent trust", check_type="GRAPH", subject="AGENT",
          description="Applies when people interact with the agent. Satisfied by an AI-disclosure guardrail.",
          config=dict(code="ASI09", fix_label="Add disclosure", unsatisfied_status="AMBER",
                      applies_if={"exists": _sel("human")}, satisfied_if=_guardrail("disclosure"),
                      flag_nodes=[_sel("human")],
                      messages={"not_applicable": "Not customer-facing",
                                "satisfied": "Customers told they are dealing with AI",
                                "unsatisfied": "Customer-facing without AI disclosure"})),
    _rule("OWASP-ASI10", "OWASP", "ASI10", "Rogue agents", check_type="GRAPH", subject="AGENT",
          description="Satisfied when the primary agent has a named owner who holds the kill switch.",
          config=dict(code="ASI10", fix_label="Assign owner",
                      satisfied_if={"exists": _sel("agent", {"owner": {"nonempty": True}}, primary=True)},
                      flag_nodes=[_sel(primary=True)],
                      vars={"owner": {"prop": {"select": _sel(primary=True), "name": "owner"}}},
                      messages={"satisfied": "Owner {owner} holds the kill switch",
                                "unsatisfied": "No owner, so no kill-switch holder"})),
]


# Order matters: it is the order verdicts and the breakdown are listed in.
DOMAINS = [
    dict(domain_key="GENERAL", name="General / Org Policy",
         description="GDPR + EU AI Act + org policy — applies when no sector-specific domain fits.",
         rules=BASE_RULES),
    dict(domain_key="HEALTHCARE", name="Healthcare",
         description="GDPR + EU AI Act + org policy, with the special-category-data bar raised for clinical data.",
         rules=BASE_RULES + HEALTHCARE_RULES),
    dict(domain_key="FINANCIAL_SERVICES", name="Financial Services",
         description="GDPR + EU AI Act + OWASP + org policy.",
         rules=BASE_RULES + FINANCIAL_RULES),
    dict(domain_key="OWASP_AGENTIC", name="OWASP Agentic Top 10", subject="AGENT",
         description="The OWASP Top 10 for Agentic Applications, checked against an agent design.",
         rules=ASI_RULES),
]


def ensure_reference_data(session: Session) -> None:
    current = session.get(AppSetting, SEED_SETTING)
    if current is not None and int(current.value) >= SEED_VERSION:
        return

    regulations: Dict[str, Regulation] = {
        r.instrument: r for r in session.scalars(select(Regulation))
    }
    for spec in REGULATIONS:
        if spec["instrument"] not in regulations:
            reg = Regulation(**spec)
            session.add(reg)
            regulations[spec["instrument"]] = reg
    session.flush()

    rules: Dict[str, Rule] = {r.rule_key: r for r in session.scalars(select(Rule))}
    for domain_spec in DOMAINS:
        for rule_spec in domain_spec["rules"]:
            if rule_spec["rule_key"] in rules:
                continue
            fields = {k: v for k, v in rule_spec.items() if k != "instrument"}
            rule = Rule(regulation_id=regulations[rule_spec["instrument"]].id, origin="SEED", **fields)
            session.add(rule)
            rules[rule.rule_key] = rule
    session.flush()

    existing_domains = {d.domain_key: d for d in session.scalars(select(Domain))}
    for position, domain_spec in enumerate(DOMAINS):
        if domain_spec["domain_key"] in existing_domains:
            continue
        domain = Domain(
            domain_key=domain_spec["domain_key"], name=domain_spec["name"],
            description=domain_spec["description"], position=position,
            subject=domain_spec.get("subject", "MODEL"),
        )
        session.add(domain)
        session.flush()
        for rule_position, rule_spec in enumerate(domain_spec["rules"]):
            session.add(DomainRule(
                domain_id=domain.id, rule_id=rules[rule_spec["rule_key"]].id, position=rule_position,
            ))

    if current is None:
        session.add(AppSetting(key=SEED_SETTING, value=str(SEED_VERSION)))
    else:
        current.value = str(SEED_VERSION)
    session.commit()
    log.info("Seeded reference data (version %s)", SEED_VERSION)
