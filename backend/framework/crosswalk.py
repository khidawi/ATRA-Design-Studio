"""ST-AI Framework — Standards Crosswalk
====================================================================

Maps every gate condition, pillar formula, and block reason in the
ST-AI framework to authoritative external standards so adopters can
present ST-AI evidence in compliance audits without re-mapping work.

Coverage:
    • NIST AI RMF 1.0  (GOVERN, MAP, MEASURE, MANAGE subcategories)
    • ISO/IEC 42001:2023 (AI Management System clauses)
    • ISO/IEC 23894:2023 (AI risk management clauses)
    • EU AI Act 2024 (Articles)
    • GDPR 2018 (Articles)
    • NIST SP 800-53 Rev 5 (security and privacy controls)
    • ISO/IEC 27001:2022 (information security controls)

Each crosswalk row is a tuple:
    (standard, clause_id, clause_title, relevance)
where relevance is one of:
    "primary"  — this standard's clause is the direct anchor for the ST-AI rule
    "related"  — the clause covers an overlapping concern but is not the sole
                 authority
    "evidence" — the clause specifies what evidence must be produced to
                 demonstrate the ST-AI rule has been satisfied
"""
from typing import Dict, List, Tuple

# A crosswalk entry: (standard, clause_id, title, relevance)
CrosswalkEntry = Tuple[str, str, str, str]


# ─── PILLAR CROSSWALKS ────────────────────────────────────────────────────────
# For each of the six risk-vector pillars, which standards' clauses
# define the equivalent concept.

PILLAR_CROSSWALK: Dict[str, List[CrosswalkEntry]] = {
    "Likelihood": [
        ("NIST AI RMF 1.0",  "MEASURE-2.7",  "AI system security and resilience are evaluated and documented",                                                  "primary"),
        ("ISO/IEC 23894",    "§6.4.3",       "Risk identification — likelihood determination",                                                                    "primary"),
        ("ISO/IEC 42001",    "§6.1.2",       "AI risk assessment — likelihood criteria",                                                                          "related"),
        ("ISO 31000",        "§6.4.3",       "Risk analysis: techniques to determine likelihood",                                                                  "primary"),
        ("NIST SP 800-30",   "§3.2.1",       "Threat event likelihood determination",                                                                              "related"),
        ("EU AI Act",        "Art 9(2)(a)",  "Identification and analysis of known and foreseeable risks",                                                         "related"),
    ],
    "Severity": [
        ("NIST AI RMF 1.0",  "MAP-5.1",      "Likelihood and magnitude of each identified risk are assessed",                                                     "primary"),
        ("ISO/IEC 23894",    "§6.4.4",       "Risk analysis — consequence determination",                                                                          "primary"),
        ("ISO/IEC 42001",    "§6.1.2",       "AI risk assessment — consequence criteria",                                                                          "related"),
        ("COSO ERM",         "Principle 12", "Assesses severity of risk",                                                                                          "primary"),
        ("NIST SP 800-30",   "§3.2.3",       "Impact determination",                                                                                                "related"),
        ("EU AI Act",        "Art 9(2)(b)",  "Estimation and evaluation of risks that may emerge in intended use",                                                  "related"),
        ("EU AI Act",        "Annex III",    "High-risk AI systems — severity classification",                                                                      "related"),
    ],
    "Vulnerability": [
        ("NIST AI RMF 1.0",  "MEASURE-2.7",  "AI security and resilience are evaluated",                                                                          "primary"),
        ("NIST SP 800-30",   "§2.3.3",       "Vulnerability determination",                                                                                         "primary"),
        ("ISO/IEC 27001",    "Annex A 8.7",  "Protection against malware (analogous controls for AI)",                                                              "related"),
        ("ISO/IEC 42001",    "§7.5.3",       "Control of documented information / configuration",                                                                   "related"),
        ("EU AI Act",        "Art 15",       "Accuracy, robustness and cybersecurity",                                                                              "primary"),
        ("NIST AI RMF 1.0",  "MEASURE-2.6",  "AI risks related to transparency and accountability are evaluated",                                                   "related"),
    ],
    "Uncertainty": [
        ("ISO/IEC 23894",    "§6.4.6",       "Risk evaluation — uncertainty quantification",                                                                       "primary"),
        ("NIST AI RMF 1.0",  "MEASURE-2.8",  "Risks associated with transparency and accountability are evaluated",                                                "related"),
        ("NIST AI RMF 1.0",  "MAP-2.3",      "Scientific integrity and TEVV considerations are identified",                                                        "primary"),
        ("ISO/IEC 42001",    "§6.1.4",       "AI risk evaluation — measurement uncertainty",                                                                       "related"),
        ("ISO/IEC TR 24028", "§6.3",         "Trustworthiness considerations — measurement reliability",                                                            "related"),
    ],
    "Autonomy": [
        ("EU AI Act",        "Art 6",        "Classification rules for high-risk AI systems",                                                                       "primary"),
        ("EU AI Act",        "Art 14",       "Human oversight (Art 14 requires effective human oversight for high-risk AI)",                                        "primary"),
        ("NIST AI RMF 1.0",  "GOVERN-1.1",   "Legal and regulatory requirements involving AI are understood and implemented",                                       "related"),
        ("NIST AI RMF 1.0",  "MEASURE-2.9",  "AI system has explainable behaviour relative to its intended use",                                                    "related"),
        ("ISO/IEC 42001",    "§7.4",         "Communication — defines lines of authority over AI decisions",                                                        "related"),
        ("ISO/IEC 23894",    "§6.5.2",       "Risk treatment — control of automated decisions",                                                                     "related"),
    ],
    "Evolution": [
        ("EU AI Act",        "Art 9",        "Risk management system — continuous, iterative process across lifecycle",                                             "primary"),
        ("EU AI Act",        "Art 17",       "Quality management system — change-control for high-risk AI",                                                         "primary"),
        ("NIST AI RMF 1.0",  "MANAGE-4.1",   "Post-deployment AI system monitoring plans are implemented",                                                          "primary"),
        ("NIST AI RMF 1.0",  "MANAGE-2.3",   "Procedures are followed to respond to and recover from a previously unknown risk",                                    "related"),
        ("ISO/IEC 42001",    "§9.1",         "Monitoring, measurement, analysis and evaluation",                                                                    "primary"),
        ("ISO/IEC 42001",    "§10.2",        "Nonconformity and corrective action",                                                                                 "related"),
        ("ISO/IEC 23894",    "§6.6",         "Monitoring and review of AI risk",                                                                                    "related"),
    ],
}


# ─── BLOCK-REASON CROSSWALKS ──────────────────────────────────────────────────
# For each PCSBlockReasonEnum value, which standards' clauses justify
# the block and which clauses specify the evidence to lift it.

BLOCK_REASON_CROSSWALK: Dict[str, List[CrosswalkEntry]] = {
    "MODEL_TYPE_FLOOR_VIOLATION": [
        ("NIST AI RMF 1.0",  "MAP-1.2",      "Inter-disciplinary AI risk identification (model-type-specific risks)",                                                "primary"),
        ("EU AI Act",        "Annex III",    "Specific risks associated with general-purpose AI models",                                                              "related"),
        ("ISO/IEC 42001",    "§6.1.2",       "Risk assessment must consider AI model type",                                                                          "related"),
    ],
    "CONSENT_MISSING": [
        ("GDPR",             "Art 6",        "Lawfulness of processing",                                                                                              "primary"),
        ("GDPR",             "Art 7",        "Conditions for consent",                                                                                                "primary"),
        ("GDPR",             "Art 9",        "Special categories of personal data — explicit consent required",                                                       "related"),
        ("EU AI Act",        "Art 10(2)(d)", "Examination of possible biases — requires consented training data",                                                     "related"),
        ("NIST AI RMF 1.0",  "GOVERN-5.1",   "Stakeholder rights and interests are addressed",                                                                        "evidence"),
        ("ISO/IEC 27701",    "§7.2.2",       "Identifying lawful basis for processing PII",                                                                           "evidence"),
    ],
    "DOMAIN_VIOLATION": [
        ("NIST AI RMF 1.0",  "MEASURE-2.6",  "AI risks related to transparency and accountability are evaluated",                                                    "primary"),
        ("NIST AI RMF 1.0",  "MANAGE-2.4",   "Mechanisms are in place to override, disengage, or deactivate AI systems",                                              "primary"),
        ("EU AI Act",        "Art 15(4)",    "Accuracy levels relevant to the intended purpose",                                                                       "primary"),
        ("ISO/IEC 42001",    "§8.2",         "AI system operation — domain constraints",                                                                              "related"),
    ],
    "DPIA_MISSING": [
        ("GDPR",             "Art 35",       "Data protection impact assessment",                                                                                     "primary"),
        ("GDPR",             "Art 36",       "Prior consultation with supervisory authority",                                                                          "related"),
        ("EU AI Act",        "Art 27",       "Fundamental rights impact assessment for high-risk AI systems",                                                          "primary"),
        ("NIST AI RMF 1.0",  "GOVERN-1.4",   "Risk management processes prioritise sensitive data",                                                                   "related"),
        ("ISO/IEC 29134",    "Full",         "Privacy impact assessment guidelines",                                                                                  "evidence"),
    ],
    "HITL_MISSING": [
        ("EU AI Act",        "Art 14",       "Human oversight — for high-risk AI",                                                                                    "primary"),
        ("NIST AI RMF 1.0",  "GOVERN-3.2",   "Policies and procedures define and differentiate roles of AI actors",                                                   "primary"),
        ("NIST AI RMF 1.0",  "MEASURE-2.9",  "AI system has explainable behaviour relative to its intended use",                                                       "related"),
        ("ISO/IEC 42001",    "§5.3",         "Roles, responsibilities and authorities",                                                                               "related"),
        ("ISO/IEC 23894",    "§6.5.2",       "Risk treatment options — human-in-the-loop controls",                                                                   "evidence"),
    ],
    "TRAINING_MISSING": [
        ("NIST AI RMF 1.0",  "GOVERN-2.2",   "Organisation's personnel are provided with AI risk training",                                                            "primary"),
        ("EU AI Act",        "Art 14(4)(a)", "Natural persons assigned human oversight have necessary competence",                                                     "primary"),
        ("ISO/IEC 42001",    "§7.2",         "Competence requirements for AI personnel",                                                                              "primary"),
        ("ISO/IEC 27001",    "§7.2",         "Personnel competence requirements (information security)",                                                              "related"),
    ],
    "HALLUCINATION_POLICY_MISSING": [
        ("EU AI Act",        "Art 50",       "Transparency obligations for AI systems interacting with natural persons; disclosure of synthetic / generated content",   "primary"),
        ("NIST AI 600-1",    "Confabulation","Generative-AI risk category: confidently stated but erroneous outputs — mandates monitoring, disclosure, and guardrails", "primary"),
        ("NIST AI RMF 1.0",  "MEASURE-2.10", "Privacy risks of the AI system are examined and documented",                                                                "related"),
        ("ISO/IEC 23894",    "§6.5.3",       "Risk treatment plan — control of model error",                                                                              "related"),
    ],
    "LIABILITY_BOUNDARY_MISSING": [
        ("EU AI Act",        "Art 25",       "Responsibilities along the AI value chain — provider re-classification when re-branding, modifying, or repurposing high-risk AI", "primary"),
        ("NIST AI RMF 1.0",  "GOVERN-1.1",   "Legal and regulatory requirements involving AI are understood and implemented",                                         "primary"),
        ("NIST AI RMF 1.0",  "GOVERN-6.1",   "Policies are in place to address AI risks arising from third-party software",                                            "primary"),
        ("ISO/IEC 42001",    "§5.3",         "Roles, responsibilities and authorities",                                                                               "related"),
    ],
    "CHALLENGE_MISSING": [
        ("EU AI Act",        "Art 86",       "Right to explanation of individual decision-making",                                                                    "primary"),
        ("GDPR",             "Art 22",       "Automated individual decision-making, including profiling",                                                              "primary"),
        ("GDPR",             "Art 15",       "Right of access by the data subject",                                                                                    "related"),
        ("NIST AI RMF 1.0",  "GOVERN-5.1",   "Stakeholder rights and interests are addressed",                                                                         "primary"),
    ],
    "RCF_FULL_CONSOLIDATION": [
        ("NIST AI RMF 1.0",  "GOVERN-2.1",   "Roles and responsibilities for AI risk management are documented",                                                       "primary"),
        ("ISO/IEC 42001",    "§5.3",         "Roles, responsibilities and authorities",                                                                               "primary"),
        ("ISO/IEC 27001",    "§5.3",         "Segregation of duties (analogous control)",                                                                              "primary"),
        ("COBIT 2019",       "EDM01",        "Ensured governance framework setting — separation of accountability",                                                    "related"),
    ],
    "PINN_NO_DOMAIN_RULE": [
        ("EU AI Act",        "Art 15(4)",    "Accuracy levels relevant to the intended purpose",                                                                       "primary"),
        ("NIST AI RMF 1.0",  "MEASURE-2.5",  "AI system performance is regularly assessed using documented test datasets",                                              "primary"),
        ("ISO/IEC 23894",    "§6.5.2",       "Risk treatment — domain constraint controls",                                                                            "related"),
    ],
    "MODEL_CARD_MISSING": [
        ("NIST AI RMF 1.0",  "GOVERN-1.5",   "Continual improvement processes for AI risks are in place",                                                              "primary"),
        ("NIST AI RMF 1.0",  "MAP-4.2",      "Internal risk controls for components of the AI system are identified",                                                  "primary"),
        ("EU AI Act",        "Art 11",       "Technical documentation requirements",                                                                                   "primary"),
        ("EU AI Act",        "Annex IV",     "Technical documentation contents",                                                                                       "evidence"),
        ("ISO/IEC 42001",    "§7.5",         "Documented information",                                                                                                 "related"),
    ],
}


# ─── PHASE / LIFECYCLE CROSSWALKS ─────────────────────────────────────────────
# Maps the ST-AI lifecycle phases to authoritative lifecycle frameworks.

PHASE_CROSSWALK: Dict[str, List[CrosswalkEntry]] = {
    "Design-time": [
        ("NIST AI RMF 1.0",  "MAP",          "Map function — context, capabilities, risks identified before deployment",                                              "primary"),
        ("NIST AI RMF 1.0",  "GOVERN",       "Govern function — policy, accountability, risk culture established",                                                    "primary"),
        ("ISO/IEC 42001",    "Clauses 4–6",  "Context, leadership, planning",                                                                                          "primary"),
        ("EU AI Act",        "Art 9–17",     "Risk management, data governance, technical documentation, record-keeping, transparency, oversight, accuracy",            "primary"),
    ],
    "Deployment & Runtime": [
        ("NIST AI RMF 1.0",  "MEASURE",      "Measure function — analyse, assess, benchmark AI risk",                                                                  "primary"),
        ("ISO/IEC 42001",    "Clauses 7–9",  "Support, operation, performance evaluation",                                                                             "primary"),
        ("EU AI Act",        "Art 16",       "Obligations of providers of high-risk AI systems",                                                                       "primary"),
        ("EU AI Act",        "Art 26",       "Obligations of deployers of high-risk AI systems",                                                                       "primary"),
    ],
    "Governance, Culture & End-of-Life": [
        ("NIST AI RMF 1.0",  "MANAGE",       "Manage function — risks are prioritised, acted upon, monitored",                                                          "primary"),
        ("ISO/IEC 42001",    "Clause 10",    "Improvement — nonconformity, corrective action, continual improvement",                                                  "primary"),
        ("EU AI Act",        "Art 72",       "Post-market monitoring system",                                                                                          "primary"),
        ("EU AI Act",        "Art 73",       "Reporting of serious incidents",                                                                                         "related"),
    ],
}


# ─── HELPERS ──────────────────────────────────────────────────────────────────

_STANDARD_COLOURS = {
    "NIST AI RMF 1.0":  "#1976d2",
    "ISO/IEC 42001":    "#388e3c",
    "ISO/IEC 23894":    "#388e3c",
    "ISO/IEC 27001":    "#388e3c",
    "ISO 31000":        "#388e3c",
    "ISO/IEC TR 24028": "#388e3c",
    "ISO/IEC 27701":    "#388e3c",
    "ISO/IEC 29134":    "#388e3c",
    "EU AI Act":        "#6a1b9a",
    "GDPR":             "#6a1b9a",
    "NIST SP 800-30":   "#1976d2",
    "NIST SP 800-53":   "#1976d2",
    "COSO ERM":         "#d84315",
    "COBIT 2019":       "#d84315",
}


def standard_colour(standard: str) -> str:
    """Return the brand colour for a standard (used for badges in the UI)."""
    return _STANDARD_COLOURS.get(standard, "#5a6680")


def for_pillar(pillar_name: str) -> List[CrosswalkEntry]:
    """Return the crosswalk entries for a named risk-vector pillar."""
    return PILLAR_CROSSWALK.get(pillar_name, [])


def for_block_reason(reason: str) -> List[CrosswalkEntry]:
    """Return the crosswalk entries for a PCSBlockReasonEnum value."""
    return BLOCK_REASON_CROSSWALK.get(reason, [])


def for_phase(phase: str) -> List[CrosswalkEntry]:
    """Return the crosswalk entries for a lifecycle phase."""
    return PHASE_CROSSWALK.get(phase, [])


def all_standards() -> List[str]:
    """Return every distinct standard referenced in any crosswalk."""
    seen = set()
    for entries in (*PILLAR_CROSSWALK.values(),
                    *BLOCK_REASON_CROSSWALK.values(),
                    *PHASE_CROSSWALK.values()):
        for entry in entries:
            seen.add(entry[0])
    return sorted(seen)


def coverage_summary() -> Dict[str, int]:
    """Count how many ST-AI rules each standard's clauses anchor."""
    counts: Dict[str, int] = {}
    for entries in (*PILLAR_CROSSWALK.values(),
                    *BLOCK_REASON_CROSSWALK.values(),
                    *PHASE_CROSSWALK.values()):
        for std, _, _, _ in entries:
            counts[std] = counts.get(std, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))