"""ST-AI Framework — Canonical Tropos Catalogue
=================================================================

The static knowledge base of goals, anti-goals, threats, and security
constraints that the Tropos model draws from. Every PCS sub-term has
at least one Goal anchor; every Goal has at least one AntiGoal; every
AntiGoal is realised by at least one Threat; every Threat is mediated
by at least one SecurityConstraint.

This is what makes ST-AI recognisably *Tropos*-derived rather than
just risk-scoring-with-cross-references — the score is the output;
the catalogue below is the methodology behind it.

Catalogue numbering convention:
    G-<pillar>-<n>    : Goal
    AG-<pillar>-<n>   : AntiGoal
    THR-<pillar>-<n>  : Threat
    SC-<short>-<n>    : Security Constraint
"""
from framework.tropos_model import (
    Goal, AntiGoal, Threat, SecurityConstraint,
    ActorRoleEnum,
)


# ─── GOALS ────────────────────────────────────────────────────────────────────
# Each PCS sub-term is anchored to one or more goals.

CANONICAL_GOALS = [
    # ── Likelihood pillar ───────────────────────────────────────────
    Goal(
        goal_id="G-L-1",
        name="Adversarial events remain rare in the exposure window",
        description="Across the time between audits, the probability of a "
                    "successful exploit, drift breach, or supply-chain "
                    "compromise stays below the deployment risk tier's "
                    "tolerance.",
        pcs_term="L",
        held_by=ActorRoleEnum.DEPLOYER,
    ),
    Goal(
        goal_id="G-L-2",
        name="Detection latency is shorter than exposure latency",
        description="τ < Δ — events are detected before they accumulate "
                    "to harm-bearing scale.",
        pcs_term="tau",
        held_by=ActorRoleEnum.OPERATOR,
    ),

    # ── Severity pillar ─────────────────────────────────────────────
    Goal(
        goal_id="G-S-1",
        name="Per-event impact stays within declared tolerance",
        description="The consequence of any single adverse event, weighted "
                    "by system criticality and domain multiplier, stays "
                    "below the gate threshold.",
        pcs_term="I",
        held_by=ActorRoleEnum.DEPLOYER,
    ),
    Goal(
        goal_id="G-S-2",
        name="Domain-specific safety constraints are respected",
        description="The deployment's domain rule (clinical safety, "
                    "financial fairness, etc.) is encoded as a runtime "
                    "constraint, not a documentation artefact.",
        pcs_term="Dm",
        held_by=ActorRoleEnum.TRAINER,
    ),

    # ── Vulnerability pillar ────────────────────────────────────────
    Goal(
        goal_id="G-V-1",
        name="Role separation is preserved across the deployment chain",
        description="No single physical actor concentrates trainer + "
                    "validator + deployer authority — segregation of "
                    "duties is preserved.",
        pcs_term="rcf_adj",
        held_by=ActorRoleEnum.VALIDATOR,
    ),
    Goal(
        goal_id="G-V-2",
        name="Human-side controls are commensurate with model risk",
        description="Operator training, HITL specification, and override "
                    "authority match the AI criticality declared at "
                    "registration.",
        pcs_term="Wh",
        held_by=ActorRoleEnum.OPERATOR,
    ),
    Goal(
        goal_id="G-V-3",
        name="Retraining cycles are governed, not ad-hoc",
        description="Feedback loops that retrain the model are subject to "
                    "the same gate decisions as the initial deployment.",
        pcs_term="Wf",
        held_by=ActorRoleEnum.TRAINER,
    ),
    Goal(
        goal_id="G-V-4",
        name="Threat-vector exposure is enumerated and mitigated",
        description="Every declared attack vector has a mapped "
                    "compensating control in the registry.",
        pcs_term="Wr",
        held_by=ActorRoleEnum.DEPLOYER,
    ),

    # ── Uncertainty pillar ──────────────────────────────────────────
    Goal(
        goal_id="G-U-1",
        name="Model behaviour is epistemically known",
        description="The framework's belief about the model's behaviour "
                    "is grounded in evidence — model cards, validation "
                    "datasets, peer review — not vendor assertion.",
        pcs_term="eps_b",
        held_by=ActorRoleEnum.VALIDATOR,
    ),
    Goal(
        goal_id="G-U-2",
        name="Control importance ratings are evidentially grounded",
        description="The ε_ia gap between control criticality and "
                    "implementation maturity is based on documented "
                    "assessments, not self-reported numbers.",
        pcs_term="eps_ia",
        held_by=ActorRoleEnum.VALIDATOR,
    ),

    # ── Autonomy pillar ─────────────────────────────────────────────
    Goal(
        goal_id="G-A-1",
        name="Autonomous action is bounded by HITL where criticality demands",
        description="As ACM rises, the system's authority to act without "
                    "human checkpoint contracts. SAFETY_CRITICAL AI never "
                    "acts autonomously on bound consequences.",
        pcs_term="acm",
        held_by=ActorRoleEnum.OPERATOR,
    ),

    # ── Evolution pillar ────────────────────────────────────────────
    Goal(
        goal_id="G-E-1",
        name="The system's drift across time stays observable",
        description="Whatever feedback loops, retraining cycles, or "
                    "self-modification paths exist, every change is "
                    "logged and within the audit cadence's reach.",
        pcs_term="Wf",
        held_by=ActorRoleEnum.OPERATOR,
    ),
    Goal(
        goal_id="G-E-2",
        name="Change-control gates apply to model updates",
        description="A retrained model passes through the same gate "
                    "decision as the original deployment — no silent "
                    "version bumps.",
        pcs_term="Wf",
        held_by=ActorRoleEnum.DEPLOYER,
    ),
]


# ─── ANTI-GOALS ──────────────────────────────────────────────────────────────
# What an adversary wants — the explicit negation of each goal.

CANONICAL_ANTI_GOALS = [
    AntiGoal(
        anti_goal_id="AG-L-1",
        name="Compromise the deployment without detection until material harm",
        description="Attacker aims to operate undetected for longer than "
                    "the audit cadence τ, allowing exposure Δ to "
                    "accumulate.",
        threatens="G-L-1",
        attacker_role="external adversary",
    ),
    AntiGoal(
        anti_goal_id="AG-L-2",
        name="Suppress or delay detection signals",
        description="Attacker aims to disable monitoring, mask drift "
                    "indicators, or rate-limit alerts so τ effectively "
                    "expands past Δ.",
        threatens="G-L-2",
        attacker_role="insider, supply chain",
    ),
    AntiGoal(
        anti_goal_id="AG-S-1",
        name="Maximise blast radius of any single event",
        description="Attacker exploits weakest domain assumption to "
                    "convert one trigger into many simultaneous harms.",
        threatens="G-S-1",
        attacker_role="external adversary, insider",
    ),
    AntiGoal(
        anti_goal_id="AG-S-2",
        name="Operate outside the declared domain",
        description="Attacker — or organic drift — pushes the model to "
                    "act on inputs outside the validated domain envelope, "
                    "voiding the safety case.",
        threatens="G-S-2",
        attacker_role="external, organic drift",
    ),
    AntiGoal(
        anti_goal_id="AG-V-1",
        name="Concentrate authority so no peer can refuse a change",
        description="A single actor accumulates trainer + validator + "
                    "deployer rights so model changes ship without "
                    "independent review.",
        threatens="G-V-1",
        attacker_role="insider",
    ),
    AntiGoal(
        anti_goal_id="AG-V-2",
        name="Exploit untrained or overconfident operators",
        description="The deployed model is presented to operators without "
                    "training on its failure modes, so misuse goes unchecked.",
        threatens="G-V-2",
        attacker_role="organisational neglect, social engineering",
    ),
    AntiGoal(
        anti_goal_id="AG-V-3",
        name="Smuggle uncontrolled retraining through the feedback loop",
        description="Automated retraining pipelines update model weights "
                    "without passing through the deployment gate.",
        threatens="G-V-3",
        attacker_role="data poisoning, insider",
    ),
    AntiGoal(
        anti_goal_id="AG-V-4",
        name="Exploit unmitigated attack vectors (CHAINED_AI, prompt injection, …)",
        description="Attacker uses declared-but-unmitigated vectors, or "
                    "ones the framework didn't enumerate, to reach the "
                    "model's decision path.",
        threatens="G-V-4",
        attacker_role="external adversary",
    ),
    AntiGoal(
        anti_goal_id="AG-U-1",
        name="Substitute confident assertion for evidence",
        description="Vendor or owner claims behavioural properties of the "
                    "model that aren't testable — and the framework "
                    "accepts the claim at face value.",
        threatens="G-U-1",
        attacker_role="supply chain, owner self-attestation",
    ),
    AntiGoal(
        anti_goal_id="AG-U-2",
        name="Game control importance scores to mask weakness",
        description="Self-rated implementation maturity inflates so the "
                    "ε_ia gap closes on paper but not in operation.",
        threatens="G-U-2",
        attacker_role="insider, governance neglect",
    ),
    AntiGoal(
        anti_goal_id="AG-A-1",
        name="Drift into autonomous high-consequence action",
        description="Operator-mediated decisions silently become "
                    "operator-rubber-stamped, then operator-skipped, until "
                    "the AI acts autonomously on safety-critical paths.",
        threatens="G-A-1",
        attacker_role="organisational drift, automation bias",
    ),
    AntiGoal(
        anti_goal_id="AG-E-1",
        name="Ship a different system under the same gate decision",
        description="Retraining, fine-tuning, or prompt-template updates "
                    "change the deployment's behaviour without re-running "
                    "the gate.",
        threatens="G-E-1",
        attacker_role="insider, vendor",
    ),
]


# ─── THREATS ─────────────────────────────────────────────────────────────────
# Concrete attack patterns that realise the anti-goals.

CANONICAL_THREATS = [
    Threat(
        threat_id="THR-L-1",
        name="Slow-and-low drift exploitation",
        description="Adversary feeds gradually-shifted inputs over the "
                    "audit cadence to bypass detection thresholds. "
                    "Materialises AG-L-1 by making τ effectively > Δ.",
        realises="AG-L-1",
        mitre_refs=["T1078 Valid Accounts", "T1574 Hijack Execution Flow"],
    ),
    Threat(
        threat_id="THR-L-2",
        name="Monitoring suppression",
        description="Disabling drift detectors, lowering alert thresholds, "
                    "or removing log streams so legitimate alarms go silent.",
        realises="AG-L-2",
        mitre_refs=["T1562 Impair Defenses"],
    ),
    Threat(
        threat_id="THR-S-1",
        name="Out-of-distribution domain exploitation",
        description="Crafted inputs steer the model outside the validated "
                    "domain, where safety guarantees no longer apply.",
        realises="AG-S-2",
    ),
    Threat(
        threat_id="THR-RCF-1",
        name="Role consolidation (single-actor pipeline)",
        description="Trainer + validator + deployer collapses to one human, "
                    "so no peer can refuse a model change. Quantified by "
                    "the framework's Role Concentration Factor.",
        realises="AG-V-1",
    ),
    Threat(
        threat_id="THR-V-2",
        name="Operator misuse via insufficient training",
        description="Operators interact with a deployed model without "
                    "training on its failure modes, leading to "
                    "automation bias and skipped HITL steps.",
        realises="AG-V-2",
    ),
    Threat(
        threat_id="THR-V-3",
        name="Automated retraining bypassing gate",
        description="Online-learning or scheduled retraining updates "
                    "weights without rerunning the deployment gate.",
        realises="AG-V-3",
    ),
    Threat(
        threat_id="THR-V-4-CHAIN",
        name="Chained AI attack vector",
        description="Multi-model composition where one model's output is "
                    "another's input — the framework's CHAINED_AI vector. "
                    "Compromise one model, you have compromised them all.",
        realises="AG-V-4",
    ),
    Threat(
        threat_id="THR-U-1",
        name="Hallucination accepted as fact",
        description="LLM or generative output is treated as ground truth "
                    "by downstream actors with no falsifier in the loop.",
        realises="AG-U-1",
    ),
    Threat(
        threat_id="THR-A-1",
        name="Automation bias drift",
        description="HITL specified at design becomes ceremonial in "
                    "operation; operators stop second-guessing model output.",
        realises="AG-A-1",
    ),
    Threat(
        threat_id="THR-E-1",
        name="Silent model substitution",
        description="A new model version replaces the deployed one without "
                    "re-running the gate decision. Common in vendor APIs.",
        realises="AG-E-1",
    ),
]


# ─── SECURITY CONSTRAINTS ────────────────────────────────────────────────────
# Named constraints imposed by an actor on a dependency to mitigate a threat.
# Each carries cross-references to external standards (the v5 crosswalk
# anchors).

CANONICAL_CONSTRAINTS = [
    SecurityConstraint(
        constraint_id="SC-RCF-1",
        name="Trainer and Validator must be distinct natural persons",
        description="The actor who trains the model cannot be the same "
                    "natural person who validates it. Enforces segregation "
                    "of duties at the most consequential boundary.",
        imposed_by="AI Governance Board",
        on_dependency=(ActorRoleEnum.VALIDATOR, ActorRoleEnum.TRAINER),
        condition="trainer_id ≠ validator_id (different natural persons)",
        because="THR-RCF-1",
        pcs_term="rcf_adj",
        standard_refs=[
            "NIST AI RMF GOVERN-2.1",
            "ISO/IEC 42001 §5.3",
            "ISO/IEC 27001 §5.3 (Segregation of duties)",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-RCF-2",
        name="Validator and Deployer must be distinct natural persons",
        description="The actor who certifies the model is fit cannot be "
                    "the same natural person who releases it to production.",
        imposed_by="AI Governance Board",
        on_dependency=(ActorRoleEnum.DEPLOYER, ActorRoleEnum.VALIDATOR),
        condition="validator_id ≠ deployer_id",
        because="THR-RCF-1",
        pcs_term="rcf_adj",
        standard_refs=[
            "NIST AI RMF GOVERN-2.1",
            "ISO/IEC 42001 §5.3",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-HITL-1",
        name="Human oversight protocol must be formally specified",
        description="EU AI Act Article 14 mandates effective human oversight "
                    "for High-Risk AI systems listed in Annex III "
                    "(employment, credit, education, law enforcement, "
                    "essential services, etc.). This framework extends the "
                    "same control to any deployment at OPERATIONAL "
                    "criticality or higher, as a proportionate "
                    "risk-stratification measure. The deployment must include "
                    "a documented oversight protocol describing which "
                    "decisions require a human checkpoint, who acts as the "
                    "checkpoint, and the override authority (\"stop button\").",
        imposed_by="Operator role (with Deployer co-signature)",
        on_dependency=(ActorRoleEnum.OPERATOR, ActorRoleEnum.DEPLOYER),
        condition="hitl_formally_specified = True for ACM ≥ CRITICAL",
        because="THR-A-1",
        pcs_term="Wh",
        standard_refs=[
            "EU AI Act Art 14 (High-Risk AI, Annex III)",
            "NIST AI RMF GOVERN-3.2 (Roles and responsibilities for human oversight)",
            "ISO/IEC 42001 §5.3 (Roles, responsibilities and authorities)",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-DPIA-1",
        name="DPIA must be approved before special-category data is processed",
        description="GDPR Art 35 / EU AI Act Art 27 — special-category "
                    "personal data triggers a mandatory Data Protection "
                    "Impact Assessment. The DPIA must be on file before "
                    "the deployment gate can open.",
        imposed_by="Data Protection Officer",
        on_dependency=(ActorRoleEnum.DEPLOYER, ActorRoleEnum.TRAINER),
        condition="dpia_approved = True when data_sensitivity = SPECIAL_CATEGORY",
        because="THR-S-1",
        pcs_term="Dm",
        standard_refs=[
            "GDPR Art 35",
            "EU AI Act Art 27",
            "ISO/IEC 29134",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-DOMAIN-1",
        name="PINN deployments require an active DomainRule",
        description="Physics-informed neural networks make their safety "
                    "claim only inside the validated physical domain. "
                    "Without an active DomainRule, the safety case has no "
                    "anchor.",
        imposed_by="Trainer (with Validator co-signature)",
        on_dependency=(ActorRoleEnum.VALIDATOR, ActorRoleEnum.TRAINER),
        condition="model_type = PINN ⇒ domain_rule_active = True",
        because="THR-S-1",
        pcs_term="Dm",
        standard_refs=[
            "EU AI Act Art 15(4)",
            "NIST AI RMF MEASURE-2.5",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-TRAIN-1",
        name="Operator training must be complete before go-live",
        description="No deployment can pass the gate until all named "
                    "operators have completed framework-specific training "
                    "on the model's failure modes, HITL protocol, and "
                    "incident-reporting procedure.",
        imposed_by="Deployer",
        on_dependency=(ActorRoleEnum.CONSUMER, ActorRoleEnum.OPERATOR),
        condition="operator_training_complete = True",
        because="THR-V-2",
        pcs_term="Wh",
        standard_refs=[
            "EU AI Act Art 14(4)(a)",
            "NIST AI RMF GOVERN-2.2",
            "ISO/IEC 42001 §7.2",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-HALLU-1",
        name="Generative-AI confabulation policy must be declared",
        description="Generative AI models (LLMs and similar) can produce "
                    "confidently stated but erroneous outputs — what NIST "
                    "AI 600-1 terms \"confabulation\" and what is colloquially "
                    "called hallucination. EU AI Act Article 50 mandates "
                    "transparency obligations for generative AI, including "
                    "user disclosure when interacting with an AI system. "
                    "This framework requires a declared policy covering "
                    "(a) automated hallucination monitoring, "
                    "(b) end-user disclosure when AI output is presented, "
                    "and (c) downstream guardrails that constrain how "
                    "unverified generative outputs propagate.",
        imposed_by="Trainer",
        on_dependency=(ActorRoleEnum.OPERATOR, ActorRoleEnum.TRAINER),
        condition="hallucination_constraint_declared = True for generative models",
        because="THR-U-1",
        pcs_term="eps_b",
        standard_refs=[
            "EU AI Act Art 50 (Transparency obligations for generative AI)",
            "NIST AI 600-1 — Confabulation (GAI risk category)",
            "ISO/IEC 23894 §6.5.3 (Risk treatment — control of model error)",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-LIAB-1",
        name="Value-chain accountability boundary must be declared",
        description="EU AI Act Article 25 governs responsibilities along the "
                    "AI value chain: any distributor, importer, deployer or "
                    "third-party that puts its name on a high-risk AI system, "
                    "substantially modifies it, or changes its intended "
                    "purpose is re-classified as a \"provider\" and inherits "
                    "the provider's full compliance burden under Article 16. "
                    "This constraint requires the deployment to document its "
                    "position in the value chain and the modification "
                    "thresholds that would trigger provider re-classification. "
                    "Note: civil tort and corporate liability for AI-mediated "
                    "harm is addressed by the separate (proposed) EU AI "
                    "Liability Directive.",
        imposed_by="AI Governance Board",
        on_dependency=(ActorRoleEnum.CONSUMER, ActorRoleEnum.DEPLOYER),
        condition="liability_boundary_declared = True",
        because="AG-A-1",
        pcs_term="Wh",
        standard_refs=[
            "EU AI Act Art 25 (Responsibilities along the AI value chain)",
            "NIST AI RMF GOVERN-1.1 (Legal and regulatory requirements understood)",
            "EU AI Liability Directive (proposed) — civil liability framework",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-CHALL-1",
        name="Right to explanation and challenge must be documented",
        description="Two complementary rights apply when AI affects "
                    "individuals: (a) GDPR Article 22(3) gives data subjects "
                    "the right to obtain human intervention, express their "
                    "view, and contest decisions taken solely on automated "
                    "processing that produce legal or similarly significant "
                    "effects; (b) EU AI Act Article 86 gives any person "
                    "affected by a high-risk AI decision (Annex III) the "
                    "right to obtain a clear and meaningful explanation of "
                    "the role of the AI system and the main elements of the "
                    "decision. The deployment must document both the "
                    "explanation path and the contestability path, with a "
                    "named human reviewer and an SLA.",
        imposed_by="Data Protection Officer",
        on_dependency=(ActorRoleEnum.CONSUMER, ActorRoleEnum.OPERATOR),
        condition="right_to_challenge_documented = True",
        because="AG-A-1",
        pcs_term="Wh",
        standard_refs=[
            "GDPR Art 22 (Automated individual decision-making, right to contest)",
            "EU AI Act Art 86 (Right to explanation of individual decision-making)",
            "GDPR Art 15 (Right of access by the data subject)",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-MC-1",
        name="Model card must be approved before deployment",
        description="The model's capabilities, limitations, training data "
                    "provenance, and validation results must be summarised "
                    "in an approved model card.",
        imposed_by="Validator",
        on_dependency=(ActorRoleEnum.DEPLOYER, ActorRoleEnum.VALIDATOR),
        condition="model_card_approved = True",
        because="AG-U-1",
        pcs_term="eps_b",
        standard_refs=[
            "EU AI Act Art 11",
            "EU AI Act Annex IV",
            "NIST AI RMF MAP-4.2",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-MAP-1",
        name="Pre-deployment fairness/bias-proxy assessment must be complete",
        description="Deployments that process special-category data or make "
                    "CRITICAL / SAFETY_CRITICAL decisions about people must "
                    "declare a fairness/bias metric and configure an output-"
                    "validation gate before deployment, so proxy-variable "
                    "bias is caught in the MAP phase rather than in "
                    "production (the Optum / Obermeyer 2019 failure mode).",
        imposed_by="Validator",
        on_dependency=(ActorRoleEnum.DEPLOYER, ActorRoleEnum.VALIDATOR),
        condition="bias_metric is not None and "
                  "output_validation_gate_configured = True",
        because="AG-U-1",
        pcs_term="eps_b",
        standard_refs=[
            "NIST AI RMF MAP 3.x",
            "NIST AI RMF MAP-2.3",
            "EU AI Act Art 10 (Data and data governance)",
            "GDPR Art 35 (DPIA — complementary)",
        ],
    ),
    SecurityConstraint(
        constraint_id="SC-CONSENT-1",
        name="Consent provenance must be signed at data collection",
        description="Personal-data training sets must carry a signed "
                    "consent record from the collection point — not "
                    "after-the-fact re-papering.",
        imposed_by="Data Protection Officer",
        on_dependency=(ActorRoleEnum.VALIDATOR, ActorRoleEnum.TRAINER),
        condition="signed_at_collection = True",
        because="THR-S-1",
        pcs_term="Dm",
        standard_refs=[
            "GDPR Art 6",
            "GDPR Art 7",
            "ISO/IEC 27701 §7.2.2",
        ],
    ),
]