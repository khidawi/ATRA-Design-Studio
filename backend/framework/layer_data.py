"""
ST-AI Framework v2 — Layer Definitions
All 11 layers with concept classes, relationships, and enumerations.
Used by the Reference Tables page in the Streamlit app.
"""

LAYER_META = {
    1:  {"name": "Pre-deployment & Governance Setup",              "phase": "Design-time",    "colour": "#E3E3E3", "req": "1"},
    2:  {"name": "Training Data Provenance & Supply Chain",        "phase": "Design-time",    "colour": "#DCE6F2", "req": "2"},
    3:  {"name": "Constraints, Measures & Mechanisms",             "phase": "Design-time",    "colour": "#D2E1F5", "req": "3,4,5"},
    4:  {"name": "Adversarial Threat Analysis",                    "phase": "Design-time",    "colour": "#D2E1F5", "req": "4"},
    5:  {"name": "Risk Quantification (PCS)",                      "phase": "Design-time",    "colour": "#FFECCE", "req": "5"},
    6:  {"name": "Deployment, Lifecycle & Business Continuity",    "phase": "Deployment",     "colour": "#DEF0DE", "req": "6,15"},
    7:  {"name": "Runtime Monitoring & Drift Detection",           "phase": "Deployment",     "colour": "#DEF0DE", "req": "7"},
    8:  {"name": "Governance, Compliance, Liability & Rights",     "phase": "Governance",     "colour": "#E6DEF0", "req": "8,13,16,17"},
    9:  {"name": "Epistemic Governance",                           "phase": "Governance",     "colour": "#E6DEF0", "req": "9,10,11"},
    10: {"name": "Organisational Culture & Misuse",                "phase": "Governance",     "colour": "#EBE1F5", "req": "12,13"},
    11: {"name": "AI Decommissioning & End-of-Life",               "phase": "Governance",     "colour": "#F5DCDC", "req": "14"},
}

# ── Concept class tables ──────────────────────────────────────────────────────
CONCEPT_TABLES = {

1: [
    ("Organisation",             "The legal entity deploying the AI system with sector, jurisdiction, and declared AI system type.", "Without formally declaring AI system type, every downstream security decision lacks context.", "1.4"),
    ("Actor",                    "Any human entity interacting with the AI at any lifecycle stage.", "The most dangerous vulnerabilities are human. Identifying every actor and authority is critical.", "1.1"),
    ("AIActor ★",                "An AI system as an active entity with model type, accuracy class, version, retrained_by, and retrains_on fields.", "Conventional software does not retrain itself. The person with retraining authority is a unique attack vector.", "1.2.1"),
    ("DomainRule ★",             "A physical, financial, or clinical law the AI must satisfy, classified by LawTypeEnum, with tolerance and financial exposure.", "Makes domain laws enforceable constraints. A custody transfer AI is subject to ISO 17089.", "3.1"),
    ("ModelCard ★",              "Pre-deployment document recording purpose, training data, evaluation, limitations, bias evaluation, hallucination profile.", "Without a model card the organisation cannot demonstrate it understood what it was deploying.", "3.4"),
    ("RiskClassification ★",     "Assignment of the AI to a risk tier (CRITICAL/HIGH/MEDIUM/LOW) based on regulatory, safety, and financial exposure.", "Risk classification determines which of the eleven layers are mandatory.", "3.4.1"),
    ("OwnershipMatrix ★",        "Record of who owns model, data, and infrastructure, and who holds retraining, deployment, and decommissioning authority.", "Ambiguous ownership is the most common root cause of AI security failures.", "1.1.1"),
    ("ApprovalFlow ★",           "Defined sequence of approvers before high-risk changes proceed, with quorum adjusted by minimum_quorum_by_size.", "Single-person retraining authority means a single compromised employee can corrupt the AI.", "1.2.3"),
    ("OrganisationalProfile ★",  "Organisation size, governance maturity, budget band, DPO availability, security team presence.", "Without this profile the framework cannot determine mandatory vs compensatable controls.", "1.5"),
    ("RoleConcentrationRecord ★","Records which actors perform Trainer, Validator, Deployer roles and computes RCF (1.0=separated, 3.0=same person).", "Role consolidation in small teams is invisible. Making it auditable allows RCF_adj to apply.", "1.5.1"),
    ("ControlImportanceRating ★","Stakeholder-entered importance rating per security control compared against framework minimum.", "Without ratings the framework cannot detect systematic under-prioritisation of essential controls.", "1.6"),
    ("CompensatingControlRecord ★","Formal record of an approved substitute for a control, specifying mechanism, residual risk delta, and review date.", "Provides an auditable, time-limited alternative path with disclosed residual risk.", "1.5.2"),
    ("SizeAdjustedControlProfile ★","System-computed record translating (OrgSize×RiskTier×Sector) into per-control enforcement level.", "Without this profile all organisations receive identical mandatory controls regardless of capacity.", "1.5.3"),
],

2: [
    ("DataAsset",                "Any data resource used by the AI system, categorised by role and sensitivity via SensitivityEnum.", "Formal categorisation ensures the right security controls are applied to the right data.", "2.1"),
    ("DataLineage ★",            "Provenance record tracking source, consent status, and transformation history. signed_at_collection=FALSE blocks TRAIN stage.", "Without lineage the organisation cannot prove training data was clean at any point.", "2.2"),
    ("DataVersion ★",            "Versioned snapshot of a training dataset identified by a cryptographic hash with a reproducibility flag.", "Without versioning the organisation cannot investigate incidents or defend against regulatory scrutiny.", "2.2.1"),
    ("TrainingDataDependency ★", "Formal record of poisoning risk, opacity, feedback loop type, and retraining trigger. AUTOMATED loop feeds W_f.", "When opacity=NONE for Type 3, the organisation formally records it has no training data visibility.", "2.4"),
    ("LabelingProcess ★",        "Record of annotation workflow including quality threshold, whether audited, and whether labellers have production access.", "A malicious labeller with production access can systematically introduce poisoned labels.", "2.4.1"),
    ("SupplyChainItem ★",        "Formal inventory entry for any third-party dataset, model, library, or AI service with VettingStatusEnum.", "A backdoored pre-trained model introduces vulnerabilities before a single line of code is written.", "2.3"),
    ("ProviderSLA ★",            "SLA record with Type 2/3 provider including GDPR Art.28 DPA status, update notification terms, and uptime.", "If gdprArticle28DPA=FALSE the organisation may be in GDPR breach every time user data enters the AI.", "2.3.3"),
],

3: [
    ("Constraint",               "Parent concept for all restriction types, classified by ConstraintTypeEnum and prioritised by ConstraintPriorityEnum.", "Constraints specified before the system is built, not discovered after deployment.", "5"),
    ("SecurityConstraint",       "Restriction based on IT security criteria: CIA, model integrity, non-repudiation of outputs.", "Without formal security constraints requirements remain implicit.", "5.1"),
    ("DomainConstraint ★",       "Restriction derived from a physical, financial, or clinical law. When violated, raises D_m in PCS.", "No prior methodology treats domain laws as security constraints.", "3.2"),
    ("BiasConstraint ★",         "Restriction requiring AI outputs satisfy a fairness criterion quantified by BiasMetricEnum.", "Without a specified bias metric, Layer 7 FairnessAudit has no measurable criterion.", "5.2"),
    ("HallucinationConstraint ★","Restriction limiting what the AI may do with potentially hallucinated outputs. Feeds W_h and ε_b into PCS.", "Treating hallucination as a constraint shifts response from defect fixing to deployment gating.", "10.1"),
    ("ConfidenceSignalConstraint ★","Constraint requiring confidence communication with thresholds. Absence maps to NO_SIGNALING in Layer 10.", "Confidence signalling is the primary design-time mechanism for mitigating automation bias.", "10.2"),
    ("Measure",                  "Abstract security measure specifying how a constraint should be satisfied without prescribing realisation.", "Enables reuse of solutions across different concrete mechanisms.", "5"),
    ("Mechanism",                "Concrete engineering control implementing a Measure.", "Ensures every constraint is traceable to a deployed control.", "5"),
    ("AISecurityPattern ★",      "Pre-defined bundle of mechanisms classified by PatternTypeEnum (PAS/DCFL/DADP/RDM/AROBUST).", "Reduces engineering effort by providing validated, reusable solutions.", "3.2"),
    ("AIOutputAsset ★",          "Formally typed AI-generated output with assigned ConfidenceSignalEnum. Extended in Layer 9.", "Without a formally typed output asset, confidence constraints cannot be applied per output type.", "11"),
    ("Conflict",                 "Formally modelled tension between two constraints with documented resolution via ConflictResolutionEnum.", "Conflicts silently resolved in favour of performance without formal modelling.", "5"),
],

4: [
    ("Attacker",                 "Malicious entity characterised by identity, motivation via MotivationEnum, and capability via CapabilityEnum.", "Threat modelling begins with the attacker.", "4.3"),
    ("AdversarialAttack ★",      "Extension of AttackMethod adding ATLAS ID, AttackPhaseEnum, distortion %, and computePCS() method.", "Adversarial ML attacks target learned behaviour, not code.", "4.1"),
    ("DataPoisoning ★",          "Attack corrupting training data to manipulate learned behaviour, with feedback loop exploitation flag.", "Data poisoning produces no observable infrastructure anomaly.", "4.1.1"),
    ("ModelTampering ★",         "Attack modifying model weights directly, invalidating the physics-anchored signature.", "A tampered model passes all standard evaluation metrics.", "4.1"),
    ("EvasionAttack ★",          "Inference-time attack crafting inputs to produce incorrect outputs below detection threshold.", "The model produces wrong outputs that appear correct across all conventional monitoring.", "4.1.5"),
    ("BackdoorAttack ★",         "Attack embedding a hidden trigger pattern during training causing targeted misbehaviour.", "Backdoor attacks pass every benchmark because the trigger is absent during evaluation.", "4.1.2"),
    ("MembershipInferenceAttack ★","Attack reconstructing whether a specific record was used in training via repeated query access.", "Violates GDPR by revealing personal data inclusion. Applicable to all Type 3 deployments.", "4.1.4"),
    ("AIVulnerability ★",        "AI-specific weakness classified by VulnerabilityTypeEnum, SilentFailureEnum, and ExploitWindowEnum.", "silentByDefault distinguishes AI vulnerabilities from conventional ones.", "4.4"),
],

5: [
    ("PhysicsConsequenceScore ★","PCS computation engine aggregating all upstream risk inputs from L1-L4 into a single numeric score.", "Without defining PCS as a concept, the relationships feeding it have no target entity.", "5"),
    ("CyberRiskComponent",       "Attack-side inputs: L, I, Δ, τ, and ATLAS ID. Populated from Layer 4 adversarial threat records.", "Inputs multiplied by domain multiplier and weights rather than added to a risk matrix.", "5.1"),
    ("WeightingScheme",          "Organisational context multipliers: Wr, Ws, Wf, Wh, RCF_adj, governance maturity factor.", "Role consolidation raises score by up to 30% via RCF_adj.", "5.2"),
    ("EpistemicRiskComponent ★", "Parallel risk input capturing hallucination risk, human review, cascade risk, and ε_ia.", "Systematic under-prioritisation amplifies epistemic risk by up to 0.5 via ε_ia.", "9"),
    ("PCSResult",                "Structured output per threat: score, financial impact, ActionTierEnum, regulatory breach flag, mitigation reference.", "Every field answers a specific stakeholder question.", "5.3.3"),
    ("ThreatRegister",           "Ranked collection of all PCSResult records ordered by ActionTierEnum.", "Without a ranked register, security investment cannot be prioritised.", "4"),
    ("ValidationReport ★",       "Pre-deployment gate document with CompliancePathEnum, compensating controls applied, residual risk band.", "Replaces binary pass/fail with a four-state outcome meaningful to all organisation sizes.", "6.1"),
],

6: [
    ("ModelLifecycle ★",         "Complete AI deployment pipeline of ordered Stage records. Every retraining event re-enters from COLLECT.", "Without a formal lifecycle model, retrained models bypass security checkpoints.", "6.1"),
    ("Stage",                    "Single ordered pipeline step classified by StageNameEnum with responsible actor and gate-passed flag.", "Without Stage as a concept the pipeline stages are implied but not auditable.", "6.1"),
    ("DomainGate ★",             "Gate between VALIDATE and SIGN checking two independent conditions: PCS < CRITICAL and DomainRule.validate()=TRUE.", "Prevents models violating physical laws or exceeding CRITICAL PCS from entering production.", "6.1.1"),
    ("OutputGate ★",             "Gate controlling AI outputs post-deployment, blocking regulatory submissions when EvidenceStatusEnum=BLOCKED.", "Passing the deployment gate does not eliminate hallucination risk.", "10.1"),
    ("ModelQuarantine ★",        "Mechanism for isolating a compromised model version without full rollback. Only containment for Type 3.", "Quarantine allows rapid containment while retaining forensic evidence.", "6.2.3"),
    ("CanaryDeployment ★",       "Controlled deployment routing defined traffic % to a candidate version with abort conditions.", "Without canary deployment every retraining event is a full production release.", "6.3"),
    ("AIResilienceRequirement ★","Formal specification of how operations continue if AI becomes unavailable.", "Replacing manual processes with AI without a resilience plan creates a latent single point of failure.", "15.1"),
    ("ManualFallbackProcedure ★","Documented procedure enabling manual execution of AI-assisted tasks with throughput estimates.", "Only control preventing AI unavailability from escalating into a business continuity incident.", "15.2"),
    ("ResilienceTestRecord ★",   "Formal record of resilience testing including test date, throughput achieved, and gaps.", "Untested fallback procedures are theoretical controls.", "15.4"),
],

7: [
    ("TelemetryCollector",       "Runtime component continuously sampling AI actor behaviour across input distributions and confidence scores.", "Without a telemetry collector drift and domain violations are invisible.", "7.1"),
    ("DriftDetector",            "Component analysing telemetry to identify distribution shifts using DriftTypeEnum and DriftMethodEnum.", "Drift not detected until it causes failures; Δ already extended, raising PCS retrospectively.", "7.2"),
    ("AlertRule",                "Formally defined threshold rule producing ConsequenceEnum, and recording ShutdownTriggerEnum when SHUTDOWN fires.", "Monitoring observations have no operational consequence without alert rules.", "7.3"),
    ("FairnessAudit",            "Scheduled audit of BiasConstraint compliance at frequency in SizeAdjustedControlProfile. QUARTERLY for Micro/Small.", "Bias drift undetected between audit cycles without formally scheduled audits.", "7.4"),
    ("ExplainabilityEngine",     "Runtime component generating human-interpretable explanation for an AIOutputAsset. Fulfils GDPR Art.22.", "Without an explainability engine the organisation cannot fulfil individual rights to explanation.", "7.5"),
    ("HumanOverride",            "Formally recorded operator decision to reject an AI output with actor identity, reason, and timestamp.", "Symbolic review producing no audit trail is indistinguishable from no review.", "7.6"),
    ("AIIncidentPlan",           "Formally defined response plan triggered when AlertRule fires, specifying activities and notification obligations.", "An alert not connected to a response procedure does not constitute a security control.", "7.7"),
],

8: [
    ("DPIA",                     "Data Protection Impact Assessment required under GDPR Art.35 for high-risk AI processing.", "Without an approved DPIA, GDPR Art.35 compliance cannot be demonstrated.", "8.1"),
    ("HumanInLoop",              "Formally specified human review control verified at runtime by RealHumanInLoopVerification in Layer 10.", "Human-in-the-loop is frequently symbolic; without formal specification it cannot be verified.", "8.2"),
    ("ImpactedStakeholderProfile","Formal record of individual/group affected, classified by StakeholderVulnerabilityEnum.", "Transparency obligations cannot be fulfilled per-individual without stakeholder profiles.", "8.3"),
    ("StakeholderImpactNotification ★","Formal record of how affected individuals are informed, including NotificationTimingEnum.", "Without a formal notification record, Article 13 transparency duties cannot be demonstrated.", "16.1"),
    ("RightToChallenge ★",       "Documented process allowing individuals to challenge AI-influenced decisions within defined timelines.", "Without a formal challenge process, GDPR Art.22 compliance cannot be demonstrated.", "16.2"),
    ("AILiabilityBoundary ★",    "Formal specification of output ownership, LiabilityAllocationEnum, indemnification, and jurisdiction.", "Unresolved liability is a primary reason legal teams block AI deployment.", "17.1"),
    ("OutputOwnershipRecord ★",  "Declaration of ownership of AI-generated outputs classified by OutputOwnershipEnum.", "Using AI outputs without clarifying ownership may infringe third-party IP.", "17.1"),
    ("IndemnificationRecord ★",  "Record of contractual indemnification from AI provider covering hallucination, bias, regulatory breaches.", "Absent indemnification, all AI failure consequences fall on the deploying organisation.", "17.3"),
    ("OrganisationalAIPolicy ★", "Formal policy governing AI output usage, prohibited use cases, and hallucination acknowledgement.", "Failure to acknowledge hallucination risk is a governance gap. Absence = NO_POLICY in Layer 10.", "10.1"),
],

9: [
    ("EpistemicRisk ★",          "Risk entity capturing knowledge-based AI risk: silent, non-adversarial, amplified by trust.", "No prior methodology treats incorrect AI knowledge as a security risk.", "9"),
    ("HallucinationProfile ★",   "Characterisation of AI hallucination behaviour: rate, high-risk tasks, grounding capability, knowledge cutoff.", "Every AI system exhibits hallucination. Without formal profiling, high-risk tasks cannot be identified.", "10.3"),
    ("OutputValidationGate ★",   "Formal gate evaluating each AIOutput before consumption assigning OutputTrustLevelEnum and EvidenceStatusEnum.", "Without this gate hallucinated outputs reach regulators and automated executors with no check.", "11"),
    ("OutputUsageContext ★",     "Formal record of consumption context including ConsumptionRoleEnum, human review presence, cascade risk.", "The same output carries different epistemic risk for an ADVISORY_READER vs AUTOMATED_EXECUTOR.", "9.2"),
    ("HallucinationIncident ★",  "Formally recorded hallucination event classified as security incident, triggering AIIncidentPlan.", "Treating hallucination as a quality defect triggers no escalation or forensic analysis.", "9.3"),
    ("EpistemicRiskScore ★",     "Quantified epistemic risk for a specific AIOutput in a given OutputUsageContext. Feeds ε_b back to Layer 5.", "Without it the ThreatRegister is blind to epistemic failure modes primary for LLM deployments.", "9.2"),
    ("AIOutput",                 "Runtime instance of AIOutputAsset with assigned OutputTrustLevelEnum and EvidenceStatusEnum.", "Without distinguishing runtime instance from design-time type, gate decisions cannot be applied per-output.", "11"),
],

10: [
    ("AIOutputConsumptionProfile","Quantitative record of how an actor actually consumes AI outputs. symbolic_oversight flag computed.", "Over-trust is invisible until an incident makes it visible.", "9.1"),
    ("HumanConsumer",            "Human actor consuming AI outputs in a defined role subject to AIOutputConsumptionProfile monitoring.", "Without profiling human consumers systematic over-trust patterns cannot be detected.", "9"),
    ("AutomationBiasRisk",       "Formally identified risk of operator over-trust characterised by AutomationBiasTriggerEnum and BiasRiskLevelEnum.", "Without a formal record, training interventions remain generic.", "9.2"),
    ("MisuseIncident ★",         "Formally recorded AI misuse event classified as security incident linked to RootCauseEnum and AccountabilityFailureEnum.", "Treating misuse as user error means the systemic design gap is never identified.", "10"),
    ("RealHumanInLoopVerification","Structured assessment of whether human review control is substantive or symbolic.", "Symbolic controls are reported as effective while providing zero actual oversight.", "8.2"),
    ("HumanInLoop",              "Formally specified human review control verified at runtime to distinguish substantive from symbolic oversight.", "Human-in-the-loop exists in policy but is frequently not implemented in practice.", "8.2"),
],

11: [
    ("AIEndOfLifePlan ★",        "Formal plan specifying AI retirement governing DecommissioningStatusEnum state machine.", "Without controlled retirement, model weights persist indefinitely violating GDPR storage limitation.", "14.1"),
    ("ModelWeightDisposal ★",    "Formal record of how model weights are handled at retirement classified by DisposalMethodEnum.", "Model weights are IP. Uncontrolled disposal creates IP risk and potential data leakage.", "14.2"),
    ("DataRetentionDecision ★",  "Formal decision record specifying which training data is retained, for how long, and under what legal basis.", "GDPR storage limitation requires data retained no longer than necessary.", "14.3"),
    ("LegalHoldRecord ★",        "Record of any legal hold preventing premature deletion. Blocks WEIGHTS_DISPOSED transition when active.", "Premature deletion during an active investigation constitutes spoliation.", "14.5"),
    ("PostRetirementVerification ★","Four-check closure: credentials disabled, API keys revoked, automation hooks removed, downstream notified.", "Without disabling all entry points, automated processes may continue to invoke the retired model.", "14.6"),
],
}

# ── Relationship tables ───────────────────────────────────────────────────────
RELATIONSHIP_TABLES = {

1: [
    ("contains",                  "Organisation",              "Actor",                    "The organisation employs or authorises these actors.",                                          "No formal record of who is authorised to interact with the AI."),
    ("retrained_by ★",            "AIActor",                   "Actor",                    "This specific human has authority to trigger retraining.",                                     "Most critical single-point-of-failure. AI can be corrupted by anyone with system access."),
    ("retrains_on ★",             "AIActor",                   "AIActor",                  "One AI system uses another's live outputs as training data, creating a chained dependency.",   "This is the chained AI attack path."),
    ("governed_by",               "AIActor",                   "DomainRule",               "The AI actor's outputs must satisfy this domain law.",                                         "Domain violations are invisible to conventional security tools."),
    ("classified_as ★",           "AIActor",                   "RiskClassification",       "The AI system is formally assigned to a risk tier before any layer assessment begins.",        "Without this assignment the framework cannot determine which layers are mandatory."),
    ("documented_in ★",           "AIActor",                   "ModelCard",                "The AI system's pre-deployment documentation is formally linked to the system record.",        "Without this link the model card is a free-floating document."),
    ("declared_by ★",             "Organisation",              "OwnershipMatrix",           "The organisation formally declares the ownership matrix before any AI system is registered.", "Ownership ambiguity is the most common root cause of AI security failures."),
    ("defines_authority_for ★",   "OwnershipMatrix",           "AIActor",                  "The ownership matrix records retraining, deployment, and decommissioning authority.",         "Without this link, authority accountability is unenforceable."),
    ("enforced_by ★",             "OwnershipMatrix",           "ApprovalFlow",             "Quorum and authority requirements are operationalised through the linked approval flow.",     "minimum_quorum_by_size is a data field with no structural enforcement."),
    ("profiled_by ★",             "Organisation",              "OrganisationalProfile",    "The organisation has a formally declared capability and size profile.",                       "Framework cannot calibrate enforcement levels or quorum requirements."),
    ("concentrates_roles_in ★",   "AIActor",                   "RoleConcentrationRecord",  "This AI system has a formal record of which actors perform which lifecycle roles and the RCF.", "Role consolidation in small teams is invisible."),
    ("rated_importance_of ★",     "Actor",                     "ControlImportanceRating",  "A named actor has provided a formal importance rating for a specific security control.",      "Framework cannot detect systematic under-prioritisation."),
    ("compensated_by ★",          "SizeAdjustedControlProfile","CompensatingControlRecord","A control that cannot be fully implemented has an approved compensating mechanism on record.", "SMEs either falsely claim compliance or are permanently blocked."),
    ("adjusts ★",                 "OrganisationalProfile",     "SizeAdjustedControlProfile","The profile drives which controls are mandatory, compensatable, or optional.",              "Enforcement depth is uniform across all organisations."),
    ("inflates_pcs ★",            "RoleConcentrationRecord",   "WeightingScheme",          "High RCF scores inflate the PCS via the RCF_adj term.",                                       "PCS does not capture the elevated risk from consolidated roles."),
    ("surfaces_gap ★",            "ControlImportanceRating",   "PCSBlockReasonEnum",       "A CRITICAL importance gap blocks the relevant deployment gate.",                              "An organisation that rated critical monitoring as NOT_RELEVANT could still pass."),
],

2: [
    ("has_lineage",               "DataAsset",         "DataLineage",               "This data asset has a full provenance record tracking every transformation.",          "No way to verify training data integrity retrospectively."),
    ("versioned_as",              "DataAsset",         "DataVersion",               "This data asset exists as a reproducible, cryptographically hashed version.",          "Cannot reproduce training runs."),
    ("has_dependency",            "DataAsset",         "TrainingDataDependency",    "The AI system depends on this data asset with formal classification of poisoning risk.", "Training data not formally treated as a security surface."),
    ("trained_on ★",              "AIActor",           "DataAsset",                 "The AI actor's behaviour was determined by this data asset.",                           "Connection between AI behaviour and data source is invisible."),
    ("feeds_back_to ★",           "AIActor",           "DataAsset",                 "A deployed AI actor's live outputs feed this data asset used in retraining.",           "Feedback loop attack path is invisible."),
    ("collected_with_consent ★",  "DataAsset",         "DataConsentEnum",           "The data asset's legal consent basis is formally recorded before training begins.",    "Personal data enters training pipeline without a documented legal basis."),
    ("annotated_by ★",            "DataAsset",         "LabelingProcess",           "This data asset was annotated through the formally recorded labelling workflow.",      "Insider threat via annotation has no formal connection to the affected data asset."),
    ("governs_labeling ★",        "SupplyChainItem",   "LabelingProcess",           "A third-party labelling service is formally registered governing this process.",       "External labelling services are an unmonitored entry point for data poisoning."),
    ("inventories",               "Organisation",      "SupplyChainItem",           "The organisation has a formal record of this third-party component.",                  "Supply chain attacks cannot be detected or attributed."),
    ("covered_by_sla ★",          "SupplyChainItem",   "ProviderSLA",               "This supply chain item is governed by a formally recorded SLA.",                       "Provider data processing obligations cannot be audited."),
    ("constrains_deployment ★",   "ProviderSLA",       "AIActor",                   "The provider SLA formally constrains what the organisation may do with this AI.",      "The SLA is a free-floating document with no enforceable connection to the AI."),
    ("triggers_pcs_wf ★",         "TrainingDataDependency","WeightingScheme",        "When FeedbackLoopEnum=AUTOMATED, this elevates W_f in the PCS formula.",              "PCS does not capture elevated risk from automated feedback loops."),
],

3: [
    ("restricts",                 "Constraint",          "Asset",                "This constraint formally limits how this asset can be processed.",                   "Assets have no formal protection requirements."),
    ("typed_as ★",                "Constraint",          "ConstraintTypeEnum",   "Each constraint is formally classified by type enabling gate logic.",                "All constraints treated identically regardless of severity."),
    ("satisfies",                 "Measure",             "Constraint",           "This measure is the formally recognised solution approach to this constraint.",      "Constraints are identified but no solution is specified."),
    ("implements",                "Mechanism",           "Measure",              "This concrete control implements this abstract measure in the deployed system.",     "Security requirements exist on paper but have no engineering realisation."),
    ("applied_to ★",              "AISecurityPattern",   "Constraint",           "This pre-defined security pattern is applied to satisfy this constraint.",           "AISecurityPattern is an orphan concept with no connection to the constraint it satisfies."),
    ("implemented_by ★",          "DomainConstraint",    "AISecurityPattern",    "This domain constraint is satisfied through a formally registered security pattern.", "Organisations derive domain constraint solutions independently each time."),
    ("governs ★",                 "DomainConstraint",    "AIActor",              "The domain law this AI actor's outputs must satisfy.",                               "Domain violations are not treated as security events."),
    ("feeds_dm ★",                "DomainConstraint",    "WeightingScheme",      "A domain constraint violation raises D_m in the PCS formula.",                      "PCS does not reflect domain law exposure."),
    ("feeds_wh ★",                "HallucinationConstraint","WeightingScheme",   "The hallucination constraint feeds W_h and ε_b into the PCS formula.",              "PCS does not capture hallucination risk as a design-time variable."),
    ("involves",                  "Conflict",            "Constraint",           "These two constraints are in tension and cannot both be fully satisfied.",           "Conflicts silently resolved in favour of performance."),
    ("resolved_by ★",             "Conflict",            "ConflictResolutionEnum","Every conflict has a documented resolution mode.",                                   "Conflicts resolved ad hoc with no documented justification."),
    ("quantified_by ★",           "BiasConstraint",      "BiasMetricEnum",       "The bias constraint specifies which fairness metric measures compliance.",           "Bias constraints stated without a measurable criterion."),
    ("audited_by ★",              "BiasConstraint",      "FairnessAudit",        "This bias constraint is monitored at runtime by the Layer 7 FairnessAudit.",         "Design-time constraint and runtime audit are disconnected."),
    ("signals_confidence ★",      "AIOutputAsset",       "ConfidenceSignalEnum", "Each AI output asset formally records how uncertainty was communicated.",            "Users receive AI outputs with no indication of confidence level."),
],

4: [
    ("uses",                      "Attacker",          "AttackMethod",         "The attacker uses this technique to compromise the AI system.",                       "No connection between attacker identity and attack technique."),
    ("attacks",                   "AttackMethod",      "Vulnerability",        "This technique exploits this specific weakness in the AI system.",                   "Attack techniques not connected to vulnerabilities they exploit."),
    ("exploits ★",                "AdversarialAttack", "AIVulnerability",      "This AI-specific attack exploits this AI-specific vulnerability.",                   "Attack and vulnerability exist as independent records."),
    ("classified_by_vector ★",    "AdversarialAttack", "VectorTypeEnum",       "Each adversarial attack is formally classified by its attack vector.",               "CHAINED_AI attacks cannot be distinguished from DATA attacks."),
    ("insider_dep ★",             "Attacker",          "Actor",                "The attacker is also an authorised internal actor.",                                 "Insider threats are invisible in the threat model."),
    ("targets ★",                 "AdversarialAttack", "AIActor",              "This adversarial attack targets this specific AI system.",                           "Threat register without target binding cannot drive system-specific gate decisions."),
    ("performed_by ★",            "AdversarialAttack", "InsiderRoleEnum",      "The attack is linked to the insider role most likely to execute it.",                "Insider threat modelling is generic rather than mapped to specific roles."),
    ("computePCS() ★",            "AdversarialAttack", "PCSResult",            "Each adversarial attack automatically generates a consequence score.",               "Threats are identified but not ranked by financial consequence."),
    ("fails_silently_as ★",       "AIVulnerability",   "SilentFailureEnum",    "The vulnerability is classified by its silent failure mode.",                        "Silent failures not categorised; targeted monitoring rules impossible."),
    ("extends_delta ★",           "AIVulnerability",   "CyberRiskComponent",   "SilentFailureEnum extends Δ from immediate to weeks or months.",                    "PCS does not capture temporal amplification of silent failures."),
    ("elevates_ws ★",             "AdversarialAttack", "WeightingScheme",      "CHAINED_AI vector elevates W_s and W_r in the PCS WeightingScheme.",                "PCS does not distinguish CHAINED_AI from DATA attacks in weighting."),
    ("mitigated_by ★",            "AIVulnerability",   "AISecurityPattern",    "This AI vulnerability is linked to the Layer 3 security pattern for mitigation.",   "Vulnerability records and security patterns exist as independent artefacts."),
],

5: [
    ("calibrates",                "DomainRule",            "PhysicsConsequenceScore","Domain rule provides financial exposure and tolerance data to the PCS engine.",   "All attacks scored identically regardless of domain consequence."),
    ("feeds",                     "CyberRiskComponent",    "PhysicsConsequenceScore","Attack-side inputs L, I, Δ, τ provided to the PCS formula.",                     "No quantitative connection between threat and financial consequence."),
    ("weights",                   "WeightingScheme",       "PhysicsConsequenceScore","Organisational context multipliers including RCF_adj applied to the base score.", "Regulatory and governance context not captured in the risk score."),
    ("boosts ★",                  "EpistemicRiskComponent","PhysicsConsequenceScore","Epistemic risk adds ε_b + ε_ia multiplier to the final score.",                  "Epistemic risk not quantified alongside technical attack risk."),
    ("produces",                  "PhysicsConsequenceScore","PCSResult",             "The PCS engine produces a structured PCSResult record for each threat entry.",    "Risk is described qualitatively with no actionable score."),
    ("populates",                 "PCSResult",             "ThreatRegister",         "Each PCSResult is ranked by ActionTierEnum and recorded in the threat register.", "No prioritised list exists to guide security investment."),
    ("ordered_by ★",              "ThreatRegister",        "ActionTierEnum",         "The threat register is formally ranked by ActionTierEnum.",                       "Ranking criterion is informal; gate logic cannot determine which result drives the decision."),
    ("gates",                     "ThreatRegister",        "ValidationReport",       "CRITICAL results or IMPORTANCE_GAP_CRITICAL blocks deployment approval.",         "Deployment proceeds regardless of unresolved critical risks."),
    ("weighted_by ★",             "PCSResult",             "RegulatoryImpactEnum",   "Each PCS result is tagged with regulatory jurisdiction scope.",                   "Financial impact does not account for multi-jurisdiction regulatory exposure."),
    ("blocks_due_to ★",           "ValidationReport",      "PCSBlockReasonEnum",     "A blocked report records the specific reason deployment was blocked.",            "Blocked deployments have no structured rationale."),
    ("triggers_recomputation ★",  "ValidationReport",      "PhysicsConsequenceScore","A retraining event or drift signal triggers PCS recomputation.",                  "PCS is a point-in-time score computed once at pre-deployment and never updated."),
],

6: [
    ("stages",                    "ModelLifecycle",        "Stage",                  "The lifecycle is composed of ordered security stages; no bypass permitted.",       "No formal order or accountability exists for the deployment pipeline."),
    ("gates_at",                  "DomainGate",            "Stage",                  "The domain gate must be passed at VALIDATE→SIGN before deployment proceeds.",      "Models can bypass the security checkpoint and enter production unchecked."),
    ("consumes_pcs ★",            "DomainGate",            "ValidationReport",       "The domain gate consumes the Layer 5 ValidationReport to verify PCS < CRITICAL.", "Domain gate and PCS engine are structurally disconnected."),
    ("controls",                  "OutputGate",            "AIOutputAsset",          "The output gate governs what may be done with each AI output post-deployment.",    "AI outputs reach regulators and clients without review."),
    ("re_enters_gate ★",          "ModelLifecycle",        "DomainGate",             "Every retraining event re-enters at COLLECT and must pass the DomainGate again.",  "The foundational principle — retraining is redeployment — has no structural enforcement."),
    ("defines_fallback_for ★",    "ManualFallbackProcedure","AIActor",               "This procedure allows the organisation to operate without this AI system.",        "No manual fallback exists; AI unavailability immediately becomes an operational crisis."),
    ("tested_by ★",               "ManualFallbackProcedure","ResilienceTestRecord",  "The fallback procedure is formally validated by this resilience test record.",     "ResilienceTestRecord is disconnected from the procedure it tests."),
    ("isolates",                  "ModelQuarantine",       "ModelLifecycle",         "Quarantine removes the compromised model from the active lifecycle.",              "Compromise persists while a full rollback is prepared."),
    ("activates_fallback ★",      "ModelQuarantine",       "ManualFallbackProcedure","When quarantine is triggered, the linked fallback procedure is activated.",        "Quarantine has no operational consequence for business continuity."),
    ("requires_for_type3 ★",      "AIActor",               "ProviderSLA",            "A Type 3 AI actor formally requires a validated ProviderSLA including GDPR Art.28 DPA.", "A Type 3 system can reach DEPLOY without a validated SLA."),
    ("rollback_controlled_by ★",  "ModelLifecycle",        "Actor",                  "A named actor is formally responsible for authorising rollback decisions.",        "Rollback has no designated authority."),
    ("fallback_state ★",          "ModelLifecycle",        "ContinuityStateEnum",    "The lifecycle formally records its current operational continuity state.",         "No formal record of whether the system is operating normally or on fallback."),
],

7: [
    ("collects",                  "TelemetryCollector",    "AIActor",               "The collector continuously monitors this AI actor's runtime behaviour.",            "No runtime observability of AI-specific metrics."),
    ("detects",                   "DriftDetector",         "TelemetryCollector",    "The drift detector analyses telemetry to identify distribution shifts.",            "Drift not detected until it causes observable failures."),
    ("triggers",                  "AlertRule",             "AIIncidentPlan",        "Alert rules fire the incident plan when thresholds are breached.",                  "Monitoring observations have no operational consequence."),
    ("triggers_shutdown ★",       "AlertRule",             "ShutdownTriggerEnum",   "An alert rule with SHUTDOWN consequence formally records the triggering condition.", "Shutdowns happen without a documented triggering condition."),
    ("activates_quarantine ★",    "AlertRule",             "ModelQuarantine",       "When DOMAIN_VIOLATION fires, the alert immediately activates ModelQuarantine.",     "Domain violations trigger an alert but do not structurally activate quarantine."),
    ("recomputes_pcs ★",          "AlertRule",             "PhysicsConsequenceScore","A runtime alert triggers PCS recomputation with updated Δ, τ, D_m, W_f values.", "PCS is static after deployment; a model under active drift carries its pre-deployment score."),
    ("explains",                  "ExplainabilityEngine",  "AIOutputAsset",         "The engine provides a runtime explanation for this AI output.",                    "No mechanism to fulfil GDPR Art.22 rights at runtime."),
    ("overrides",                 "HumanOverride",         "AIOutputAsset",         "The operator formally rejects this AI output and records a human decision.",       "Human-in-the-loop exists in policy but has no operational realisation."),
    ("audits",                    "FairnessAudit",         "BiasConstraint",        "Continuous fairness auditing verifies BiasConstraint bounds are maintained.",       "Bias drift undetected between audit cycles."),
    ("audited_at ★",              "FairnessAudit",         "AuditFrequencyEnum",    "The fairness audit frequency is formally specified per SizeAdjustedControlProfile.", "Fairness audits happen ad hoc, creating uncontrolled gaps."),
],

8: [
    ("requires_dpia ★",           "Organisation",          "DPIA",                   "The organisation formally produces a DPIA for each high-risk AI activity.",        "DPIA exists as a concept but no entity is formally responsible."),
    ("requires",                  "DPIA",                  "AIActor",                "High-risk AI processing by this actor requires a completed approved DPIA.",        "GDPR Art.35 compliance cannot be demonstrated."),
    ("governs_policy ★",          "OrganisationalAIPolicy","AIActor",                "This policy formally governs what this AI actor's outputs may be used for.",       "Policy is a free-floating document with no enforceable connection to the AI."),
    ("acknowledged_in ★",         "OrganisationalAIPolicy","HallucinationConstraint","Policy hallucination acknowledgement links to the Layer 3 HallucinationConstraint.", "Inconsistencies between policy and design constraint cannot be detected."),
    ("gates",                     "ModelCard",             "ValidationReport",       "An unapproved model card blocks deployment certification.",                         "AI deployed without documented understanding of its limitations."),
    ("notifies ★",                "StakeholderImpactNotification","ImpactedStakeholderProfile","Affected individuals are formally notified of AI involvement.", "Individuals subject to AI decisions without knowledge of their rights."),
    ("enables ★",                 "RightToChallenge",      "HumanInLoop",            "The challenge process connects to the HumanInLoop control.",                       "The right to challenge exists formally but has no operational implementation."),
    ("assigns_liability ★",       "AILiabilityBoundary",   "LiabilityHolderEnum",   "The liability boundary formally assigns which party holds liability.",              "When harm occurs the organisation defaults to full liability."),
    ("challenged_by ★",           "AIOutputAsset",         "ImpactedStakeholderProfile","An affected individual has formally contested this specific AI output.",        "Systemic bias patterns are invisible; repeated challenges cannot be identified."),
    ("resolved_as ★",             "RightToChallenge",      "ChallengeOutcomeEnum",   "A challenge has a formally recorded outcome including REMEDIATED.",                "Challenge outcomes not recorded; accountability and redress unenforceable."),
],

9: [
    ("characterises",             "HallucinationProfile",  "AIActor",               "Every AI actor has a documented hallucination profile.",                            "Organisation cannot identify which AI tasks carry the highest hallucination risk."),
    ("gates ★",                   "OutputValidationGate",  "AIOutput",              "The gate must be passed before this AI output reaches its consumer.",               "AI outputs flow to consumers without any epistemic safety check."),
    ("scores ★",                  "EpistemicRiskScore",    "OutputUsageContext",     "The epistemic risk score is computed for this output in this usage context.",       "Epistemic risk not quantified and cannot be compared with PCS-ranked adversarial risks."),
    ("feeds_epistemic_to_pcs ★",  "EpistemicRiskScore",    "EpistemicRiskComponent", "The epistemic score feeds ε_b back into the Layer 5 EpistemicRiskComponent.",      "PCS does not capture epistemic risk dynamically."),
    ("assigned_trust ★",          "AIOutput",              "OutputTrustLevelEnum",   "Each AI output has a formally assigned trust level before reaching its consumer.", "AI outputs are treated as equally trustworthy regardless of confidence level."),
    ("classified_as_evidence ★",  "AIOutput",              "EvidenceStatusEnum",     "Each AI output is formally classified for its admissibility as evidence.",         "AI outputs submitted as regulatory evidence without a formal admissibility assessment."),
    ("logged_as_incident ★",      "HallucinationIncident", "AIIncidentPlan",         "A hallucination event triggers the AIIncidentPlan classifying it as a security incident.", "Hallucination treated as a quality defect; no escalation follows."),
],

10: [
    ("profiles",                  "AIOutputConsumptionProfile","HumanConsumer",      "The profile formally quantifies how this human actor actually consumes AI outputs.", "Over-trust is invisible until an incident occurs."),
    ("identifies",                "AutomationBiasRisk",    "AIOutputConsumptionProfile","The bias risk identifies which psychological trigger drives over-trust.",        "Training interventions remain generic and ineffective."),
    ("classifies ★",              "MisuseIncident",        "AIIncidentPlan",         "AI misuse is classified as a security incident and triggers the AIIncidentPlan.",  "Misuse handled as user error with no security consequence."),
    ("verifies",                  "RealHumanInLoopVerification","HumanInLoop",        "This assessment verifies whether human review is substantive or symbolic.",        "Symbolic controls are reported as effective."),
    ("failed_due_to ★",           "MisuseIncident",        "AccountabilityFailureEnum","Each misuse incident is linked to the specific control that failed.",             "Misuse incidents investigated individually without identifying systemic failure."),
    ("inflates_pcs_from_misuse ★","MisuseIncident",        "WeightingScheme",        "Recurrent misuse inflates L and Δ in the PCS WeightingScheme.",                   "Misuse accumulation has no quantitative consequence in the risk score."),
    ("maps_to_design_gap ★",      "MisuseIncident",        "Constraint",             "Each misuse incident is linked to the Layer 3 Constraint whose absence enabled it.", "Misuse addressed by retraining operators rather than fixing structural design gap."),
],

11: [
    ("retires ★",                 "AIEndOfLifePlan",       "AIActor",                "This plan formally governs how this AI system is retired.",                        "No controlled retirement process; systems switched off without formal governance."),
    ("triggers_decommission ★",   "AIEndOfLifePlan",       "DecommissioningStatusEnum","The plan formally drives the DecommissioningStatusEnum state machine.",           "State machine values are a classification without enforcement."),
    ("disposes ★",                "ModelWeightDisposal",   "Asset",                  "Model weights are formally disposed of using DisposalMethodEnum.",                 "Weights persist in accessible storage after retirement."),
    ("retains ★",                 "DataRetentionDecision", "DataAsset",              "Training data is retained or deleted under this formal decision record.",           "Data retention obligations violated after system retirement."),
    ("prevents",                  "LegalHoldRecord",       "DataRetentionDecision",  "The legal hold prevents premature deletion until the hold is lifted.",              "Evidence deleted during an active investigation; spoliation."),
    ("confirms",                  "PostRetirementVerification","AIEndOfLifePlan",     "Post-retirement verification confirms all four closure conditions are satisfied.",  "Organisation cannot confirm the AI is no longer influencing decisions."),
    ("notifies_downstream ★",     "PostRetirementVerification","AIActor",             "The verification records which downstream systems have been notified.",             "Downstream systems continue consuming stale outputs from a retired model."),
    ("retired_for_reason ★",      "AIActor",               "DecommissionReasonEnum", "The reason for retirement is formally documented before decommissioning begins.",   "REGULATORY retirement triggers evidence obligations that cannot be activated without the reason."),
    ("weights_handled_as ★",      "AIActor",               "DataDispositionEnum",    "The model weight disposition decision is formally recorded before retirement.",     "Weights are handled informally with no record."),
    ("evidence_preserved_by ★",   "AIActor",               "LegalHoldRecord",        "A legal hold is formally linked to the AI actor whose artefacts must be preserved.", "Evidence deleted during active investigation."),
],
}

# ── Enumeration tables ────────────────────────────────────────────────────────
ENUM_TABLES = {

1: [
    ("AISystemTypeEnum",        "TYPE_1_INHOUSE, TYPE_2_FINETUNED, TYPE_3_THIRDPARTY_API",                "Three fundamentally different security profiles. Type 3 has no training data access and no rollback.",                             "Prevents applying wrong security controls to wrong AI architecture."),
    ("ModelTypeEnum",           "NN, RL, ENSEMBLE, PINN, LLM, CNN, HYBRID",                               "Each type has a different threat surface. LLMs hallucinate; RL models manipulated through reward signal; PINNs must satisfy physics.", "Enables threat-type-specific countermeasures."),
    ("RiskTierEnum",            "CRITICAL, HIGH, MEDIUM, LOW",                                            "Risk tier drives which of the eleven layers are mandatory.",                                                                      "Prevents under-governed deployment of high-risk AI."),
    ("LawTypeEnum ★",           "PHYSICAL_LAW, FINANCIAL_REGULATION, CLINICAL_SAFETY, MEASUREMENT_STANDARD, DATA_PROTECTION, SECTOR_SPECIFIC", "Classifies the category of law the DomainRule enforces.",                              "Without this enum the domain rule cannot be filtered by law category."),
    ("OwnershipRoleEnum ★",     "MODEL_OWNER, DATA_OWNER, DEPLOYMENT_OWNER, ROLLBACK_OWNER, DECOMMISSIONING_OWNER", "Formal role boundaries ensure no actor holds conflicting ownership.",                                               "Prevents a single actor holding MODEL_OWNER and DEPLOYMENT_OWNER simultaneously."),
    ("ApprovalModeEnum ★",      "SINGLE_ACTOR, DUAL_CONTROL, BOARD_APPROVAL",                             "DUAL_CONTROL is the minimum for CRITICAL or HIGH tier AI.",                                                                       "Structurally enforces dual-control governance."),
    ("ActorLifecycleRoleEnum ★","TRAINER, VALIDATOR, DEPLOYER, MONITOR, RETIRER",                         "An actor holding all three of TRAINER, VALIDATOR, DEPLOYER triggers RCF=3.0.",                                                   "Enforces role separation."),
    ("OrgSizeEnum ★",           "MICRO(1-9), SMALL(10-49), MEDIUM(50-249), LARGE(250-4999), ENTERPRISE(5000+)", "Maps to UK/EU SME definitions. Drives mandatory vs compensatable controls.",                                             "Prevents applying enterprise-grade requirements to a 5-person startup."),
    ("GovernanceMaturityEnum ★","AD_HOC, DOCUMENTED, MANAGED, MEASURED, OPTIMISING",                      "AD_HOC means no formal AI governance exists. Feeds governance maturity factor in PCS.",                                           "A CRITICAL-tier AI deployed by an AD_HOC organisation carries higher residual risk."),
    ("BudgetBandEnum ★",        "UNDER_10K, BAND_10K_50K, BAND_50K_250K, BAND_250K_1M, OVER_1M",         "Annual AI security budget. UNDER_10K constrains which compensating controls are realistic.",                                      "Ensures only budget-realistic alternatives are recommended."),
    ("ImportanceRatingEnum ★",  "NOT_RELEVANT, LOW, MEDIUM, HIGH, CRITICAL",                              "Stakeholder-entered importance. NOT_RELEVANT must trigger explicit justification.",                                               "Enables gap detection when stakeholder rating < framework minimum."),
    ("GapSeverityEnum ★",       "NONE, ADVISORY, SIGNIFICANT, CRITICAL",                                  "CRITICAL (3+ levels below minimum) blocks the relevant deployment gate.",                                                         "Distinguishes minor under-prioritisation from fundamental governance gap."),
    ("EnforcementLevelEnum ★",  "MANDATORY, COMPENSATABLE, RECOMMENDED, OPTIONAL",                        "Core mechanism distinguishing what the framework requires vs recommends per org profile.",                                         "Without this enum all controls are uniformly mandatory for all organisations."),
    ("CompensatingMechanismEnum ★","EXTERNAL_AUDIT, PEER_REVIEW, CERTIFIED_TOOLING, PERIODIC_MANUAL_REVIEW, DOCUMENTED_RISK_ACCEPT, EXTERNAL_VALIDATOR, SIMPLIFIED_DPIA", "Each value provides a specific accepted substitute.", "Maps directly to audit-defensible compensating controls."),
],

2: [
    ("DataConsentEnum ★",       "EXPLICIT, IMPLIED, NONE, UNKNOWN",                                       "UNKNOWN must block deployment for any AI processing personal data.",                                                              "Prevents personal data entering AI training pipelines without a documented legal basis."),
    ("FeedbackLoopEnum ★",      "NONE, HUMAN_REVIEWED, AUTOMATED",                                        "AUTOMATED feedback loops are the highest data poisoning risk configuration.",                                                    "Captures the chained AI attack path; AUTOMATED elevates W_f in PCS."),
    ("SensitivityEnum ★",       "PUBLIC, INTERNAL, CONFIDENTIAL, SENSITIVE_PERSONAL, SPECIAL_CATEGORY",  "SPECIAL_CATEGORY corresponds to GDPR Art.9 data requiring explicit legal basis and DPIA.",                                        "Without sensitivity classification, GDPR obligations for training data cannot be calibrated."),
    ("SupplyChainTypeEnum ★",   "DATASET, PRETRAINED_MODEL, LIBRARY, API_SERVICE, LABELING_SERVICE",      "Each type carries a different vetting requirement.",                                                                              "Without type classification all supply chain items receive the same vetting treatment."),
    ("VettingStatusEnum ★",     "UNVETTED, IN_REVIEW, APPROVED, REJECTED, CONDITIONALLY_APPROVED",        "UNVETTED and IN_REVIEW block the component from entering the training pipeline.",                                                  "Supply chain items enter pipeline before assessment is complete."),
    ("SupplyChainRiskEnum ★",   "LEGAL, SECURITY, OPACITY, JURISDICTION",                                 "OPACITY applies to any pre-trained model whose training data cannot be inspected.",                                               "Enables targeted supply chain mitigation."),
    ("PoisoningRiskEnum",       "LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN",                                   "UNKNOWN is the most operationally important value for Type 3 systems.",                                                           "Forces the organisation to formally document its inability to assess training data integrity."),
    ("OpacityEnum",             "FULL, PARTIAL, NONE",                                                    "FULL=Type1; PARTIAL=Type2; NONE=Type3 black box.",                                                                                "Prevents applying data provenance controls that cannot be executed for a given system type."),
    ("RetrainingTriggerEnum ★", "SCHEDULED, DRIFT_DETECTED, MANUAL, FEEDBACK_LOOP",                       "FEEDBACK_LOOP is the highest-risk trigger: retraining initiated by the deployed model's own outputs.",                           "Without classification the organisation cannot determine whether retraining is autonomous."),
],

3: [
    ("ConstraintTypeEnum ★",    "SECURITY, PRIVACY, DOMAIN, BIAS, HALLUCINATION, CONFIDENCE_SIGNAL, OUTPUT_PROVENANCE", "Seven constraint types. DOMAIN triggers D_m; HALLUCINATION triggers W_h and ε_b.",                             "Provides controlled vocabulary enabling gate logic to apply type-specific enforcement."),
    ("ConstraintPriorityEnum ★","BLOCKING, ADVISORY, COMPENSATABLE, WAIVED_WITH_JUSTIFICATION",           "BLOCKING means violation unconditionally prevents deployment.",                                                                    "Without priority classification all constraints produce the same gate response."),
    ("ConflictResolutionEnum ★","PRIORITISE_PRIVACY, PRIORITISE_SAFETY, HUMAN_DECISION, BOARD_DECISION",  "BOARD_DECISION is required when the conflict affects regulatory or safety-critical operations.",                                  "Prevents conflicts being silently resolved in favour of performance."),
    ("BiasMetricEnum ★",        "DEMOGRAPHIC_PARITY, EQUALISED_ODDS, CALIBRATION",                        "The choice of metric must be documented and justified before deployment.",                                                        "Makes bias constraints measurable and enforceable."),
    ("ConfidenceSignalEnum ★",  "NONE, QUALITATIVE, NUMERIC, INTERVAL",                                   "NONE is only acceptable for purely advisory outputs. NUMERIC or INTERVAL required for decision-making.",                          "Specifies minimum confidence communication requirement per output type."),
    ("PatternTypeEnum ★",       "PAS, DCFL, DADP, RDM, AROBUST",                                         "PAS=Privacy-Aware Shield; DCFL=Domain Constraint Firewall; DADP=Data-Aware Deployment Protocol.",                               "Without this enum the AISecurityPattern concept has no structured classification."),
],

4: [
    ("VectorTypeEnum ★",        "DATA, MODEL, INFERENCE, ACCESS, SUPPLY_CHAIN, CHAINED_AI",               "CHAINED_AI is unique to ST-AI. Captures attack where one AI's outputs become another's training data.",                           "Provides controlled vocabulary for the chained AI attack surface that no prior framework names."),
    ("InsiderRoleEnum ★",       "DATA_ENGINEER, ML_ENGINEER, CLOUD_OPERATOR",                             "Each role maps to a different attack surface requiring different dual-control countermeasures.",                                  "Converts generic insider threat into role-specific attack surface mapping."),
    ("AttackPhaseEnum ★",       "TRAINING, INFERENCE, SUPPLY_CHAIN",                                      "TRAINING-phase attacks (poisoning, backdoor) are hardest to detect post-deployment.",                                            "Threat model cannot determine at which lifecycle stage each attack must be mitigated."),
    ("SilentFailureEnum ★",     "PERFORMANCE_DRIFT, BIAS_DRIFT, DATA_LEAK",                               "These three produce no crash, no error log, and no alert. PERFORMANCE_DRIFT extends Δ to months.",                              "Drives monitoring architecture design."),
    ("ExploitWindowEnum ★",     "IMMEDIATE, DAYS, WEEKS, MONTHS",                                         "Maps directly to Δ in the PCS formula. PERFORMANCE_DRIFT=MONTHS (highest financial exposure).",                                 "Without this enum Δ cannot be set per vulnerability type."),
    ("VulnerabilityTypeEnum ★", "DATA_POISONING, MODEL_EXTRACTION, MEMBERSHIP_INFERENCE, BACKDOOR, EVASION, SILENT_DRIFT", "Each type requires a different mitigation pattern from Layer 3.",                                        "Vulnerability records cannot be automatically routed to the correct mitigation pattern."),
    ("CapabilityEnum",          "LOW, MEDIUM, HIGH, APT",                                                 "APT is the capability level for state-sponsored attacks on critical infrastructure AI.",                                          "Ensures countermeasure investment is calibrated to realistic attacker capability."),
    ("MotivationEnum ★",        "FINANCIAL, POLITICAL, COMPETITIVE, SABOTAGE, INSIDER_GRIEVANCE",         "Motivation determines persistence, sophistication, and target selection.",                                                       "Without motivation classification insider threat profiling remains generic."),
],

5: [
    ("ActionTierEnum",          "CRITICAL(≥60), HIGH(≥30), MODERATE(≥10), LOW(<10)",            "CRITICAL means deployment is blocked unconditionally regardless of organisation size.",                                           "Acts as the formal deployment gate signal."),
    ("RegulatoryImpactEnum ★",  "NONE, LOCAL, NATIONAL, MULTI_JURISDICTION",                              "MULTI_JURISDICTION triggers the highest regulatory weight (2.5×) in the PCS formula.",                                          "Calibrates PCS to multi-jurisdictional regulatory exposure."),
    ("PCSBlockReasonEnum ★",    "DOMAIN_VIOLATION, HALLUCINATION_RISK, FAIRNESS_BREACH, CRITICAL_THREAT, MISSING_VALIDATION, IMPORTANCE_GAP_CRITICAL, UNCOMPENSATED_ROLE_CONCENTRATION, MAP_VALIDATION_MISSING", "Two values address organisational-dimension failures directly; MAP_VALIDATION_MISSING fires from SC-MAP-1 (NIST AI RMF MAP).", "Extends remediation routing to organisational and sociotechnical-context failures."),
    ("HallucinationRiskEnum",   "NONE, LOW, MEDIUM, HIGH, CRITICAL",                                      "CRITICAL means AI used in high-stakes domain without adequate human review gates.",                                              "Feeds directly into W_h and the EpistemicRiskComponent."),
    ("CompliancePathEnum ★",    "FULL_COMPLIANCE, COMPENSATED_COMPLIANCE, CONDITIONAL_DEPLOYMENT, NON_COMPLIANT_BLOCKED", "Replaces binary passed=TRUE/FALSE with a four-state outcome.",                                              "Correctly classifies SMEs with approved compensating controls."),
    ("ResidualRiskBandEnum ★",  "NEGLIGIBLE(<0.5), LOW(0.5-2.0), MEDIUM(2.0-5.0), HIGH(5.0-10.0), UNACCEPTABLE(>10.0)", "UNACCEPTABLE blocks COMPENSATED_COMPLIANCE. HIGH triggers 90-day reassessment.",                             "Without this enum residual_risk_from_compensations is a raw float with no actionable classification."),
],

6: [
    ("StageNameEnum ★",         "COLLECT, TRAIN, VALIDATE, SIGN, DEPLOY, MONITOR",                        "SIGN is blocked by DomainGate; TRAIN blocked when signed_at_collection=FALSE.",                                                  "Without this enum pipeline stages are referenced as free-text strings."),
    ("RollbackModeEnum ★",      "AUTOMATED, MANUAL, NOT_POSSIBLE",                                        "NOT_POSSIBLE is mandatory for all Type 3 deployments.",                                                                          "Prevents organisations designing rollback plans for systems where rollback is impossible."),
    ("ContinuityStateEnum ★",   "NORMAL, DEGRADED, FALLBACK, MANUAL_ONLY",                                "MANUAL_ONLY means AI-assisted operations have ceased entirely.",                                                                  "Provides formal operational readiness signal."),
    ("AIDependencyLevelEnum",   "CRITICAL_NO_FALLBACK, CRITICAL_WITH_FALLBACK, IMPORTANT, ADVISORY",      "CRITICAL_NO_FALLBACK is an unconditional pre-deployment blocker regardless of organisation size.",                               "The most direct business continuity gate in the framework."),
    ("GateDecisionEnum",        "APPROVED, BLOCKED, REQUIRES_REVIEW",                                     "REQUIRES_REVIEW is the intermediate state for borderline cases requiring human decision.",                                        "Provides three-state gate logic rather than binary pass/fail."),
    ("DeploymentModeEnum ★",    "STANDARD, CANARY, SHADOW, BLUE_GREEN, EMERGENCY_ROLLBACK",               "CANARY routes defined traffic % to candidate while baseline remains active.",                                                     "CanaryDeployment concept has no formal classification without this enum."),
],

7: [
    ("ShutdownTriggerEnum ★",   "DRIFT_THRESHOLD, BIAS_BREACH, DOMAIN_VIOLATION",                         "DOMAIN_VIOLATION must activate ModelQuarantine immediately.",                                                                     "Elevates domain law violations from performance events to security-critical shutdowns."),
    ("ConsequenceEnum ★",       "ALERT, RETRAIN_TRIGGER, SHUTDOWN, QUARANTINE, ESCALATE_PCS",             "SHUTDOWN stops the model entirely; QUARANTINE isolates while activating fallback.",                                              "Without this enum all alert consequences are undifferentiated."),
    ("AuditFrequencyEnum ★",    "CONTINUOUS, DAILY, WEEKLY, QUARTERLY",                                   "CONTINUOUS required for real-time decisions affecting protected groups. QUARTERLY accepted for Micro/Small.",                    "Makes fairness auditing frequency a formal design requirement."),
    ("DriftTypeEnum",           "DATA_DRIFT, CONCEPT_DRIFT, PERFORMANCE_DRIFT, PREDICTION_DRIFT",         "Concept drift requires retraining rather than recalibration.",                                                                    "Ensures correct monitoring and remediation strategy is applied."),
    ("DriftMethodEnum",         "KS_TEST, PSI, CUSUM, PAGE_HINKLEY, ADWIN",                               "CUSUM and PAGE_HINKLEY are sequential methods for real-time streams.",                                                           "Enables method selection proportionate to operational context."),
],

8: [
    ("OutputOwnershipEnum ★",   "DEPLOYING_ORGANISATION, AI_PROVIDER, JOINT, UNRESOLVED",                 "UNRESOLVED is a pre-deployment blocker for any commercial or regulatory use.",                                                   "Prevents deployment of AI systems whose output ownership is unresolved."),
    ("LiabilityAllocationEnum ★","DEPLOYING_ORGANISATION_ONLY, SHARED, PROVIDER_INDEMNIFIED, CONTRACTUALLY_DISPUTED", "PROVIDER_INDEMNIFIED achievable only through explicit contractual negotiation.",                                "Forces explicit liability negotiation before deployment."),
    ("LiabilityHolderEnum ★",   "ORGANISATION, VENDOR, SHARED",                                           "Formally records which legal entity holds liability at the time of any AI-caused harm.",                                        "Creates an auditable liability assignment."),
    ("ChallengeOutcomeEnum ★",  "ACCEPTED, REJECTED, REMEDIATED",                                         "REMEDIATED triggers mandatory review of the OutputGate configuration.",                                                          "Closes the feedback loop between challenge resolution and systemic design improvement."),
    ("NotificationTimingEnum ★","BEFORE_DECISION, AT_DECISION, AFTER_DECISION, ON_REQUEST",               "BEFORE_DECISION required for high-impact automated decisions affecting HIGH_DEPENDENCY stakeholders.",                            "Transparency obligations cannot be fulfilled proportionately without timing classification."),
    ("StakeholderVulnerabilityEnum ★","GENERAL_PUBLIC, CONSUMER, PATIENT, EMPLOYEE, MINOR, PROTECTED_CHARACTERISTIC, HIGH_DEPENDENCY", "HIGH_DEPENDENCY means the individual has no practical alternative.", "Calibrates stakeholder rights obligations to actual harm potential."),
],

9: [
    ("OutputTrustLevelEnum ★",  "LOW, MEDIUM, HIGH",                                                      "LOW means the output must not be used in any decision without independent human verification.",                                  "Drives output gate selection."),
    ("EvidenceStatusEnum ★",    "ADMISSIBLE, BLOCKED, REVIEW_REQUIRED",                                   "BLOCKED means the output must not be submitted as regulatory evidence under any circumstances.",                                 "Structurally prevents hallucinated outputs from reaching regulators."),
    ("EpistemicRiskCategoryEnum ★","HALLUCINATION, OVER_TRUST, MISUSE, COMPLIANCE_HALLUCINATION, EMBEDDED_AUTOMATION, SUMMARY_DISTORTION, DECISION_CONTAMINATION", "Each category requires a different mitigation pathway.", "Enables category-specific mitigation design."),
    ("ConsumptionRoleEnum ★",   "ADVISORY_READER, DECISION_MAKER, AUTOMATED_EXECUTOR, REGULATOR_SUBMITTER, AUDITOR", "AUTOMATED_EXECUTOR is the highest-risk consumer.",                                                              "Calibrates gate stringency to consumer role."),
],

10: [
    ("TrainingCoverageEnum ★",  "PARTIAL, COMPLETE, EXPIRED",                                             "EXPIRED means training completed but refresh interval elapsed. Equivalent to no training for CRITICAL-tier AI.",               "Prevents stale training records from satisfying governance requirements."),
    ("AccountabilityFailureEnum ★","NO_POLICY, NO_SIGNALING, NO_OVERRIDE",                                "NO_POLICY=missing OrganisationalAIPolicy. NO_SIGNALING=missing ConfidenceSignalConstraint. NO_OVERRIDE=missing HumanOverride.", "Maps misuse incidents to specific remediable design gaps."),
    ("RootCauseEnum ★",         "NO_TRAINING, TRAINING_INADEQUATE, REVIEW_BYPASSED_DELIBERATELY, REVIEW_BYPASSED_INADVERTENTLY, SYSTEM_DID_NOT_SIGNAL_UNCERTAINTY, ORGANISATION_DID_NOT_ACCEPT_HALLUCINATION_RISK", "ORGANISATION_DID_NOT_ACCEPT_HALLUCINATION_RISK is a root cause no prior security framework expresses.", "Provides the first root cause taxonomy for AI misuse incidents."),
    ("MisuseScenarioTypeEnum ★","BOARD_REPORT_HALLUCINATION, COMPLIANCE_HALLUCINATION, EMBEDDED_CASCADE_FAILURE, AUTOMATION_BIAS_DECISION, REVIEW_BYPASS, EVIDENCE_USE_WITHOUT_REVIEW, MEETING_SUMMARY_DISTORTION", "Seven highest-impact AI misuse patterns.", "Enables pre-deployment scenario assessment."),
    ("AutomationBiasTriggerEnum ★","AUTHORITY_BIAS, CONSISTENCY_BIAS, AUTOMATION_COMPLACENCY, CONFIRMATION_BIAS, TIME_PRESSURE", "Each trigger requires a different training intervention.",                                           "Targeted training significantly more effective than generic AI literacy programmes."),
    ("BiasRiskLevelEnum ★",     "LOW, MEDIUM, HIGH, CRITICAL",                                            "CRITICAL means operator review rate is effectively zero and human-in-the-loop is entirely symbolic.",                          "Without risk level classification all automation bias patterns receive the same response."),
],

11: [
    ("DecommissioningStatusEnum ★","PLANNED, IN_PROGRESS, WEIGHTS_DISPOSED, DATA_DELETED, AUDIT_COMPLETE, LEGALLY_HELD", "LEGALLY_HELD blocks the WEIGHTS_DISPOSED transition when a LegalHoldRecord is active.",                      "Implements formally ordered state machine for AI retirement."),
    ("DecommissionReasonEnum ★","RISK, OBSOLESCENCE, REGULATORY, BUSINESS",                               "REGULATORY triggers the highest evidence preservation obligations and mandatory stakeholder notification.",                      "Without reason classification REGULATORY retirements cannot be distinguished from routine BUSINESS decisions."),
    ("DataDispositionEnum ★",   "DELETE, ARCHIVE, RETAIN_UNDER_HOLD",                                     "RETAIN_UNDER_HOLD is only valid when a LegalHoldRecord is active.",                                                            "Enforces legal hold integrity."),
    ("RetentionBasisEnum ★",    "GDPR_LEGAL_OBLIGATION, REGULATORY_INVESTIGATION, CONTRACTUAL, LEGITIMATE_INTEREST, NONE", "NONE means deletion is mandatory and cannot be deferred.",                                               "Creates a post-retirement data governance trail."),
    ("DisposalMethodEnum ★",    "SECURE_DELETE, CRYPTOGRAPHIC_DESTRUCTION, ARCHIVE_ENCRYPTED, TRANSFER_TO_SUCCESSOR", "CRYPTOGRAPHIC_DESTRUCTION means the encryption key is destroyed, making weights irrecoverable.",             "Without disposal method classification the ModelWeightDisposal record cannot be verified as irreversible."),
],
}
