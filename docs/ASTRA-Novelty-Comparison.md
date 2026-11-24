# ASTRA: novelty against the literature and industry

Status: working draft. Paper rows are taken from summaries pasted by the author, not from reading the papers. Industrial rows are from general knowledge and must be checked against current product documentation before anything is cited. "ASTRA" means what is built today; nothing planned is counted.

## What ASTRA does (the baseline for every comparison)

1. A formal socio-technical model (Secure Tropos) yields machine-checked control statuses (satisfied, unverified, violated, not applicable) over 22 divergence classes mapped to OWASP agentic rows, with department tolerances and impact tiers ratified by people.
2. A design is assessed, accepted as a baseline by a second person, and signed (Ed25519) as a versioned behavioural contract.
3. The Probe replays a planted attack and a harmless boundary case against the exact design version. A pass is required before signing. Results are reported as caught, missed, waits for a person, advisory, not tested. Evidence expires after 30 days.
4. The signed contract is enforced by a runtime check.
5. Learned detectors (statistical baseline, TGN, GNN) are advisory only. A person adopts one only after a recorded evaluation on held-out attack families passes the platform's gate, including a minimum share of catches the rules and baseline missed. No model has passed this gate yet.

## Table 1: academic papers

| Paper (as summarised) | What it does | Overlap with ASTRA | What ASTRA adds or does differently | Novelty verdict for ASTRA |
|---|---|---|---|---|
| Spatio-temporal GNN for human-AI collaborative decision-making | Graph of humans, agents and options; tracks trust drift and over-reliance | Temporal graph learning over agent interactions (our TGN) | Learned output is advisory, gated by held-out evaluation, tied to a contract | Not novel (graph learning). Gate and governance are the difference |
| Multi-Agent Framework for Threat Mitigation (heterogeneous GNN) | Fuses code, model artefacts and tool-use topology; scores cascading vulnerabilities | Graph model over agent topology (our GNN) | Our GNN scores behaviour against the contract's permitted set, with attacks built only from permitted targets | Not novel. Evaluation protocol is the difference |
| Early-warning temporal GNNs; spatial-temporal GNN for container escape | Anomaly detection on system and audit graphs | Anomaly detection on event streams | Real-traces mode injects attacks only into held-out time windows; families split into development and test | Not novel. Evaluation design is a method detail, not a headline |
| GNN control admissibility models | Predicts sets of safe actions for many agents | Admissible-set idea resembles a permitted set | Ours is derived from a signed contract, not learned | Not novel |
| NVIDIA OpenShell formal policy prover | Permissions and policies to formal logic; deterministic proof of invariant violations | Deterministic policy check at action time | Policy comes from an assessed, baselined, signed design with two-person approval; Probe tests it first | Partly overlapping. Lifecycle around the policy is the difference |
| Knowledge-graph-constrained POMDP risk-aware planning | Formalises socio-technical risk under partial observability | Socio-technical risk with organisational structure | Ours is a checking and governance system, not a planner | Not novel (socio-technical risk modelling) |
| Formal verification of human-agent interaction (belief graphs, dialogue games) | Verifies how an agent shifts human beliefs | Formal reasoning about human-agent relations | Ours covers permissions, delegation and data flow, not persuasion | Different scope, little overlap |
| 4C framework (core, connection, cognition, compliance) | Layered defence including human factors | Layered view; compliance layer | Executable checks and signed artefacts rather than a conceptual layering | Not novel as a framework |
| Trustworthy agent development lifecycle (six phases) | Lifecycle with technical controls, oversight and audit gates | Lifecycle shape: design, evaluate, deploy, monitor | Concrete gates with recorded evidence and a signature | Not novel as a lifecycle. Mechanism is the difference |
| ARC framework | Maps capabilities and design choices to risks and to organisational risk tolerance | Control to tolerance mapping (our tiers and tolerances) | Tolerances are ratified by a second person and used in machine assessment | Not novel (concept) |
| Mirror-mapped governance (cognitive friction, override controls) | Five failure modes, each with a structural remedy | Two-person rule and human adoption gate are cognitive friction | Friction is enforced by the system, not advised | Not novel (concept). Enforcement is the difference |
| Heartbeat orchestration (agent-initiated reconfiguration) | Governance tiers for agents creating unauthorised workflows | Drift and divergence classes | Drift is detected against a signed baseline | Partly overlapping |
| Iterative sandboxing under the EU AI Act | Re-test when models, tools, permissions or roles change | A changed design needs a new assessment, baseline, Probe and signature | Automated, version-pinned, with expiry of evidence | Not novel (idea). Automation is the difference |
| ATFAA and SHIELD | Threat model and enterprise mitigations for agents | Trust boundaries, lateral movement, cross-system flow | Contract-bound runtime check and department-flow counts | Partly overlapping |
| Multi-agent risk taxonomies (miscoordination, conflict, collusion) | Taxonomy and mitigation directions | Divergence classes act as a taxonomy | Our classes are tied to executable checks and Probe scenarios | Not novel as a taxonomy |

## Table 2: industrial solutions (general knowledge, verify before citing)

| Category and examples | What they typically do | Overlap with ASTRA | What ASTRA adds or does differently | Novelty verdict for ASTRA |
|---|---|---|---|---|
| Identity and access for agents (for example Microsoft Entra agent identity, Okta for AI agents) | Give agents identities, credentials and access policy | Who may act and what they may reach | Behavioural contract with design-level assessment, not only identity and scope | Different layer, complementary |
| Policy engines (OPA, Cedar-based agent policy) | Deterministic allow or deny by written policy | Deterministic runtime decision | Policy is generated from the assessed design and signed; two-person approval; Probe before signing | Partly overlapping. Lifecycle is the difference |
| Guardrail products (NeMo Guardrails, Guardrails AI, prompt-injection filters) | Input and output filtering, often probabilistic | Runtime protection | Contract-based permitted set; learned parts advisory only | Different mechanism |
| AI security posture and agent security platforms (for example Wiz AI-SPM, Zenity, Noma, Cisco AI Defense, Palo Alto AI security) | Inventory, misconfiguration findings, runtime detection | Inventory, posture, detection | Formal model, signed contract, Probe, gated learning | Overlap in goals. Mechanisms differ; verify current features |
| AI governance and GRC platforms (Credo AI, IBM watsonx.governance, ServiceNow AI control tower) | Inventories, risk assessments, approvals, attestations | Approvals and recorded assessment | Machine-checked assessment bound to a runtime-enforced artefact | Partly overlapping. Enforcement link is the difference |
| Red-team and eval tools (PyRIT, garak, promptfoo) | Generate attacks and score model or agent responses | Probe plants attacks | Probe tests the design against the contract and gates signing; scenarios are approved by a person | Partly overlapping. Pre-sign gate is the difference |
| Observability (LangSmith, Arize, Langfuse) | Traces, evaluations, dashboards | Event capture | Events feed contract conformity and learned detectors | Different purpose |
| Supply-chain signing (Sigstore, in-toto) | Sign and attest software artefacts | Signature and attestation | Signs a behavioural contract, not a build artefact | Same primitive, different object |
| Taxonomies (OWASP agentic, MITRE ATLAS) | Shared vocabulary of threats | Our classes map to OWASP rows | Taxonomy turned into executable checks | Not novel (vocabulary) |

## Table 3: capability matrix (what each category covers)

Cells say what the category does according to the sources above; "no" means I found nothing in the summaries, not that it does not exist.

| Capability | Frameworks and taxonomies | Graph-learning papers | Formal-verification papers | Policy engines | Guardrail products | AI-SPM and agent security | GRC platforms | Red-team tools | ASTRA |
|---|---|---|---|---|---|---|---|---|---|
| Formal socio-technical model | concept only | no | partly | no | no | no | no | no | yes |
| Machine-checked control status | no | no | yes (invariants) | yes (rules) | no | partly | no | no | yes |
| Organisational tolerance and impact tiers | concept (ARC) | no | partly | no | no | partly | partly | no | yes |
| Two-person approval | advice | no | no | no | no | no | workflow | no | yes |
| Signed, versioned behavioural contract | no | no | no | policy files | no | no | no | no | yes |
| Attack test before approval | no | no | no | no | no | no | no | after the fact | yes |
| Runtime enforcement | no | detect | no | yes | yes | yes | no | no | yes |
| Learned detector with admission gate | no | no gate | no | no | no | no gate known | no | no | yes (none passed yet) |
| Evidence that expires | no | no | no | no | no | no | partly | no | yes |

## Defensible novelty (and its limits)

Defensible: the integration and governance of known techniques as one pipeline (assess, second-person baseline, Probe before signing, signed contract, runtime check, gated advisory learning).

Not defensible: the formal model's scope, the divergence taxonomy, graph learning on agent traces, or the lifecycle concept. Each exists in the sources above.

Unproven, and needed before the claim holds in a paper:
- a real pilot with a real agent and an independent assessor;
- a TGN or GNN that passes the gate on real traces;
- a case where Probe before signing catches something that signing first and testing later would have missed;
- a proper literature and product search confirming no system chains these steps.
