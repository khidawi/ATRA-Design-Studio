# ASTRA: build phases for the proposal in Figure 1

Status: plan for decision. Nothing in this document is built yet. It is written so that you can say "build phase N" and each phase is a complete, reviewable, committable unit.

Sources: the ASTRA specification v0.2, the formal agent-model paper (22 divergence classes, gate, Probe, learned layer), the architecture proposal, and the repository as it stands today.

## 1. How each phase is run

Every phase follows the same routine, so that nothing reaches GitHub unreviewed:

1. **Branch.** `astra/phase-N-short-name` from `main`. One phase, one branch.
2. **Build and test.** New suites follow the repository's style (`backend/tests/test_*.py`, run as `python -m tests.test_x`, printing `PASS`/`FAIL` lines). They run only on the scratch database `stai_test`, never on the live `stai` database (the guard in `tests/_guard.py` enforces this).
3. **Docker review.** `docker compose up --build`, you check it on localhost. This is your standing rule from earlier work.
4. **Commit.** Only when you say so. One commit per phase, or a few if the phase has sub-steps (listed below). Migrations are additive: nothing drops or rewrites live data (`company_nodes`, `company_edges`, contracts, findings).
5. **Push and CI.** Push the branch and open a pull request into `main`. CI runs the backend suites against a real PostgreSQL, the SDK tests, the studio page parse check, the linters, the vulnerability scans and the image builds. Merge only when it is green.
6. **Tag** (optional, at the end of a group of phases) so the signed-release workflow produces a release with an SBOM.

**Before Phase 1:** the working tree already holds uncommitted changes from earlier work (14 modified files, including `studio/index.html`, `backend/db/models.py`, `backend/main.py`, and an untracked migration `0036_st_ai_policy.py`). Commit or stash those on their own first, so that no phase mixes unrelated changes. The first migration of this plan is therefore `0037`.

## 2. Decisions needed before the phases that depend on them

| # | Decision | Needed by | Recommendation |
|---|---|---|---|
| D1 | Contract format: the specification's Appendix A schema (and sign it), or the compact contract with the specification updated | Phase 5 | Appendix A for export and signing; keep the compact view as a projection for the UI |
| D2 | Signing: algorithm and key custody | Phase 5 | Ed25519 (the `cryptography` library is already a dependency); a signing key separate from `ASTRA_SECRET_KEY`, with a key id and rotation list |
| D3 | Workflow: branch and pull request per phase, or direct pushes to `main` | Phase 0 | Branch and pull request, so CI runs before merge |
| D4 | Impact tiers: 1 to 4, who ratifies | Phase 2 | 1 to 4; compliance role ratifies, owner proposes |
| D5 | Learned layer: build now or after real traces exist | Phase 10 | Build the harness now, enable detectors only when the adoption gate passes |

## 3. What the paragraph promises, and which phase delivers it

| Sentence of the manager paragraph | Delivered by |
|---|---|
| The organisation describes the agent inside its structure: departments, tools, data, harm per department | Phases 2, 3 |
| ASTRA checks every possible attack path before release | Phases 3, 4 |
| A testing component measures how risky each path is and whether the protections work | Phase 8 |
| If too risky, add controls and check again | Phase 4 |
| A person accepts the baseline; only then is a signed contract issued | Phase 5 |
| Every action is compared with the signed contract; a departure raises a typed alert | Phase 6 |
| The same checks re-run and give an updated verdict | Phase 7 |
| Fail-closed: anything unverifiable is never treated as safe | Phases 1, 6, 7 |
| Learned detectors: order and timing of actions; connections across departments | Phases 9, 10, 11 |
| Halt stays with a person | Phase 7 |
| Tamper-evident record and an evidence report mapped to EU AI Act, ISO 42001, OWASP | Phase 12 |

## 4. The phases at a glance

| Phase | Name | Size | Depends on | Visible result |
|---|---|---|---|---|
| 0 | Ground work and decisions | S | none | clean tree, decisions logged |
| 1 | Formal agent model core | M | 0 | tested pure module in the backend |
| 2 | Organisation risk layer | M | 1 | Organisation risk screen |
| 3 | Estate builder and exposure analysis | M | 1, 2 | Assessment tab (read-only) |
| 4 | Agent gate and the design loop | M | 3 | Add controls loop, gate verdict |
| 5 | Ratification and signed contracts | M | 4, D1, D2 | draft, ratified, signed contract |
| 6 | The 22 divergence classes | L | 5 | typed findings with basis and response |
| 7 | Runtime gate re-run and verdicts | M | 6 | verdict per agent, department risk vector |
| 8 | ASTRA Probe | L | 4, 6 | scenario suite, incident-to-test, PR check |
| 9 | Learned layer foundation and baseline | M | 7, 8 | Learned detectors screen, baseline |
| 10 | TGN | L | 9 | temporal detector behind an adoption gate |
| 11 | GNN | L | 9 | graph detector behind an adoption gate |
| 12 | Assurance outputs and roles | M | 7, 8 | class-level coverage and evidence packs |
| 13 | Hardening and pilot | M | all | end-to-end script, security review, one real agent |

Sizes are relative: S is about one working session, M two to three, L four or more. Phases 10 and 11 are independent of each other.

---

## Phase 0: Ground work and decisions
**Goal.** Start from a clean, reviewable position.
**Scope.**
- Commit or stash the existing uncommitted work separately.
- Record decisions D1 to D5 in `docs/ASTRA-Decisions.md`.
- Add this plan to the repository.
- Run the current suites on `stai_test` and record the baseline result.
**Commit.** `Add ASTRA build phases and decision log`.
**Acceptance.** `git status` is clean, baseline suites pass, decisions are written down.

## Phase 1: Formal agent model core
**Goal.** The model of the paper exists in the backend as pure, tested Python, before any screen depends on it.
**Scope.**
- New package `backend/astra_model/`: `estate.py`, `statuses.py` (SAT/UNV/VIO/NA, evidence, expiry), `exposure.py` (attack paths, required controls), `gate.py` (verdict, risk vector), `events.py` (event kinds, required attributes), `classes.py` (the 22 classes as data: basis, severity, control kind, ASI), `contract.py` (canonical form, hash, validity).
- A port of the reference implementation in `docs/astra-formal-agent-model-paper/code/astra_ref`, kept as the oracle.
- No database changes and no API yet.
**Tests.** `tests/test_astra_model.py`: the ten properties; the 14 planted defects, each failing at least one property; a differential test of the backend implementation against the reference implementation on random estates.
**Commit.** `Add the formal agent model core with property tests`.
**Acceptance.** All properties pass; all 14 planted defects are detected; differential test shows zero disagreements.
**Risk.** Drift between the paper and the code: keep the class table generated from one source file.

## Phase 2: Organisation risk layer
**Goal.** Departments declare how much harm matters, and a person ratifies it.
**Scope.**
- Migration `0037`: `risk_asset_tiers` (asset ext id, tier 1 to 4, confidentiality, integrity, availability, rationale), `risk_department_tolerance` (department ext id, tolerance 0 to 4), `risk_posture` (tier, severity, posture: observe, flag, block, halt), each with proposer, ratifier and time. Additive only. The organisation graph (`company_nodes` of type department and data store) is read, never rewritten.
- API `/api/risk/*`: list, propose, ratify. The compliance role ratifies; the engineer role cannot. Every change goes into the audit chain.
- Screen: **Organisation risk** (as in the mockup).
**Tests.** `tests/test_risk_layer.py`: permissions by role, ratification recorded, posture is monotone in tier and severity, audit events written.
**Commit.** `Add organisation risk layer: impact tiers, tolerance, response posture`.
**Acceptance.** Tiers and tolerance can be set, ratified and read back; the live organisation data is unchanged.

## Phase 3: Estate builder and exposure analysis
**Goal.** From an existing agent design, build the estate model and show every attack path per department.
**Scope.**
- `backend/astra_estate.py`: build an `Estate` from a design snapshot (the design nodes: agent, tool, mcp, data, memory, input, approval, guardrail, constraint) and the organisation graph (owner department).
- Control statuses from the design (declared constraints), from `evidence_records` (with their existing expiry) and from later Probe results. Map the existing inherent, declared and verified levels onto SAT/UNV/VIO.
- API `GET /api/agents/{key}/assessment`: paths, required controls with status, risk vector per department.
- Screen: **Assessment tab** in the design studio, read-only (paths, exposure by department).
**Tests.** Golden estates from the paper (BLOCKED, REQUIRES_REVIEW, APPROVED); path depth bound; narrowing never lowers the verdict.
**Commit.** `Add estate builder and exposure analysis`.
**Acceptance.** For a demo agent, the Assessment tab shows the same paths and verdict as the reference implementation.
**Risk.** Mapping design nodes to model attributes loses information; list unmapped fields in the response instead of guessing.

## Phase 4: Agent gate and the design loop
**Goal.** The gate decides; failing paths suggest controls; adding a control re-assesses.
**Scope.**
- Gate verdict (INVALID_CONTRACT, BLOCKED, REQUIRES_REVIEW, APPROVED) over the statuses.
- Suggested controls: a table from (ASI row, failed control kind) to a design node to add (approval step, guardrail, constraint), with the reason.
- "Add to design" writes the node into the draft design through the existing autosave (with the version conflict check).
- Migration `0038`: `assessments` (agent, design version hash, verdict, risk vector, created by, time), immutable.
**Tests.** The loop of the mockup as a test: BLOCKED, add three controls, probe results stubbed, APPROVED.
**Commit.** `Add the agent gate, suggested controls and assessment history`.
**Acceptance.** Same loop works end to end in the UI on a demo agent.

## Phase 5: Ratification and signed contracts
**Goal.** A contract is signed only after the gate approves and a person ratifies the baseline.
**Scope.**
- Migration `0039`: on `contracts`, add `signature`, `key_id`, `signed_by`, `not_before`, `expires_at`, `baseline_assessment_id`; a `DRAFT` state beside `ACTIVE`. The document itself stays immutable.
- Signing with Ed25519; keys from a separate environment secret with a key id; a rotation list; a verify endpoint.
- D1: export in the Appendix A schema (validated with a JSON Schema check) and keep the compact view for the UI.
- Reconciler ignores drafts (`_active` already requires ACTIVE).
- Screen: **Contract** (draft banner, ratify, sign, signature block).
**Tests.** Tamper with any field: invalid; expired and revoked: invalid; INVALID_CONTRACT outranks every verdict; only compliance can ratify and sign; an engineer or an API key can never sign.
**Commit.** `Add baseline ratification and signed behavioural contracts`.
**Acceptance.** A draft cannot be used at runtime; a signed contract verifies; a change widening the agent needs a new assessment.
**Risk.** Key custody: document it in the deployment guide; never log keys.

## Phase 6: The 22 divergence classes
**Goal.** The reconciler checks every class that can be checked deterministically, with typed records.
**Scope.** In three steps, each its own commit:
- **6a Event schema v2 and records.** New event kinds (`exec`, `goal_set`, `msg`, `id`, `life`, `spawn`, `component`, and hitl confirmation with presented and executed hashes), backward compatible with the five existing types. Migration `0040`: findings gain `detection_basis`, `contract_element`, `construct`, `asi_signal`, `evidence_refs`, `response_recommended`. Runtime binding: a selector per monitorable element, defaulting to the name match; an unbound event is UNVERIFIED, never conforming.
- **6b Policy classes.** TOOL-02, TOOL-03, EXEC-01, MEM-02, DEL-02, DEL-03, AUT-01, AUT-02, AUT-03, ID-01, LIFE-01, SPAWN-01, then the existing five (TOOL-01, RES-01, MEM-01, DEL-01, SUP-02).
- **6c Cryptographic and semantic classes.** COMM-01 (new message-authentication check) and SUP-01 (extend the existing unsigned-server check to provenance); GOAL-01 and GOAL-02 as PENDING with a human adjudication queue.
- SDK: emit the new kinds; the OpenTelemetry adapter maps what spans carry and marks the rest unbound.
**Tests.** One planted-defect scenario and one boundary case per class (the same table the Probe uses); the existing `test_findings_drift` and `test_runtime` stay green.
**Commit.** Three commits, one per step.
**Acceptance.** The Divergence classes screen shows the number of classes monitored rising from 6 to 21 (19 deterministic classes plus the 2 semantic ones as pending; the baseline class waits for Phase 9).
**Risk.** Some classes need telemetry that frameworks do not emit; the screen must say "needs collector event" instead of claiming coverage.

## Phase 7: Runtime gate re-run and verdicts
**Goal.** Live evidence changes the verdict; severity decides what it means for each department.
**Scope.**
- Status update from findings: High and Critical give VIO, Medium gives UNV, UNVERIFIED and PENDING give UNV; supportive evidence only from a Probe pass, an attestation, a human adjudication, or a new contract version.
- Evidence expiry reads the clock.
- `GET /api/runtime/verdicts`: verdict per agent and the department risk vector; the existing halt request stays a recorded recommendation, with the response posture shown.
- Screen: **Live runtime** (verdict per agent, risk vector, typed feed).
**Tests.** DB-backed versions of the properties: monotone, fail-closed, expiry, a High divergence below tolerance gives review, not block.
**Commit.** `Add runtime gate re-run, verdicts and department risk vector`.
**Acceptance.** Sending a violating event moves the agent's verdict and the risk vector as the model says.

## Phase 8: ASTRA Probe
**Goal.** Generate scenarios from the model, test the controls in isolation, feed the results back as evidence.
**Scope.** Four steps:
- **8a Generator and runner (replay mode).** Templates per ASI row and construct produce scripted event sequences; the expected outcome comes from the class table, never from the reconciler under test. Migration `0041`: `probe_scenarios`, `probe_runs`, `probe_results`. A pass is supportive evidence with a lifetime; a miss sets the control to VIO. Runs on every contract compile and on a nightly schedule. Screen: **ASTRA Probe**.
- **8b Incident-to-test.** Promote a finding to a scenario (the existing drafted test is the starting point); a person approves it into the standing suite.
- **8c Admission check.** A command-line check, `astra-check`, and a GitHub Action using the existing repository webhook flow: fail a change if an applicable ASI row has no passing scenario or a standing scenario regresses.
- **8d Sandbox twin (optional, later).** Scripted test agents in an isolated container; kept out of this phase unless you ask.
**Safety rules built into the phase.** The Probe holds no production credentials, runs only against a copy, and has no route to the production collectors. A language model may only rephrase attack text, and a person approves each scenario.
**Tests.** Suite of 22 scenarios plus boundary cases; mutation test: break a class check and show the Probe fails it.
**Commits.** One per step (8a, 8b, 8c).
**Acceptance.** The Probe reports the catch rate per class, and the Assessment tab's "Run Probe" now runs real scenarios.

## Phase 9: Learned layer foundation and the statistical baseline
**Goal.** A safe place for learned evidence, and the simplest detector first.
**Scope.**
- Migration `0042`: `learned_models` (detector, version, trained on, parameters), `learned_scores` (agent, detector, window, score, threshold), `learned_flags` (status, adjudicated by, outcome, expiry).
- API and screen **Learned detectors**: status per detector, flags ordered by the impact tier of what the agent can reach, adjudication (benign with expiry, or real: add a control).
- **Rule enforced in code and tested:** a learned detector can only move the `base` control to UNV. It can never produce VIO, never SAT, and is not an allowed source of supportive evidence (Lemma 3).
- Statistical baseline per agent (rates, tool-sequence transition counts) in plain Python, with a calibration window. A monitored baseline starts UNV until calibration is validated by a Probe pass or an attestation.
**Tests.** The lemma at database level; calibration state machine; a flag never blocks on its own.
**Commit.** `Add the learned layer foundation and statistical baseline`.
**Acceptance.** A synthetic unusual sequence raises a flag; the verdict moves to review at worst.

## Phase 10: TGN in detail
**Goal.** A temporal graph network that scores each event given the history of the agents and tools involved: order and timing.
**Why separate.** It needs PyTorch and a graph library, which are heavy. It runs as its own service, `learned`, with its own image (a docker compose profile), so the main backend image, its scans and its CI stay unchanged. Check that PyTorch wheels exist for the Python version in use; if not, pin that image to an earlier Python.
**Steps, each its own commit:**
- **10a Data.** Event-stream builder from `runtime_events` (agent, kind, target, time gap, department and tier from the estate); no prompts or content are ever read. Since there are no real traces yet, a **normal-traffic simulator** plus Probe attack traces (labelled) provide data. Splits are by **attack family**, so test families are never seen in training. Versioned dataset schema.
- **10b Model.** Per-node memory (a GRU), message function, temporal attention embedding, and a decoder that predicts the next (agent, target, event kind). Trained self-supervised on normal traffic only. Surprise is the negative log-likelihood of an event; per agent per window it is aggregated to one score. The threshold comes from a false-positive budget on validation data.
- **10c Evaluation gate.** Compare against the Phase 9 baseline on held-out families at a fixed false-positive budget, and record the result in a `learned_evaluations` table shown on the screen. The service refuses to switch the detector on unless the gate passes.
- **10d Operation.** Scheduled scoring through the collector-role API; model versions, rollback, and monitoring of the detector's own drift.
**Tests.** Determinism with fixed seeds; no leakage between train and test families; flag path ends in UNV only.
**Acceptance.** Either the TGN beats the baseline on held-out families and is enabled advisory-only, or the evaluation says it does not and it stays off. Both are valid outcomes and both get recorded.
**Honest risk.** Evaluation on simulated traffic is simulator evidence. The simulator and the detector must not share generation rules.

## Phase 11: GNN in detail
**Goal.** A graph model that flags permitted-but-unusual flows across departments.
**Why it may not be needed.** Reachability over delegations is already exact. The GNN is justified only for flows that are allowed but unlike the agent's peers, so the phase has an explicit go or no-go step.
**Steps, each its own commit:**
- **11a Snapshots.** Build the observed interaction graph per window from events: nodes are agents, tools, resources and departments; edges are invokes, accesses and delegates; features are counts, rates, tier, department and event kinds.
- **11b Model.** A two-layer GraphSAGE trained self-supervised on normal snapshots (neighbour-feature reconstruction and link prediction). Node score is the reconstruction error, normalised robustly against the node's own normal spread (median and median absolute deviation). Runs on a schedule in the same `learned` service.
- **11c Go or no-go.** The same adoption gate as the TGN, plus a second question: does it catch anything the exact reachability check and the baseline miss? If not, stop here and record why.
- **11d Integration.** Scores become evidence on the `base` control; flags appear in the Learned detectors screen, ordered by the risk vector.
**Tests.** Held-out attack families; no train and test overlap; the tighten-only rule.
**Acceptance.** Enabled advisory-only if it passes both questions; otherwise documented as not adopted.

## Phase 12: Assurance outputs and roles
**Goal.** Evidence packs and coverage report what is actually covered, per class.
**Scope.**
- Coverage per ASI row from three facts: the constraint exists, a Probe scenario passed, and the monitored classes for that row; a verdict of covered, partial or gap with a named owner.
- Evidence packs gain the assessment history, the signed contract version, the Probe results, the monitored class list, the learned-layer evaluation, and the limits.
- A security view (the specification names developer, security, compliance and auditor); the existing roles stay.
- A regulation-change watch that flags mappings needing review instead of letting them drift.
**Commit.** `Add class-level coverage and extended evidence packs`.
**Acceptance.** A pack for one agent resolves every claim to a record and a clause, and states its gaps.

## Phase 13: Hardening and pilot
**Goal.** Make it safe to put in front of a real deployment.
**Scope.**
- Extend `tests/e2e.py` with the whole loop: describe, assess, add controls, ratify, sign, run, divergence, verdict, Probe, pack.
- Security review of signing keys, the sandbox boundary, role checks and the audit trail; add the new endpoints to the permission table (default-protected).
- Update the deployment and user guides.
- Performance bounds: path enumeration with a depth limit and a size warning.
- A vertical pilot: one real agent in production, with the pack reviewed by an independent assessor against a named obligation.
**Acceptance.** The e2e script passes; the pilot produces a reviewed pack.

---

## 5. Order that gives you something visible soonest

1. Phases 1 to 5 deliver the design-time story: describe, assess, add controls, ratify, sign. That alone changes how an agent enters the platform.
2. Phases 6 and 7 deliver the runtime story: typed alerts and a live verdict.
3. Phase 8 (the Probe) closes the loop and lets you claim verified controls.
4. Phases 9 to 11 add the learned layer only when there is something to measure it against.
5. Phases 12 and 13 turn it into reports and a pilot.

If you want to start with the smallest useful slice: Phases 1, 2 and 3 give you a read-only assessment of an existing agent against department impact, with no change to runtime.

## 6. What I need from you for each "build phase N"

- The decision that blocks it (table in section 2), if any.
- Whether to work on a branch with a pull request (recommended) or directly on `main`.
- Your go-ahead after the Docker review, and a separate go-ahead to commit, and another to push.
