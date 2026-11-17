# ASTRA user guide: the agent assurance loop (phases 1 to 13)

This guide covers what was added to the agent side of the platform. The screens and workflows that existed before (the organisation, the design studio's Fix and Compliance tabs, drift, findings, packs, the model side) are in the earlier user manual and are unchanged.

The idea in one paragraph: an agent is **described** as a design, **assessed** against the organisation (which departments and data it can reach, how much a loss would matter there, how much each department accepts), **given controls** until the gate approves, **ratified** by people, **signed** as a behavioural contract, **watched** while it runs (every event is compared with that contract), **tested** by the Probe, and **reported** with the records that back each claim.

## Who does what

| You are | You do |
|---|---|
| Engineer | describe a design, read its assessment, record it, run the Probe, propose a Probe scenario from a finding |
| Compliance or administrator | ratify what the organisation accepts, accept the baseline, sign, revoke, approve scenarios, judge findings and flags, adopt a learned model, review regulation mappings |
| Security | see everything, run the Probe, read the audit log. Cannot sign off |
| Auditor | read, and the audit log |

Two people are always involved: the person who records an assessment is not the one who accepts it; the person who proposes a risk value is not the one who ratifies it.

## 1. Organisation risk (menu: Organisation, then Organisation risk)

Declare, per department, **how much it accepts** (a tolerance from 0 to 4) and, per data store, **how much a loss would matter** (an impact tier from 1 to 4). Both are proposed by one person and ratified by another. Until a value is ratified the platform assumes the strictest one: tier 4 and tolerance 0. A change that lowers a department's tolerance is decided the same way. The same screen holds the **response posture** matrix: what ASTRA recommends (observe, flag, block, halt) when a divergence of a given severity touches an asset of a given tier. It never gives a higher tier or severity a milder response.

## 2. Assessing a design (design studio, Assessment tab)

Save the design, open the **Assessment** tab. You see:

- the **verdict**: APPROVED, REQUIRES_REVIEW or BLOCKED, with what the department accepts versus the highest tier of what the agent can reach;
- each **attack path** (an untrusted input, the delegation chain, the data it can reach) and the controls that path needs, each satisfied, unverified or violated;
- **what keeps it from being approved**, each with a reason; where the studio already has a fix ("Add to design") it is one click;
- "A path starts only at an untrusted input the design declares": a design that declares none has no paths. That is stated, not hidden.

Evidence: an attested record with the control key `astra:<kind>` (for example `astra:least`) makes a declared control satisfied until it lapses. A design that fails a check is not rescued by evidence.

## 3. Ratify and sign (Assessment tab, Behavioural contract)

1. **Record this assessment** (Recorded assessments). Each one is kept and never edited.
2. A **different** person with sign-off permission presses **Accept as baseline**. It needs a recorded assessment of the design as it is now, with the verdict APPROVED, and nothing in the organisation, risk layer or evidence changed since.
3. **Sign contract** (compliance or administrator). The contract is written in the Appendix A format, signed with Ed25519, valid for a year by default. **Signing is refused unless the Probe has passed on this exact version of the design** (run it first, see section 5); signing then runs it once more for the record.
4. **Verify** checks hash, signature, validity window and status. **Revoke** needs a reason and does not change the signed bytes.

If the design changes afterwards, the contract applies to the older version: assess, record, accept and sign again. A change that widens the agent always needs a new assessment.

## 4. Live runtime

Each agent needs a collector key and the SDK. The page shows:

- **Runtime verdicts**: per agent with a signed contract, the verdict re-run with live evidence laid over it, the department risk vector, the controls that moved and why, the recommended response, any recorded halt request. Evidence can only lower a verdict. A contract that is revoked, expired or tampered with gives INVALID_CONTRACT, and events for that agent are unverified, never waved through.
- **Divergence classes**: all 22. "Monitored" means the check exists; the **events** column is what collectors really sent. A class with none says what it needs ("needs collector event").
- **Who talks to whom** (map, above the charts): the organisation's departments as communities of its real people, roles, data stores and AI agents, with the real edges between them. The events collectors report fly along those edges. A red glow is a rule of a signed contract broken; a colour glow is a detector flag. Beside the map there is one lane per detector, each in its own colour: **Rules** (red), **Baseline, statistics** (teal), **TGN, temporal graph network** (amber) and **GNN, GraphSAGE** (violet). Each lane shows the platform's real state. A detector that is not adopted says so and flags nothing; the TGN and the GNN are not adopted until a person adopts a model that has passed its evaluation, and neither can ever block.
- **Simulated preview** (button above the map, off by default, remembered in your browser): draws the TGN and the GNN with two simple stand-ins that read your real events in the browser, for demonstrations. Everything it shows is marked simulated. They are not the trained models; they write nothing, create no finding and change no verdict. Turn it off to see only what the platform produces.
- **Findings** now carry the class, the contract element, the detection basis and the OWASP row. A **semantic** finding (a goal out of scope, an integrity violation) is **waiting for a person**: confirm or dismiss it on the Findings screen. Nothing is blocked by it until a person says so.

An event that cannot be judged (an attribute is missing) is **unverified**, which lowers a satisfied control to unverified. It is never counted as conforming.

## 5. ASTRA Probe

For every divergence class the Probe plants a defect it must catch and a boundary case it must leave alone, from the contract of the saved design, and replays them in memory through the same check the runtime uses. It writes nothing and reaches no collector. A pass is evidence for the control for 30 days (never for a control the design shows to be missing); a miss marks the control violated.

- **Turn into Probe scenario** on a finding proposes a regression test from a real incident. A different person approves it into the standing suite; from then on every run replays it.
- **Admission check**: `astra-check --design KEY --run` (SDK) exits 0 if the newest run is of this version and everything passed, 1 if refused (with reasons), 2 if the check could not be made. Put it in a pipeline (`sdk/python/examples/astra-check.workflow.yml`).

### The Probe at design time (phase 14)

In the Design studio, the architecture view has a **Run Probe** button. It saves the design, runs the Probe on it and opens a panel under the architecture view with one row for each of the 22 divergence classes:

- **Caught**: the planted attack was caught and its boundary case left alone.
- **Missed**: the check did not catch the planted attack. That is a defect of the check; no design change fixes it, so it has to be reported.
- **Waits for a person**: a semantic class. The attack is handed to a person, as the class table demands. It is never counted as a pass.
- **Advisory**: the behavioural-baseline class.
- **Not tested**: the contract declares nothing to test for this class, so nothing in the design defends against the attack and the Probe cannot plant it. The row says why and, where the design format can say it, what to add. For example, a write tool with an Approval that gates it makes the two confirmation classes testable.

Open a row to see what the planted attack does, the event that was replayed, what the class table expects and what the check did, what it would mean for the department that bears it (the tier and tolerance from the assessment; an undeclared tier or tolerance is read at its strictest and the row says so), and the regulation clauses the class touches. The elements of the design the attack concerns are marked on the architecture view.

The **Probe tab** next to Assessment and Compliance sums the run up, shows whether the Probe lets a contract be signed, and lists the regulation clauses the design must adhere to with their state: met by Probe evidence, at risk, not tested, or waiting for a person. The Assessment tab already uses the run: a missed attack makes the control violated, a pass makes it satisfied for 30 days on this version only. When the design changes, the run is marked as of an earlier version and its evidence no longer counts until you run it again. **Open ASTRA Probe page** goes to the main Probe page for the same agent.

The clause anchors are the specification's article-level, indicative table. A class whose OWASP row has no clause in that table (ASI09, human-agent trust) shows none; the studio does not invent one.

## 6. Learned detectors

- **Statistical baseline** per agent: calibrated from the agent's conforming events by compliance or an administrator. Once calibrated, the agent's **baseline control** is required and starts unverified until a Probe run or an attested record `astra:base` validates it.
- **Temporal graph network** and **graph model**: separate service, off by default. Each must pass an evaluation against the baseline on attack families it never saw (the graph model must also add something to the reachability check) and be adopted by a person. Both first evaluations did **not** pass and are recorded.
- A flag from any of them can do one thing: mark the baseline control **unverified**. It never blocks an agent. A person judges each flag: benign (for a number of days) or real (it stays until a new contract is signed, and you add a control).
- Every figure for a learned model says what it was measured on: **simulated traffic**, or (TGN, phase 16; graph model, phase 17) your own **real normal traffic with attacks injected** by the evaluator (`tgn evaluate --real`). Neither is a measurement against real attacks.

## 7. Assurance and the Security view

- **Assurance**: for each of the ten OWASP rows, three facts per agent (a constraint in the signed contract, a passed Probe scenario for the row, events really received and judged in the last 30 days). Covered needs all three; a missed Probe scenario is a gap; a row no divergence class signals (cascading failures) can be at most partial. Set an owner and a due date for any row. **Download dossier** gives one agent's claims, each resolved to a record and to the clauses its contract maps to, with its gaps and its limits.
- **Regulation-change watch**: each clause a signed contract maps to is compared with the rules the platform holds for it. **Changed** or **unreviewed** means a person has to review the mapping; **unresolved** means the platform holds no rule for that clause (the anchors are indicative). A review changes no contract.
- **Security view**: contracts invalid or expiring, agents not conforming, open findings, learned flags, Probe misses, coverage gaps and mappings to review, in one place.
- **Evidence packs** now carry an ASTRA section (class-level coverage, signed contract hashes, Probe results, monitored classes, learned-model evaluations, limits). The short trust form carries counts only and names no agent.

## What is not claimed

Coverage is read from records. It is not a penetration test, and a Probe pass shows the checks catch what the Probe generated. The learned detectors are advisory and evaluated on simulation. No real agent has been through an independent assessment yet (see `docs/pilot/`).
