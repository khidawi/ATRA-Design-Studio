# Vertical pilot: one real agent, one named obligation, an independent reviewer

**Status: not done.** This is the plan and the kit for the last acceptance criterion of phase 13 ("the pilot produces a reviewed pack"). It needs a real agent in production and a person who is not on the project to review the result. Nothing in the repository can substitute for either.

## Purpose

Show that ASTRA's evidence stands up when a stranger reads it. A pack that its authors find convincing proves little; a pack an independent assessor can take apart or accept, against an obligation they chose, proves something.

## What is needed

1. **One real agent**, running in production (or production-like, with real tools and real data stores), that the organisation is willing to put under a signed contract. Not a demo agent: a demo agent's findings and events are disclosed as simulated and prove nothing here.
2. **One named obligation** the agent is subject to, written down before the pilot starts (for example "EU AI Act Art. 14, human oversight, for the refund agent"; or an internal control; or a customer's contractual clause). The assessor chooses or confirms it. See `OBLIGATION-MAPPING.md`.
3. **An independent assessor**: someone who did not design the agent, did not configure ASTRA and does not report to the person who did. An external auditor, an internal audit function or a security reviewer from another team. They get the **auditor** role (read-only plus the audit log), never more.
4. **The signing key** configured and backed up (deploy guide), and a **collector key** for the agent.
5. **Four to six weeks** of the agent running under the contract with the SDK reporting, so that the runtime evidence is real traffic and not a demonstration.

## People and roles

| Who | Role in ASTRA | Does |
|---|---|---|
| Agent owner | engineer | describes the design, runs the Probe, adds controls |
| Compliance lead | compliance | ratifies the risk layer, accepts the baseline, signs, reviews regulation mappings |
| A second sign-off person | administrator or compliance | the other half of every two-person step |
| Security reviewer | security | watches the Security view during the pilot |
| Independent assessor | auditor | reviews the pack; has no write access |

## Timeline

| Week | Step | Records produced |
|---|---|---|
| 0 | Name the obligation. Declare tolerance and tiers for the departments and data stores the agent reaches (two people). Describe the real agent. | ratified risk values, saved design |
| 0 | Assess, add controls until the gate approves, record, accept the baseline (a different person), sign. | recorded assessment, baseline, signed contract, first Probe run |
| 1 to 4 | The agent runs with the SDK. Nightly: `probe/run-all`. Divergences become findings and are judged. Do **not** tidy the data: a finding the pilot raises is evidence. | runtime events, findings, verdicts, Probe runs |
| 4 | Generate the **dossier** (`deploy/pilot_export.py`) and an **Assurance pack**. Fill in `OBLIGATION-MAPPING.md`. | the export folder with its manifest |
| 5 | The assessor works through `REVIEWER-CHECKLIST.md` with auditor access. | the assessor's written findings |
| 6 | Resolve what the assessor found; record what was changed and what was not, and why. | the closing note |

## Success criteria (set before the pilot, not after)

- The assessor can trace **every claim** about the named obligation to a record without asking the project team where it is.
- The assessor finds **no claim the records do not support**. Gaps the pack states are fine; gaps it does not state are failures.
- Every gap the pack states has an owner and a due date.
- The signed contract verifies, from the export folder alone, with the public key.
- Either outcome of the review is recorded, including "not accepted".

## What would count as the pilot failing

- The assessor cannot tell what a claim rests on.
- A claim is contradicted by a record (for example "monitored" for a class that received no events).
- The agent behaved in a way ASTRA had no class or evidence for and the pack was silent about it.

A pilot that finds these is a success of the review and a finding for the project. It is recorded either way.

## Honest limits to tell the assessor up front

- Coverage is read from records; it is not a penetration test.
- A Probe pass shows the checks catch the scenarios the Probe generates from the contract.
- Clause anchors in contracts are article-level and indicative; the regulation watch flags mappings for review and says when the platform holds no rule for a clause.
- The learned detectors are advisory and were evaluated on simulated traffic; neither is adopted unless the pilot's own evaluation says otherwise.
- Keys live in the environment; there is no hardware module.
