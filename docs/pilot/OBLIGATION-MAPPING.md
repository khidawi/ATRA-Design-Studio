# Obligation mapping (fill in for the pilot)

Fill this in **before** looking at the pack. The assessor owns the obligation; ASTRA does not choose it.

| Field | Value |
|---|---|
| Agent (design key, agent id) | |
| Signed contract id and version | |
| Named obligation (source, clause, in the assessor's words) | |
| Who set the obligation (assessor, regulator, customer, internal policy) | |
| Date the pilot started / the pack was generated | |

## Claims against the obligation

One row per thing the pack says about this obligation. Every row must name a record someone can open. Rows with no record are not claims; they are gaps and go in the second table.

| # | Claim | OWASP row(s) | Record(s) the dossier cites (kind and id) | Clause anchor(s) in the contract | Where the assessor can open it |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |

How the dossier names a record: `signed contract` (the contract id), `probe run` (the run id), `runtime events` (the class, the agent and the 30-day window), an assessment id, a model id with its evaluation. Each is in `dossier.json` under `claims[].evidence[].record`, and the export folder holds the contract, the Probe run and the verification results the records point to.

## Gaps the pack states

| # | Gap (row and reason, as the dossier states it) | Owner | Due | Accepted by the assessor? |
|---|---|---|---|---|
| 1 | | | | |

The dossier lists these under `gaps`, and the rows with no clause anchor under `unmapped_rows`. A gap the pack states is acceptable; a gap it does not state is a failure of the pack.

## What the assessor decides

- [ ] Every claim above resolves to a record the assessor opened.
- [ ] No claim is contradicted by a record.
- [ ] The gaps listed are all the gaps the assessor found.
- [ ] The named obligation is **supported / partly supported / not supported** by the evidence (circle one), because: ______________________

Assessor: ____________________ Date: __________ Role: auditor (read-only)
