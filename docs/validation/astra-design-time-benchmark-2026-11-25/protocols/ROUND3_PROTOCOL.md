# Round 3: a harder test of the fixed pipeline (protocol, written before the run)

Round 2 was a regression check: the flaws were the ones the fixes were designed against, and one author wrote everything. Round 3 tries to lower that dependence in three ways.
1. The flaws are derived from the ten risks of the OWASP Top 10 for Agentic Applications (ASI01 to ASI10), not from what was fixed, and many are **evasions**: designs that look protected but are not.
2. Each case has two separate columns, written now. **Truth**: should a reviewer refuse to approve this design? (by threat reasoning, regardless of what the platform can express). **Forecast**: what the pipeline will do. Detection is scored against Truth; the forecast measures how well the author understands the pipeline.
3. A randomised **metamorphic test** needs no oracle of mine: relations that must hold on any design (renaming changes nothing; adding a control or evidence never makes the verdict worse; removing one never makes it better).

Still one author. This is a harder test, not an independent one; an independent set needs another person.

Baselines B1 (single agent) and B2 (B1 plus a delegation to a sound saved agent, with astra:auth) as in round 2; both must be APPROVED. Tolerances: Finance 2, HR 1. Verdict order: BLOCKED < REQUIRES_REVIEW < APPROVED.

## Part 1: flaws (Truth: should not be approved)

| ID | Risk | Change | Forecast |
|---|---|---|---|
| R1 | ASI01 | the injection filter exists but is linked to nothing | BLOCKED |
| R2 | ASI01 | on B2, the injection filter limits only the delegate, not the primary | BLOCKED |
| R3 | ASI01 | the untrusted input feeds the write tool directly instead of the agent | APPROVED (miss: a path starts only at an input that feeds the agent) |
| R4 | ASI02 | the write tool is declared read-only (a false declaration) | APPROVED (miss: a design cannot be checked against reality) |
| R5 | ASI02 | the approval edge goes to the agent, not to the write tool | BLOCKED |
| R6 | ASI03 | the owner is only spaces | APPROVED (miss, low confidence: a non-empty test may count spaces) |
| R7 | ASI03 | a second store above tolerance, purpose is the single letter "x" | APPROVED (miss: a purpose is self-declared) |
| R8 | ASI03 | the agent is unknown to the organisation (no department) | REQUIRES_REVIEW |
| R9 | ASI03 | the store is not a store of the organisation, with a purpose and all controls attested | APPROVED (miss at the gate; reported as unmapped only) |
| R10 | ASI04 | a second, unsigned MCP server beside a signed one | BLOCKED |
| R11 | ASI04 | the MCP server has no "signed" property at all | BLOCKED |
| R12 | ASI06 | two long-term memories, one retention constraint | APPROVED (miss: any retention constraint satisfies the check) |
| R13 | ASI07 | a delegate that delegates to an agent with no saved design (two hops) | REQUIRES_REVIEW |
| R14 | ASI07 | a three-hop chain to a tier-4 store | APPROVED (miss: the default depth bound is two hops) |
| R15 | ASI07 | a five-hop chain to a tier-4 store | APPROVED (miss: same) |
| R16 | ASI07 | a two-hop chain to a tier-4 store, no authentication attested (control: this must be caught) | REQUIRES_REVIEW |
| R17 | ASI08 | B2 with the rate limit of the wrong kind | BLOCKED |
| R18 | ASI08 | B2 with two more delegates and no rate limit | BLOCKED |
| R19 | ASI10 | B2 whose delegate has no attested evidence at all | REQUIRES_REVIEW |
| R20 | ASI02 | the evidence for the approval control has lapsed | REQUIRES_REVIEW |
| R21 | ASI02 | no untrusted input is declared and the write tool has no approval | APPROVED (miss: a design that declares no untrusted input has no paths) |

## Part 1: neutral designs (Truth: may be approved) and a policy case

N1 store name in capitals; N2 store name with extra spaces; N3 duplicated edges; N4 isolated note, goal and human nodes; N5 a second approval on a read-only tool; N6 two extra injection filters of different wording;
N7 a very long purpose text; N8 a store within tolerance, no purpose; N9 a second sound saved delegate (B2); N10 a delegate renamed (B2); N11 B2 with nodes reordered; N12 an extra egress constraint;
N13 autonomy set to autonomous with the approval kept; N14 session-only memory with no retention constraint; N15 the rate limit removed from a single agent with no human (advisory only); N16 six read-only tools;
N17 a code tool with a sandbox and attestation in the delegate (B2); N18 a sound two-hop chain with astra:auth and astra:deleg on both agents; N19 an MCP server declared signed with extra properties; N20 an extra data store within tolerance with a purpose.
P1 (policy): flaw R1 with the department's tolerance raised to 4 (Truth: may be approved, the department accepts it). Forecast for all N and P: APPROVED.

## Part 2: metamorphic test

3,000 random designs (one agent, 0 to 2 inputs, 1 to 4 tools, 0 to 3 stores, 0 to 2 memories, 0 to 2 MCP servers, 0 to 2 delegates, random approvals, guardrails, owner, purposes, evidence, tolerance and tiers). For each, the relations below are checked.
M1 reordering and renaming node ids: verdict unchanged. M2 determinism: the same design twice gives the same verdict. M3 add a read-only tool: unchanged. M4 raise the tolerance: not worse. M5 lower a store's tier: not worse.
M6 add evidence for a control: not worse. M7 remove evidence: not better. M8 remove an approval: not better. M9 remove an injection filter: not better. M10 add a purpose to every store: not better to worsen, i.e. not worse. M11 remove purposes: not better.
M12 mark an MCP server unsigned: not better. M13 add an untrusted input that feeds the agent: not better. M14 remove a delegation: not worse.
Forecast: zero violations of every relation. A violation is a bug or an ambiguity in the specification, and will be reported either way.

## Scoring
Sensitivity = flaws the pipeline does not approve, over all flaws. Specificity = neutral designs approved. Forecast accuracy = cases where the verdict equals the forecast. The misses forecast above are expected and are documented limits (the vocabulary of the design, the depth bound, self-declared purposes), not surprises; I will say which unforecast outcomes occur.
