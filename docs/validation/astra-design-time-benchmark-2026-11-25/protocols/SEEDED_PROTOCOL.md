# Seeded-flaw test of the design-time assessment: protocol (written before the run)

Pipeline under test: the platform's own code, on a scratch database. A design document -> the OWASP agentic checks (`astra_assessment_api._rows`, the rules seeded in `db/seed.py`) -> `astra_estate.build` -> `astra_model` gate.
Nothing in the pipeline is re-implemented here.

Baseline: one sound design (approval on every route to the write tool, injection filter, retention limit on long-term memory, signed MCP server, named owner, rate limit, AI disclosure),
every control attested, one store in a department that tolerates tier 2 and holds the store at tier 3. Its verdict must be APPROVED, or the test is void.

Seeded flaws (single change to the baseline; the ground truth is that the design must NOT be approved):
F1 remove the approval gate on the write tool            F8  injection filter of the wrong kind
F2 remove the injection filter                            F9  over-broad data access (a tier-4 store the agent does not need)
F3 declare an unsigned MCP server                         F10 over-broad delegation to an agent that reaches a tier-4 store
F4 long-term memory without a retention limit             F11 delegation to an agent with no saved design (reach unknown)
F5 no named owner                                         F12 no rate limit            F13 customer-facing with no AI disclosure
F6 add a second write tool with no approval               F14 code execution: cannot be expressed in the design vocabulary (ASI05 is "never applicable"); recorded, not run
F7 approval placed beside the route, not on it

Neutral variants (the design must STAY approved): N1 renamed nodes, N2 added read-only tool, N3 second injection filter, N4 second approval on the write tool,
N5 second untrusted input (the filter limits the agent), N6 reordered nodes and edges, N7 second retention constraint.

Predictions, stated before running:
* Detected at the gate: F1 F2 F3 F4 F5 F6 F7 F8 F10.
* NOT detected at the gate: F9 (ASI03 is "always satisfied", so over-broad scope cannot lower a control), F12 and F13 (ASI08 and ASI09 are checked but do not feed the gate), F11 (an unknown agent has no resources, so there is no path).
  F12 and F13 should be caught at the check level (rows) even though the gate does not use them.
* Neutral variants: all stay APPROVED.
* Pairs of F1..F8 (28 pairs): adding a flaw never improves the verdict.
* Runtime link, for F1, F6, F9, F10: an event that exploits the flaw is flagged by the contract of the sound design and accepted by the contract of the flawed design
  (the runtime check inherits the design's permissions, so it cannot catch what the design allows).

Limits stated now: one baseline design; flaws and expected outcomes chosen by the author, not by an independent party; the rules are the platform's seeded OWASP checks only.
