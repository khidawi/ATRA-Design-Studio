# Seeded-flaw test, round 2 (after the fixes): protocol, written before the re-run

What changed in the platform (backend/astra_estate.py, studio/index.html; astra_model is untouched):
 G1 least privilege: a data store above its department's tolerance needs a purpose on the data node; without one the least-privilege control cannot be satisfied, evidence or not.
 G2 cascading failure: no rate limit is a gap in the delegation control of an agent that delegates; for an agent that delegates to no one, and for a missing AI disclosure, it is advisory only.
 G3 a delegate with no saved design is read at its strictest (write to a tier-4 resource, no known department).
 G4 code execution: a tool marked as running code makes the sandbox control required; no sandbox constraint is a violation.
 G5 (found while building round 2) delegated-message authentication could never be satisfied, so any delegation toward a store above tolerance could never be approved; an attested record astra:auth now supports it.

What round 2 can and cannot show. F9 to F14 are the flaws the fixes were designed against, so catching them is a regression check, not evidence that the fixes generalise.
The held-out group H was written after the fixes, by the same author who knows them: it checks for regressions and for neighbouring flaws, and is NOT an independent test. An independent set needs another person.

Baselines: B1 as in round 1 plus a purpose on the ledger store. B2 = B1 plus a delegation to a sound saved agent that reads a tier-4 store with a purpose; its evidence includes astra:auth. Both must be APPROVED or the test is void.

Predictions (verdict at the gate unless stated):
 Round-1 flaws F1 to F8 on B1: unchanged, all BLOCKED.            F10 on B1: REQUIRES_REVIEW (no astra:auth attested for B1).
 F9 over-broad access: REQUIRES_REVIEW.   F11 unknown delegate: REQUIRES_REVIEW.   F14 code tool without sandbox: BLOCKED.
 F12 no rate limit on the single agent: APPROVED at the gate, reported as advisory (by decision, not a miss).   F13 no AI disclosure: same.
 F12b no rate limit on B2 (delegating): BLOCKED.
 Held-out on B1: H1 second tier-3 store, no purpose: REQUIRES_REVIEW. H2 purpose that is only spaces: REQUIRES_REVIEW.
 Held-out on B2: H3 delegate with an unsigned MCP server: BLOCKED. H4 delegate with no owner: BLOCKED. H5 delegate with an ungated write tool: BLOCKED. H6 delegate with a code tool and no sandbox: BLOCKED.
 Neutral (must stay APPROVED): N1 to N7 as in round 1 on B1; N8 purpose added to a second tier-3 store; N9 second store at tier 2 (within tolerance) with no purpose; N10 code tool WITH sandbox and attestation; N11 B2 renamed nodes.
 Pairs: all pairs of the gate-affecting flaws on B1 (F1 to F11, F14): a pair is never better than its better single flaw. Singles now include REQUIRES_REVIEW ones, so the check can fail.
 Runtime link: unchanged (four flaws): the sound contract flags the exploit, the flawed one accepts it.

Limits stated now: one author wrote the flaws, the fixes and the predictions; the flaws are single changes; the delegation baseline has one delegate.
