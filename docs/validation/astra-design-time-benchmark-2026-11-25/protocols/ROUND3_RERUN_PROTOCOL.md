# Round 3 re-run after fixing the three findings: protocol, written before the run

Results of the first run are kept in `results/seeded3_before_fixes.json`. The three findings were fixed in `backend/astra_estate.py`:
 R5 an approval that gates the agent now covers every tool it uses, so the confirmation reaches the contract (the check and the contract agree);
 R8 an agent that the organisation does not know cannot have its identity control satisfied, whatever the evidence says;
 R4 the injection control (ASI01) is "not applicable", with the reason recorded, for an agent that has no write-capable tool (the platform's own check says it applies only where an injected instruction can change something).

What the re-run can and cannot show: the fixes were made by the author who saw the results, so the three cases are now designed-against (a regression check, as in round 2); the other 18 flaws and 20 neutral designs were not touched and are the real test of whether the fixes broke anything.

Predictions:
1. R5: still APPROVED at the gate (an approval on the agent is a valid design). The contract built from it flags an unconfirmed `refund` call as DVG-AUT-02, as the contract of the sound design does. Before the fix it accepted the call.
2. R8: REQUIRES_REVIEW (was APPROVED).
3. R4 (a write tool falsely declared read-only): APPROVED (was REQUIRES_REVIEW). It stops being "caught"; that was a side effect, and a false declaration cannot be checked against reality. This is a documented limit and I expect it.
4. New neutral design N21, a pure read-only agent with no write tool and no approval: APPROVED (it would have been REQUIRES_REVIEW before the fix).
5. Every other case has the same verdict as in the first run (a regression diff of all 21 flaws, 20 neutral designs and the policy case; the only differences allowed are R4, R5 (none at the gate) and R8).
6. Metamorphic test: 0 violations in all 14 relations, on a new random set of 3,000 designs (same seed, so the same designs; the fixes can change their verdicts).
7. Estate unit tests, full backend suite and the mutation score of `astra_estate.py` are re-run; the score is expected to stay at or above the earlier 153 of 171.

Sensitivity after the fixes, forecast from the above: 12 of 21 flaws not approved, the same count as before but a different set (R4 drops out, R8 comes in; R5 stays a pass at the gate and is judged on the contract instead). The change is in what is caught and why, not in the count.
