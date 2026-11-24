# ASTRA model validation run, 24 November 2026

Branch `astra/phase-18-handoff-notices`. No live data touched: the reference checks ran in a scratch copy (standard library only, fixed seeds) and the production-model test ran in a throwaway container with no database.

| Check | Result |
|---|---|
| Ten properties, reference implementation (`docs/astra-formal-agent-model-paper/code`) | 10 of 10 hold; 0 violations |
| Ten properties, production model (`backend/astra_model`, `tests.test_astra_model`) | 10 of 10 hold; 0 violations |
| Planted defects, reference | 14 of 14 detected |
| Planted defects, production | 14 of 14 detected; model intact after patching |
| Production vs frozen reference oracle | agree on 4,500 random estates and 4,000 perturbed events |
| Prototype reconciler vs reference, 5 overlapping event kinds | 5,000 of 5,000 agree |
| ASTRA Probe scenarios against the prototype | detects 6 of 22 classes (6 of 19 deterministic); the other 16 have no event type in the prototype |
| Class table | 22 classes: 17 policy, 2 cryptographic, 1 baseline, 2 semantic; 14 high, 5 critical, 3 medium |
| OWASP agentic coverage | every ASI risk except ASI08 has at least one class |

Differences between the two runs (both pass): P1 uses 21,089 checks on the reference and 15,593 on production; P8 uses 57 and 62; defect `drop_class_spawn` is caught by P5 on the reference and by P3 and P5 on production.

Figures: fig1_properties.png, fig2_defect_detection.png, fig3_prototype_coverage.png, fig4_coverage_by_basis.png. Raw output: run.log, results.json (reference run).

## Limits
Small-scope checks of a reference implementation written by the model's authors; not a model-checker proof, not field evidence. The reference signature is a keyed MAC. Runtime-binding selectors, credential and goal-influence rules, the full admission rule and response postures are not covered by the reference implementation. The production figures in fig1 were copied from the test output, not from a JSON file.

# Round 2: extended validation of the production model (24 November 2026)

Scripts and raw output are in `extended/`: `ext_validation.py` (E1 to E6), `mutate.py`, `ext_full.json`, `mutation.json`, `mutation_run1_existing_test.log`, `figs2.py`. They run inside the backend image with no database: `python /ext/ext_validation.py` and `python /ext/mutate.py out.json` with the backend mounted read-only at `/app`.

| Check | Cases | Result |
|---|---|---|
| E1 Exhaustive gate: every assignment of violated, unverified, satisfied to the required controls of 120 small estates, against a table oracle; monotone by single steps; approved implies no violated control and no unverified control above tolerance; NA behaves as SAT; invalid contract on top; risk vector | 272,160 assignments, 1.6 million gate calls | 0 violations |
| E2 Evidence: adverse evidence never raises a control over event sequences; final state independent of event order and of repeats; `conforms` is pure | 250 event sets, 11,280 orderings, 53,304 steps | 0 violations |
| E3 Attack paths: the model's enumeration equals an independent depth-first search; required controls equal an independent derivation; no repeated agent in a chain; the depth cap | 1,200 random estates (with cycles, unknown targets, depth bounds to 6), 15,125 paths | 0 violations |
| E4 Contract: every leaf of the signed document, every structural edit, every hex digit of the signature and hash, header fields, status, validity window boundaries, wrong keys, malformed input | 336 tamper and malformed cases | 0 violations, never raises |
| E5 Learned evidence only tightens, exhaustive over the four statuses | 40 | 0 violations |
| E6 Boundaries: expiry instant, default clock, threshold equality, depth cap on an eight-agent line, non-ASCII canonical form, validly signed but malformed documents | 19 | 0 violations |

**Mutation testing** (88 small code changes in `gate.py`, `statuses.py`, `exposure.py`, `contract.py`): the existing test catches 63 (72%), the extended suite 79 (90%), both together 86. The 2 that survive both are equivalent: a number in the status ordering table changed without changing the order, and `<=` against `<` where both sides are the same status. Judged by hand.

**Gaps found and closed.** The first version of the extended suite caught 69. The 11 it missed were checked by hand: 9 were real test gaps (the expiry instant, the default clock, a learned score exactly at its threshold, the depth cap never reached by the random estates, non-ASCII text in the canonical form, validly signed documents missing required fields) and were closed by E6; 2 were equivalent. No defect was found in the model itself.

Figures: fig6_mutation_score.png, fig7_mutants_by_file.png, fig8_extended_checks.png.

**Limits of round 2.** Mutation covers four files; `events.py` (the class predicates) and `classes.py` are covered by the earlier planted-defect and boundary checks, not by mutation. Mutants are one change each and simple operators only. Equivalence was judged by hand. Exhaustive means every assignment on small estates (up to eight controls), not on all estates. The first mutation run on the extended suite was invalid (the mutated copy was not loaded because of import order); it was fixed, an assertion now stops that from happening silently, and everything above is from the corrected run.
