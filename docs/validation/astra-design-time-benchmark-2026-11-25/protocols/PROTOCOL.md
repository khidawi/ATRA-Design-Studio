# Design-time benchmark: protocol (written before the run)

Data: MAST traces of HyperAgent (30 human-labelled runs of 223; 29,723 events in all) and AG2 (31 human-labelled runs). Public data, no licence declared; not redistributed.

## A. Does the declared design match real behaviour, and does it catch attacks?
- The design is written from the documented HyperAgent roles, NOT from the logs: Planner plans and delegates to Navigator (reads the repository), Editor (writes it) and Executor (runs code); interns report back to Planner.
  Allowed actions per agent are fixed in the script before it is run.
- A1 conformity of real normal traffic: every real event checked with astra_model.events.conforms. Report the divergence rate and which classes fire.
- A2 attacks: the 7 injected families of learned/real.py (5 seeds: 7, 11, 12, 13, 14, same as the learned-layer run). A window is flagged when any event in it DIVERGES.
  Report detection per family and false flags on normal test windows. Expectation, stated now: structural families (lateral_chain, novel_target, kind_switch) are caught by the design;
  behavioural families (order_swap, burst_repeat, metronome, slow_drip) use only allowed actions and are NOT caught by a design-time contract.
- A3 verdict loop: start from a design whose every control is SAT (verdict APPROVED), replay one window, recompute the gate. Report how often the verdict leaves APPROVED, per family and for normal windows.
  This is conformance to the declared design by construction; it shows the loop works, not that the design is right.

## B. Does the design-time verdict relate to labelled failure modes?
- Per human-labelled run: design from the agents the run engaged; assigned tiers (repo 3, sandbox 4), tolerance 3, all controls unassessed (UNV). Predictors: number of attack paths, highest tier reachable, verdict at tolerance 2, 3, 4.
- Outcome: number of human-labelled failure modes in the run. Spearman correlation with a permutation p-value, steps (run length) reported as the confound.
- Expectation, stated now: little or no relation, because MAST failure modes are task failures, not security failures, and runs of one framework share one design.

## C. Coverage
- Each MAST failure mode is tagged by the author as covered / adjacent / outside the 22 ASTRA classes. This is one rater's judgement and is reported as such.

What this cannot show: that ASTRA assessments predict real attacks (the data has none), or anything about a design with different agents and resources (the assigned tiers, tolerance and timestamps are not measurements).
