# The learned service (ASTRA phase 10)

A temporal graph network (TGN) that scores each runtime event by how surprising it is given the history of the agents and tools involved: order and timing. It runs on its own, in its own image,
so the main backend image, its scans and its CI are unchanged.

What it may do is fixed on the platform, not here:

- It is trained on **normal traffic only** (self-supervised: it predicts the next event), so it needs no examples of attacks.
- It is **advisory-only**. A flag from it can do one thing: mark an agent's baseline control *unverified*. It can never mark a control violated or satisfied, and never blocks (Lemma 3,
  enforced in code and by a check constraint on the flag table).
- It is **off** until a person adopts a model on the platform, and the platform refuses to adopt one whose recorded evaluation did not pass. The platform recomputes that decision itself from
  the numbers the service reports.
- It holds a **collector-role key**: it can read the event stream (time, agent, kind, a target name, the agent's department and tier; never content), post an evaluation and post window scores.

## Evaluation (the gate)

`evaluate` simulates normal traffic for four agents, trains on the first part, chooses its settings on the **dev** attack families only, and is judged once on **test** families it never saw
(training sees no attack at all). It is compared with the phase 9 statistical baseline at the same false-positive budget (5%, set on validation traffic that was normal). It passes only if it
beats the baseline by a clear margin on at least two held-out families and its false positives on held-out normal traffic stay within twice the budget. Either outcome is recorded.

**Honest limit:** the traffic is simulated, so this is simulator evidence. The simulator (`simulate.py`) is a process model of workflows and does not share any rule with the detector.

## Use

```bash
docker compose build learned
docker compose run --rm learned evaluate                  # train and evaluate, print the numbers (nothing is sent)
docker compose run --rm learned evaluate --post           # also record it on the platform (needs ASTRA_LEARNED_KEY)
docker compose --profile learned up -d learned             # score live windows every five minutes with the adopted model
```

Tests: `docker build -f learned/Dockerfile -t astra-learned . && docker run --rm --entrypoint python astra-learned -m unittest learned.tests.test_tgn`
