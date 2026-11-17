# The learned service (ASTRA phases 10 and 11)

Two learned detectors run here, each behind the same adoption gate: a temporal graph network (TGN, phase 10) and a graph neural network (GNN, phase 11). The rest of this page is written about the TGN; the GNN follows the same rules and is described at the end.

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

### On a company's own traffic (`tgn evaluate --real`)

`evaluate --real [--days 14] [--episodes 14] --post` reads the organisation's own events from the platform (`learned/stream`), splits them by time (60% train, 20% validation, 20% test) and injects
attack episodes, built from that company's own agents, tools and targets, into held-out windows only (dev families into validation, held-out families into test). Training sees normal traffic only.
The result is recorded with `simulated=false` and a data summary, and the platform recomputes the decision exactly as before. It is **semi-synthetic**: real normal behaviour, injected attacks; it
is not a measurement against real attacks, and the result says so. Too little history is refused with the reason (exit code 3): at least 300 events overall, 40 training events per agent and 10
active agent-minutes in each of validation and test. A family the estate cannot host (a lateral chain needs a second agent) is skipped and named. Tests: `learned/tests/test_real.py`.

### The graph model on a company's own traffic (`gnn evaluate --real`, phase 17)

Same command and the same honesty, plus two things the graph model needs and the TGN does not. **Peers** are the agents of the same department (the stream's department; "(unassigned)" has none).
**Permissions** are what each agent's *active signed contract* permits, read from the platform's own contract view (`GET /api/runtime/contract/{key}`, readable with the collector key); an agent
without an active contract is left out and named. Every injected attack uses only targets its contract permits, so the exact reachability check detects none of them and the evaluation fails if
one is not permitted. Dev families: `rare_resource`, `rare_delegate`; held-out: `cross_peer_read`, `volume_shift`, `mix_shift`. It is **refused** (exit code 3, with the reason) when fewer than two
contract-holding agents produced events, when no dev family can be built (no department with two agents that have history, or nothing permitted that peers never use), or under the same data floors
as the TGN. To pass, it must also catch at least 25% of the attacks that neither the baseline nor the reachability check catches, on two held-out families: on a small estate that is often not
possible, and a "not passed" is a valid, recorded answer. Tests: `learned/tests/test_gnn_real.py`.

**Honest limit:** with the simulator the traffic is simulated, so this is simulator evidence. The simulator (`simulate.py`) is a process model of workflows and does not share any rule with the detector.

## Use

```bash
docker compose build learned
docker compose run --rm learned tgn evaluate             # train and evaluate, print the numbers (nothing is sent)
docker compose run --rm learned tgn evaluate --post      # also record it on the platform (needs ASTRA_LEARNED_KEY)
docker compose run --rm learned gnn evaluate --post      # the same for the graph model
docker compose --profile learned up -d learned            # score live windows every five minutes with whichever models are adopted
```

Tests: `docker build -f learned/Dockerfile -t astra-learned . && docker run --rm --entrypoint python astra-learned -m unittest learned.tests.test_tgn learned.tests.test_gnn`

## The graph model (GNN, phase 11)

A two-layer GraphSAGE over the graph of one time window (agents, tools, data stores, departments; what each did to what), trained on normal windows only to reconstruct each node's own features and
its neighbours' and to predict links. An agent's score is its reconstruction error against its own normal spread (median and MAD). Nodes carry no identity, only what they do and what is around
them, so an agent that joined yesterday can be scored against its peers.

The platform already has an exact reachability check (what the contract permits) and a per-agent baseline, so the graph model faces **two** questions, both on attack families it never saw:

1. does it detect clearly more than the baseline at the same false-positive budget?
2. does it catch things that neither the reachability check nor the baseline catch? At least a quarter of the attacks, on at least two held-out families.

Every attack in its simulator is something the estate permits (the evaluation fails if one is not), so it is about flows that are allowed but unlike the agent's peers. If it does not clear both,
it is **not adopted** and the reason is recorded. On the first evaluation it cleared the first and not the second: no-go.
