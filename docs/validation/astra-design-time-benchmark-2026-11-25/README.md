# Design-time benchmark and seeded-flaw tests (2026-11-25)

What was tested, what came out, and what it does not show. Written for the EuroS&P 2027 paper on ASTRA's design-time assessment. Everything here ran on throwaway databases and containers; no live data was touched.

Predictions were written down **before** each run, in `protocols/`.

## 1. Results

| Test | Result | How much weight it carries |
|---|---|---|
| Formal model core (`astra_model`): property checks, exhaustive enumeration, differential testing, mutation testing | 86 of 88 mutants caught, the 2 survivors equivalent. Extended suite E1 to E6 re-run: all pass (`results/ext_round3.json`). `astra_model` is byte-identical to `main`. | Strongest evidence |
| Runtime checks (`astra_model/events.py`), mutation testing | 93 of 93 caught by the existing tests (`results/mut_events.json`) | Strong |
| Estate builder (`astra_estate.py`), mutation testing | 101 of 171 before, 153 of 171 after hardening the tests. 17 of the 18 survivors judged equivalent or cosmetic (one rater, one unclassified) (`results/mut_estate*.json`) | Test hardening: the tests were written after seeing the survivors |
| Seeded flaws, round 1 (`results/seeded.json`) | 11 of 13 flaws caught (gate 9, OWASP checks 10), 0 of 7 false alarms. Found four gaps. | Predictions held; one author |
| Seeded flaws, round 2, after the fixes (`results/seeded2.json`) | 32 of 32 variants as predicted (19 flaws, 2 advisory by decision, 11 neutral); 66 of 66 flaw pairs monotone | Regression check only: fixes, flaws and predictions share an author. Six flaws (H1 to H6) were written after the fixes and are not independent |
| Public traces, HyperAgent (MAST), 5 seeds (`results/bench.json`, `seed_*.json`, `tgn_metrics.json`) | A contract written from the documented design flagged 70/70, 70/70 and 20/20 injected structural attacks, 0 of 280 behavioural ones, and 0 of 3,290 normal windows. The temporal graph network passed the platform's adoption check on 5 of 5 seeds (average detection 0.65, baseline 0.25, false alarms 8.5% to 9.1%, above the 5% budget). | Attacks are injected; timestamps, departments and tiers are assigned; the action vocabulary has about nine values, so conformity was close to guaranteed |
| Full MAST-Data, 1,636 traces, 7 frameworks (`results/mad_bench.json`, `mad_analysis_strata.json`) | Design exposure does not predict failure modes: pooled within-group partial correlation -0.07 (p about 0.01), run length removed; 5 of 11 framework-benchmark groups have no design variation. 68% of the design verdict's variation lies between framework-benchmark groups. 9% of 5,138 failure-mode occurrences are covered by an ASTRA class, 41% adjacent, 50% outside. | A negative, scope result. Capabilities and tiers are assigned; the labels are an LLM judge's; the coverage tags are one rater's |

## 2. The four gaps the first round found, and what was done

All fixes are in `backend/astra_estate.py` (the formally validated `astra_model` is untouched), with a studio form field for each new property.

| Gap | Fix |
|---|---|
| ASI03 (least privilege) was "always satisfied": an agent reading a store it does not need was approved | A data store above its department's tolerance needs a purpose on the data node; without one the control cannot be satisfied, evidence or not |
| ASI08 (no rate limit) and ASI09 (no AI disclosure) never reached the gate | A missing rate limit lowers the delegation control of an agent that delegates; for others, and for ASI09, it is reported as advisory |
| A delegate with no saved design was approved with a note | It is read at its strictest: a write to a tier-4 resource in no known department |
| Code execution could not be written in a design (ASI05 "never applicable") | A tool can be marked "runs code"; the design then needs a sandbox constraint |
| Found while building round 2: delegated-message authentication could never be satisfied | An attested record `astra:auth` now supports it |

Behaviour change to be aware of: an existing design that reads a store above its department's tolerance without a purpose now needs review. Recorded assessments are not changed.

## 3. What this does not show

- No real attacks: every attack is injected, and the MAST failure modes are task failures, not security incidents.
- No independent assessor or pilot. The seeded-flaw rounds, the fixes and the predictions have one author.
- The learned-layer pass is semi-synthetic and on one dataset; the false-alarm rate was above the budget.
- The new tests of the estate builder raise a mutation score by construction.
- The studio form fields were checked for parsing only, not in a browser.

## 4. Layout and how to re-run

- `protocols/`: the predictions, written before each run. `PROTOCOL.md` (public-trace benchmark), `SEEDED_PROTOCOL.md` and `SEEDED_PROTOCOL_ROUND2.md` (seeded flaws), `MAD_PROTOCOL.md` (full MAST-Data).
- `scripts/`: the code. They expect the repository at `/w` (read only), the data at `/data` and, for the mutation scripts, the backend at `/app` and `../astra-model-run-2026-11-24/extended/mutate.py` at `/ext`; they ran in the backend image on a network with no internet, with a throwaway Postgres (a database name ending `_test`) for the seeded-flaw scripts. A local `.env` in the project root changes the signing tests: run with it hidden.
- `results/`: the raw outputs. `figures/`: the figures.
- The datasets are **not** included. MAST traces: <https://github.com/multi-agent-systems-failure-taxonomy/MAST> (no licence declared in the repository). MAST-Data: <https://huggingface.co/datasets/mcemri/MAST-Data> (CC-BY-4.0, please cite it). The converted HyperAgent event file is left out because it derives from the repository traces.

## 5. Corrections made during the work

Two numbers were wrong in intermediate messages and are right here: round 2 is 32 of 32 variants (19 flaws, 2 advisory, 11 neutral), not 31; and an apparent "significant" effect of design exposure in AG2 disappeared once the benchmark was held fixed, because the four-agent AG2 traces are a different, easier benchmark (MMLU).
