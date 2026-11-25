# Design-time benchmark on the full MAST-Data set (MAD): protocol, written before the run

Data: mcemri/MAST-Data (CC-BY-4.0), 1,642 traces, 7 frameworks (AG2 597, MetaGPT 430, ChatDev 330, Magentic 195, AppWorld 30, HyperAgent 30, OpenManus 30).
Labels: the 14 MAST failure modes per trace, assigned by an LLM judge (the dataset's own validation against humans is the cited kappa, not mine). Traces with a null label for a mode are not counted for that mode.

For each trace, a design is built from what the trace shows: the agents that spoke and the hand-overs between consecutive speakers (a parser per framework).
Capabilities are assigned from the role name by a fixed rule written here, not by looking at outcomes:
  roles that write or edit code or data (coder, engineer, programmer, developer, editor, assistant, app agents) -> write the workspace (tier 3)
  roles that run code (terminal, executor, tester, QA, the math proxy that executes code) -> write the runtime (tier 4)
  roles that read (reviewer, navigator, web surfer, file surfer, architect) -> read the sources (tier 2)
  roles that plan or delegate (orchestrator, supervisor, manager, officers, planner) -> no resource
The task prompt is the one untrusted input and enters at the first speaker. All agents are in one department; every control is unassessed. Verdict at tolerance 2, 3 and 4 from astra_model.

Questions and predictions:
Q1 Does the design-time exposure of a trace (number of attack paths, highest tier reachable) relate to its number of failure modes once run length and framework are removed?  Prediction: no relation.
Q2 Does the design verdict differ between frameworks?  Prediction: yes, almost entirely between frameworks (the design is nearly fixed by the framework); within a framework the verdict varies little.
Q3 Which failure modes does an ASTRA class cover?  Each of the 14 modes is tagged covered / adjacent / outside by the author. Prediction: most occurrences fall in modes outside the classes (verification, specification).

Method for Q1: Spearman rank correlation after removing the framework mean from each rank and the effect of run length (partial correlation on ranks), with a permutation p-value (10,000 shuffles within framework).
What this cannot show: that design exposure predicts security incidents (the labels are task failures), anything about attacks, or more than one rater's judgement of coverage. Capabilities and tiers are assigned.
