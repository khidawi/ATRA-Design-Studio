"""Convert the MAST HyperAgent traces (public SWE-bench runs) into ASTRA's tgn-events-v1 events, and ask the real-traces gate whether they can support an evaluation.

What is real: the order of who spoke to whom, and the agent names (Planner, Navigator, Editor, Executor) in 223 recorded runs.
What is assigned by this script (and must be disclosed): t (the logs have no clock), dept and tier (public data has neither), and the 'target' of an inner step
(the logs hold reasoning text, not tool names, so a coarse label is read from the text).
"""
import glob
import json
import re
import sys
from collections import Counter

sys.path.insert(0, sys.argv[1])                                      # the ASTRA repo root (trusted, this project)
from learned import real                                              # noqa: E402
from learned.tgn import schema                                        # noqa: E402

SRC = sys.argv[2]
STEP, GAP = 6.0, 900.0                                                # seconds between lines in a run, and between runs (assigned, not measured)
DEPT = {"Planner": ("orchestration", 3), "Navigator": ("engineering", 2), "Editor": ("engineering", 3), "Executor": ("engineering", 4)}
LINE = re.compile(r"^HyperAgent_\S+ - INFO - (?P<who>Planner|Inner-(?:Navigator|Editor|Executor)-Assistant|Navigator->Planner|Editor->Planner|Executor->Planner)(?:'s Response)?:?\s?(?P<body>.*)$", re.S)
INTERN = {"Codebase Navigator": "Navigator", "Codebase Editor": "Editor", "Executor": "Executor"}


def label(body: str) -> str:
    if "```bash" in body or "```python" in body:
        return "run_code"
    if "Final Answer" in body:
        return "final_answer"
    if "Action:" in body:
        return "act"
    return "reason"


events, runs = [], 0
for f in sorted(glob.glob(SRC + "/*.json")):
    tr = json.load(open(f, encoding="utf-8"))["trajectory"]
    t = runs * GAP * 4
    runs += 1
    for i, ln in enumerate(tr):
        m = LINE.match(ln)
        if not m:
            continue
        who, body = m.group("who"), m.group("body")
        if who == "Planner":                                          # a response runs over several lines of the log: read to the next logged line
            j = i + 1
            while j < len(tr) and not tr[j].startswith("HyperAgent_"):
                body += chr(10) + tr[j]
                j += 1
        if who == "Planner":
            im = re.search(r"Intern Name:\s*([A-Za-z ]+)", body)
            tgt = INTERN.get((im.group(1).strip() if im else ""), None)
            agent, kind, target = "Planner", ("delegation" if tgt else "tool_call"), (tgt or "plan")
        elif "->" in who:
            agent, kind, target = who.split("->")[0], "delegation", "Planner"
        else:
            agent, kind, target = who.split("-")[1], "tool_call", label(body)
        t += STEP
        d, tier = DEPT[agent]
        events.append({"t": t, "agent": agent, "kind": kind, "target": target, "dept": d, "tier": tier})
print(f"{runs} runs, {len(events)} events; agents {dict(Counter(e['agent'] for e in events))}")
print("kind/target vocabulary:", dict(Counter((e['kind'], e['target']) for e in events)))
json.dump(events, open(SRC + "/../hyperagent_events.json", "w"))
try:
    ds = real.make_dataset(events)
    print("GATE: accepted"); print(real.summary(ds))
except real.DataError as exc:
    print("GATE: refused ->", exc)
