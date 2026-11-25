"""Design-time benchmark on MAST-Data (see MAD_PROTOCOL.md). Runs in the backend image: repo at /w (read only), data at /data. Writes /data/mad_bench.json."""
import json
import re
import sys
from collections import Counter

sys.path.insert(0, "/w/backend")
from astra_model import exposure, gate, statuses          # noqa: E402
from astra_model.estate import Agent, Estate              # noqa: E402

D = json.load(open("/data/mad/MAD_full_dataset.json", encoding="utf-8"))
VN = gate.VERDICT_NAME


def text(r):
    x = r["trace"]["trajectory"]
    return x if isinstance(x, str) else json.dumps(x)


def parse(fw, x):
    """The ordered speakers of a trace."""
    if fw == "ChatDev":
        return [m.strip() for m in re.findall(r"INFO\] ([A-Za-z ]+?): \*\*[A-Za-z ]+?<->[A-Za-z ]+? on :", x)]
    if fw == "MetaGPT":
        s = [m.strip() for m in re.findall(r"FROM: ([A-Za-z][\w ]*?) TO:", x)]
        s = [m for m in s if m != "Human"]
        return s or [m for m in re.findall(r"NEW MESSAGES:\s*\n\s*\n(\w+):", x)]
    if fw == "Magentic":
        return re.findall(r"^---------- (\w+) ----------\s*$", x, re.M)
    if fw == "AG2":
        return re.findall(r"^\s*name: (\w+)\s*$", x, re.M) or re.findall(r"""['"]name['"]: ['"](\w+)['"]""", x)
    if fw == "AppWorld":
        return [m.strip() for m in re.findall(r"Response from ([A-Za-z ]+?Agent)", x)]
    if fw == "HyperAgent":
        return [{"Inner-Navigator-Assistant": "Navigator", "Inner-Editor-Assistant": "Editor", "Inner-Executor-Assistant": "Executor"}.get(m, m)
                for m in re.findall(r"(Planner|Inner-Navigator-Assistant|Inner-Editor-Assistant|Inner-Executor-Assistant)", x)]
    if fw == "OpenManus":
        return ["Manus"] * max(1, len(re.findall(r"\| INFO\s+\| .*Step \d+", x)))
    return []


def role(name):
    n = name.lower()
    if re.search(r"terminal|execut|tester|test|qa|mathproxy|runner", n):
        return "run"
    if re.search(r"review|navigator|surfer|architect|research|analyst|critic", n):
        return "read"
    if re.search(r"orchestrat|supervisor|manager|officer|planner|counselor|ceo|cto|cpo|human|user|product", n):
        return "plan"
    return "write"                                                   # coder, engineer, programmer, developer, editor, assistant, app agents, manus


def build(seq, tau):
    names = sorted(set(seq))[:12]
    seq = [s for s in seq if s in names]
    succ = {n: set() for n in names}
    for a, b in zip(seq, seq[1:]):
        if a != b:
            succ[a].add(b)
    ag, used = {}, set()
    for n in names:
        r = role(n)
        res = {"workspace": "write"} if r == "write" else {"runtime": "write"} if r == "run" else {"sources": "read"} if r == "read" else {}
        used |= set(res)
        ag[n] = Agent(n, "eng", autonomy="auto", may_delegate_to=set(succ[n]), accepts_from={a for a in names if n in succ[a]}, resources=res, max_depth=2)
    ag[names[0]].inputs = {"task"} if seq else set()
    if seq:
        ag[seq[0]].inputs = {"task"}
        if names[0] != seq[0]:
            ag[names[0]].inputs = set()
    allres = {"workspace": ("eng", 3, "data"), "runtime": ("eng", 4, "data"), "sources": ("eng", 2, "data")}
    return Estate(ag, {r: v for r, v in allres.items() if r in used}, {"eng": tau}), succ


rows = []
for r in D:
    fw = r["mas_name"]
    x = text(r)
    seq = parse(fw, x)
    lab = r["mast_annotation"]
    known = {k: v for k, v in lab.items() if v in (0, 1)}
    if not seq or not known:
        rows.append({"fw": fw, "skipped": "no speakers" if not seq else "no labels"})
        continue
    row = {"fw": fw, "bench": r["benchmark_name"], "llm": r["llm_name"], "steps": len(seq), "n_known": len(known), "n_modes": sum(known.values()), "modes": [k for k, v in known.items() if v == 1]}
    for tau in (2, 3, 4):
        E, succ = build(seq, tau)
        row[f"v{tau}"] = VN[gate.gate(E, statuses.State())]
        if tau == 3:
            P = exposure.paths(E)
            row["agents"] = len(E.agents)
            row["edges"] = sum(len(v) for v in succ.values())
            row["paths"] = len(P)
            row["max_tier"] = max([E.res[p[2]][1] for p in P] or [0])
            row["roles"] = sorted(Counter(role(n) for n in E.agents).items())
    rows.append(row)
json.dump(rows, open("/data/mad_bench.json", "w"))
ok = [r for r in rows if "skipped" not in r]
print(len(rows), "traces;", len(ok), "usable;", Counter(r.get("skipped") for r in rows if "skipped" in r), Counter(r["fw"] for r in rows if "skipped" in r))
