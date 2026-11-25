"""Design-time benchmark (see PROTOCOL.md). Runs in the backend image with the repo at /w (read only) and the data at /data. Writes /data/bench.json."""
import glob
import json
import os
import random
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, "/w")
sys.path.insert(0, "/w/backend")
from astra_model import events as EV                                   # noqa: E402
from astra_model import exposure, gate, statuses                       # noqa: E402
from astra_model.estate import Agent, Estate                           # noqa: E402
from learned import real                                               # noqa: E402
from learned.tgn import simulate as S                                  # noqa: E402

TR = "/data/mast/repo/traces"
VN = gate.VERDICT_NAME


# ---------- the declared design (from the documented HyperAgent roles, fixed before the run) ----------
def design(tau=3, engaged=("Navigator", "Editor", "Executor")):
    ag = {"Planner": Agent("Planner", "orchestration", autonomy="auto", tools={"plan": {}}, may_delegate_to=set(engaged), accepts_from=set(engaged), inputs={"issue"}, max_depth=2)}
    spec = {"Navigator": ({"reason", "act", "final_answer"}, {"repo": "read"}, False),
            "Editor": ({"reason", "act", "final_answer"}, {"repo": "write"}, False),
            "Executor": ({"reason", "act", "final_answer", "run_code"}, {"repo": "read", "sandbox": "write"}, True)}
    for n in engaged:
        tools, res, code = spec[n]
        ag[n] = Agent(n, "engineering", autonomy="auto", tools={t: {} for t in tools}, resources=dict(res), may_delegate_to={"Planner"}, accepts_from={"Planner"}, runs_code=code, max_depth=2)
    used = {r for n in engaged for r in spec[n][1]}
    res_all = {"repo": ("engineering", 3, "data"), "sandbox": ("engineering", 4, "data")}
    return Estate(ag, {r: v for r, v in res_all.items() if r in used}, {"orchestration": 4, "engineering": tau})


def to_astra(e):
    k, a, tg, t = e["kind"], e["agent"], e["target"], e["t"]
    if k == "delegation":
        return {"kind": "deleg_out", "agent": a, "t": t, "target": tg, "mode": "execution", "depth": 1}
    if k == "tool_call":
        return {"kind": "tool_call", "agent": a, "t": t, "tool": tg}
    if k == "data_access":
        return {"kind": "res_access", "agent": a, "t": t, "resource": tg, "mode": "read"}
    if k == "memory_write":
        return {"kind": "res_access", "agent": a, "t": t, "resource": tg, "mode": "write"}
    raise ValueError(k)


def all_sat(E):
    st = statuses.State()
    for c in exposure.all_controls(E):
        statuses.support(st, c, "attestation", 0)
    return st


def window_events(events):
    by = defaultdict(list)
    for e in events:
        by[(e["agent"], S.window_of(e["t"]))].append(e)
    return by


# ---------- Part A ----------
def part_a():
    events = json.load(open("/data/hyperagent_events.json"))
    E = design()
    base_state = all_sat(E)
    out = {"design_verdict_unassessed": VN[gate.gate(E, statuses.State())], "design_verdict_all_satisfied": VN[gate.gate(E, base_state)], "paths": len(exposure.paths(E)), "seeds": {}}
    # A1: conformity of every real event
    cnt, cls = Counter(), Counter()
    ex = defaultdict(list)
    for e in events:
        r = EV.conforms(E, to_astra(e))
        cnt[r["outcome"]] += 1
        for c in r["classes"]:
            cls[c] += 1
            if len(ex[c]) < 3:
                ex[c].append([e["agent"], e["kind"], e["target"]])
    out["A1"] = {"events": len(events), "outcomes": dict(cnt), "classes": dict(cls), "examples": ex}
    # A2/A3 per seed
    for seed in (7, 11, 12, 13, 14):
        ds = real.make_dataset(events, seed=seed, episodes=14)
        prof = set(ds["data"]["agents"])
        res = {"normal": {}, "families": {}}

        def judge(evs):
            flagged, verd = False, None
            st = base_state.copy()
            for e in evs:
                r = EV.apply_event(E, st, to_astra(e))
                flagged = flagged or r["outcome"] == "DIVERGES"
            return flagged, VN[gate.gate(E, st)]

        # normal test windows (those with no injected attack: the plain test stream)
        nw = [k for k, v in window_events(ds["test"]).items() if k[0] in prof and len(v) >= 3]
        wins = window_events(ds["test"])
        n_flag, n_verd = 0, Counter()
        for k in nw:
            f, v = judge(wins[k])
            n_flag += f
            n_verd[v] += 1
        res["normal"] = {"windows": len(nw), "flagged": n_flag, "verdicts": dict(n_verd)}
        for fam, a in ds["attacks"].items():
            w2 = window_events(a["events"])
            fl, vd = 0, Counter()
            for k in a["victims"]:
                f, v = judge(w2[tuple(k)])
                fl += f
                vd[v] += 1
            res["families"][fam] = {"episodes": len(a["victims"]), "flagged": fl, "verdicts": dict(vd), "role": a["role"]}
        out["seeds"][seed] = res
    return out


# ---------- Part B ----------
LINE = re.compile(r"^HyperAgent_\S+ - INFO - (Inner-(?:Navigator|Editor|Executor)-Assistant|Navigator->Planner|Editor->Planner|Executor->Planner|Planner)")


def rank(xs):
    idx = sorted(range(len(xs)), key=lambda i: xs[i])
    r = [0.0] * len(xs)
    i = 0
    while i < len(idx):
        j = i
        while j + 1 < len(idx) and xs[idx[j + 1]] == xs[idx[i]]:
            j += 1
        for k in range(i, j + 1):
            r[idx[k]] = (i + j) / 2 + 1
        i = j + 1
    return r


def spearman(x, y):
    if len(set(x)) < 2 or len(set(y)) < 2:
        return None
    rx, ry = rank(x), rank(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den


def perm_p(x, y, n=10000, seed=1):
    r0 = spearman(x, y)
    if r0 is None:
        return None
    rng, y2, hit = random.Random(seed), list(y), 0
    for _ in range(n):
        rng.shuffle(y2)
        if abs(spearman(x, y2)) >= abs(r0) - 1e-12:
            hit += 1
    return (hit + 1) / (n + 1)


def part_b():
    runs = []
    for f in sorted(glob.glob(TR + "/HyperAgent/*_human.json")):
        d = json.load(open(f, encoding="utf-8"))
        eng, steps = set(), 0
        for ln in d["trajectory"]:
            m = LINE.match(ln)
            if m:
                steps += 1
                w = m.group(1)
                n = w.split("-")[1] if w.startswith("Inner") else w.split("->")[0] if "->" in w else None
                if n:
                    eng.add(n)
        modes = [k for k, v in d["note"]["options"].items() if v == "yes"]
        if not eng:
            continue
        row = {"run": d["instance_id"], "engaged": sorted(eng), "steps": steps, "modes": modes, "n_modes": len(modes)}
        for tau in (2, 3, 4):
            E = design(tau, tuple(sorted(eng)))
            row[f"verdict_tau{tau}"] = VN[gate.gate(E, statuses.State())]
        E = design(3, tuple(sorted(eng)))
        P = exposure.paths(E)
        row["n_paths"] = len(P)
        row["max_tier"] = max([E.res[p[2]][1] for p in P] or [0])
        runs.append(row)
    y = [r["n_modes"] for r in runs]
    corr = {}
    for name in ("n_paths", "max_tier", "steps"):
        x = [r[name] for r in runs]
        corr[name] = {"spearman": spearman(x, y), "p_perm": perm_p(x, y), "distinct_values": len(set(x))}
    # AG2: the design has no resource, so no exposure path
    ag2 = []
    for f in sorted(glob.glob(TR + "/AG2/*_human.json")):
        d = json.load(open(f, encoding="utf-8"))
        names = {t.get("name") for t in d["trajectory"]}
        A = {"mathproxyagent": Agent("mathproxyagent", "engineering", autonomy="auto", may_delegate_to={"assistant"}, inputs={"problem"}, max_depth=2),
             "assistant": Agent("assistant", "engineering", autonomy="auto", may_delegate_to={"mathproxyagent"}, accepts_from={"mathproxyagent"})}
        E = Estate(A, {}, {"engineering": 3})
        modes = [k for k, v in d["note"]["options"].items() if v == "yes"]
        ag2.append({"run": d["instance_id"], "agents": sorted(n for n in names if n), "verdict": VN[gate.gate(E, statuses.State())], "paths": len(exposure.paths(E)), "modes": modes, "n_modes": len(modes), "correct": d["other_data"].get("correct")})
    return {"hyperagent": runs, "corr": corr, "ag2": ag2}


if __name__ == "__main__":
    out = {"A": part_a(), "B": part_b()}
    json.dump(out, open("/data/bench.json", "w"), indent=1)
    print("written", os.path.getsize("/data/bench.json"))
