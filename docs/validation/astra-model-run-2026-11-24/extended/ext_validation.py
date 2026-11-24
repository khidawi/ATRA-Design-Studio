"""Extended validation of the production ASTRA model (backend/astra_model). Pure functions, no database.

    python ext_validation.py [--quick] [--json out.json]

E1  exhaustive gate: every assignment of VIO/UNV/SAT to the required controls of small estates, against a table oracle written from the paper's table
E2  evidence: adverse evidence never raises a control over event sequences; the result does not depend on order or repetition; conforms is pure
E3  attack paths: the model's enumeration equals an independent depth-first search on random estates; required controls equal an independent derivation
E4  contract: every field is covered by the signature (tamper tests), boundaries of the validity window, malformed input never raises
E5  learned evidence: exhaustive over the four statuses and both sides of the threshold

Environment variable MUT_DIR puts a (mutated) copy of astra_model first on the import path.
"""
import copy
import itertools
import json
import os
import random
import sys
import time

sys.path.insert(0, "/app")
if os.environ.get("MUT_DIR"):
    sys.path.insert(0, os.environ["MUT_DIR"])                   # after /app, so the mutated copy is found first
import astra_model  # noqa: E402
assert not os.environ.get("MUT_DIR") or astra_model.__file__.startswith(os.environ["MUT_DIR"]), "the mutated package was not loaded"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from astra_model import contract, events, exposure, gate, statuses  # noqa: E402
from astra_model.estate import Agent, Estate  # noqa: E402
from astra_model.statuses import NA, SAT, UNV, VIO, State  # noqa: E402

QUICK = "--quick" in sys.argv
LV = {VIO: 0, UNV: 1, SAT: 2, NA: 2}
INVALID, BLOCKED, REVIEW, APPROVED = 0, 1, 2, 3


# ---------------------------------------------------------------- E1
def o_path(worst, tier, tau):
    if worst == 0:
        return BLOCKED if tier > tau else REVIEW
    if worst == 1:
        return REVIEW if tier > tau else APPROVED
    return APPROVED


def o_gate(E, S):
    vs = []
    for p in exposure.paths(E):
        worst = min([LV[S.status(c)] for c in exposure.required(E, p)])
        vs.append(o_path(worst, E.res[p[2]][1], E.tau[E.res[p[2]][0]]))
    return min(vs or [APPROVED])


def o_risk(E, S):
    out = {d: 0 for d in E.tau}
    for p in exposure.paths(E):
        if any(LV[S.status(c)] < 2 for c in exposure.required(E, p)):
            d, tier, _ = E.res[p[2]]
            out[d] = max(out[d], tier)
    return out


def single(tier, tau, mode, kind, runs, base):
    a = Agent("x", "D", baseline_monitored=base, runs_code=runs, inputs={"i"}, resources={"r": mode})
    return Estate({"x": a}, {"r": ("D", tier, kind)}, {"D": tau})


def chain(tier, tau, mode, kind):
    a = Agent("a", "D", inputs={"i"}, may_delegate_to={"b"}, max_depth=1)
    b = Agent("b", "D", resources={"r": mode})
    return Estate({"a": a, "b": b}, {"r": ("D", tier, kind)}, {"D": tau})


def e1():
    t0 = time.time()
    cfgs = [("write", "data", False, False), ("write", "memory", False, False)] if QUICK else \
        [("write", "data", False, False), ("write", "memory", False, False), ("read", "memory", True, False), ("read", "data", False, True), ("write", "data", True, True)]
    tiers, taus = ([2, 3], [1, 2, 3]) if QUICK else ([1, 2, 3, 4], [0, 1, 2, 3, 4])
    estates = [single(t, u, *c) for c in cfgs for t in tiers for u in taus] + [chain(t, u, "write", "memory") for t in tiers for u in taus]
    n = dict(estates=len(estates), assignments=0, gate_calls=0)
    bad = dict(oracle=0, monotone=0, failclosed=0, na_as_sat=0, empty_is_unv=0, invalid_top=0, risk=0)
    for E in estates:
        cs = exposure.all_controls(E)
        free = cs if len(cs) <= 8 else [("deleg", "a"), ("auth", "a"), ("least", "b"), ("hitl", "b"), ("memval", "b"), ("ident", "a"), ("supply", "b"), ("iso", "a")][:8]
        free = [c for c in free if c in cs]
        for combo in itertools.product((VIO, UNV, SAT), repeat=len(free)):
            S = State()
            for c in cs:
                S.st[c] = SAT
            for c, v in zip(free, combo):
                S.st[c] = v
            n["assignments"] += 1
            g = gate.gate(E, S)
            n["gate_calls"] += 1
            bad["oracle"] += g != o_gate(E, S)
            bad["risk"] += gate.department_risk(E, S) != o_risk(E, S)
            for c in free:                                                   # raising one control by one step never lowers the verdict
                if S.st[c] != SAT:
                    S2 = S.copy()
                    S2.st[c] = UNV if S.st[c] == VIO else SAT
                    bad["monotone"] += gate.gate(E, S2) < g
                    n["gate_calls"] += 1
            if g == APPROVED:                                                # approved means no violated control anywhere and no unverified one above tolerance
                for p in exposure.paths(E):
                    sts = [S.status(c) for c in exposure.required(E, p)]
                    tier, tau = E.res[p[2]][1], E.tau[E.res[p[2]][0]]
                    bad["failclosed"] += (VIO in sts) or (UNV in sts and tier > tau)
            S3 = S.copy()
            for c in cs:
                if S3.st[c] == SAT:
                    S3.st[c] = NA
                    S3.rationale[c] = "test"
            bad["na_as_sat"] += gate.gate(E, S3) != g
            bad["invalid_top"] += gate.gate(E, S, contract_ok=False) != INVALID
        U, V = State(), State()
        for c in cs:
            V.st[c] = UNV
        bad["empty_is_unv"] += gate.gate(E, U) != gate.gate(E, V)
    return dict(name="E1 exhaustive gate", ok=sum(bad.values()) == 0, counts=n, violations=bad, seconds=round(time.time() - t0, 1))


# ---------------------------------------------------------------- E2
def helpers():
    """conv, perturb, demo_estate and _good_events, taken from the model test without running it (that module runs its checks when imported)."""
    import ast
    src = open("/app/tests/test_astra_model.py", encoding="utf-8").read()
    tree = ast.parse(src)
    want = {"conv", "perturb", "demo_estate", "_good_events"}
    keep = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in want)
            or (isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "POOL" for t in n.targets))]
    ns = {"copy": copy, "Agent": Agent, "Estate": Estate}
    from tests.astra_ref_oracle import probe as RP
    ns["RP"] = RP
    exec(compile(ast.Module(body=keep, type_ignores=[]), "helpers", "exec"), ns)
    return ns["_good_events"], ns["demo_estate"], ns["perturb"]


def e2(seed=7):
    t0 = time.time()
    _good_events, demo_estate, perturb = helpers()
    rng = random.Random(seed)
    E = demo_estate()
    pool = []
    for _E, ev in _good_events()[1]:
        for _ in range(6):
            pool.append(perturb(ev, rng))
        pool.append(ev)
    pool += [dict(kind="score", agent=a, score=0.9, theta=0.5) for a in sorted(E.agents)]
    n = dict(multisets=0, orderings=0, steps=0, purity=0)
    bad = dict(raised=0, order=0, repeat=0, impure=0)
    for _ in range(40 if QUICK else 250):
        evs = rng.sample(pool, rng.randint(3, 5))
        finals = []
        for perm in itertools.permutations(evs):
            S = State()
            for ev in perm:
                before = {c: LV[S.status(c)] for c in exposure.all_controls(E)}
                events.apply_event(E, S, ev)
                n["steps"] += 1
                bad["raised"] += any(LV[S.status(c)] > before[c] for c in before)
            finals.append(dict(S.st))
            n["orderings"] += 1
        bad["order"] += any(f != finals[0] for f in finals)
        S, S2 = State(), State()
        for ev in evs:
            events.apply_event(E, S, ev)
            events.apply_event(E, S2, ev)
            events.apply_event(E, S2, ev)
        bad["repeat"] += S.st != S2.st
        n["multisets"] += 1
    for ev in pool:
        E0 = copy.deepcopy(E)
        r1 = events.conforms(E, ev)
        r2 = events.conforms(E, ev)
        bad["impure"] += (r1 != r2) or (E.agents.keys() != E0.agents.keys()) or any(vars(E.agents[k]) != vars(E0.agents[k]) for k in E.agents)
        n["purity"] += 1
    return dict(name="E2 evidence order and monotone trajectory", ok=sum(bad.values()) == 0, counts=n, violations=bad, seconds=round(time.time() - t0, 1))


# ---------------------------------------------------------------- E3
def brute_paths(E):
    out = []

    def go(i, ch):
        last = E.agents[ch[-1]]
        for r, mode in last.resources.items():
            if r in E.res:
                out.append((i, ch, r, mode))
        if len(ch) - 1 < min(E.agents[ch[0]].max_depth, 4):
            for b in last.may_delegate_to:
                if b in E.agents and b not in ch:
                    go(i, ch + (b,))
    for a0 in E.agents:
        for i in E.agents[a0].inputs:
            go(i, (a0,))
    return out


def brute_required(E, p):
    i, ch, r, mode = p
    c = {("iso", ch[0])}
    for a in ch:
        for k in ("least", "ident", "life", "supply"):
            c.add((k, a))
        if E.agents[a].baseline_monitored:
            c.add(("base", a))
        if E.agents[a].may_spawn:
            c.add(("spawn", a))
    for k in range(len(ch) - 1):
        c.add(("deleg", ch[k]))
        if E.agents[ch[k]].auth_required:
            c.add(("auth", ch[k]))
    last = E.agents[ch[-1]]
    _d, tier, kind = E.res[r]
    if mode == "write" and tier >= 3:
        c.add(("hitl", ch[-1]))
    if kind == "memory":
        c.add(("memval", ch[-1]))
    if last.runs_code:
        c.add(("sandbox", ch[-1]))
    return c


def random_estate(rng):
    names = [f"a{k}" for k in range(rng.randint(2, 5))]
    res = {f"r{k}": ("D", rng.randint(1, 4), rng.choice(["data", "memory"])) for k in range(rng.randint(1, 4))}
    ags = {}
    for nme in names:
        a = Agent(nme, "D", max_depth=rng.randint(0, 6), auth_required=rng.random() < 0.7, baseline_monitored=rng.random() < 0.4,
                  runs_code=rng.random() < 0.3, may_spawn={"c"} if rng.random() < 0.2 else set())
        a.resources = {r: rng.choice(["read", "write"]) for r in rng.sample(sorted(res), rng.randint(0, min(2, len(res))))}
        a.inputs = set(rng.sample(["i1", "i2"], rng.randint(0, 2)))
        ags[nme] = a
    for nme in names:
        ags[nme].may_delegate_to = set(rng.sample(names, rng.randint(0, len(names))))          # self-loops and cycles are allowed on purpose
        if rng.random() < 0.1:
            ags[nme].may_delegate_to.add("ghost")                                            # a target that is not in the estate
    return Estate(ags, res, {"D": rng.randint(0, 3)})


def e3(seed=11):
    t0 = time.time()
    rng = random.Random(seed)
    n = dict(estates=0, paths=0, required=0, longest_chain=0)
    bad = dict(path_set=0, duplicates=0, count=0, limit=0, required=0, chain_repeats=0, depth=0)
    for _ in range(150 if QUICK else 1200):
        E = random_estate(rng)
        got, ref = exposure.paths(E), brute_paths(E)
        n["estates"] += 1
        n["paths"] += len(got)
        bad["path_set"] += set(got) != set(ref)
        bad["duplicates"] += len(got) != len(set(got)) or len(ref) != len(set(ref))
        bad["count"] += exposure.count_paths(E, 10 ** 9) != len(ref)
        lim = rng.randint(0, max(1, len(ref)))
        bad["limit"] += exposure.count_paths(E, lim) != (len(ref) if len(ref) <= lim else lim + 1)
        for p in got:
            n["required"] += 1
            bad["required"] += exposure.required(E, p) != brute_required(E, p)
            bad["chain_repeats"] += len(set(p[1])) != len(p[1])
            bad["depth"] += len(p[1]) - 1 > min(E.agents[p[1][0]].max_depth, 4)
            n["longest_chain"] = max(n["longest_chain"], len(p[1]))
    return dict(name="E3 attack paths against an independent search", ok=sum(bad.values()) == 0, counts=n, violations=bad, seconds=round(time.time() - t0, 1))


# ---------------------------------------------------------------- E4
def leaves(o, path=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from leaves(v, path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaves(v, path + (i,))
    else:
        yield path


def set_at(o, path, fn):
    for k in path[:-1]:
        o = o[k]
    o[path[-1]] = fn(o[path[-1]])


def e4(seed=3):
    t0 = time.time()
    _g, demo_estate, _p = helpers()
    E = demo_estate()
    doc = contract.contract_of(E)
    priv = Ed25519PrivateKey.from_bytes(bytes(range(32))) if hasattr(Ed25519PrivateKey, "from_bytes") else Ed25519PrivateKey.generate()
    pub = priv.public_key()
    other = Ed25519PrivateKey.generate().public_key()
    c = contract.sign(doc, "k1", priv, 100, 200)
    keys = {"k1": pub}
    n = dict(field_edits=0, structure_edits=0, hex_flips=0, header_edits=0, malformed=0, window=0)
    bad = dict(baseline=0, field_edit=0, structure=0, sig_flip=0, hash_flip=0, header=0, status=0, window=0, key=0, malformed=0, canonical=0, raised=0)
    bad["baseline"] += not contract.valid(c, keys, 150)
    for path in list(leaves(doc)):                                           # every leaf of the signed document
        c2 = copy.deepcopy(c)

        def bump(v):
            return (not v) if isinstance(v, bool) else v + 1 if isinstance(v, int) else v + "x" if isinstance(v, str) else v
        set_at(c2["document"], path, bump)
        n["field_edits"] += 1
        bad["field_edit"] += contract.valid(c2, keys, 150)
    for path in [p for p in leaves(doc)][:200]:                              # remove a key or an element, add a key
        c2 = copy.deepcopy(c)
        o = c2["document"]
        for k in path[:-1]:
            o = o[k]
        if isinstance(o, dict):
            o.pop(path[-1])
        else:
            o.pop(path[-1])
        n["structure_edits"] += 1
        bad["structure"] += contract.valid(c2, keys, 150)
    c2 = copy.deepcopy(c)
    c2["document"]["extra"] = 1
    n["structure_edits"] += 1
    bad["structure"] += contract.valid(c2, keys, 150)
    for k in range(len(c["signature"])):
        c2 = dict(c)
        s = c["signature"]
        c2["signature"] = s[:k] + ("0" if s[k] != "0" else "1") + s[k + 1:]
        n["hex_flips"] += 1
        bad["sig_flip"] += contract.valid(c2, keys, 150)
    for k in range(len(c["hash"])):
        c2 = dict(c)
        h = c["hash"]
        c2["hash"] = h[:k] + ("0" if h[k] != "0" else "1") + h[k + 1:]
        n["hex_flips"] += 1
        bad["hash_flip"] += contract.valid(c2, keys, 150)
    for field, new in (("not_before", 99), ("not_before", 101), ("expires", 199), ("expires", 201), ("key_id", "k2")):      # the signed message binds them
        c2 = dict(c)
        c2[field] = new
        n["header_edits"] += 1
        bad["header"] += contract.valid(c2, keys if field != "key_id" else {"k1": pub, "k2": pub}, 150)
    for st in ("REVOKED", "DRAFT", "active", None):
        c2 = dict(c)
        c2["status"] = st
        bad["status"] += contract.valid(c2, keys, 150)
    for t, want in ((99, False), (100, True), (150, True), (200, True), (201, False)):
        n["window"] += 1
        bad["window"] += contract.valid(c, keys, t) != want
    bad["key"] += contract.valid(c, {"k1": other}, 150) or contract.valid(c, {}, 150) or contract.valid(c, {"zz": pub}, 150)
    for k in list(c):
        for mal in ("missing", None, 5, []):
            c2 = dict(c)
            if mal == "missing":
                c2.pop(k)
            else:
                c2[k] = mal
            n["malformed"] += 1
            try:
                bad["malformed"] += contract.valid(c2, keys, 150)
            except Exception:
                bad["raised"] += 1
    for junk in (None, 5, "x", [], {}):
        n["malformed"] += 1
        try:
            bad["malformed"] += contract.valid(junk, keys, 150)
        except Exception:
            bad["raised"] += 1
    rev = json.loads(json.dumps(doc), object_pairs_hook=lambda ps: dict(reversed(ps)))
    bad["canonical"] += contract.digest(rev) != contract.digest(doc) or contract.canonical(rev) != contract.canonical(doc)
    return dict(name="E4 contract signature and validity", ok=sum(bad.values()) == 0, counts=n, violations=bad, seconds=round(time.time() - t0, 1))


# ---------------------------------------------------------------- E5
def e5():
    t0 = time.time()
    n, bad = dict(cases=0), dict(raised=0, sat=0, vio=0, others=0, below=0)
    for start, hasbase in itertools.product((VIO, UNV, SAT, NA, None), (True, False)):
        for score, theta in ((0.4, 0.5), (0.5, 0.5), (0.9, 0.5), (0.0, 0.0)):
            S = State()
            S.st[("base", "x")] = SAT
            S.st[("least", "x")] = SAT
            if start is not None:
                S.st[("base", "x")] = start
                if start == NA:
                    S.rationale[("base", "x")] = "r"
            before = S.copy()
            statuses.learned_evidence(S, "x", score, theta)
            n["cases"] += 1
            after = S.status(("base", "x"))
            was = before.status(("base", "x"))
            bad["raised"] += LV[after] > LV[was]
            bad["sat"] += after == SAT and was != SAT
            bad["vio"] += after == VIO and was != VIO
            bad["others"] += S.st[("least", "x")] != SAT
            bad["below"] += (score < theta) and (S.st != before.st)
    return dict(name="E5 learned evidence only tightens", ok=sum(bad.values()) == 0, counts=n, violations=bad, seconds=round(time.time() - t0, 1))


# ---------------------------------------------------------------- E6
def e6():
    """Boundaries that the sampled checks do not reach: expiry instant, threshold equality, the depth cap, canonical encoding, validly signed but malformed documents."""
    t0 = time.time()
    n, bad = dict(cases=0), dict(expiry=0, default_now=0, threshold=0, depth_cap=0, encoding=0, malformed_signed=0)
    S = State()
    S.st[("least", "x")] = SAT
    S.fresh[("least", "x")] = 10
    for now, want in ((9, SAT), (10, SAT), (10.001, UNV), (11, UNV)):               # fresh until the expiry instant, unverified after it
        n["cases"] += 1
        bad["expiry"] += S.status(("least", "x"), now) != want
    S.fresh[("least", "x")] = 0.5
    n["cases"] += 1
    bad["default_now"] += S.status(("least", "x")) != SAT                           # the default clock reading is 0
    E = single(4, 2, "read", "data", False, False)                                 # tier above the tolerance, so an unverified control would change the verdict
    S2 = State()
    for c in exposure.all_controls(E):
        S2.st[c] = SAT
        S2.fresh[c] = 0.5
    n["cases"] += 2
    bad["default_now"] += gate.gate(E, S2) != APPROVED or gate.department_risk(E, S2) != {"D": 0}
    for score, theta, flagged in ((0.4, 0.5, False), (0.5, 0.5, True), (0.6, 0.5, True)):   # a flag when the score reaches the threshold
        S3 = State()
        S3.st[("base", "x")] = SAT
        statuses.learned_evidence(S3, "x", score, theta)
        n["cases"] += 1
        bad["threshold"] += (S3.status(("base", "x")) == UNV) != flagged
    names = [f"n{k}" for k in range(8)]                                              # a delegation line of eight agents with a depth bound above the cap
    ags = {nm: Agent(nm, "D", max_depth=7, may_delegate_to={names[k + 1]} if k < 7 else set(), inputs={"i"} if k == 0 else set(),
                     resources={"r": "read"} if k == 7 else {}) for k, nm in enumerate(names)}
    E8 = Estate(ags, {"r": ("D", 2, "data")}, {"D": 2})
    for pos, reachable in ((4, True), (5, False), (7, False)):                       # four hops are followed, a fifth is not, whatever the agent's own bound
        Ep = single_chain_resource(E8, pos)
        got, ref = exposure.paths(Ep), brute_paths(Ep)
        n["cases"] += 1
        bad["depth_cap"] += set(got) != set(ref) or (len(got) > 0) != reachable or exposure.count_paths(Ep, 10 ** 6) != len(ref)
    doc = {"schema_version": "0.1", "agents": {"Zoë": {"dept": "D"}}, "name": "Ünï"}
    cb = contract.canonical(doc)
    n["cases"] += 1
    bad["encoding"] += ("Zoë".encode("utf-8") not in cb) or (b"\\u00eb" in cb)
    priv = Ed25519PrivateKey.generate()
    keys = {"k": priv.public_key()}
    for d, want in (({"schema_version": "0.1", "agents": {}}, True), ({"agents": {}}, False), ({"schema_version": "0.1"}, False), ({}, False),
                    ({"schema_version": None, "agents": {}}, False)):
        n["cases"] += 1
        bad["malformed_signed"] += contract.valid(contract.sign(d, "k", priv, 0, 10), keys, 5) != want
    return dict(name="E6 boundaries", ok=sum(bad.values()) == 0, counts=n, violations=bad, seconds=round(time.time() - t0, 1))


def single_chain_resource(E, k):
    """The delegation line cut so that its resource sits at position k (a copy)."""
    E2 = copy.deepcopy(E)
    names = sorted(E2.agents, key=lambda s: int(s[1:]))
    for nm in names:
        E2.agents[nm].resources = {"r": "read"} if nm == names[k] else {}
    return E2


def main():
    out = []
    for f in (e1, e2, e3, e4, e5, e6):
        try:
            r = f()
        except Exception as ex:                                              # an exception is a failure, not a pass
            r = dict(name=f.__name__, ok=False, error=f"{type(ex).__name__}: {ex}")
        out.append(r)
        print(("PASS " if r["ok"] else "FAIL ") + r["name"], r.get("counts", ""), r.get("violations", r.get("error", "")), r.get("seconds", ""), flush=True)
    if "--json" in sys.argv:
        json.dump(out, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
    sys.exit(0 if all(r["ok"] for r in out) else 1)


if __name__ == "__main__":
    main()
