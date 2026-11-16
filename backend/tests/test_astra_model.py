"""
Tests for astra_model: the formal model for AI agents as pure functions (phase 1).

    docker compose exec backend python -m tests.test_astra_model          (needs no database)

Three kinds of check:
  * the ten properties of the paper (monotone gate, learned evidence only tightens, fail-closed events, one planted defect per class, narrowing, expiry,
    contract validity, Probe regression, depth bound) on the model as written;
  * fourteen planted defects, each switched on by patching one function, and each must make some property fail (so the properties can fail);
  * a differential test against a frozen copy of the paper's reference implementation (tests/astra_ref_oracle), on random estates, states and events.
"""
import copy
import itertools
import random
import sys
from contextlib import contextmanager

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astra_model import classes, contract, estate, events, exposure, gate, statuses
from astra_model.estate import Agent, Estate
from astra_model.statuses import NA, SAT, UNV, VIO, State
from tests.astra_ref_oracle import model as RM
from tests.astra_ref_oracle import probe as RP

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


LEVELS = [VIO, UNV, SAT]
PRIV = Ed25519PrivateKey.generate()
KEYS = {"k1": PRIV.public_key()}


# ------------------------------------------------------------------ helpers
def conv(E_ref):
    """An estate of the reference implementation as an estate of astra_model (the fields are the same)."""
    agents = {n: Agent(**copy.deepcopy(vars(a))) for n, a in E_ref.agents.items()}
    return Estate(agents, copy.deepcopy(E_ref.res), dict(E_ref.tau), set(E_ref.inventory))


def conv_state(S_ref):
    S = State()
    S.st, S.fresh = dict(S_ref.st), dict(S_ref.fresh)
    return S


def random_ref_estate(rng):
    depts = ["D1", "D2", "D3"]
    res = {f"r{i}": (rng.choice(depts), rng.randint(1, 4), rng.choice(["data", "memory"])) for i in range(rng.randint(3, 6))}
    names = [f"a{i}" for i in range(rng.randint(2, 4))]
    agents = {}
    for n in names:
        a = RM.Agent(n, rng.choice(depts), max_depth=rng.randint(0, 2), auth_required=rng.random() < 0.7, baseline_monitored=rng.random() < 0.4,
                     runs_code=rng.random() < 0.3, may_spawn={"c"} if rng.random() < 0.2 else set())
        a.resources = {r: rng.choice(["read", "write"]) for r in rng.sample(sorted(res), rng.randint(1, 3))}
        a.inputs = set(rng.sample(["i1", "i2"], rng.randint(0, 2)))
        agents[n] = a
    for n in names:
        others = [m for m in names if m != n]
        agents[n].may_delegate_to = set(rng.sample(others, rng.randint(0, len(others))))
    return RM.Estate(agents, res, {d: rng.randint(0, 3) for d in depts})


def random_estate(rng):
    return conv(random_ref_estate(rng))


def tiny_estate():
    a = Agent("x", "D", baseline_monitored=True, inputs={"i"}, resources={"r": "write"})
    return Estate({"x": a}, {"r": ("D", 3, "data")}, {"D": 2})


def random_state(E, rng):
    S = State()
    for c in exposure.all_controls(E):
        S.st[c] = rng.choice(LEVELS)
    return S


def improve(level):
    return {VIO: UNV, UNV: SAT, SAT: SAT}[level]


def demo_estate():
    return conv(RP.demo_estate())


@contextmanager
def patched(obj, name, func):
    old = getattr(obj, name)
    setattr(obj, name, func)
    try:
        yield
    finally:
        setattr(obj, name, old)


# ------------------------------------------------------------------ the ten properties: each returns (ok, number of checks, detail)
def p1_gate_monotone(rng):
    n, bad = 0, 0
    E = tiny_estate()
    cs = exposure.all_controls(E)
    for combo in itertools.product(LEVELS, repeat=len(cs)):            # exhaustive: every assignment and every single-step improvement
        S = State()
        S.st = dict(zip(cs, combo))
        v = gate.gate(E, S)
        for c in cs:
            S2 = S.copy()
            S2.st[c] = improve(S.st[c])
            n += 1
            bad += gate.gate(E, S2) < v
    for _ in range(300):
        E = random_estate(rng)
        cs = exposure.all_controls(E)
        if not cs:
            continue
        S = random_state(E, rng)
        v = gate.gate(E, S)
        c = rng.choice(cs)
        S2 = S.copy()
        S2.st[c] = improve(S.st[c])
        n += 1
        bad += gate.gate(E, S2) < v
    return bad == 0, n, f"{bad} violations"


def p2_learned_only_tightens(rng):
    n, bad = 0, 0
    E = tiny_estate()
    cs = exposure.all_controls(E)
    for combo in itertools.product(LEVELS, repeat=len(cs)):
        S = State()
        S.st = dict(zip(cs, combo))
        v = gate.gate(E, S)
        for score in (0.9, 0.1):
            S2 = S.copy()
            statuses.learned_evidence(S2, "x", score, 0.5)
            n += 1
            bad += gate.gate(E, S2) > v
    S = State()
    S.st = {c: SAT for c in cs}
    S2 = S.copy()
    statuses.learned_evidence(S2, "x", 0.9, 0.5)
    n += 1
    bad += gate.gate(E, S2) < gate.REQUIRES_REVIEW                       # learned evidence alone never blocks
    try:
        statuses.support(State(), ("base", "x"), "gnn", 0)
        bad += 1                                                         # a learned detector is not a source of supportive evidence
    except ValueError:
        pass
    n += 1
    for _ in range(300):
        E = random_estate(rng)
        S = random_state(E, rng)
        v = gate.gate(E, S)
        S2 = S.copy()
        statuses.learned_evidence(S2, rng.choice(sorted(E.agents)), rng.choice([0.9, 0.1]), 0.5)
        n += 1
        bad += gate.gate(E, S2) > v
    return bad == 0, n, f"{bad} violations"


def _good_events():
    E = demo_estate()
    out = []
    for sc in RP.scenarios(RP.demo_estate()):
        if sc["good"]["kind"] != "score":
            out.append((conv(sc["estate"]), sc["good"]))
    return E, out


def p3_missing_attribute_never_conforms(rng):
    _E, goods = _good_events()
    optional = {"semantic", "prev_tool", "host", "scope", "depth", "t", "kind"}
    n, bad = 0, []
    for est, ev in goods:
        assert events.conforms(est, ev)["outcome"] == "CONFORMS", ev
        for k in list(ev):
            if k in optional:
                continue
            n += 1
            if events.conforms(est, {a: b for a, b in ev.items() if a != k})["outcome"] == "CONFORMS":
                bad.append((ev["kind"], k))
    return not bad, n, f"{len(bad)} events conformed with an attribute missing"


def p4_gate_fail_closed(rng):
    n, bad = 0, 0
    for _ in range(400):
        E = random_estate(rng)
        S = random_state(E, rng)
        v = gate.gate(E, S)
        for p in exposure.paths(E):
            sts = [S.status(c) for c in exposure.required(E, p)]
            tier = E.res[p[2]][1]
            tau = E.tau[E.res[p[2]][0]]
            n += 1
            if VIO in sts and v > gate.REQUIRES_REVIEW:
                bad += 1                                                 # a violated control is never approved
            if VIO in sts and tier > tau and v > gate.BLOCKED:
                bad += 1                                                 # above tolerance it blocks
            if UNV in sts and tier > tau and v > gate.REQUIRES_REVIEW:
                bad += 1                                                 # an unverified control above tolerance is never approved
    return bad == 0, n, f"{bad} violations"


def p5_each_class_fires(rng):
    n, bad = 0, []
    for sc in RP.scenarios(RP.demo_estate()):
        est = conv(sc["estate"])
        out_bad, out_good = events.conforms(est, sc["bad"]), events.conforms(est, sc["good"])
        exp_out, exp_cls = sc["expected"]
        n += 2
        if not (out_bad["outcome"] == exp_out and out_bad["classes"] == exp_cls and out_good["outcome"] == "CONFORMS"):
            bad.append(sc["cls"])
    return not bad, n, f"failing classes: {bad}"


def p6_narrowing_never_lowers(rng):
    n, bad = 0, 0
    for _ in range(400):
        E = random_estate(rng)
        S = random_state(E, rng)
        ops = [("res", a, r) for a, ag in E.agents.items() for r in ag.resources] + [("del", a, b) for a, ag in E.agents.items() for b in ag.may_delegate_to]
        if not ops:
            continue
        op = rng.choice(ops)
        E2 = estate.narrow(E, op)
        n += 1
        p0, p1 = set(exposure.paths(E)), set(exposure.paths(E2))
        bad += not p1 <= p0
        bad += op[0] == "res" and any(p[1][-1] == op[1] and p[2] == op[2] for p in p1)
        bad += op[0] == "del" and any((op[1], op[2]) in zip(p[1], p[1][1:]) for p in p1)
        bad += gate.gate(E2, S) < gate.gate(E, S)
    return bad == 0, n, f"{bad} violations"


def p7_expired_evidence_is_unverified(rng):
    n, bad = 0, 0
    for _ in range(400):
        E = random_estate(rng)
        if not any(E.res[p[2]][1] > E.tau[E.res[p[2]][0]] for p in exposure.paths(E)):
            continue
        S = State()
        for c in exposure.all_controls(E):
            S.st[c] = SAT
            S.fresh[c] = 5
        n += 1
        bad += gate.gate(E, S, now=0) != gate.APPROVED
        bad += gate.gate(E, S, now=6) > gate.REQUIRES_REVIEW
    return bad == 0 and n > 0, n, f"{bad} violations"


def p8_contract_validity(rng):
    E = demo_estate()
    doc = contract.contract_of(E)
    c = contract.sign(doc, "k1", PRIV, 0, 100)
    n, bad = 1, []
    if not contract.valid(c, KEYS, 50):
        bad.append("valid contract rejected")
    for name, ch in (("expires", dict(c, expires=40)), ("status", dict(c, status="REVOKED")), ("signature", dict(c, signature="0" * 128)),
                     ("hash", dict(c, hash="0" * 64)), ("key id", dict(c, key_id="unknown")), ("not_before", dict(c, not_before=-5))):
        n += 1
        if contract.valid(ch, KEYS, 50):
            bad.append("tampered " + name)
    n += 2
    if contract.valid(c, KEYS, 101):
        bad.append("expired contract accepted")
    if contract.valid(dict(c, not_before=60), KEYS, 50):
        bad.append("contract accepted before its window")
    n += 1
    other = Ed25519PrivateKey.generate()
    if contract.valid(contract.sign(doc, "k1", other, 0, 100), KEYS, 50):
        bad.append("signature by another key accepted")
    leaves = []

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, path + [k])
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, path + [i])
        else:
            leaves.append(path)
    walk(doc, [])
    for path in leaves:                                                  # change every leaf of the document; hash and signature stay
        d2 = copy.deepcopy(doc)
        o = d2
        for k in path[:-1]:
            o = o[k]
        o[path[-1]] = "tampered" if not isinstance(o[path[-1]], bool) else not o[path[-1]]
        n += 1
        if contract.valid(dict(c, document=d2), KEYS, 50):
            bad.append(("leaf", path))
    S = State()
    for ctl in exposure.all_controls(E):
        S.st[ctl] = VIO
    n += 1
    if gate.gate(E, S, contract_ok=False) != gate.INVALID_CONTRACT:
        bad.append("INVALID_CONTRACT is not on top")
    S = State()
    for ctl in exposure.all_controls(E):
        S.st[ctl] = SAT
    n += 1
    if gate.gate(E, S, contract_ok=False) != gate.INVALID_CONTRACT:
        bad.append("an invalid contract was approved")
    return not bad, n, f"{len(leaves)} leaves; {bad[:3]}"


def p9_failed_probe_sets_violated(rng):
    n, bad = 0, 0
    for _ in range(300):
        E = random_estate(rng)
        cs = exposure.all_controls(E)
        if not cs:
            continue
        c = rng.choice(cs)
        S = State()
        S.st = {x: SAT for x in cs}
        v = gate.gate(E, S)
        statuses.probe_result(S, c, False, 0, 5)
        n += 1
        bad += S.status(c) != VIO
        bad += gate.gate(E, S) > v
        statuses.probe_result(S, c, True, 1, 5)
        bad += S.status(c, 2) != SAT or S.status(c, 7) != UNV
    return bad == 0, n, f"{bad} violations"


def p10_depth_bound(rng):
    n, bad = 0, 0
    for _ in range(400):
        E = random_estate(rng)
        for a in E.agents:
            for ch in exposure.chains(E, a):
                n += 1
                bad += len(ch) > E.agents[a].max_depth + 1
    return bad == 0, n, f"{bad} chains longer than the bound"


PROPERTIES = [
    ("P1 gate is monotone in the control statuses", p1_gate_monotone),
    ("P2 learned evidence can only tighten", p2_learned_only_tightens),
    ("P3 an event with a missing attribute never conforms", p3_missing_attribute_never_conforms),
    ("P4 a violated or unverified control above tolerance is never approved", p4_gate_fail_closed),
    ("P5 each of the 22 classes fires on its planted defect and not on its boundary case", p5_each_class_fires),
    ("P6 narrowing a capability never lowers the verdict", p6_narrowing_never_lowers),
    ("P7 expired evidence reads as unverified", p7_expired_evidence_is_unverified),
    ("P8 contract validity and INVALID_CONTRACT on top", p8_contract_validity),
    ("P9 a failed Probe scenario sets the control to violated", p9_failed_probe_sets_violated),
    ("P10 delegation chains respect the depth bound", p10_depth_bound),
]


def run_properties(seed=1):
    out = {}
    for name, f in PROPERTIES:
        try:
            out[name] = f(random.Random(seed))
        except Exception as e:                       # a property that cannot even run has failed
            out[name] = (False, 0, f"raised {type(e).__name__}: {e}")
    return out


# ------------------------------------------------------------------ the planted defects: one patched function each
def _conforms_wrapper(fn):
    orig = events.conforms

    def conforms(E, ev, hist=()):
        return fn(orig(E, ev, hist), E, ev)
    return conforms


def mut_ignore_unv(E, S, now, p):
    sts = [S.status(c, now) for c in exposure.required(E, p)]
    tier, tau = E.res[p[2]][1], E.tau[E.res[p[2]][0]]
    if VIO in sts:
        return gate.BLOCKED if tier > tau else gate.REQUIRES_REVIEW
    return gate.APPROVED


def mut_vio_tolerated(E, S, now, p):
    sts = [S.status(c, now) for c in exposure.required(E, p)]
    tier, tau = E.res[p[2]][1], E.tau[E.res[p[2]][0]]
    if VIO in sts:
        return gate.APPROVED if tier <= tau else gate.BLOCKED
    if UNV in sts:
        return gate.REQUIRES_REVIEW if tier > tau else gate.APPROVED
    return gate.APPROVED


def mut_learned_supportive(S, agent, score, theta):
    if score >= theta:
        statuses.adverse(S, ("base", agent), UNV)
    else:
        S.st[("base", agent)] = SAT


def mut_ignore_expiry(self, c, now=0):
    return self.st.get(c, UNV)


def mut_chains(E, a0):
    out = [(a0,)]
    frontier = [(a0,)]
    for _ in range(E.agents[a0].max_depth + 3):
        nxt = []
        for ch in frontier:
            for b in sorted(E.agents[ch[-1]].may_delegate_to):
                if b in E.agents and b not in ch:
                    nxt.append(ch + (b,))
        out += nxt
        frontier = nxt
    return out


def mut_skip_signature(c, public_keys, now):
    try:
        doc = c["document"]
        if doc.get("schema_version") is None or "agents" not in doc or contract.digest(doc) != c["hash"]:
            return False
        return c["status"] == "ACTIVE" and c["not_before"] <= now <= c["expires"]
    except (KeyError, TypeError, AttributeError):
        return False


def mut_invalid_not_top(E, S, now=0, contract_ok=True):
    v = min([gate.path_verdict(E, S, now, p) for p in exposure.paths(E)] or [gate.APPROVED])
    if not contract_ok and v >= gate.REQUIRES_REVIEW:
        return gate.INVALID_CONTRACT
    return v


def mut_probe_fail_ignored(S, c, passed, now, ttl):
    if passed:
        statuses.support(S, c, "probe_pass", now, ttl)


def mut_narrow_noop(E, op):
    return copy.deepcopy(E)


def _dc(outcome, classes_, missing=()):
    return dict(outcome=outcome, classes=list(classes_), missing=list(missing))


def _w_ignore_missing(res, E, ev):
    return _dc("CONFORMS", []) if res["outcome"] == "UNVERIFIED" else res


def _w_off_by_one(res, E, ev):
    if res["outcome"] == "CONFORMS" and ev["kind"] == "tool_call":
        bounds = E.agents[ev["agent"]].tools.get(ev["tool"], {})
        for p, val in (ev.get("params") or {}).items():
            if p in bounds and val in bounds[p]:
                return _dc("DIVERGES", ["DVG-TOOL-02"])
    return res


def _w_drop_spawn(res, E, ev):
    return _dc("CONFORMS", []) if ev["kind"] == "spawn" else res


def _w_semantic_deterministic(res, E, ev):
    return _dc("DIVERGES", res["classes"]) if res["outcome"] == "PENDING" else res


def _w_hitl_bypass(res, E, ev):
    return _dc("CONFORMS", []) if res["outcome"] == "DIVERGES" and res["classes"] == ["DVG-AUT-02"] else res


def mutants():
    """(name, description, list of (object, attribute, replacement))."""
    return [
        ("ignore_unv", "the gate treats UNV as satisfied", [(gate, "path_verdict", mut_ignore_unv)]),
        ("vio_tolerated", "a violated control below the tolerance is approved", [(gate, "path_verdict", mut_vio_tolerated)]),
        ("learned_supportive", "a learned detector can raise a control to SAT", [(statuses, "learned_evidence", mut_learned_supportive)]),
        ("ignore_missing", "a missing attribute is ignored", [(events, "conforms", _conforms_wrapper(_w_ignore_missing))]),
        ("ignore_expiry", "evidence expiry is ignored", [(State, "status", mut_ignore_expiry)]),
        ("ignore_depth", "the delegation depth bound is ignored", [(exposure, "chains", mut_chains)]),
        ("off_by_one_bound", "parameter bounds are exclusive instead of inclusive", [(events, "conforms", _conforms_wrapper(_w_off_by_one))]),
        ("drop_class_spawn", "DVG-SPAWN-01 never fires", [(events, "conforms", _conforms_wrapper(_w_drop_spawn))]),
        ("semantic_deterministic", "a semantic class is treated as deterministic", [(events, "conforms", _conforms_wrapper(_w_semantic_deterministic))]),
        ("hitl_bypass", "DVG-AUT-02 never fires", [(events, "conforms", _conforms_wrapper(_w_hitl_bypass))]),
        ("skip_signature", "the contract signature is not checked", [(contract, "valid", mut_skip_signature)]),
        ("invalid_not_top", "INVALID_CONTRACT is shadowed by BLOCKED", [(gate, "gate", mut_invalid_not_top)]),
        ("probe_fail_ignored", "a failed Probe scenario is ignored", [(statuses, "probe_result", mut_probe_fail_ignored)]),
        ("narrowing_noop", "narrowing does not remove the capability", [(estate, "narrow", mut_narrow_noop)]),
    ]


# ------------------------------------------------------------------ run: the model as written
print("-- properties on the model as written")
base = run_properties()
for name, (ok, n, detail) in base.items():
    check(f"{name} [{n} checks]", ok, detail)

# ------------------------------------------------------------------ run: planted defects
print("-- planted defects: each must make some property fail")
killed = 0
for name, desc, patches in mutants():
    stack = []
    try:
        for obj, attr, fn in patches:
            stack.append((obj, attr, getattr(obj, attr)))
            setattr(obj, attr, fn)
        res = run_properties()
    finally:
        for obj, attr, old in reversed(stack):
            setattr(obj, attr, old)
    failing = [k.split(" ")[0] for k, v in res.items() if not v[0]]
    check(f"defect '{name}' ({desc}) is detected by {','.join(failing) or 'nothing'}", bool(failing))
    killed += bool(failing)
check("all 14 planted defects are detected", killed == 14, f"{killed}/14")
check("the model is intact after the patches", all(v[0] for v in run_properties().values()))

# ------------------------------------------------------------------ the class table
print("-- the divergence classes")
C = classes.CLASSES
check("22 classes", len(C) == 22)
check("17 policy, 2 cryptographic, 1 baseline, 2 semantic", sorted(c.basis for c in C.values()).count("policy") == 17 and sum(c.basis == "cryptographic" for c in C.values()) == 2
      and sum(c.basis == "baseline" for c in C.values()) == 1 and sum(c.basis == "semantic" for c in C.values()) == 2)
check("14 high, 5 critical, 3 medium", sum(c.severity == "High" for c in C.values()) == 14 and sum(c.severity == "Critical" for c in C.values()) == 5 and sum(c.severity == "Medium" for c in C.values()) == 3)
check("every class reads a known event kind and protects a known control kind", all(c.event in events.REQUIRED or c.event == "score" for c in C.values())
      and all(c.control in {"iso", "least", "ident", "life", "supply", "spawn", "deleg", "auth", "hitl", "memval", "sandbox", "base"} for c in C.values()))
check("the class table agrees with the reference implementation", all((C[k].control, C[k].basis, C[k].severity, C[k].event) == RM.CLASSES[k] for k in RM.CLASSES) and set(C) == set(RM.CLASSES))
check("every ASI risk except ASI08 has at least one class", {a for c in C.values() for a in c.asi} == {f"ASI{i:02d}" for i in range(1, 11)} - {"ASI08"})

# ------------------------------------------------------------------ behaviour that is specific to this implementation
print("-- behaviour")
E = demo_estate()
S = State()
check("an unassessed control is unverified", S.status(("iso", "support")) == UNV)
for c in exposure.all_controls(E):
    S.st[c] = SAT
check("all controls satisfied: APPROVED", gate.gate(E, S) == gate.APPROVED and gate.department_risk(E, S) == {"Customer": 0, "Finance": 0, "HR": 0})
try:
    statuses.mark_not_applicable(S, ("iso", "support"), "  ")
    check("not applicable needs a rationale", False)
except ValueError:
    check("not applicable needs a rationale", True)
statuses.mark_not_applicable(S, ("iso", "support"), "no untrusted input reaches this agent")
check("not applicable with a rationale counts as satisfied", gate.gate(E, S) == gate.APPROVED and S.rationale[("iso", "support")])
try:
    statuses.adverse(S, ("least", "support"), SAT)
    check("adverse evidence cannot carry level SAT", False)
except ValueError:
    check("adverse evidence cannot carry level SAT", True)
check("the runtime names: APPROVED is CONFORMING, BLOCKED is DIVERGENT", gate.RUNTIME_NAME[gate.APPROVED] == "CONFORMING" and gate.RUNTIME_NAME[gate.BLOCKED] == "DIVERGENT")

# a High divergence on an agent that reaches only low-tier assets within tolerance leads to review; above the tolerance it blocks
Et = Estate({"x": Agent("x", "D", inputs={"i"}, resources={"r": "read"})}, {"r": ("D", 1, "data")}, {"D": 2})
St = State()
for c in exposure.all_controls(Et):
    St.st[c] = SAT
check("the small estate starts approved", gate.gate(Et, St) == gate.APPROVED)
res = events.apply_event(Et, St, dict(kind="res_access", agent="x", resource="elsewhere", mode="read", t=1))        # outside the agent's scope: DVG-RES-01 (High)
check("DVG-RES-01 is a divergence that marks 'least' violated", res["outcome"] == "DIVERGES" and res["classes"] == ["DVG-RES-01"] and St.status(("least", "x")) == VIO)
check("a High divergence below the department's tolerance leads to review, not to a block", gate.gate(Et, St) == gate.REQUIRES_REVIEW)
Et.tau["D"] = 0
check("the same divergence blocks when the tolerance is 0", gate.gate(Et, St) == gate.BLOCKED)
St2 = State()
for c in exposure.all_controls(Et):
    St2.st[c] = SAT
events.apply_event(Et, St2, dict(kind="life", agent="x", now_t=1, t=1))
check("a conforming event changes nothing", gate.gate(Et, St2) == gate.APPROVED)
Et.agents["x"].expires = 0
St3 = State()
for c in exposure.all_controls(Et):
    St3.st[c] = SAT
events.apply_event(Et, St3, dict(kind="life", agent="x", now_t=5, t=1))                                           # DVG-LIFE-01 is Medium: the control becomes unverified, not violated
check("a Medium divergence makes the control unverified, not violated", St3.status(("life", "x")) == UNV)

check("an event for an unknown agent is unverified", events.conforms(E, dict(kind="tool_call", agent="ghost", tool="search"))["outcome"] == "UNVERIFIED")
try:
    events.conforms(E, dict(kind="nonsense", agent="support"))
    check("an unknown event kind is refused", False)
except ValueError:
    check("an unknown event kind is refused", True)

# well-formedness
check("the demo estate is well-formed", estate.problems(E) == [])
broken = copy.deepcopy(E)
broken.res["x"] = ("Nowhere", 9, "blob")
broken.agents["support"].may_delegate_to.add("ghost")
check("a malformed estate is described", len(estate.problems(broken)) >= 3)
try:
    estate.validate(broken)
    check("validate refuses a malformed estate", False)
except ValueError:
    check("validate refuses a malformed estate", True)

# ------------------------------------------------------------------ differential test against the reference implementation
print("-- differential test against the reference implementation")
rng = random.Random(11)
n_est = n_dis = 0
for _ in range(300):
    Er = random_ref_estate(rng)
    Ep = conv(Er)
    if exposure.paths(Ep) != RM.paths(Er):
        n_dis += 1
    for p in RM.paths(Er):
        if exposure.required(Ep, p) != RM.required(Er, p):
            n_dis += 1
    for _ in range(5):
        Sr = RM.State()
        for c in RM.all_controls(Er):
            Sr.st[c] = rng.choice(LEVELS)
            if Sr.st[c] == SAT and rng.random() < 0.3:
                Sr.fresh[c] = rng.randint(1, 8)
        Sp = conv_state(Sr)
        for now in (0, 4, 9):
            n_est += 1
            if gate.gate(Ep, Sp, now) != RM.gate(Er, Sr, now) or gate.department_risk(Ep, Sp, now) != RM.department_risk(Er, Sr, now):
                n_dis += 1
check(f"paths, required controls, gate and risk vector agree on {n_est} cases", n_dis == 0, f"{n_dis} disagreements")

POOL = ["search", "refund", "hr", "payments", "x", "ledger", "crm", "mcp://docs", "orchestrator", "shell.exec", "read_db", "send_email"]


def perturb(ev, rng):
    e = copy.deepcopy(ev)
    keys = [k for k in e if k not in ("kind", "agent")]
    for _ in range(rng.randint(0, 2)):
        if not keys:
            break
        k = rng.choice(keys)
        op = rng.choice(["drop", "flip", "swap", "num"])
        v = e.get(k)
        if op == "drop":
            e.pop(k, None)
        elif op == "flip" and isinstance(v, bool):
            e[k] = not v
        elif op == "swap" and isinstance(v, str):
            e[k] = rng.choice(POOL)
        elif op == "num" and isinstance(v, int) and not isinstance(v, bool):
            e[k] = v + rng.choice([-1, 1, 200])
        elif op == "num" and isinstance(v, dict):
            e[k] = {a: (b + rng.choice([-1, 1, 200]) if isinstance(b, int) else b) for a, b in v.items()}
    return e


def safe(f, *a):
    """The result, or the kind of exception: both implementations must also fail in the same way."""
    try:
        return f(*a)
    except Exception as e:
        return ("EXC", type(e).__name__)


rng = random.Random(23)
n_ev = n_dis = 0
scen = RP.scenarios(RP.demo_estate())
for _ in range(4000):
    sc = rng.choice(scen)
    Er = sc["estate"]
    Ep = conv(Er)
    ev = perturb(rng.choice([sc["bad"], sc["good"]]), rng)
    n_ev += 1
    if safe(events.conforms, Ep, ev) != safe(RM.conforms, Er, ev):
        n_dis += 1
    Sr, Sp = RM.State(), State()
    safe(RM.apply_event, Er, Sr, ev)
    safe(events.apply_event, Ep, Sp, ev)
    if Sr.st != Sp.st:
        n_dis += 1
check(f"conforms and apply_event agree on {n_ev} perturbed events", n_dis == 0, f"{n_dis} disagreements")

sys.exit(1 if fails else 0)
