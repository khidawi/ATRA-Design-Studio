"""Mutation testing of backend/astra_model: break the code one small change at a time and see whether the validation suites notice.

    python /ext/mutate.py OUT.json [files...]

Tier 1: the extended suite (ext_validation.py --quick). Tier 2: the survivors are run against the existing test (tests.test_astra_model).
"""
import ast
import copy
import json
import os
import shutil
import subprocess
import sys
import time
from multiprocessing import Pool

SRC = "/app/astra_model"
FILES = sys.argv[2:] or ["gate.py", "statuses.py", "exposure.py", "contract.py"]
CMP = {ast.Lt: [ast.LtE, ast.Gt], ast.LtE: [ast.Lt, ast.Gt], ast.Gt: [ast.GtE, ast.Lt], ast.GtE: [ast.Gt, ast.Lt], ast.Eq: [ast.NotEq], ast.NotEq: [ast.Eq],
       ast.In: [ast.NotIn], ast.NotIn: [ast.In], ast.Is: [ast.IsNot], ast.IsNot: [ast.Is]}


class Mut(ast.NodeTransformer):
    """Counts the sites; when `target` is set, applies exactly the target-th mutation."""

    def __init__(self, target=None):
        self.target, self.n, self.sites = target, 0, []

    def hit(self, line, what):
        self.sites.append((line, what))
        k = self.n
        self.n += 1
        return self.target == k

    def visit_Compare(self, node):
        self.generic_visit(node)
        for i, op in enumerate(node.ops):
            for new in CMP.get(type(op), []):
                if self.hit(node.lineno, f"{type(op).__name__} -> {new.__name__}"):
                    node.ops[i] = new()
        return node

    def visit_BoolOp(self, node):
        self.generic_visit(node)
        if self.hit(node.lineno, f"{type(node.op).__name__} swapped"):
            node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        return node

    def visit_UnaryOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Not) and self.hit(node.lineno, "not removed"):
            return node.operand
        return node

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, (ast.Add, ast.Sub)) and self.hit(node.lineno, "+ and - swapped"):
            node.op = ast.Sub() if isinstance(node.op, ast.Add) else ast.Add()
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        swap = {"min": "max", "max": "min", "any": "all", "all": "any"}
        if isinstance(node.func, ast.Name) and node.func.id in swap and self.hit(node.lineno, f"{node.func.id} -> {swap[node.func.id]}"):
            node.func = ast.Name(id=swap[node.func.id], ctx=ast.Load())
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, bool):
            if self.hit(node.lineno, f"{node.value} flipped"):
                return ast.copy_location(ast.Constant(value=not node.value), node)
        elif isinstance(node.value, int):
            if self.hit(node.lineno, f"{node.value} -> {node.value + 1}"):
                return ast.copy_location(ast.Constant(value=node.value + 1), node)
        return node


def make(fname, k):
    tree = ast.parse(open(os.path.join(SRC, fname), encoding="utf-8").read())
    m = Mut(k)
    new = m.visit(copy.deepcopy(tree))
    ast.fix_missing_locations(new)
    return ast.unparse(new), m.sites


def run(job):
    fname, k, line, what = job
    d = f"/tmp/mut/{fname}_{k}"
    shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(SRC, d + "/astra_model", ignore=shutil.ignore_patterns("__pycache__"))
    code, _ = make(fname, k)
    open(f"{d}/astra_model/{fname}", "w", encoding="utf-8").write(code)
    t0 = time.time()
    try:
        p = subprocess.run([sys.executable, "/ext/ext_validation.py", "--quick"], env=dict(os.environ, MUT_DIR=d), capture_output=True, text=True, timeout=150, cwd="/app")
        killed = p.returncode != 0
        by = [ln.split()[1] for ln in p.stdout.splitlines() if ln.startswith("FAIL")] or (["crash"] if killed else [])
    except subprocess.TimeoutExpired:
        killed, by = True, ["timeout"]
    return dict(file=fname, line=line, mutation=what, killed=killed, by=by, seconds=round(time.time() - t0, 1), dir=d)


def tier2(r):
    try:
        p = subprocess.run([sys.executable, "-c", f"import sys; sys.path.insert(0, {r['dir']!r}); import runpy; runpy.run_module('tests.test_astra_model', run_name='__main__')"],
                           capture_output=True, text=True, timeout=400, cwd="/app")
        return dict(r, killed_by_existing=p.returncode != 0)
    except subprocess.TimeoutExpired:
        return dict(r, killed_by_existing=True)


if __name__ == "__main__":
    out = sys.argv[1]
    jobs = []
    for f in FILES:
        _c, sites = make(f, None)
        jobs += [(f, k, ln, w) for k, (ln, w) in enumerate(sites)]
    print(f"{len(jobs)} mutants in {FILES}", flush=True)
    with Pool(os.cpu_count() or 2) as pool:
        res = []
        for r in pool.imap_unordered(run, jobs):
            res.append(r)
            print(("killed   " if r["killed"] else "SURVIVED ") + f"{r['file']}:{r['line']} {r['mutation']} {r['by']}", flush=True)
        surv = [r for r in res if not r["killed"]]
        print(f"tier 1: {len(res) - len(surv)} of {len(res)} killed; {len(surv)} survivors; running them against the existing test", flush=True)
        cache = {}
        if os.path.exists("/ext/mutation_old.json"):                 # tier-2 results from the first run (same mutants, same existing test)
            for o in json.load(open("/ext/mutation_old.json")):
                cache.setdefault((o["file"], o["line"], o["mutation"]), set()).add(o.get("killed_by_existing", True if o["killed"] else None))
        todo, res2 = [], []
        for r in surv:
            vals = cache.get((r["file"], r["line"], r["mutation"]), set())
            if len(vals) == 1 and None not in vals:
                res2.append(dict(r, killed_by_existing=next(iter(vals))))
            else:
                todo.append(r)
        res2 += list(pool.imap_unordered(tier2, todo))
    final = [r for r in res if r["killed"]] + res2
    for r in res2:
        print(("existing test kills " if r["killed_by_existing"] else "STILL SURVIVES      ") + f"{r['file']}:{r['line']} {r['mutation']}", flush=True)
    for r in final:
        r.pop("dir", None)
    json.dump(final, open(out, "w"), indent=1)
    print("done", flush=True)
