"""Mutation testing of two more modules: astra_estate.py (the estate builder, changed in this round) and astra_model/events.py (not mutated in round 2).

    python /ext/mutate2.py estate|events OUT.json

Each mutant is one small change (same operators as mutate.py). It is run against the existing tests for that module; a mutant that survives them is then run against the extended
suite (events only: that suite exercises astra_model, not the estate builder). A mutant that survives every suite is listed for review, not assumed equivalent.
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

sys.path.insert(0, "/ext")
from mutate import Mut                                         # noqa: E402

KIND = sys.argv[1]
OUT = sys.argv[2]
SPEC = {"estate": dict(src="/app/astra_estate.py", rel="astra_estate.py", whole=None, tests=["tests.test_astra_estate"], ext=False),
        "events": dict(src="/app/astra_model/events.py", rel="astra_model/events.py", whole="/app/astra_model", tests=["tests.test_astra_model", "tests.test_astra_classes"], ext=True)}[KIND]


def make(k):
    tree = ast.parse(open(SPEC["src"], encoding="utf-8").read())
    m = Mut(k)
    new = m.visit(copy.deepcopy(tree))
    ast.fix_missing_locations(new)
    return ast.unparse(new), m.sites


def run_tests(d, tests):
    for t in tests:
        code = (f"import sys; sys.path.insert(0, {d!r}); import runpy; "
                f"import astra_estate as _e; assert _e.__file__.startswith({d!r}) if {KIND == 'estate'} else True; "
                f"import astra_model as _m; assert _m.__file__.startswith({d!r}) if {KIND == 'events'} else True; "
                f"runpy.run_module({t!r}, run_name='__main__')")
        try:
            p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300, cwd="/app", env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        except subprocess.TimeoutExpired:
            return True, t + " (timeout)"
        if p.returncode != 0:
            return True, t
    return False, None


def run(job):
    k, line, what = job
    d = f"/tmp/mut2_{KIND}/{k}"
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)
    if SPEC["whole"]:
        shutil.copytree(SPEC["whole"], d + "/astra_model", ignore=shutil.ignore_patterns("__pycache__"))
    code, _ = make(k)
    dest = os.path.join(d, SPEC["rel"])
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    open(dest, "w", encoding="utf-8").write(code)
    killed, by = run_tests(d, SPEC["tests"])
    killed_ext = None
    if not killed and SPEC["ext"]:
        try:
            p = subprocess.run([sys.executable, "/ext/ext_validation.py", "--quick"], env=dict(os.environ, MUT_DIR=d), capture_output=True, text=True, timeout=200, cwd="/app")
            killed_ext = p.returncode != 0
        except subprocess.TimeoutExpired:
            killed_ext = True
    return dict(file=SPEC["rel"], line=line, mutation=what, killed_by_existing=killed, by=by, killed_by_extended=killed_ext)


if __name__ == "__main__":
    _c, sites = make(None)
    jobs = [(k, ln, w) for k, (ln, w) in enumerate(sites)]
    print(f"{len(jobs)} mutants in {SPEC['rel']}", flush=True)
    t0 = time.time()
    with Pool(os.cpu_count() or 2) as pool:
        res = []
        for r in pool.imap_unordered(run, jobs):
            res.append(r)
            tag = "killed " if r["killed_by_existing"] else ("ext-kill" if r["killed_by_extended"] else "SURVIVED")
            print(f"{tag:8s} {r['file']}:{r['line']} {r['mutation']}", flush=True)
    json.dump(sorted(res, key=lambda r: r["line"]), open(OUT, "w"), indent=1)
    kill = sum(1 for r in res if r["killed_by_existing"] or r["killed_by_extended"])
    print(f"done: {kill} of {len(res)} killed in {time.time() - t0:.0f}s", flush=True)
