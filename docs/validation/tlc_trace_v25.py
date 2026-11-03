"""Prints the counterexample trace of one TLC run in compact form.  Usage: python -X utf8 tlc_trace_v25.py <scenario> <mut> <auth TRUE|FALSE> <props,comma> [spec]"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_tlc_v25 as r

scen, mut, auth, props = sys.argv[1], sys.argv[2], sys.argv[3] == "TRUE", sys.argv[4].split(",")
spec = sys.argv[5] if len(sys.argv) > 5 else "Spec"
inv = not any(p.startswith(("NoTimelock", "ObligationResolved", "IncidentResolved")) for p in props)
d = os.path.join(tempfile.gettempdir(), "tla_dbg2")
os.makedirs(d, exist_ok=True)
open(os.path.join(d, "t.cfg"), "w").write(r.cfg(scen, mut, auth, props, inv, spec))
open(os.path.join(d, "AstraV25.tla"), "w", encoding="utf-8").write(open(os.path.join(HERE, "AstraV25.tla"), encoding="utf-8").read())
env = dict(os.environ, MSYS_NO_PATHCONV="1")
out = subprocess.run(["docker", "run", "--rm", "-v", f"{d}:/w", "-v", f"{r.JAR_DIR}:/jar", "-w", "/w", "eclipse-temurin:17-jre", "java", "-cp", "/jar/tla2tools.jar", "tlc2.TLC", "-workers", "4",
                      "-config", "t.cfg", "AstraV25.tla"], capture_output=True, text=True, env=env).stdout
keys = ["clock", "st", "prod", "apPol", "apUntil", "pol", "rvw", "rvwPol", "rv", "evs", "ee", "oblOpen", "oblT", "oblBreach", "inc", "t0", "lock", "pend"]
prev = {}
for blk in re.split(r"\n(?=State \d+:|Back to state|Stuttering)", out[out.find("State 1:"):] if "State 1:" in out else out[-1500:]):
    head = blk.split("\n")[0]
    cur = {}
    for l in blk.split("\n")[1:]:
        m = re.match(r"/\\ (\w+) = (.*)", l.strip())
        if m:
            cur[m.group(1)] = m.group(2)
    diff = {k: v for k, v in cur.items() if k in keys and prev.get(k) != v}
    print(head[:60], diff)
    prev = {**prev, **cur}
