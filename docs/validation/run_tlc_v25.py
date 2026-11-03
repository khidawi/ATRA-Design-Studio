"""Runs TLC (TLA+ model checker) on AstraV25.tla in a Java container, for the specification and for planted defects (mutations).
Usage: python -I run_tlc_v25.py [probe|spec|mut|all]  -> writes tlc_results_v25.json"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
JAR_DIR = os.path.join(tempfile.gettempdir(), "tla_probe")
WORK = os.path.join(tempfile.gettempdir(), "tla_v25_work")
os.makedirs(WORK, exist_ok=True)
BASE = dict(CM=3, VE=2, VE2=3, AP_LEN=1, DR=1, DC=1)
SCEN = {"core": dict(NV=2, NE=1, POLCH="FALSE", RET="FALSE", INCI="FALSE"), "core1": dict(NV=1, NE=1, POLCH="TRUE", RET="FALSE", INCI="FALSE"), "retire": dict(NV=1, NE=1, POLCH="TRUE", RET="TRUE", INCI="FALSE"), "incident": dict(NV=1, NE=1, POLCH="TRUE", RET="FALSE", INCI="TRUE")}

SAFETY = ["ApproveSafety", "ReleaseSafety", "UpdateSafety", "RevokePersist", "NoImprove"]
LIVE = ["NoTimelock", "ObligationResolved"]
LIVE_INC = ["NoTimelock", "IncidentResolved"]


def cfg(scen, mut, auth, props, inv, spec="Spec"):
    lines = [f"SPECIFICATION {spec}"]
    if inv:
        lines.append("INVARIANT InvProdStatus InvExpiry InvReleasable InvRetire InvDecom InvReviewBasis InvHold InvObligation InvIncident")
    if props:
        lines.append("PROPERTY " + " ".join(props))
    lines.append("CONSTANTS")
    for k, v in {**BASE, **SCEN[scen]}.items():
        lines.append(f"  {k} = {v}")
    lines.append(f"  AUTH = {'TRUE' if auth else 'FALSE'}")
    lines.append(f'  MUT = "{mut}"')
    return "\n".join(lines) + "\n"


def run(name, scen, mut, auth, props, inv=True, timeout=900, spec="Spec"):
    cfg_name = f"{name}.cfg"
    open(os.path.join(WORK, cfg_name), "w").write(cfg(scen, mut, auth, props, inv, spec))
    open(os.path.join(WORK, "AstraV25.tla"), "w", encoding="utf-8").write(open(os.path.join(HERE, "AstraV25.tla"), encoding="utf-8").read())
    cname = "tlc_" + name
    subprocess.run(["docker", "rm", "-f", cname], capture_output=True)
    cmd = ["docker", "run", "--rm", "--name", cname, "-v", f"{WORK}:/w", "-v", f"{JAR_DIR}:/jar", "-w", "/w", "eclipse-temurin:17-jre", "java", "-XX:+UseParallelGC", "-Xmx3g",
           "-cp", "/jar/tla2tools.jar", "tlc2.TLC", "-workers", "auto", "-metadir", f"/tmp/m_{name}", "-config", cfg_name, "AstraV25.tla"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = p.stdout + p.stderr
        os.makedirs(os.path.join(HERE, 'tlc_logs_v25'), exist_ok=True)
        open(os.path.join(HERE, 'tlc_logs_v25', name + '.log'), 'w', encoding='utf-8').write(open(os.path.join(WORK, cfg_name)).read() + chr(10) + out)
    except subprocess.TimeoutExpired as ex:
        subprocess.run(["docker", "kill", cname], capture_output=True)
        res = {"scenario": scen, "mut": mut, "auth": auth, "properties": props, "invariant": inv, "no_error": False, "timeout_seconds": timeout, "violation": "NO RESULT: time limit reached before the search finished"}
        print(name, res["violation"], flush=True)
        return res
    m = re.search(r"(\d+) states generated, (\d+) distinct states found", out)
    depth = re.search(r"The depth of the complete state graph search is (\d+)", out)
    violated = re.search(r"Error: ([^\n]*(?:violated|deadlock|Deadlock)[^\n]*)", out)
    ok = "Model checking completed. No error has been found." in out
    res = {"scenario": scen, "mut": mut, "auth": auth, "properties": props, "invariant": inv, "no_error": ok, "generated": int(m.group(1)) if m else None,
           "distinct": int(m.group(2)) if m else None, "depth": int(depth.group(1)) if depth else None, "violation": None if ok else (violated.group(1) if violated else "see tail"),
           "tail": None if ok else out[-1200:]}
    print(name, "OK" if ok else "VIOLATION: " + str(res["violation"]), res["distinct"], flush=True)
    return res


if __name__ == "__main__":
    R = {"constants": BASE, "scenarios": SCEN}
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which == "probe":
        print(json.dumps(run("probe", "core", "none", True, SAFETY), indent=1))
        sys.exit(0)
    if which in ("all", "spec", "rest"):
        if which == "rest":
            txt = open(os.path.join(tempfile.gettempdir(), "probe_out.txt"), encoding="utf-8").read()
            R["core_safety"] = json.loads(txt[txt.index("{"):])
        else:
            R["core_safety"] = run("core_safety", "core", "none", True, SAFETY)
        R["core1_safety_with_policy_change"] = run("core1_safety_with_policy_change", "core1", "none", True, SAFETY)
        R["core_live_auth"] = run("core_live_auth", "core1", "none", True, LIVE, inv=False)
        R["core_live_noauth"] = run("core_live_noauth", "core1", "none", False, LIVE, inv=False)
        R["retire_safety"] = run("retire_safety", "retire", "none", True, SAFETY)
        R["incident_safety_auth"] = run("incident_safety_auth", "incident", "none", True, SAFETY)
        R["incident_safety_noauth"] = run("incident_safety_noauth", "incident", "none", False, SAFETY)
        R["incident_live_auth"] = run("incident_live_auth", "incident", "none", True, LIVE_INC, inv=False)
        R["incident_live_noauth"] = run("incident_live_noauth", "incident", "none", False, LIVE_INC, inv=False)
    if which in ("all", "mut", "rest"):
        for mut in ("oldSatisfies", "noRelDeploy", "reviewOverrides", "noSupersede", "updateKeepsStatus", "reinstate", "keepCredentials", "noObligation", "noRelApprove", "reviewNoBasis", "noRatchet"):
            R[f"mut_{mut}"] = run(f"mut_{mut}", "core", mut, True, SAFETY)
        for mut in ("retireNoBasis", "keepRetired"):
            R[f"mut_{mut}"] = run(f"mut_{mut}", "retire", mut, True, SAFETY)
        R["mut_strictTick_live"] = run("mut_strictTick_live", "core1", "strictTick", True, ["NoTimelock"], inv=False)
        R["mut_deadlineTick_noauth_live"] = run("mut_deadlineTick_noauth_live", "incident", "deadlineTick", False, ["NoTimelock"], inv=False)
    if which in ("all", "mut", "rest"):
        R["weak_fairness_for_tick_live"] = run("weak_fairness_for_tick_live", "core1", "none", True, ["NoTimelock"], inv=False, spec="SpecWF")
    json.dump(R, open(os.path.join(HERE, "tlc_results_v25.json" if which in ("all", "rest") else f"tlc_results_v25_{which}.json"), "w"), indent=1)
