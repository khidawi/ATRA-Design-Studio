"""
Tests for threshold_policy.py: compliance floors, owner tuning, waivers.

    docker compose exec backend python -m tests.test_threshold_policy
"""
import sys

import decision_stats as ds
import model_stats as ms
import threshold_policy as tp

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


check("every governed threshold exists in the monitor", set(tp.MODEL) <= set(ms.DEFAULT_THRESHOLDS) and set(tp.DECISIONS) <= set(ds.DEFAULTS))
check("direction: a higher PSI is looser, a higher parity limit is stricter", tp.looser("lower", 0.3, 0.25) and not tp.looser("lower", 0.2, 0.25) and tp.looser("higher", 0.7, 0.8) and not tp.looser("higher", 0.85, 0.8))
F = {"model": {"psi_drift": 0.25, "parity_breach": 0.80}, "decisions": {"perfunctory_seconds": 5.0}}
check("floors are validated", tp.clean_floors({"model": {"psi_drift": "0.2"}}) == {"model": {"psi_drift": 0.2}})
for bad in ({"nope": {}}, {"model": {"min_n": 5}}, {"model": {"psi_drift": "x"}}):
    try:
        tp.clean_floors(bad)
        check(f"refused {bad}", False)
    except ValueError:
        check(f"refused {bad}", True)

check("tightening is always allowed", tp.loosened("model", {"psi_drift": 0.15, "parity_breach": 0.85}, F) == [])
check("loosening is found", [o["key"] for o in tp.loosened("model", {"psi_drift": 0.4, "parity_breach": 0.7}, F)] == ["psi_drift", "parity_breach"])
check("a key with no floor is the owner's", tp.loosened("model", {"error_drift": 0.5}, F) == [])

D = {k: v for k, v in ms.DEFAULT_THRESHOLDS.items()}
e = tp.effective("model", D, {"psi_drift": 0.4}, F, set())
check("a value looser than the floor is held to it", e["psi_drift"] == 0.25 and e["psi_watch"] == 0.10)
check("unless waived", tp.effective("model", D, {"psi_drift": 0.4}, F, {"psi_drift"})["psi_drift"] == 0.4)
check("a floor stricter than the default raises the default", tp.effective("model", D, {}, {"model": {"psi_drift": 0.15}}, set())["psi_drift"] == 0.15)
check("the owner's stricter value stands", tp.effective("model", D, {"psi_drift": 0.12}, F, set())["psi_drift"] == 0.12)

now = "2026-10-14T09:00:00+00:00"
try:
    tp.apply_change("model", {"psi_drift": 0.4}, F, [], can_waive=False, reason=None, by="owner", at=now)
    check("an owner cannot loosen past the floor", False)
except PermissionError as ex:
    check("an owner cannot loosen past the floor, and is told which threshold", "psi_drift 0.4" in str(ex) and "floor 0.25" in str(ex), ex)
try:
    tp.apply_change("model", {"psi_drift": 0.4}, F, [], can_waive=True, reason="  ", by="Compliance lead", at=now)
    check("a waiver needs a reason", False)
except ValueError:
    check("a waiver needs a reason", True)
w, made = tp.apply_change("model", {"psi_drift": 0.4}, F, [], can_waive=True, reason="Seasonal traffic makes this input swing.", by="Compliance lead", at=now)
check("a signed-off waiver is recorded with who, when, why and the floor", len(made) == 1 and w[0]["by"] == "Compliance lead" and w[0]["floor"] == 0.25 and w[0]["value"] == 0.4 and "Seasonal" in w[0]["reason"], w)
w2, made2 = tp.apply_change("model", {"psi_drift": 0.4, "error_drift": 0.2}, F, w, can_waive=False, reason=None, by="owner", at=now)
check("an existing waiver keeps covering the same value, with no new sign-off", made2 == [] and len(w2) == 1)
try:
    tp.apply_change("model", {"psi_drift": 0.5}, F, w, can_waive=False, reason=None, by="owner", at=now)
    check("changing a waived value to another loose value needs a new waiver", False)
except PermissionError:
    check("changing a waived value to another loose value needs a new waiver", True)
w3, _ = tp.apply_change("model", {"psi_drift": 0.2}, F, w, can_waive=False, reason=None, by="owner", at=now)
check("tightening back inside the floor drops the waiver", w3 == [])
other = [{"scope": "decisions", "key": "perfunctory_seconds", "value": 2.0, "floor": 5.0, "reason": "x" * 6, "by": "c", "at": now}]
w4, _ = tp.apply_change("model", {"psi_drift": 0.2}, F, other, can_waive=False, reason=None, by="o", at=now)
check("waivers of another group are left alone", w4 == other)
check("current waivers are those whose value is still in use", tp.current_waivers("model", w, {"psi_drift": 0.4}) == w and tp.current_waivers("model", w, {"psi_drift": 0.3}) == [])
sys.exit(1 if fails else 0)
