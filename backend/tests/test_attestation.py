"""
Tests for attestation.py: claims that lapse unless someone confirms them again.

    docker compose exec backend python -m tests.test_attestation
"""
import sys
from datetime import datetime, timedelta, timezone

import attestation as at

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


now = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
iso = lambda d: (now - timedelta(days=d)).isoformat()   # noqa: E731

check("a claim that lowers the risk is relied on, one that raises it is not", at.relied_on("dpia_approved", {"dpia_approved": True}) and not at.relied_on("dpia_approved", {"dpia_approved": False}) and not at.relied_on("dpia_approved", {}))
check("human review counts as substantive unless said otherwise", at.relied_on("hitl_verified_substantive", {}) and not at.relied_on("hitl_verified_substantive", {"hitl_verified_substantive": False}))
check("a favourable choice is relied on, an unfavourable one is not", at.relied_on("audit_frequency", {"audit_frequency": "CONTINUOUS"}) and not at.relied_on("audit_frequency", {"audit_frequency": "QUARTERLY"}) and not at.relied_on("rollback_mode", {"rollback_mode": "MANUAL"}))

old = {"life": {"dpia_approved": True, "fallback_tested": True}, "attest": {"fallback_tested": {"by": "Priya", "at": iso(10), "value": True}}}
new = {"life": {"dpia_approved": True, "fallback_tested": True, "operator_training_complete": True, "drift_detected": True}}
s = at.stamp(old, new, "Alex", now.isoformat())
check("a claim changed in this save is stamped with the person who saved", s["operator_training_complete"]["by"] == "Alex" and s["operator_training_complete"]["at"] == now.isoformat())
check("a claim that did not change keeps who confirmed it and when", s["fallback_tested"] == old["attest"]["fallback_tested"])
check("a claim that was already there with no attestation is not credited to whoever saves", "dpia_approved" not in s)
check("a claim that raises the risk is never attested", "drift_detected" not in s)
check("changing a claim re-attests it", at.stamp(old, {"life": {"fallback_tested": False}}, "Alex", now.isoformat())["fallback_tested"]["by"] == "Alex")
check("a claim withdrawn from the design loses its attestation", "fallback_tested" not in at.stamp(old, {"life": {}}, "Alex", now.isoformat()))
forged = {"life": {"fallback_tested": True}, "attest": {"fallback_tested": {"by": "Priya", "at": iso(0), "value": True}}}
check("what the client sends as an attestation is ignored", at.stamp(None, forged, "Alex", now.isoformat())["fallback_tested"]["by"] == "Alex")

life = {"dpia_approved": True, "fallback_tested": True, "operator_training_complete": True, "model_card_approved": True, "drift_detected": True}
att = {"dpia_approved": {"by": "P", "at": iso(400), "value": True}, "fallback_tested": {"by": "P", "at": iso(170), "value": True}, "operator_training_complete": {"by": "P", "at": iso(10), "value": True}}
rows = {r["fact"]: r for r in at.evaluate(life, att, None, now)}
check("a claim older than its period has lapsed", rows["dpia_approved"]["state"] == "lapsed" and rows["dpia_approved"]["days_left"] < 0, rows["dpia_approved"])
check("one close to its end is due soon", rows["fallback_tested"]["state"] == "due_soon" and 0 <= rows["fallback_tested"]["days_left"] <= 14, rows["fallback_tested"])
check("a fresh one is current and names who confirmed it", rows["operator_training_complete"]["state"] == "current" and rows["operator_training_complete"]["by"] == "P")
check("one nobody has confirmed is never confirmed", rows["model_card_approved"]["state"] == "never" and rows["model_card_approved"]["by"] is None)
check("a claim that raises the risk has no row", "drift_detected" not in rows)
check("human review, relied on by default, shows as never confirmed", rows["hitl_verified_substantive"]["state"] == "never")
check("a changed value voids the attestation", {r["fact"]: r for r in at.evaluate({"dpia_approved": True}, {"dpia_approved": {"by": "P", "at": iso(1), "value": False}}, None, now)}["dpia_approved"]["state"] == "never")
check("compliance can shorten a period", {r["fact"]: r for r in at.evaluate(life, att, {"operator_training_complete": 7}, now)}["operator_training_complete"]["state"] == "lapsed")
sm = at.summary(list(rows.values()))
check("the summary counts each state", sm["claims"] == len(rows) and sm["lapsed"] == 1 and sm["due_soon"] == 1 and sm["current"] == 1 and sm["never"] >= 2, sm)

c = at.confirm({"dpia_approved": True}, {}, ["dpia_approved"], "Priya", now.isoformat())
check("confirming stamps the person and the date", c["dpia_approved"] == {"by": "Priya", "at": now.isoformat(), "value": True})
for what, facts in (("a claim that cannot lapse", ["drift_detected"]), ("one not stated", ["fallback_tested"])):
    try:
        at.confirm({"dpia_approved": True}, {}, facts, "Priya", now.isoformat())
        check(f"refused: {what}", False)
    except ValueError:
        check(f"refused: {what}", True)
check("human review can be confirmed even though it is only implied", at.confirm({}, {}, ["hitl_verified_substantive"], "Priya", now.isoformat())["hitl_verified_substantive"]["by"] == "Priya")
check("periods are validated", at.clean_days({"dpia_approved": "200"}) == {"dpia_approved": 200})
for bad in ({"nope": 30}, {"dpia_approved": 3}, {"dpia_approved": 5000}, {"dpia_approved": "x"}):
    try:
        at.clean_days(bad)
        check(f"refused {bad}", False)
    except ValueError:
        check(f"refused {bad}", True)
sys.exit(1 if fails else 0)
