"""
Tests for llm_safety.py: safety flags and canary checks.

    docker compose exec backend python -m tests.test_llm_safety
"""
import sys

import llm_safety as ls

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


q = ls.evaluate_flags({}, 1000)
check("nothing flagged, nothing said", q["reasons"] == [] and len(q["rows"]) == len(ls.SAFETY_FLAGS))
s = ls.evaluate_flags({"secret_in_prompt": 1}, 5000)
check("one credential in a prompt is a data-egress finding even among thousands", s["reasons"][0]["kind"] == "DATA_EGRESS" and s["reasons"][0]["level"] == "drift", s)
check("one credential in a reply is an output-safety finding", ls.evaluate_flags({"secret_in_output": 1}, 100)["reasons"][0]["kind"] == "OUTPUT_SAFETY")
p = ls.evaluate_flags({"pii_in_prompt": 20}, 1000)
check("personal data in 2% of prompts is a watch", p["reasons"][0]["level"] == "watch" and "pattern match" in p["reasons"][0]["text"], p)
check("in 6% it is more", ls.evaluate_flags({"pii_in_prompt": 60}, 1000)["reasons"][0]["level"] == "drift")
check("a couple of matches among many is not a rate", ls.evaluate_flags({"pii_in_prompt": 2}, 100)["reasons"] == [])
check("injection attempts are watched", ls.evaluate_flags({"injection_suspected": 30}, 1000)["reasons"][0]["level"] == "watch")

st = ls.new_canaries()
for i in range(6):
    ls.fold_canary(st, "refund-policy", True, "v1", f"2026-10-01T10:0{i}")
r = ls.evaluate_canaries(st, "v1")
check("a canary that passes raises nothing", r["reasons"] == [] and r["rows"][0]["fail_rate"] == 0.0)
for i in range(4):
    ls.fold_canary(st, "refund-policy", i == 0, "v2", f"2026-10-05T10:0{i}")
r = ls.evaluate_canaries(st, "v2")
check("passing before and failing on the new version is called out as the model changing", r["reasons"] and r["reasons"][0]["level"] == "drift" and "v2" in r["reasons"][0]["text"] and "earlier versions" in r["reasons"][0]["text"], r)
check("each version's rate is listed", {v["version"] for v in r["rows"][0]["versions"]} == {"v1", "v2"})
st2 = ls.new_canaries()
for i in range(5):
    ls.fold_canary(st2, "x", False, None, f"2026-10-01T10:0{i}")
check("five failures in a row, with no version known, is serious", ls.evaluate_canaries(st2)["reasons"][0]["level"] == "drift")
st3 = ls.new_canaries()
for ok, i in zip([True, False, False, True, False], range(5)):
    ls.fold_canary(st3, "y", ok, None, f"2026-10-01T10:0{i}")
check("three of five failing is a watch", ls.evaluate_canaries(st3)["reasons"][0]["level"] == "watch")
st4 = ls.new_canaries()
for i in range(3):
    ls.fold_canary(st4, "z", False, "v9", f"2026-10-01T10:0{i}")
check("too few runs to compare versions is not judged", ls.evaluate_canaries(st4, "v9")["reasons"] == [])
big = ls.new_canaries()
for i in range(ls.MAX_CANARIES + 10):
    ls.fold_canary(big, f"c{i}", True, None, "2026-10-01T10:00")
check("canaries are capped", len(big["items"]) == ls.MAX_CANARIES)
sys.exit(1 if fails else 0)
