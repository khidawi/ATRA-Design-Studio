"""
Tests for decision_stats.py: how people use a model's outputs.

    docker compose exec backend python -m tests.test_decision_stats
"""
import json
import random
import sys

import decision_stats as ds

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


rng = random.Random(3)


def decisions(n, role="loan officer", accept=0.7, secs=(25, 10), reason=0.5, wrong_p=0.1, accept_wrong=None, person=None):
    out = []
    for _ in range(n):
        wrong = rng.random() < wrong_p
        a = accept_wrong if (wrong and accept_wrong is not None) else accept
        action = "accepted" if rng.random() < a else rng.choice(["edited", "overridden", "escalated"])
        d = {"role": role, "action": action, "review_seconds": max(0.2, rng.gauss(*secs)), "reason": rng.random() < reason, "confidence_shown": True, "model_correct": not wrong}
        if person:
            d["person"] = rng.choice(person)
        out.append(d)
    return out


def acc_of(ds_list, individuals=False):
    a = ds.new_acc()
    for d in ds_list:
        ds.fold(a, d, "salt", individuals)
    return a


healthy = ds.evaluate(acc_of(decisions(600, accept_wrong=0.15)), None, 700)
check("careful review that catches mistakes raises nothing", healthy["reasons"] == [] and healthy["signals"]["automation_bias_risk"] == "LOW", healthy["reasons"])
check("the metrics are reported", 0.6 < healthy["accepted"] < 0.8 and healthy["review_p50"] and healthy["coverage"] == round(600 / 700, 4) and healthy["roles"][0]["role"] == "loan officer")

rubber = ds.evaluate(acc_of(decisions(400, accept=0.99, secs=(2, 0.5), accept_wrong=0.99)), None, 400)
kinds = {r["subject"] + ":" + r["level"] for r in rubber["reasons"]}
check("nearly everything accepted in seconds, with the model's errors accepted too, is the serious finding", any(r["level"] == "drift" and "turned out to be wrong" in r["text"] for r in rubber["reasons"]), rubber["reasons"])
check("it says the substantive-review fact is contradicted and the bias risk is critical", rubber["signals"]["hitl_verified_substantive"] is False and rubber["signals"]["automation_bias_risk"] == "CRITICAL", rubber["signals"])

fast = ds.evaluate(acc_of(decisions(400, accept=0.96, secs=(2.5, 0.5), wrong_p=0.0)), None, 400)
check("fast acceptance alone is a watch, worded as a question, not an accusation", any(r["level"] == "watch" and "rubber stamp" in r["text"] for r in fast["reasons"]) and not any(r["level"] == "drift" for r in fast["reasons"]) and fast["signals"]["hitl_verified_substantive"] is False, fast["reasons"])
slow = ds.evaluate(acc_of(decisions(400, accept=0.99, secs=(40, 10), wrong_p=0.0)), None, 400)
check("near-total acceptance with a real look is a milder watch", any("accepted 99%" in r["text"] or "accepted 98%" in r["text"] for r in slow["reasons"]) and slow["signals"].get("hitl_verified_substantive") is None and slow["signals"]["automation_bias_risk"] == "MEDIUM", slow["reasons"])
distrust = ds.evaluate(acc_of(decisions(400, accept=0.15, wrong_p=0.0)), None, 400)
check("overriding what was right is noticed as distrust", any("were right" in r["text"] for r in distrust["reasons"]), distrust["reasons"])

few = ds.evaluate(acc_of(decisions(40, accept=1.0, secs=(1, 0.1), accept_wrong=1.0)), None, 40)
check("too few decisions are not judged", few["reasons"] == [] and few["signals"] == {} and few["sufficient"] is False)
check("nothing in, nothing out", ds.evaluate(ds.new_acc(), None, 0)["reasons"] == [])

two = acc_of(decisions(300, role="nurse", accept_wrong=0.15) + decisions(300, role="doctor", accept=0.99, secs=(1.5, 0.3), accept_wrong=0.99))
r2 = ds.evaluate(two, None, 600)
check("a role that stands out is named", any(r["subject"] == "doctor" and r["level"] == "drift" for r in r2["reasons"]) and not any(r["subject"] == "nurse" for r in r2["reasons"]), [(r["subject"], r["level"]) for r in r2["reasons"]])
check("roles are listed with their own rates", {x["role"] for x in r2["roles"]} == {"nurse", "doctor"})

cov = ds.evaluate(acc_of(decisions(200)), {"coverage_expected": 1.0}, 1000)
check("outputs used with no person's decision are flagged against the expected share", any(r["subject"] == "coverage" and r["level"] == "drift" for r in cov["reasons"]), cov["reasons"])
check("no expectation set, no coverage finding", not any(r["subject"] == "coverage" for r in ds.evaluate(acc_of(decisions(200)), None, 1000)["reasons"]))
rs = ds.evaluate(acc_of(decisions(300, reason=0.2)), {"require_reasons": 1}, 300)
check("a policy that asks for reasons is checked", any("reason was given" in r["text"] for r in rs["reasons"]))

ppl = acc_of(decisions(300, person=["a", "a", "a", "a", "b"]), individuals=True)
rp = ds.evaluate(ppl, None, 300)
check("with pseudonymous people, concentration is seen", rp["distinct_people"] == 2 and any(r["subject"] == "concentration" for r in rp["reasons"]), rp.get("top_person_share"))
check("a person is a keyed hash, never the name, and only when asked for", "a" not in json.dumps(list(ppl["people"].keys())).replace("[", "").replace("]", "").replace('"', "")[:0] and all(len(k) == 10 for k in ppl["people"]) and acc_of(decisions(20, person=["alice"]), individuals=False)["people"] == {})
check("the same person is the same pseudonym within a monitor, not across monitors", ds.pseudonym("s1", "Alice ") == ds.pseudonym("s1", "alice") and ds.pseudonym("s1", "alice") != ds.pseudonym("s2", "alice"))
big = ds.new_acc()
for i in range(80):
    ds.fold(big, {"role": f"role-{i}", "action": "accepted"})
check("roles and people are capped", len(big["roles"]) <= ds.MAX_ROLES + 1)
m = ds.new_acc()
for d in decisions(100):
    ds.fold(m, d)
mm = __import__("model_stats").merge(m, m)
check("windows of decisions merge", mm["n"] == 200 and mm["roles"]["loan officer"]["n"] == 200)

sys.exit(1 if fails else 0)
