"""
Tests for model_versions.py: telling when a third-party model changed behind its name.

    docker compose exec backend python -m tests.test_model_versions
"""
import random
import sys
from datetime import datetime, timedelta, timezone

import model_versions as mv

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


rng = random.Random(5)
now = datetime.now(timezone.utc)


def feed(state, version, n, start, out_p=(0.7, 0.3), lat=(120, 20), err=0.01, conf=0.8, kind="categorical"):
    ev = []
    for i in range(n):
        at = (start + timedelta(seconds=i)).isoformat()
        out = rng.choices(["yes", "no"], out_p)[0] if kind == "categorical" else rng.gauss(out_p[0], out_p[1])
        e = mv.fold(state, version, {"output": out, "latency_ms": abs(rng.gauss(*lat)), "error": rng.random() < err, "confidence": min(1, max(0, rng.gauss(conf, 0.05)))}, at, kind)
        if e:
            ev.append(e)
    return ev


s = mv.new_state()
t0 = now - timedelta(hours=30)
check("the first version is not a change", feed(s, "gpt-a-2026-01", 400, t0) == [] and s["current"] == "gpt-a-2026-01" and not s["events"])
ev = feed(s, "gpt-a-2026-01", 200, t0 + timedelta(hours=1))
check("more of the same version is not a change", ev == [])
quiet = mv.evaluate(s, "categorical", None, now.isoformat())
check("one version raises nothing", quiet["reasons"] == [] and len(quiet["versions"]) == 1 and quiet["current"] == "gpt-a-2026-01")

ev = feed(s, "gpt-a-2026-04", 300, t0 + timedelta(hours=20), out_p=(0.7, 0.3))
check("a new version is a change event, once", len(ev) == 1 and ev[0]["from"] == "gpt-a-2026-01" and ev[0]["to"] == "gpt-a-2026-04" and len(s["events"]) == 1)
check("the newest version is the current one", s["current"] == "gpt-a-2026-04")
r = mv.evaluate(s, "categorical", None, now.isoformat())
check("a change with unchanged behaviour is a watch, and says so", len(r["reasons"]) == 1 and r["reasons"][0]["level"] == "watch" and "alike" in r["reasons"][0]["text"], r["reasons"])

s2 = mv.new_state()
feed(s2, "m1", 400, t0)
feed(s2, "m2", 400, t0 + timedelta(hours=20), out_p=(0.2, 0.8), lat=(300, 40), err=0.08, conf=0.6)
r2 = mv.evaluate(s2, "categorical", None, now.isoformat())
shift = r2["reasons"][0]
check("a change whose answers, errors, latency and confidence moved is a drift naming each", shift["level"] == "drift" and {x["what"] for x in shift["shifts"]} >= {"answers", "errors", "latency", "confidence"}, shift)

s3 = mv.new_state()
feed(s3, "n1", 400, t0, out_p=(10, 2), kind="numeric")
feed(s3, "n2", 400, t0 + timedelta(hours=20), out_p=(14, 2), kind="numeric")
r3 = mv.evaluate(s3, "numeric", None, now.isoformat())
check("a numeric output is compared by how far the average moved", r3["reasons"] and any(x["what"] == "answers" for x in r3["reasons"][0]["shifts"]), r3["reasons"])

s4 = mv.new_state()
feed(s4, "p1", 400, t0)
feed(s4, "p2", 30, t0 + timedelta(hours=20), out_p=(0.1, 0.9))
r4 = mv.evaluate(s4, "categorical", None, now.isoformat())
check("too few answers from the new version are not judged", r4["reasons"][0]["level"] == "watch" and "Too few" in r4["reasons"][0]["text"])

old = mv.new_state()
feed(old, "q1", 400, now - timedelta(days=20))
feed(old, "q2", 400, now - timedelta(days=15))
check("a change older than a week is no longer called out, but stays in the history", mv.evaluate(old, "categorical", None, now.isoformat())["reasons"] == [] and len(mv.evaluate(old, "categorical", None, now.isoformat())["events"]) == 1)

back = mv.new_state()
feed(back, "r1", 300, t0)
feed(back, "r2", 300, t0 + timedelta(hours=10))
feed(back, "r1", 5, t0 + timedelta(hours=25))
check("a roll-back is seen by the version that last answered", back["current"] == "r1" and len(back["events"]) == 1)

many = mv.new_state()
for i in range(mv.MAX_VERSIONS + 15):
    mv.fold(many, f"v{i}", {"output": "yes"}, (t0 + timedelta(minutes=i)).isoformat(), "categorical")
check("versions are capped", len(many["items"]) <= mv.MAX_VERSIONS + 1)
check("a version is cleaned", mv.clean("  gpt-4o-2026 ") == "gpt-4o-2026" and mv.clean("   ") is None and mv.clean(None) is None and len(mv.clean("x" * 500)) == 120)
txt = mv.new_state()
mv.fold(txt, "t", {"output": "a secret reply about someone"}, now.isoformat(), "text")
check("a text output is kept as a length class, never the text", all(k.startswith("len~") for k in txt["items"]["t"]["out"]))
sys.exit(1 if fails else 0)
