"""
Tests for the charts' data: runtime.py /series (activity over time) and findings.py /series (trends).

    docker compose exec -e DATABASE_URL=...stai_test backend python -m tests.test_runtime_series     # a scratch database: see tests/_guard.py
"""
import sys

from tests._auth import authed_client
from tests.test_runtime import KEY, keyed, ratified, send, wipe

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


try:
    with authed_client("admin", "Compliance lead") as api:
        wipe()
        ratified(api)
        col = keyed(api.post("/api/keys", json={"name": "zz-test-collector", "role": "collector"}).json()["key"])
        send(col, KEY, [{"type": "tool_call", "name": "ehr.records.read", "write": False}] * 5 + [{"type": "tool_call", "name": "email.send.external", "write": True}] * 2)
        send(col, KEY, [{"type": "tool_call", "name": "shell.exec", "write": True}, {"type": "data_access", "name": "payroll"}, {"type": "memory_write", "scope": "long_term"}])
        send(col, "zz-test-quiet-agent", [{"type": "heartbeat"}])

        s = api.get("/api/runtime/series?hours=24").json()
        total = sum(b["total"] for b in s["buckets"])
        check("events are counted per bucket, over a full window with no gaps", total == 11 and s["step_hours"] == 1 and len(s["buckets"]) in (24, 25), (total, len(s["buckets"])))
        check("those outside the contract are split out", sum(b["divergent"] for b in s["buckets"]) == 3, [b["divergent"] for b in s["buckets"]])
        check("the mix of kinds of event is given, with how many diverged", {t["type"]: (t["total"], t["divergent"]) for t in s["types"]}["tool_call"] == (8, 1) and {t["type"] for t in s["types"]} >= {"data_access", "memory_write"}, s["types"])
        a = next(x for x in s["by_agent"] if x["agent_key"] == KEY)
        check("each agent has a trend as long as the window, and its own totals", a["total"] == 10 and a["divergent"] == 3 and len(a["spark"]) == len(s["buckets"]) and sum(a["spark"]) == 10 and sum(a["spark_divergent"]) == 3, a)
        caps = {(c["type"], c["name"]) for c in s["new_capabilities"]}
        check("capabilities first seen outside the contract are listed, memory with a readable name", ("tool_call", "shell.exec") in caps and ("data_access", "payroll") in caps and ("memory_write", "long-term memory") in caps, caps)
        check("the findings raised in the window are marked, each with its severity", len(s["findings"]) >= 3 and all(f["key"].startswith("F-") and f["severity"] in ("High", "Medium", "Low") for f in s["findings"]), s["findings"])
        check("and the runtime drift item", len(s["drift_items"]) >= 1 and s["drift_items"][0]["agent_key"] == KEY, s["drift_items"])
        one = api.get(f"/api/runtime/series?hours=24&agent=zz-test-quiet-agent").json()
        check("one agent can be looked at alone", sum(b["total"] for b in one["buckets"]) == 1 and [x["agent_key"] for x in one["by_agent"]] == ["zz-test-quiet-agent"] and one["new_capabilities"] == [])
        wide = api.get("/api/runtime/series?hours=168").json()
        check("a week is shown in six-hour steps", wide["step_hours"] == 6 and len(wide["buckets"]) in (28, 29) and sum(b["total"] for b in wide["buckets"]) == 11, (wide["step_hours"], len(wide["buckets"])))
        check("an absurd window is clamped", api.get("/api/runtime/series?hours=100000").json()["hours"] == 168 and api.get("/api/runtime/series?hours=0").json()["hours"] == 3)

        f = api.get("/api/findings/series?days=14").json()
        check("findings are counted per day over the whole window, split by severity", len(f["by_day"]) == 14 and sum(d["High"] + d["Medium"] + d["Low"] for d in f["by_day"]) == f["total"] >= 3 and f["by_day"][-1]["High"] >= 1, f["by_day"][-1])
        classes = {c["class_code"]: c for c in f["by_class"]}
        check("and by divergence class, each with its OWASP agentic category", "DVG-TOOL" in classes and classes["DVG-TOOL"]["category"].startswith("ASI02") and "DVG-DATA" in classes and "DVG-MEM" in classes, f["by_class"])
        ag = next(x for x in f["by_agent"] if x["agent_key"] == KEY)
        check("by agent, open against acknowledged", ag["open"] == ag["total"] >= 3 and ag["acknowledged"] == 0, ag)
        first = api.get("/api/findings").json()[0]["finding_key"]
        ack = api.post(f"/api/findings/{first}/acknowledge", json={})
        check("a finding can be acknowledged", ack.status_code == 200, ack.text)
        f2 = api.get("/api/findings/series?days=14").json()
        ag2 = next(x for x in f2["by_agent"] if x["agent_key"] == KEY)
        check("acknowledging one moves it from open to acknowledged", ag2["acknowledged"] == 1 and ag2["open"] == ag["open"] - 1 and f2["open"] == f["open"] - 1, ag2)
finally:
    try:
        wipe()
    except Exception as exc:
        print("cleanup failed", exc)
sys.exit(1 if fails else 0)
