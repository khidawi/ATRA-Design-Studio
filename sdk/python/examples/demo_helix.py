"""
Runtime demo for the Helix Logistics example (examples/company-helix-logistics.json): an AI agent and an AI model, each first behaving normally and then drifting.

  agent  an agent with a ratified contract (default: customs-agent). It reads what the contract allows, behaves inside it ("normal"), then does things the
         contract does not allow ("drift"): an unlisted write tool, an unsigned MCP server, a handoff to another agent, other departments' data, long-term memory.
         ASTRA answers each batch with a verdict per event, raises findings and, for new capabilities, a runtime drift item for compliance.
  model  the demand-forecast-model. "normal" sends a baseline period; "drift" sends a heatwave, a price change and a bigger forecast error.

Set up (see the walkthrough): upload the Helix file on the Organisation page; ratify the agent; create the model's monitor on AI Models -> Runtime (use
`model --show-record`); create an API key of role "collector" under Users -> API keys. Then:

    set ASTRA_URL=http://localhost:5173          (PowerShell: $env:ASTRA_URL="http://localhost:5173")
    set ASTRA_KEY=astra_xxxxxxxx

    python demo_helix.py contract                      # what the agent's contract allows
    python demo_helix.py agent --phase normal          # every event conforms
    python demo_helix.py agent --phase drift           # events outside the contract: findings and a drift item
    python demo_helix.py model --phase normal -n 1500  # the first 1,000 records become the baseline
    python demo_helix.py model --phase drift

Standard library plus the astra_runtime SDK in this repository; nothing to install.
"""
import argparse
import json
import math
import os
import random
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
rng = random.Random(5)


def need_env():
    url, key = os.environ.get("ASTRA_URL", "").rstrip("/"), os.environ.get("ASTRA_KEY", "")
    if not (url and key):
        sys.exit("Set ASTRA_URL (for example http://localhost:5173) and ASTRA_KEY (a collector key from Users -> API keys).")
    return url, key


def http(method, path, body=None):
    url, key = need_env()
    req = urllib.request.Request(url + path, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach {url}: {e.reason}")


# ── the agent ───────────────────────────────────────────────────────────────

def contract(agent):
    code, s = http("GET", f"/api/runtime/contract/{agent}")
    if code != 200:
        sys.exit(f"HTTP {code}: {s}")
    return s


def show_contract(agent):
    s = contract(agent)
    if s["state"] != "contract":
        sys.exit(f"{agent!r}: {s['state']}. It needs an active contract: open it in the Agent studio and ratify it first (the walkthrough, step 2).")
    a = s["allowed"]
    print(f"{agent} is under contract v{s['version']}. It may:")
    print("  call tools:        ", ", ".join(f"{t['name']} ({'writes' if t['write'] else 'reads'})" for t in a["tools"]) or "none")
    print("  connect to MCP:    ", ", ".join(m["name"] for m in a["mcp_servers"]) or "none")
    print("  hand work to:      ", ", ".join(a["delegates_to"]) or "none")
    print("  use data stores:   ", ", ".join(a["data"]) or "none")
    print("  long-term memory:  ", "yes" if a["long_term_memory"] else "no")
    return s


def normal_events(allowed, n):
    pool = [{"type": "tool_call", "name": t["name"], "write": t["write"]} for t in allowed["tools"]]
    pool += [{"type": "data_access", "name": d} for d in allowed["data"]]
    pool += [{"type": "mcp_connect", "name": m["name"], "signed": m["signed"]} for m in allowed["mcp_servers"]]
    pool += [{"type": "delegation", "name": d} for d in allowed["delegates_to"]]
    if not pool:
        sys.exit("The contract allows no tool, data store, server or handoff, so there is no normal behaviour to replay. Add some in the Agent studio and ratify again.")
    return [dict(rng.choice(pool)) for _ in range(n)]


def drift_events(allowed):
    have_tools = {t["name"] for t in allowed["tools"]}
    have_data, have_deleg, have_mcp = set(allowed["data"]), set(allowed["delegates_to"]), {m["name"] for m in allowed["mcp_servers"]}
    out = []
    for name, write in (("payments.transfer.execute", True), ("email.send.external", True), ("web.browse.any", False)):
        if name not in have_tools:
            out.append({"type": "tool_call", "name": name, "write": write})
    if "mcp://partner-ftp" not in have_mcp:
        out.append({"type": "mcp_connect", "name": "mcp://partner-ftp", "signed": False})
    for d in ("payments-agent", "claims-agent"):
        if d not in have_deleg:
            out.append({"type": "delegation", "name": d})
            break
    for d in ("Freight invoices", "Support tickets"):
        if d not in have_data:
            out.append({"type": "data_access", "name": d})
    if not allowed["long_term_memory"]:
        out.append({"type": "memory_write", "scope": "long_term"})
    return out


def label(e):
    return f"{e['type']:<12} {e.get('name') or e.get('scope', '')}" + (" (write)" if e.get("write") else "")


def send(agent, events):
    code, r = http("POST", "/api/runtime/events", {"agent": agent, "events": events, "discover": False})
    if code != 202:
        sys.exit(f"ASTRA answered HTTP {code}: {r}")
    for e, res in zip(events, r["results"]):
        mark = {"CONFORMING": "ok       ", "DIVERGENT": "DIVERGENT"}.get(res["verdict"], res["verdict"])
        print(f"  {mark}  {label(e)}" + (f"   -> finding {res['finding_key']}" if res.get("finding_key") else ""))
    return r


def run_agent(a):
    s = show_contract(a.agent)
    allowed = s["allowed"]
    print()
    n = a.n or (30 if a.phase == "normal" else 12)
    events = normal_events(allowed, n)
    if a.phase == "drift":
        events = events[: max(4, n // 2)] + drift_events(allowed)
        rng.shuffle(events)
    print(f"Sending {len(events)} events as {a.agent} ({a.phase}):")
    tot = {"accepted": 0, "divergent": 0, "findings": set(), "drift": None}
    for i in range(0, len(events), 10):
        r = send(a.agent, events[i:i + 10])
        tot["accepted"] += r["accepted"]
        tot["divergent"] += r["divergent"]
        tot["findings"].update(r["findings"])
        tot["drift"] = r["drift_item"] or tot["drift"]
        time.sleep(a.pause)
    print(f"\nASTRA accepted {tot['accepted']} events; {tot['divergent']} diverged from the contract.")
    if tot["findings"]:
        print("New findings:", ", ".join(sorted(tot["findings"])), " (AI Agents -> Findings)")
    if tot["drift"]:
        print("A runtime drift item is waiting for compliance (AI Agents -> Drift review).")
    if a.phase == "normal":
        print("Nothing outside the contract: look at AI Agents -> Live runtime, where the agent now shows as live.")


# ── the model ───────────────────────────────────────────────────────────────

FORECAST_RECORD = {"inputs": {"temperature": 18.0, "price": 20.0, "promo": False, "region": "north", "sku": "sku-7"}, "output": 120.5}
FORECAST_HELP = ("Name the monitor exactly: demand-forecast-model. 'What the model does': Predicts a number. Set temperature to a valid range of -30 to 50 and price to a minimum of 0; "
                 "make region and sku categories and promo yes/no; the output field is 'units' (a number).")


def forecast(drift):
    t = rng.gauss(29 if drift else 18, 6)
    p = max(0.5, rng.gauss(27 if drift else 20, 2))
    promo = rng.random() < (0.5 if drift else 0.2)
    units = max(0.0, 120 - 3.2 * p + 1.4 * t + (25 if promo else 0))
    region = rng.choices(["north", "south", "east", "west"], [0.1, 0.2, 0.3, 0.4] if drift else [0.3, 0.3, 0.2, 0.2])[0]
    if drift and rng.random() < 0.03:
        t = rng.choice([75.0, 90.0, -45.0])                      # a failing sensor
    return {"inputs": {"temperature": t, "price": p, "promo": promo, "region": region, "sku": f"sku-{rng.randrange(40)}"}, "output": round(units + rng.gauss(0, 4), 2),
            "label": round(units + rng.gauss(0, 14 if drift else 4), 2) if rng.random() < 0.3 else None, "latency_ms": abs(rng.gauss(45, 10)), "error": rng.random() < 0.002}


def run_model(a):
    from astra_runtime import ModelMonitor
    name = a.name or "demand-forecast-model"
    mon = ModelMonitor(name, on_error=lambda m: print("ASTRA client:", m, file=sys.stderr))
    if mon.disabled_reason:
        sys.exit(f"Not sending anything: {mon.disabled_reason}")
    n = a.n or (1500 if a.phase == "normal" else 800)
    for _ in range(n):
        r = forecast(a.phase == "drift")
        mon.log(inputs=r["inputs"], output=r["output"], label=r["label"], latency_ms=r["latency_ms"], error=r["error"])
    ok = mon.flush(timeout=60)
    print(f"{name}: {n} records ({a.phase}) sent={mon.sent} dropped={mon.dropped} rejected={mon.rejected}" + ("" if ok else "  (some not delivered yet)"))
    if a.phase == "normal":
        print("The first 1,000 records are the baseline. Open AI Models -> Runtime: the status shows within about 30 seconds.")
    else:
        print("Open AI Models -> Runtime and Incidents: drift on temperature, price and region, a bigger error, and values out of range.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=["contract", "agent", "model"])
    ap.add_argument("--phase", choices=["normal", "drift"], default="normal")
    ap.add_argument("--agent", default="customs-agent", help="an agent with a ratified contract")
    ap.add_argument("--name", default=None, help="the model monitor's name (default demand-forecast-model)")
    ap.add_argument("-n", type=int, default=None, help="how many events or records")
    ap.add_argument("--pause", type=float, default=0.4, help="seconds between agent batches, so it can be watched live")
    ap.add_argument("--show-record", action="store_true", help="for the model: print the example record for 'Suggest the fields', then stop")
    a = ap.parse_args()
    if a.what == "model" and a.show_record:
        print(json.dumps(FORECAST_RECORD, indent=2))
        print("\n" + FORECAST_HELP)
        return
    if a.what == "contract":
        show_contract(a.agent)
    elif a.what == "agent":
        run_agent(a)
    else:
        run_model(a)


if __name__ == "__main__":
    main()
