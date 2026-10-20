"""
Sets up a fresh ASTRA server for a shared test: creates the administrator, loads a demo organisation (AI agents and AI models), gives the models production
monitors with a normal period and then a period that has drifted, and creates accounts for the people who will test it. Standard library only; it talks to the
running server over HTTP, so it works against any address.

    python seed_demo.py --url http://localhost:8080 --admin-email you@example.org --admin-name "Your Name" \\
        --company ../examples/company-helix-logistics.json --company ../examples/company-lamad-llc.json \\
        --tester "Ada Lovelace <ada@example.org>" --tester "Alan Turing <alan@example.org>"

IMPORTANT: run this as soon as the server is up and before anyone else can reach it. The first person to open a new ASTRA server is offered the chance to create the
administrator, and this script is how you make sure that is you. If an administrator already exists, give their password with --admin-password.

The administrator password is read from ASTRA_ADMIN_PASSWORD or asked for; testers get a random password printed once at the end. Testers are given the engineer
role (they can design, monitor and edit; they cannot sign off or administer). Use --tester-role auditor for read-only accounts.

It is safe to run again: what already exists is skipped.
"""
import argparse
import getpass
import http.cookiejar
import json
import math
import os
import random
import re
import secrets
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

rng = random.Random(2026)


class Server:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method: str, path: str, body=None, ok=(200, 201, 204)):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={"Content-Type": "application/json", "x-astra-csrf": "1"})
        try:
            with self.opener.open(req, timeout=120) as r:
                raw = r.read().decode("utf-8")
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                detail = json.loads(raw).get("detail", raw)
            except Exception:
                detail = raw
            return e.code, detail
        except urllib.error.URLError as e:
            sys.exit(f"Cannot reach {self.url}: {e.reason}. Is the server up (docker compose ps)?")


# ── demo traffic: what a model looks like when it is normal, and when it has drifted ────────────────────────────

def _records(n, make, start, end):
    span = (end - start).total_seconds()
    return [{**make(i), "at": (start + timedelta(seconds=span * i / max(1, n))).isoformat()} for i in range(n)]


def forecast(drift):
    def make(i):
        t, p = rng.gauss(29 if drift else 18, 6), max(0.5, rng.gauss(27 if drift else 20, 2))
        promo = rng.random() < (0.5 if drift else 0.2)
        units = max(0, 120 - 3.2 * p + 1.4 * t + (25 if promo else 0))
        return {"inputs": {"temperature": t, "price": p, "promo": promo, "region": rng.choices(["north", "south", "east", "west"], [0.1, 0.2, 0.3, 0.4] if drift else [0.3, 0.3, 0.2, 0.2])[0], "sku": f"sku-{rng.randrange(40)}"},
                "output": round(units + rng.gauss(0, 4), 2), "label": round(units + rng.gauss(0, 14 if drift else 4), 2), "latency_ms": abs(rng.gauss(45, 10)), "error": rng.random() < 0.002}
    return make


def flow(drift):
    def make(i):
        p_true, wc, gor = rng.gauss(85, 8), (min(0.9, max(0, rng.gauss(0.38, 0.07))) if drift else max(0, rng.gauss(0.12, 0.03))), rng.gauss(210 if drift else 140, 20)
        p = p_true * 1.09 + rng.gauss(0, 3) if drift else p_true
        if drift and rng.random() < 0.03:
            p = rng.choice([0.0, 450.0, -3.0])
        choke, t = rng.gauss(24, 3), rng.gauss(62, 4)
        f = lambda pp, c, g, w: max(0.0, 3.2 * c ** 1.15 * math.sqrt(max(pp, 1.0)) / 10 * (1 - w) * (1 - 0.0008 * (g - 100)))   # noqa: E731
        truth, est = f(p_true, choke, gor, wc), f(max(p, 1.0), choke, 140 if drift else gor, 0.12 if drift else wc) * (1 + rng.gauss(0, 0.04))
        r = {"inputs": {"well": f"W-{rng.randrange(1, 13):02d}", "wellhead_pressure_bar": p, "wellhead_temp_c": t, "choke_size_mm": choke, "gas_oil_ratio": gor, "water_cut": wc}, "output": round(est, 2), "latency_ms": abs(rng.gauss(35, 8))}
        if rng.random() < 0.08:
            r["label"] = round(truth, 2)
        return r
    return make


def health(drift):
    def make(i):
        bad = rng.random() < (0.18 if drift else 0.05)
        noise, alarms, pf = (rng.gauss(1.4, 0.3), max(1, round(rng.gauss(5, 2))), abs(rng.gauss(0.45, 0.15))) if bad else (rng.gauss(0.4, 0.1), max(0, round(rng.gauss(1, 1))), abs(rng.gauss(0.08, 0.04)))
        called = bad and rng.random() < (0.45 if drift else 0.9)
        out = "faulty" if called else ("degraded" if (noise > 0.7 or pf > 0.2) and rng.random() < 0.8 else "healthy")
        r = {"inputs": {"meter_type": rng.choices(["coriolis", "ultrasonic", "turbine", "orifice"], [0.4, 0.25, 0.2, 0.15])[0], "dp_noise": noise, "alarm_count": alarms, "proving_factor_deviation_pct": pf, "calibration_age_days": max(0, rng.gauss(420 if drift else 150, 80))},
             "output": out, "confidence": rng.uniform(0.5, 0.8) if drift else rng.uniform(0.7, 0.95), "latency_ms": abs(rng.gauss(25, 6))}
        if rng.random() < 0.3:
            r["label"] = "faulty" if bad else out
        return r
    return make


def llm(drift):
    def make(i):
        new = drift and rng.random() < 0.7
        flags = {}
        roll = rng.random()
        if drift and roll < 0.04:
            flags["pii_in_prompt"] = True
        elif drift and roll < 0.045:
            flags["secret_in_prompt"] = True
        return {"inputs": {"topic": rng.choice(["refund", "delivery", "account"])}, "output": "refusal" if (new and rng.random() < 0.4) else "answer", "confidence": rng.gauss(0.6 if new else 0.85, 0.05),
                "latency_ms": abs(rng.gauss(1900 if new else 800, 250)), "model_version": "gpt-demo-2026-05-02" if new else "gpt-demo-2026-01-15", "error": rng.random() < (0.07 if new else 0.01), **({"flags": flags} if flags else {})}
    return make


PROFILES = {
    "demand-forecast-model": dict(make=forecast, task="regression", features=[{"name": "temperature", "kind": "numeric", "min": -30, "max": 50}, {"name": "price", "kind": "numeric", "min": 0}, {"name": "promo", "kind": "boolean"}, {"name": "region", "kind": "categorical"}, {"name": "sku", "kind": "categorical"}], output={"name": "units", "kind": "numeric"}, people=False),
    "lamad-virtual-flow-meter": dict(make=flow, task="regression", features=[{"name": "well", "kind": "categorical"}, {"name": "wellhead_pressure_bar", "kind": "numeric", "min": 5, "max": 400}, {"name": "wellhead_temp_c", "kind": "numeric", "min": 10, "max": 150}, {"name": "choke_size_mm", "kind": "numeric", "min": 0, "max": 80}, {"name": "gas_oil_ratio", "kind": "numeric", "min": 0}, {"name": "water_cut", "kind": "numeric", "min": 0, "max": 1}], output={"name": "oil_rate_m3d", "kind": "numeric"}, people=True),
    "lamad-meter-health": dict(make=health, task="classification", features=[{"name": "meter_type", "kind": "categorical"}, {"name": "dp_noise", "kind": "numeric", "min": 0}, {"name": "alarm_count", "kind": "numeric", "min": 0}, {"name": "proving_factor_deviation_pct", "kind": "numeric", "min": 0}, {"name": "calibration_age_days", "kind": "numeric", "min": 0}], output={"name": "status", "kind": "categorical"}, people=True),
    "report-drafting-assistant": dict(make=llm, task="generative", features=[{"name": "topic", "kind": "categorical"}], output={"name": "reply", "kind": "categorical"}, people=True),
}


def decisions(n, drift, start, end):
    span, out = (end - start).total_seconds(), []
    for i in range(n):
        wrong = rng.random() < 0.1
        analyst = i % 2 == 0
        accept = (0.99 if analyst else (0.4 if wrong else 0.75)) if drift else (0.25 if wrong else 0.78)
        out.append({"role": "allocation analyst" if analyst else "metering engineer", "action": "accepted" if rng.random() < accept else rng.choice(["edited", "overridden"]),
                    "review_seconds": abs(rng.gauss(2.5, 0.6)) if (drift and analyst) else abs(rng.gauss(35, 10)), "model_correct": not wrong, "confidence_shown": not drift,
                    "at": (start + timedelta(seconds=span * i / max(1, n))).isoformat()})
    return out


def post_batches(srv, path, field, items):
    for i in range(0, len(items), 500):
        code, body = srv.call("POST", path, {field: items[i:i + 500]})
        if code != 200:
            print(f"    ! {path}: HTTP {code} {str(body)[:160]}")
            return False
    return True


def seed_monitor(srv, design, prof):
    name = design["name"]
    code, body = srv.call("POST", "/api/model-monitor", {"name": name, "design_key": design["design_key"], "task": prof["task"], "features": prof["features"], "output": prof["output"], "baseline_target": 1000})
    if code == 409:
        print(f"  = {name}: a monitor already exists, skipped")
        return
    if code != 201:
        print(f"  ! {name}: could not create a monitor (HTTP {code}: {str(body)[:160]})")
        return
    key, now = body["key"], datetime.now(timezone.utc)
    ok = post_batches(srv, f"/api/model-monitor/{key}/records", "records", _records(1000, prof["make"](False), now - timedelta(hours=32), now - timedelta(hours=10)))
    ok = ok and post_batches(srv, f"/api/model-monitor/{key}/records", "records", _records(500, prof["make"](False), now - timedelta(hours=9), now - timedelta(hours=3)))
    ok = ok and post_batches(srv, f"/api/model-monitor/{key}/records", "records", _records(700, prof["make"](True), now - timedelta(hours=2), now - timedelta(minutes=2)))
    if ok and prof["people"]:
        post_batches(srv, f"/api/model-monitor/{key}/decisions", "decisions", decisions(120, False, now - timedelta(hours=30), now - timedelta(hours=4)) + decisions(260, True, now - timedelta(hours=3), now - timedelta(minutes=5)))
    srv.call("GET", f"/api/model-monitor/{key}")                       # evaluate once so the status and incidents are in place
    print(f"  + {name}: monitor created with a normal period and a drifted one")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8080", help="where the studio is reachable")
    ap.add_argument("--admin-email", required=True)
    ap.add_argument("--admin-name", default="ASTRA administrator")
    ap.add_argument("--admin-password", default=os.environ.get("ASTRA_ADMIN_PASSWORD"))
    ap.add_argument("--company", action="append", default=[], help="an organisation file to import (repeat for several); default: the Helix Logistics example")
    ap.add_argument("--tester", action="append", default=[], help='a person who will test it: "Name <email>" (repeat)')
    ap.add_argument("--tester-role", default="engineer", choices=["engineer", "auditor", "compliance"])
    ap.add_argument("--no-traffic", action="store_true", help="do not create the demo monitors")
    a = ap.parse_args()
    pw = a.admin_password or getpass.getpass("Administrator password (at least 10 characters): ")
    srv = Server(a.url)

    code, st = srv.call("GET", "/api/auth/status")
    if code != 200:
        sys.exit(f"The server answered HTTP {code} on /api/auth/status: {st}")
    if st["needs_bootstrap"]:
        code, body = srv.call("POST", "/api/auth/bootstrap", {"email": a.admin_email, "full_name": a.admin_name, "password": pw})
        if code != 201:
            sys.exit(f"Could not create the administrator: {body}")
        print(f"Administrator created: {a.admin_email}")
    else:
        code, body = srv.call("POST", "/api/auth/login", {"email": a.admin_email, "password": pw})
        if code != 200:
            sys.exit(f"An administrator already exists and these credentials were refused ({body}).")
        print(f"Signed in as {a.admin_email}")

    here = os.path.dirname(os.path.abspath(__file__))
    files = a.company or [os.path.join(here, "..", "examples", "company-helix-logistics.json")]
    for f in files:
        with open(f, encoding="utf-8") as fh:
            code, body = srv.call("POST", "/api/company/import", {"content": fh.read(), "filename": os.path.basename(f)})
        if code != 200:
            print(f"  ! {os.path.basename(f)}: HTTP {code} {str(body)[:300]}")
            continue
        print(f"  + {os.path.basename(f)}: {body['created']} items created, {body['updated']} updated, {body['connections']} connections; agents {body.get('agents_created') or []}; models {body.get('models_created') or []}")

    if not a.no_traffic:
        code, designs = srv.call("GET", "/api/designs?subject=MODEL")
        for d in designs if code == 200 else []:
            if d["name"] in PROFILES:
                seed_monitor(srv, d, PROFILES[d["name"]])

    made = []
    for t in a.tester:
        m = re.match(r"^\s*(.+?)\s*<([^>]+)>\s*$", t)
        if not m:
            print(f'  ! "{t}" is not in the form "Name <email>"')
            continue
        pw_t = secrets.token_urlsafe(12)
        code, body = srv.call("POST", "/api/users", {"email": m.group(2), "full_name": m.group(1), "password": pw_t, "role": a.tester_role})
        if code == 201:
            made.append((m.group(1), m.group(2), pw_t))
        else:
            print(f"  = {m.group(2)}: {body if code != 409 else 'already has an account'}")
    if made:
        print("\nTester accounts (share each password with its owner privately, once; they can change it under their account):")
        for n, e, p in made:
            print(f"  {n:<24} {e:<34} {p}   [{a.tester_role}]")
    print(f"\nDone. Open {a.url}")


if __name__ == "__main__":
    main()
