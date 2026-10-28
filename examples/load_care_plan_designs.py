"""
Loads the two care-plan designs in care-plan-designs.json into a running ASTRA server as agent designs, so they can be opened in the Design studio and set side by side
under Compare designs. Standard library only.

    set ASTRA_URL=http://localhost:5173                 (PowerShell: $env:ASTRA_URL="http://localhost:5173")
    set ASTRA_EMAIL=you@example.org
    set ASTRA_PASSWORD=...                              (or you are asked for it)
    python load_care_plan_designs.py

The sign-offs in the bespoke design are recorded as the person signed in (ASTRA only accepts a sign-off from the signed-in person), so run it as someone who may
sign off: an administrator or a member of compliance. It is safe to run again: a design that already exists is left as it is. Nothing is ratified.
"""
import getpass
import http.cookiejar
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("ASTRA_URL", "http://localhost:5173").rstrip("/")
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Content-Type": "application/json", "x-astra-csrf": "1"})
    try:
        with opener.open(req, timeout=60) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def main():
    email = os.environ.get("ASTRA_EMAIL") or input("Email: ")
    password = os.environ.get("ASTRA_PASSWORD") or getpass.getpass("Password: ")
    code, _ = call("POST", "/api/auth/login", {"email": email, "password": password})
    if code != 200:
        sys.exit(f"Could not sign in ({code}).")
    code, me = call("GET", "/api/auth/me")
    name = me["user"]["full_name"]
    raw = (pathlib.Path(__file__).parent / "care-plan-designs.json").read_text(encoding="utf-8").replace("SIGNER", name)
    existing = {d["name"] for d in (call("GET", "/api/designs?subject=AGENT")[1] or [])}
    for d in json.loads(raw)["designs"]:
        if d["name"] in existing:
            print(f"  = {d['name']}: already there")
            continue
        code, out = call("POST", "/api/designs", {"name": d["name"], "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": d["document"]})
        print(("  + " if code == 201 else "  ! ") + d["name"] + ("" if code == 201 else f": {code} {str(out)[:200]}"))
    print("Open Compare designs in the AI Agents module to set them side by side.")


if __name__ == "__main__":
    main()
