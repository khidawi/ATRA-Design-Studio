"""
Prepares the Helix Logistics demo on a running ASTRA server: takes customs-agent from "just uploaded" to "signed", with the two-person rule honoured by two real accounts.
Standard library only; it talks to the server over HTTP.

    1. Upload examples/company-helix-logistics.json on the Organisation page (this script does not do that).
    2. Have two accounts: an administrator and a compliance user. Their passwords are read from the environment or asked for; they are never printed.
         PowerShell:   $env:ASTRA_ADMIN_EMAIL="..."; $env:ASTRA_ADMIN_PASSWORD="..."; $env:ASTRA_COMPLIANCE_EMAIL="..."; $env:ASTRA_COMPLIANCE_PASSWORD="..."
    3. Look first (changes nothing):      python prepare_demo.py --url http://localhost:5173
       Then do it:                        python prepare_demo.py --url http://localhost:5173 --apply

What it does, skipping whatever is already done:
    the administrator proposes the Operations tolerance and the Shipment records impact tier, the compliance user ratifies them (a different person, as the platform requires);
    it makes the agent's design from the organisation if there is none, and gives it a read-only tool and an owner email (a signed contract needs both);
    it runs the Probe, and only goes on if the Probe passes and the assessment is APPROVED;
    the administrator records the assessment, the compliance user accepts it as the baseline and signs, and the signature is verified.

The values below are DEMO values. The tool is read-only on a store the agent already reads; the owner email is on the reserved .example domain, so it reaches nobody.
Pass --owner-email to use a real address. Run it only on a stack where you are happy to add these records: --apply writes risk values, a design change, an assessment,
a baseline and a signed contract, and none of them can be deleted. Exit code 0 if the agent ends up signed and verified, 1 if a step failed, 2 if it cannot start.
"""
import argparse
import getpass
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

CSRF = {"x-astra-csrf": "1"}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Stop(Exception):
    pass


class Person:
    def __init__(self, base: str, label: str) -> None:
        self.base, self.label = base, label
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.name = self.role = self.email = ""

    def call(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json", **CSRF})
        try:
            with self.opener.open(req, timeout=60) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw
        except urllib.error.URLError as e:
            raise Stop("Cannot reach %s: %s" % (self.base, e.reason))

    def ok(self, method: str, path: str, body=None, what: str = ""):
        code, data = self.call(method, path, body)
        if code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else data
            raise Stop("%s failed (HTTP %s, %s): %s" % (what or method + " " + path, code, self.label, str(detail)[:400]))
        return data

    def sign_in(self, email: str, password: str) -> None:
        code, data = self.call("POST", "/api/auth/login", {"email": email, "password": password})
        if code != 200:
            raise Stop("The %s account could not sign in (HTTP %s). Check the email and password." % (self.label, code))
        self.email, self.name, self.role = email, data["user"]["full_name"], data["user"]["role"]


def secret(name: str, prompt: str, hidden: bool) -> str:
    v = os.environ.get(name, "")
    if v:
        return v
    if not sys.stdin.isatty():
        raise Stop("Set %s (or run this in a terminal to be asked)." % name)
    return getpass.getpass(prompt) if hidden else input(prompt)


def say(kind: str, text: str) -> None:
    print("%-6s %s" % (kind, text))


def pick(rows, key, value):
    return next((r for r in rows if r.get(key) == value), None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="address of the ASTRA server, for example http://localhost:5173")
    ap.add_argument("--apply", action="store_true", help="make the changes; without it the script only looks")
    ap.add_argument("--allow-remote", action="store_true", help="allow a server that is not on this computer")
    ap.add_argument("--agent", default="customs-agent")
    ap.add_argument("--agent-id", default="AG-CUSTOMS", help="the agent's id in the organisation file")
    ap.add_argument("--department", default="D-OPS", help="the department whose tolerance is declared")
    ap.add_argument("--tolerance", type=int, default=2)
    ap.add_argument("--asset", default="DS-SHIP", help="the data store whose impact tier is declared")
    ap.add_argument("--tier", type=int, default=2)
    ap.add_argument("--tool", default="shipment-lookup", help="the read-only tool given to the agent")
    ap.add_argument("--owner-email", default="elena.rossi@helix-logistics.example")
    a = ap.parse_args()

    host = urllib.parse.urlparse(a.url).hostname or ""
    if host not in ("localhost", "127.0.0.1", "::1") and not a.allow_remote:
        print("%s is not on this computer. Pass --allow-remote if you really mean it." % a.url, file=sys.stderr)
        return 2
    if not EMAIL.match(a.owner_email):
        print("--owner-email must be an email address.", file=sys.stderr)
        return 2
    base = a.url.rstrip("/")
    try:
        return run(a, base)
    except Stop as e:
        print("STOP   " + str(e), file=sys.stderr)
        return 1


def run(a, base: str) -> int:
    admin, comp = Person(base, "administrator"), Person(base, "compliance")
    admin.sign_in(secret("ASTRA_ADMIN_EMAIL", "Administrator email: ", False), secret("ASTRA_ADMIN_PASSWORD", "Administrator password: ", True))
    comp.sign_in(secret("ASTRA_COMPLIANCE_EMAIL", "Compliance email: ", False), secret("ASTRA_COMPLIANCE_PASSWORD", "Compliance password: ", True))
    if admin.role not in ("admin", "compliance") or comp.role not in ("admin", "compliance"):
        raise Stop("Both accounts need the administrator or compliance role (got %s and %s)." % (admin.role, comp.role))
    if admin.email.lower() == comp.email.lower():
        raise Stop("The two accounts must be different people: the platform refuses one person on both sides of a sign-off.")
    say("who", "%s (%s) and %s (%s)" % (admin.name, admin.role, comp.name, comp.role))
    say("mode", "APPLY: changes will be made" if a.apply else "LOOK ONLY: nothing is changed (add --apply to make the changes)")

    # already signed and current? then there is nothing to do
    code, dos = admin.call("GET", "/api/astra/assurance/agent/" + urllib.parse.quote(a.agent))
    if code == 200 and dos["contract"]["valid_now"] and not any("design has changed" in " ".join(g["why"]) for g in dos["gaps"]):
        say("ok", "%s already has a valid signed contract for its current design (%s). Nothing to do." % (a.agent, dos["contract"]["id"]))
        return 0

    # 1 and 2: risk values, proposed by one person and ratified by the other
    ratify_risk(a, admin, comp, "tolerance", a.department, a.tolerance)
    ratify_risk(a, admin, comp, "asset", a.asset, a.tier)

    # 3: the design
    key = ensure_design(a, admin)
    if key is None:
        say("would", "run the Probe, record, accept the baseline, sign and verify (after the design exists)")
        return 0

    # 4: the Probe, then the assessment must be APPROVED
    adm = admin.ok("GET", "/api/astra/probe/admission?design_key=" + key, what="read Probe admission")
    if adm["admit"]:
        say("ok", "the newest Probe run is of this design and passed")
    elif not a.apply:
        say("would", "run the Probe on the design as it is now")
    else:
        run_ = admin.ok("POST", "/api/astra/probe/run", {"design_key": key}, "run the Probe")
        s = run_["summary"]
        say("done", "Probe: %s of %s applicable scenarios caught, %s missed" % (s["caught"], s["applicable"], s["missed"]))
        adm = admin.ok("GET", "/api/astra/probe/admission?design_key=" + key, what="read Probe admission")
        if not adm["admit"]:
            raise Stop("The Probe does not admit this design: " + "; ".join(adm["reasons"]))
    asm = admin.ok("GET", "/api/agents/designs/%s/assessment" % key, what="read the assessment")
    if asm["verdict"] != "APPROVED":
        for d in asm["departments"]:
            say("note", "%s: tolerance %s, highest open tier %s, %s" % (d["department"], d["tolerance"], d["highest_open_tier"], d["verdict"]))
        for s_ in asm.get("suggestions", [])[:6]:
            say("note", s_["label"] + ": " + s_["why"][:140])
        if a.apply:
            raise Stop("The assessment is %s, not APPROVED, so it cannot be recorded as a baseline." % asm["verdict"])
        say("would", "stop here: the assessment is %s" % asm["verdict"])
        return 0
    say("ok", "the assessment is APPROVED")
    if not a.apply:
        say("would", "%s records the assessment, %s accepts it as the baseline and signs, then the signature is verified" % (admin.name, comp.name))
        return 0

    # 5: record (one person), baseline and sign (the other), verify
    rec = admin.ok("POST", "/api/agents/designs/%s/assessments" % key, {}, "record the assessment")
    say("done", "%s recorded the assessment (%s)" % (admin.name, rec["id"][:8]))
    comp.ok("POST", "/api/agents/designs/%s/baseline" % key, {}, "accept the baseline")
    say("done", "%s accepted it as the baseline" % comp.name)
    sg = comp.ok("POST", "/api/agents/designs/%s/sign" % key, {"valid_days": 365}, "sign the contract")
    say("done", "%s signed contract %s with key %s, valid until %s" % (comp.name, sg["id"], sg["key_id"], sg["expires_at"]))
    v = comp.ok("GET", "/api/astra/contracts/%s/verify" % sg["id"], what="verify the signature")
    if not v["valid"]:
        raise Stop("The signature does not verify: " + "; ".join(v["reasons"]))
    say("ok", "the signature verifies (status %s)" % v["status"])
    pr = sg.get("probe") or {}
    if pr.get("missed") or pr.get("error"):
        say("note", "the Probe run made at signing reports a problem: %s" % json.dumps(pr)[:200])
    print("\nNext: create a collector key (Users, API keys) and run the runtime demo, see sdk/python/examples/demo_helix.py.")
    return 0


def ratify_risk(a, admin: Person, comp: Person, kind: str, ext: str, value: int) -> None:
    """Propose with the administrator, ratify with the compliance user; if someone else already proposed the same value, the other of the two ratifies it."""
    field = "tolerance" if kind == "tolerance" else "tier"
    label = ("%s tolerance %s" if kind == "tolerance" else "%s impact tier %s") % (ext, value)
    risk = admin.ok("GET", "/api/risk", what="read the risk values")
    row = pick(risk["departments"], "department_ext", ext) if kind == "tolerance" else (pick(risk["assets"], "ext", ext) or pick(risk["assets"], "asset_ext", ext))
    if row is None:
        raise Stop("%s is not in the organisation. Upload the Helix file first." % ext)
    if kind == "tolerance":
        in_force = bool(row.get("declared")) and row.get("effective_tolerance") == value
    else:
        in_force = bool(row.get("ratified")) and row.get("tier") == value
    if in_force:
        say("ok", label + " is already ratified")
        return
    pending = row.get("pending")
    if pending is not None and pending.get(field) != value:
        raise Stop("%s has a pending proposal of %s by %s. Decide that one first." % (ext, pending.get(field), pending.get("proposed_by")))
    if not a.apply:
        say("would", ("%s proposes and %s ratifies " if pending is None else "%s ratifies the pending proposal ") % ((admin.name, comp.name) if pending is None else (comp.name,)) + label)
        return
    who_ratifies = comp
    if pending is None:
        body = {"department_ext": ext, "tolerance": value, "rationale": "Demo preparation: Helix Logistics. Ratified by a second person."} if kind == "tolerance" else \
               {"asset_ext": ext, "department_ext": a.department, "tier": value, "rationale": "Demo preparation: Helix Logistics. Ratified by a second person."}
        pending = admin.ok("POST", "/api/risk/tolerances" if kind == "tolerance" else "/api/risk/assets", body, "propose " + label)
        say("done", "%s proposed %s" % (admin.name, label))
    elif pending.get("proposed_by") == comp.name:
        who_ratifies = admin
    who_ratifies.ok("POST", "/api/risk/proposals/%s/%s/ratify" % (kind, pending["id"]), {"note": "Ratified for the Helix demo"}, "ratify " + label)
    say("done", "%s ratified %s" % (who_ratifies.name, label))


def ensure_design(a, admin: Person):
    agents = admin.ok("GET", "/api/agents", what="list the agents")
    row = pick(agents, "name", a.agent)
    if row is None:
        raise Stop("%s is not in the organisation. Upload the Helix file first." % a.agent)
    # the platform links an organisation agent to a design only at the older ratify step, so look for the agent's design by name (newest first)
    mine = [d for d in admin.ok("GET", "/api/designs?subject=AGENT", what="list the agent designs") if d.get("name") == a.agent]
    key = mine[0]["design_key"] if mine else row.get("design_key")
    if len(mine) > 1:
        say("note", "%d designs are named %s; using the newest (%s)" % (len(mine), a.agent, key))
    if key is None:
        if not a.apply:
            say("would", "make %s's design from the organisation, with a read-only tool %s and the owner email" % (a.agent, a.tool))
            return None
        seed = admin.ok("GET", "/api/company/systems/%s/agent-seed" % urllib.parse.quote(a.agent_id), what="read the agent from the organisation")
        doc = design_from_seed(seed, a)
        made = admin.ok("POST", "/api/designs", {"name": seed["name"], "domain": "OWASP_AGENTIC", "subject": "AGENT", "document": doc}, "create the design")
        say("done", "made the design from the organisation (%s)" % made["design_key"])
        return made["design_key"]
    cur = admin.ok("GET", "/api/designs/" + key, what="read the design")
    doc = cur["document"]
    prim = next((n for n in doc["nodes"] if n.get("primary")), None)
    if prim is None:
        raise Stop("The design has no primary agent.")
    needs_owner = not EMAIL.match(str((prim.get("p") or {}).get("owner", "")))
    needs_tool = not any(n.get("type") == "tool" for n in doc["nodes"])
    if not (needs_owner or needs_tool):
        say("ok", "the design already has a tool and an owner email")
        return key
    todo = ", ".join(x for x, f in (("an owner email", needs_owner), ("the read-only tool " + a.tool, needs_tool)) if f)
    if not a.apply:
        say("would", "add " + todo + " to the design (a new version)")
        return key
    if needs_owner:
        prim.setdefault("p", {})["owner"] = a.owner_email
    if needs_tool:
        add_tool(doc, prim["id"], a.tool)
    out = admin.ok("PUT", "/api/designs/" + key, {"name": cur["name"], "domain": cur["domain"], "subject": cur.get("subject"), "document": doc, "version": cur["version"]}, "save the design")
    say("done", "added %s: design is now version %s" % (todo, out["version"]))
    return key


def add_tool(doc, prim_id: str, name: str) -> None:
    n = int(doc.get("n") or 100)
    doc["n"] = n + 1
    doc["nodes"].append({"id": "n%d" % n, "type": "tool", "name": name, "p": {"write": False}})
    doc["edges"].append({"from": prim_id, "to": "n%d" % n, "label": "uses"})


def design_from_seed(seed, a) -> dict:
    """The design the studio makes for 'Start from the organisation', plus the two guardrails its Fix tab suggests, a read-only tool and the owner email."""
    nodes = [{"id": "a1", "type": "agent", "name": seed["name"], "p": {"owner": a.owner_email, "auto": "approval"}, "primary": True}]
    edges = []
    doc = {"nodes": nodes, "edges": edges, "n": 100, "profile": "payments", "req": {}, "ratified": False,
           "org": {"id": seed["id"], "name": seed["name"], "department": seed.get("department")}}

    def add(kind, name, p=None, label=None, direction="out"):
        nid = "n%d" % doc["n"]
        doc["n"] += 1
        nodes.append({"id": nid, "type": kind, "name": name, "p": p or {}})
        edges.append({"from": "a1", "to": nid, "label": label} if direction == "out" else {"from": nid, "to": "a1", "label": label})

    for g in seed.get("goals", []):
        add("goal", g, label="pursues")
    for h in seed.get("humans", []):
        add("human", h["name"], label="requests", direction="in")
    for i in seed.get("inputs", []):
        add("input", i["name"], {"untrusted": bool(i.get("cross_department"))}, "feeds", "in")
    for x in seed.get("externals", []):
        add("external", x["name"], label="calls")
    for ap_ in seed.get("approvals", []):
        add("approval", ap_["name"], label="gates", direction="in")
    for d in seed.get("delegates", []):
        add("agent", d["name"], {"owner": d.get("owner") or "", "auto": "approval"}, "delegates")
    for d in seed.get("data", []):
        add("data", d["name"], label="writes" if d.get("write") else "reads")
    add("guardrail", "rate-limit-20-per-hour", {"kind": "rate"}, "limits", "in")
    add("guardrail", "ai-disclosure", {"kind": "disclosure"}, "limits", "in")
    add_tool(doc, "a1", a.tool)
    return doc


if __name__ == "__main__":
    sys.exit(main())
