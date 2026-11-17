"""
Exports what an independent assessor needs to review one agent, as a folder of files with a manifest of SHA-256 hashes. Read-only: it only issues GET requests.

    ASTRA_API_KEY=astra_... python pilot_export.py https://astra.example.org --agent refund-agent --pack my-pack-key --out pilot-export

Use an API key with the auditor role (Administration > API keys). The key is read from the environment and never written to the export.
Standard library only. Exit code 0 if everything was fetched and the checks the platform reports all passed, 1 otherwise (the export is still written, so the assessor sees what failed).

Written files: dossier.json, contract.json (the signed contract), contract_verify.json, probe_run.json, pack.json, pack_verify.json, audit_verify.json,
findings.json (when readable), README.txt, MANIFEST.json.
"""
import argparse
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def fetch(base, path, key, insecure):
    req = urllib.request.Request(base + path, headers={"x-api-key": key, "Accept": "application/json"}, method="GET")
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"detail": str(e)}
        return e.code, body


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", help="base URL of the ASTRA server")
    p.add_argument("--agent", required=True, help="agent key (the design key of the agent under contract)")
    p.add_argument("--pack", help="key of an Assurance pack to include and verify")
    p.add_argument("--out", default="pilot-export", help="folder to write (must not already contain files)")
    p.add_argument("--insecure", action="store_true", help="accept a certificate from a private authority")
    a = p.parse_args()
    key = os.environ.get("ASTRA_API_KEY", "")
    if not key:
        print("Set ASTRA_API_KEY to an auditor API key.", file=sys.stderr)
        return 2
    base = a.url.rstrip("/")
    if os.path.isdir(a.out) and os.listdir(a.out):
        print("%s is not empty; choose a new folder so an old export cannot be mixed with this one." % a.out, file=sys.stderr)
        return 2
    os.makedirs(a.out, exist_ok=True)

    problems, files = [], {}

    def save(name, data):
        raw = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        with open(os.path.join(a.out, name), "wb") as f:
            f.write(raw)
        files[name] = hashlib.sha256(raw).hexdigest()

    def get(path, name, required=True):
        code, body = fetch(base, path, key, a.insecure)
        if code != 200:
            if required:
                problems.append("%s: HTTP %s %s" % (path, code, body.get("detail", "") if isinstance(body, dict) else ""))
            print("FAIL %s  (HTTP %s)" % (path, code) if required else "skip %s  (HTTP %s)" % (path, code))
            return None
        save(name, body)
        print("ok   %s -> %s" % (path, name))
        return body

    dossier = get("/api/astra/assurance/agent/" + urllib.parse.quote(a.agent), "dossier.json")
    if dossier:
        cid = dossier["contract"]["id"]
        get("/api/astra/contracts/%s" % cid, "contract.json")
        v = get("/api/astra/contracts/%s/verify" % cid, "contract_verify.json")
        if v is not None and not v.get("ok", v.get("valid", False)):
            problems.append("the platform reports the contract does not verify: %s" % json.dumps(v)[:300])
        if dossier.get("probe"):
            get("/api/astra/probe/latest?design_key=" + urllib.parse.quote(dossier["contract"]["design_key"]), "probe_run.json", required=False)
        if not dossier["contract"].get("valid_now"):
            problems.append("the contract is not valid now: %s" % "; ".join(dossier["contract"].get("reasons") or []))
    if a.pack:
        get("/api/packs/" + urllib.parse.quote(a.pack), "pack.json")
        v = get("/api/packs/%s/verify" % urllib.parse.quote(a.pack), "pack_verify.json")
        if v is not None and not v.get("ok", v.get("valid", False)):
            problems.append("the platform reports the pack does not verify: %s" % json.dumps(v)[:300])
    v = get("/api/audit/verify", "audit_verify.json")
    if v is not None and not v.get("ok", v.get("valid", False)):
        problems.append("the audit log chain does not verify: %s" % json.dumps(v)[:300])
    get("/api/findings?agent_key=" + urllib.parse.quote(a.agent), "findings.json", required=False)

    readme = """ASTRA pilot export
Generated: %s
Server: %s
Agent: %s

Every file is listed in MANIFEST.json with its SHA-256. Recompute them first.

To check the signed contract without the platform: contract.json holds the signed bytes (the Appendix A document, its hash, its Ed25519 signature
and key id). Hash the document the way the platform does (canonical JSON, sorted keys, no extra spaces) and compare with the stated hash, then
verify the signature with the public key the organisation gives you for that key id (ASTRA_SIGNING_PUBLIC_KEYS). Change one character and it must fail.

dossier.json lists each claim with the record it stands on. Work through docs/pilot/REVIEWER-CHECKLIST.md.
%s
""" % (datetime.now(timezone.utc).isoformat(), base, a.agent,
       ("\nPROBLEMS FOUND DURING EXPORT:\n- " + "\n- ".join(problems)) if problems else "\nNo problems found during export.")
    with open(os.path.join(a.out, "README.txt"), "w", encoding="utf-8") as f:
        f.write(readme)
    files["README.txt"] = hashlib.sha256(readme.encode("utf-8")).hexdigest()
    with open(os.path.join(a.out, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "server": base, "agent": a.agent, "problems": problems, "sha256": files}, f, indent=2, sort_keys=True)
    print("\n%d files written to %s" % (len(files) + 1, a.out))
    for x in problems:
        print("PROBLEM " + x)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
