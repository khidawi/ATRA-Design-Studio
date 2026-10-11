"""
Turns an identity record (idp_providers.py) into the proposal the rest of the platform understands, and checks the identity's hygiene.

An identity says what an agent is *allowed* to do, not what it is built with: the permissions it holds become the agent's tools (each one marked
as able to write or only read), and what the identity cannot say (the framework, the goal, the data it reads, who approves its actions) is left
out rather than assumed. Credentials are only ever seen as dates: how old a secret is and when it expires, never its value.

Pure functions, no network: the same record always gives the same proposal and the same fingerprint, so a later scan can tell that a
permission was added (the change that matters most) from a record that merely refreshed.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from agent_import import WRITE_WORDS, _clean, _first_sentence, _manifest, agent_key
from idp_providers import Provider, PROVIDERS, parse_time

MAX_TOOLS = 40
SECRET_MAX_AGE_DAYS = 180
EXPIRY_WARN_DAYS = 30
WRITE_RX = re.compile(r"(write|manage|create|delete|update|send|modify|execute|invoke|import|impersonat|admin|full|\*)", re.I)
READ_RX = re.compile(r"(read|list|view|get|query|search|openid|profile|email|offline_access)", re.I)
PRIVILEGED_RX = re.compile(r"(readwrite\.all|\.manage$|rolemanagement|directory\.readwrite|application\.readwrite|approleassignment\.readwrite|policy\.readwrite|full_access|fullcontrol|"
                           r"impersonat|realm-admin|manage-realm|manage-users|manage-clients|\*|(^|[:.\-_])admin($|[:.\-_])|create:client|update:client|delete:client)", re.I)
BROAD_RX = re.compile(r"(\.all$|\*|^all$)", re.I)


def classify(name: str) -> Dict[str, Any]:
    write = True if WRITE_RX.search(name) else (False if READ_RX.search(name) else None)
    return {"write": write, "privileged": bool(PRIVILEGED_RX.search(name)), "broad": bool(BROAD_RX.search(name))}


def _label(p: Dict[str, Any]) -> str:
    return f"{p['resource']}:{p['name']}" if p.get("resource") and p["resource"] not in ("realm", "client scope") else p["name"]


def hygiene(rec: Dict[str, Any], now: Optional[datetime] = None) -> List[str]:
    """What is wrong with how this identity is looked after, from its credential dates and its owners."""
    now = now or datetime.now(timezone.utc)
    out: List[str] = []
    if not rec["owners"]:
        out.append("Nobody is recorded as the owner of this identity, so nobody is accountable for what the agent can do (OWASP ASI03).")
    if not rec["enabled"]:
        out.append("The identity is disabled in the identity provider.")
    secrets = [c for c in rec["credentials"] if c.get("kind") == "secret" and c.get("active", True)]
    for c in rec["credentials"]:
        ends, made = parse_time(c.get("ends")), parse_time(c.get("created"))
        what = f"a {c['kind']}" + (f" ({c['label']})" if c.get("label") and c["label"] not in ("ACTIVE", "INACTIVE") else "")
        if ends is not None:
            if ends < now:
                out.append(f"{what[0].upper() + what[1:]} expired on {ends.date()}; anything still using it is failing, or it is a forgotten credential.")
            elif ends - now < timedelta(days=EXPIRY_WARN_DAYS):
                out.append(f"{what[0].upper() + what[1:]} expires in {(ends - now).days} days ({ends.date()}).")
        elif c.get("kind") == "secret" and c.get("active", True) and made is not None and now - made > timedelta(days=SECRET_MAX_AGE_DAYS):
            out.append(f"A secret is {(now - made).days} days old and does not expire; rotate it.")
    if len(secrets) > 1:
        out.append(f"{len(secrets)} secrets are active at the same time: finish a rotation, or remove the one nobody uses.")
    return out


def fingerprint(rec: Dict[str, Any]) -> str:
    core = {"name": rec["name"], "enabled": rec["enabled"], "owners": sorted(rec["owners"]), "tags": sorted(rec["tags"]),
            "permissions": sorted({(p.get("resource", ""), p["name"], p.get("kind", "")) for p in rec["permissions"]})}
    return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def to_agent(rec: Dict[str, Any], now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    name = _clean(rec["name"])
    key = agent_key(name)
    if len(key) < 2:
        return None
    label = PROVIDERS[rec["provider"]].label
    m = _manifest(name)
    m["framework"] = f"{label} identity"
    m["owner"] = _clean(rec["owners"][0], 120) if rec["owners"] else None
    if rec["description"]:
        m["goal"] = _first_sentence(rec["description"], 200)
        m["inferred"].append("goal: taken from the identity's description; confirm it")
    seen, perms = set(), []
    for p in rec["permissions"]:
        lab = _label(p)
        if lab and lab not in seen:
            seen.add(lab)
            perms.append((lab, classify(p["name"]), p))
    perms.sort(key=lambda x: (not x[1]["privileged"], x[1]["write"] is not True, x[0]))      # privileged and write-capable first, so the cap never hides them
    by_name = 0
    privileged = []
    for lab, c, p in perms[:MAX_TOOLS]:
        write = c["write"]
        if write is None:
            write = bool(WRITE_WORDS.search(p["name"]))
            by_name += 1
        m["tools"].append({"name": _clean(lab), "write": write})
        if c["privileged"] or c["broad"]:
            privileged.append(lab)
    if len(perms) > MAX_TOOLS:
        m["warnings"].append(f"{len(perms) - MAX_TOOLS} more permissions are held than an agent model can show; the privileged and write-capable ones are listed first.")
    if by_name:
        m["inferred"].append(f"{by_name} permission(s) could not be classified from their names, so they were treated as read-only unless the name suggested a write; confirm them")
    if privileged:
        m["warnings"].append("Privileged or tenant-wide permissions: " + ", ".join(privileged[:8]) + (" …" if len(privileged) > 8 else "") + ". An agent that holds these can change the identity system or reach every user's data (OWASP ASI03).")
    m["warnings"] += hygiene(rec, now) + list(rec["notes"])
    m["inferred"].append("autonomy: an identity does not say how much a person supervises the agent; acts_with_approval was assumed")
    m["inferred"].append("framework, data and approvals: an identity does not say; add them in the design")
    m["recognised"].append(f"{rec['kind'].replace('-', ' ')} in {label}" + (f", tagged {', '.join(rec['tags'][:3])}" if rec["tags"] else ""))
    m["ignored"].append("client secrets and certificates: only their dates were read, never the values")
    return {"key": key, "name": name, "framework": m["framework"], "provider": rec["provider"], "external_id": rec["external_id"], "kind": rec["kind"], "enabled": rec["enabled"],
            "fingerprint": fingerprint(rec), "manifest": m,
            "counts": {"permissions": len(perms), "write": sum(1 for _, c, _p in perms if c["write"]), "privileged": len(privileged)},
            "privileged": privileged[:12], "hygiene": hygiene(rec, now)}
