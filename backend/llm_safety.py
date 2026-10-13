"""
Safety of an LLM in production: what goes out to the provider, what comes back unsafe, and whether the model still passes the questions we know the answer to.
Pure functions: no database, no network.

ASTRA never sees prompts or replies. The organisation's own code scans the text where it runs (astra_runtime/checks.py) and sends only yes/no flags, so what
arrives here is a count: how many requests had personal data or a credential in the prompt (data leaving for a third party), how many replies contained
one, how many looked like a prompt-injection attempt. They are pattern matches, not proof: a match can be a false alarm and a miss is possible, so the
wording is "check", not "breach", except for credentials, where even one is worth a person's time.

Canary prompts are fixed questions with a known good answer, asked on a schedule through the same route as real traffic. A canary that passed on one
model version and fails on the next is the clearest evidence that a provider changed the model under the application, and it needs no baseline.
"""
from typing import Any, Dict, List, Optional

# flag name: (finding kind, what it means, watch rate, drift rate, count needed before a rate counts)
SAFETY_FLAGS: Dict[str, Dict[str, Any]] = {
    "secret_in_prompt": {"kind": "DATA_EGRESS", "label": "A credential or key was in a prompt sent out", "watch": None, "drift": 0.0, "min": 1},
    "secret_in_output": {"kind": "OUTPUT_SAFETY", "label": "A credential or key appeared in a reply", "watch": None, "drift": 0.0, "min": 1},
    "pii_in_prompt": {"kind": "DATA_EGRESS", "label": "Personal data was in a prompt sent to the provider", "watch": 0.01, "drift": 0.05, "min": 3},
    "pii_in_output": {"kind": "OUTPUT_SAFETY", "label": "Personal data appeared in a reply", "watch": 0.01, "drift": 0.05, "min": 3},
    "injection_suspected": {"kind": "OUTPUT_SAFETY", "label": "A prompt or reply looked like a prompt-injection attempt", "watch": 0.02, "drift": 0.10, "min": 5},
}
CANARY_RECENT = 20
MAX_CANARIES = 30
MAX_CANARY_VERSIONS = 20


def evaluate_flags(counts: Dict[str, int], n: int) -> Dict[str, Any]:
    """The safety flags over a period of `n` requests: a row for each, and a reason for each that is over its limit."""
    rows: List[Dict[str, Any]] = []
    reasons: List[Dict[str, Any]] = []
    for name, d in SAFETY_FLAGS.items():
        c = int(counts.get(name, 0))
        rate = c / n if n else 0.0
        level = None
        if c >= d["min"]:
            if rate >= d["drift"]:
                level = "drift"
            elif d["watch"] is not None and rate >= d["watch"]:
                level = "watch"
        rows.append({"flag": name, "label": d["label"], "kind": d["kind"], "count": c, "rate": round(rate, 5), "level": level})
        if level:
            where = "outgoing prompts" if d["kind"] == "DATA_EGRESS" else "replies"
            reasons.append({"level": level, "kind": d["kind"], "subject": name, "value": round(rate, 5), "threshold": d["drift"] if level == "drift" else d["watch"],
                            "text": f"{d['label']}: {c} of {n:,} requests ({rate:.1%}). A pattern match on {where}, so look at a sample before concluding."})
    return {"rows": rows, "reasons": reasons, "n": n}


# ── canaries ────────────────────────────────────────────────────────────────

def new_canaries() -> Dict[str, Any]:
    return {"items": {}}


def fold_canary(state: Dict[str, Any], name: str, passed: bool, version: Optional[str], at: str) -> None:
    items = state["items"]
    if name not in items and len(items) >= MAX_CANARIES:
        return
    c = items.setdefault(name, {"n": 0, "fail": 0, "last_at": at, "last_ok": passed, "recent": [], "by_version": {}})
    c["n"] += 1
    c["fail"] += 0 if passed else 1
    if at >= c["last_at"]:
        c["last_at"], c["last_ok"] = at, passed
    c["recent"] = (c["recent"] + [1 if passed else 0])[-CANARY_RECENT:]
    if version:
        bv = c["by_version"]
        if version not in bv and len(bv) >= MAX_CANARY_VERSIONS:
            return
        v = bv.setdefault(version, {"n": 0, "fail": 0, "last": at})
        v["n"] += 1
        v["fail"] += 0 if passed else 1
        v["last"] = max(v["last"], at)


def evaluate_canaries(state: Dict[str, Any], current_version: Optional[str] = None) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    reasons: List[Dict[str, Any]] = []
    for name, c in sorted(state.get("items", {}).items()):
        recent = c["recent"][-5:]
        rows.append({"canary": name, "n": c["n"], "fail_rate": round(c["fail"] / c["n"], 4) if c["n"] else 0.0, "last_at": c["last_at"], "last_ok": c["last_ok"], "recent": c["recent"][-10:],
                     "versions": [{"version": k, "n": v["n"], "fail_rate": round(v["fail"] / v["n"], 4)} for k, v in sorted(c["by_version"].items(), key=lambda kv: kv[1]["last"])]})
        cur = c["by_version"].get(current_version) if current_version else None
        others = [v for k, v in c["by_version"].items() if k != current_version and v["n"] >= 3]
        on, of = sum(v["n"] for v in others), sum(v["fail"] for v in others)
        if cur and cur["n"] >= 3 and on and of / on <= 0.2 and cur["fail"] / cur["n"] >= 0.5:
            reasons.append({"level": "drift", "kind": "CANARY", "subject": name, "value": round(cur["fail"] / cur["n"], 3), "threshold": 0.5,
                            "text": f"The check '{name}' passed {1 - of / on:.0%} of the time on earlier versions and fails {cur['fail']} of {cur['n']} times on {current_version}. The model changed in a way this check notices."})
        elif len(c["recent"]) >= 5 and recent.count(0) == 5:
            reasons.append({"level": "drift", "kind": "CANARY", "subject": name, "value": 1.0, "threshold": 1.0, "text": f"The check '{name}' has failed its last 5 runs."})
        elif len(c["recent"]) >= 5 and recent.count(0) >= 3:
            reasons.append({"level": "watch", "kind": "CANARY", "subject": name, "value": recent.count(0) / 5, "threshold": 0.6, "text": f"The check '{name}' failed {recent.count(0)} of its last 5 runs."})
    return {"rows": rows, "reasons": reasons}
