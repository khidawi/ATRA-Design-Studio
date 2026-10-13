"""
Which version of a model answered: tracking for models the organisation does not control (a third-party LLM API behind a provider's alias).

A provider can swap the model behind a name without telling anyone: the code, the contract and the approval are unchanged, and the behaviour is not. The
only evidence is on the response (the model id the API reports, a system fingerprint). So each record may carry `model_version`, and this module keeps a
small profile per version: how many answers, the answer distribution, error rate, latency, confidence. When a version appears that has not been seen
before, that is a change event; when its behaviour differs from the version before it, the change is called out as a shift. Pure functions, no database.

What this can say: "the provider's model changed on this date, and answers moved like this". What it cannot: whether the new version is worse. It is
advice for the model's owner; nothing is stopped or rerouted.
"""
from typing import Any, Dict, List, Optional

import model_stats as ms

MAX_VERSIONS = 40
MAX_OUT = 20
WATCH_HOURS = 168                                   # a change stays in view for a week
DEFAULTS = {"min_version_n": 100, "version_psi_watch": 0.1, "version_psi_drift": 0.25, "version_latency_ratio": 1.5, "version_error_delta": 0.03, "version_conf_delta": 0.10, "version_mean_shift": 0.25}


def new_state() -> Dict[str, Any]:
    return {"items": {}, "events": [], "current": None}


def _new(at: str) -> Dict[str, Any]:
    return {"n": 0, "first": at, "last": at, "errors": 0, "lat": [0] * (len(ms.LATENCY_EDGES) + 1), "conf_sum": 0.0, "conf_n": 0, "out": {}, "out_sum": 0.0, "out_sq": 0.0, "out_n": 0}


def clean(v: Any) -> Optional[str]:
    s = str(v).strip()[:120] if v is not None else ""
    return s or None


def fold(state: Dict[str, Any], version: str, rec: Dict[str, Any], at: str, out_kind: str) -> Optional[Dict[str, Any]]:
    """Adds one record under its version. Returns the change event when the version had not been seen."""
    items, event = state["items"], None
    if version not in items:
        if len(items) >= MAX_VERSIONS:
            version = "__other__"
        if version not in items:
            items[version] = _new(at)
            if state["current"] and state["current"] != version and version != "__other__":
                event = {"at": at, "from": state["current"], "to": version}
                state["events"] = (state["events"] + [event])[-30:]
    v = items[version]
    v["n"] += 1
    v["last"] = max(v["last"], at)
    v["errors"] += 1 if rec.get("error") else 0
    if rec.get("latency_ms") is not None:
        import bisect
        v["lat"][bisect.bisect_left(ms.LATENCY_EDGES, rec["latency_ms"])] += 1
    if rec.get("confidence") is not None:
        v["conf_sum"] += rec["confidence"]
        v["conf_n"] += 1
    o = rec.get("output")
    if o is not None and not rec.get("error"):
        if out_kind == "numeric":
            try:
                x = float(o)
                v["out_sum"] += x
                v["out_sq"] += x * x
                v["out_n"] += 1
            except (TypeError, ValueError):
                pass
        elif out_kind != "text":
            k = str(o)[:60]
            if k not in v["out"] and len(v["out"]) >= MAX_OUT:
                k = "__other__"
            v["out"][k] = v["out"].get(k, 0) + 1
        else:
            b = min(int(len(str(o)) ** 0.5), 40)                           # text: the length class, never the text
            k = f"len~{b * b}"
            v["out"][k] = v["out"].get(k, 0) + 1
    cur = max(items, key=lambda k: items[k]["last"])
    state["current"] = cur
    return event


def _psi(a: Dict[str, int], b: Dict[str, int]) -> float:
    keys = sorted(set(a) | set(b))
    ta, tb = sum(a.values()) or 1, sum(b.values()) or 1
    return ms.psi([a.get(k, 0) / ta for k in keys], [b.get(k, 0) / tb for k in keys])


def compare(old: Dict[str, Any], new: Dict[str, Any], out_kind: str, thr: Dict[str, float]) -> List[Dict[str, Any]]:
    """How the answers of `new` differ from those of `old`: a list of findings, empty when they behave alike or there is too little to say."""
    f: List[Dict[str, Any]] = []
    if old["n"] < thr["min_version_n"] or new["n"] < thr["min_version_n"]:
        return f
    if out_kind == "numeric":
        if old["out_n"] > 1 and new["out_n"] > 1:
            mo, mn = old["out_sum"] / old["out_n"], new["out_sum"] / new["out_n"]
            var = max(old["out_sq"] / old["out_n"] - mo * mo, 1e-12)
            z = abs(mn - mo) / (var ** 0.5)
            if z >= thr["version_mean_shift"]:
                f.append({"what": "answers", "value": round(z, 3), "threshold": thr["version_mean_shift"], "text": f"The average answer moved by {z:.2f} standard deviations ({mo:.4g} to {mn:.4g})."})
    elif old["out"] and new["out"]:
        p = _psi(old["out"], new["out"])
        if p >= thr["version_psi_watch"]:
            f.append({"what": "answers", "value": round(p, 3), "threshold": thr["version_psi_watch"], "drift": p >= thr["version_psi_drift"], "text": f"The distribution of answers changed (PSI {p:.2f})."})
    eo, en = old["errors"] / old["n"], new["errors"] / new["n"]
    if en - eo >= thr["version_error_delta"]:
        f.append({"what": "errors", "value": round(en, 4), "threshold": round(eo + thr["version_error_delta"], 4), "text": f"The error rate rose from {eo:.1%} to {en:.1%}."})
    po, pn = ms.percentile(old["lat"], 0.5), ms.percentile(new["lat"], 0.5)
    if po and pn and sum(old["lat"]) >= thr["min_version_n"] and sum(new["lat"]) >= thr["min_version_n"] and pn / po >= thr["version_latency_ratio"]:
        f.append({"what": "latency", "value": round(pn / po, 2), "threshold": thr["version_latency_ratio"], "text": f"Median response time went from about {po:g} ms to {pn:g} ms."})
    if old["conf_n"] >= thr["min_version_n"] and new["conf_n"] >= thr["min_version_n"]:
        co, cn = old["conf_sum"] / old["conf_n"], new["conf_sum"] / new["conf_n"]
        if abs(cn - co) >= thr["version_conf_delta"]:
            f.append({"what": "confidence", "value": round(cn, 3), "threshold": round(co, 3), "text": f"Average confidence went from {co:.2f} to {cn:.2f}."})
    return f


def evaluate(state: Dict[str, Any], out_kind: str, thr: Optional[Dict[str, Any]], now_iso: str) -> Dict[str, Any]:
    """The versions seen, the recent changes and, for the latest change, whether behaviour moved. `reasons` use the monitor's level words (watch, drift)."""
    t = {**DEFAULTS, **(thr or {})}
    items = state.get("items", {})
    out: Dict[str, Any] = {"current": state.get("current"), "events": [], "reasons": [], "versions": []}
    for k, v in sorted(items.items(), key=lambda kv: kv[1]["first"]):
        out["versions"].append({"version": k, "n": v["n"], "first_seen": v["first"], "last_seen": v["last"], "error_rate": round(v["errors"] / v["n"], 4) if v["n"] else 0.0,
                                "latency_p50": ms.percentile(v["lat"], 0.5), "confidence": round(v["conf_sum"] / v["conf_n"], 3) if v["conf_n"] else None})
    from datetime import datetime, timedelta
    now = datetime.fromisoformat(now_iso)
    for e in state.get("events", []):
        old, new = items.get(e["from"]), items.get(e["to"])
        shifts = compare(old, new, out_kind, t) if old and new else []
        ev = {**e, "shifts": shifts, "old_n": old["n"] if old else 0, "new_n": new["n"] if new else 0}
        out["events"].append(ev)
        age = now - datetime.fromisoformat(e["at"])
        if age > timedelta(hours=WATCH_HOURS) or e["to"] != state.get("current"):
            continue
        what = f"The model behind this monitor changed from {e['from']} to {e['to']}"
        if shifts:
            drift = any(s.get("drift") for s in shifts) or len(shifts) >= 2
            out["reasons"].append({"level": "drift" if drift else "watch", "kind": "MODEL_VERSION", "subject": e["to"], "value": float(len(shifts)), "threshold": 1.0,
                                   "text": what + ", and it behaves differently: " + " ".join(s["text"] for s in shifts[:3]), "shifts": shifts})
        else:
            sure = old and new and old["n"] >= t["min_version_n"] and new["n"] >= t["min_version_n"]
            out["reasons"].append({"level": "watch", "kind": "MODEL_VERSION", "subject": e["to"], "value": 0.0, "threshold": 1.0,
                                   "text": what + (". Behaviour looks alike so far." if sure else ". Too few answers from one of them to compare yet.")})
    return out
