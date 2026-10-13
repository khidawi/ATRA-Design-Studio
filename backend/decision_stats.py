"""
How people use a model's outputs: statistics over the decisions staff make about what the model says. Pure functions: no database, no network.

A model's risk lives in the chain output, person, decision, outcome. The ST-AI score asks whether human review is real (the human-oversight weight, the
"substantive review" and "automation bias" facts), but until now that was declared once. These statistics measure it, from decision records the
organisation's application sends:

  * what the person did with the output (accepted, edited, overrode, escalated, ignored) and how long they looked at it;
  * whether they gave a reason, and whether they were shown the model's confidence;
  * and, when the truth is later known, whether the model was right: so "staff accepted most of what turned out to be wrong" can be seen.

Roles, not people: a decision names the role of whoever decided (loan officer, triage nurse), never a person. An organisation may choose to count
distinct people as well, as pseudonyms (a keyed hash, never a name), to see whether decisions are concentrated in one pair of hands.

What this can and cannot say. It can show that review looks perfunctory (nearly everything accepted, in a few seconds) or that it is failing (most of
the model's wrong outputs were accepted). It cannot prove that a person did not think: a fast acceptance can be an expert's. So these are findings for
people to look into, shown as such; only "wrong outputs accepted" is treated as serious, because there the outcome is known.

The thresholds are common rules of thumb, not calibrated; they can be changed per monitor.
"""
import bisect
import hashlib
from typing import Any, Dict, List, Optional

import model_stats as ms

ACTIONS = ("accepted", "edited", "overridden", "escalated", "ignored")
REVIEW_EDGES = [1, 3, 5, 10, 30, 60, 180, 600]                   # seconds; one more bucket above the last edge
MAX_ROLES = 30
MAX_PEOPLE = 50
DEFAULTS = {"min_decisions": 100, "min_wrong": 10, "accept_watch": 0.98, "perfunctory_seconds": 5.0, "perfunctory_accept": 0.95, "harmful_watch": 0.30, "harmful_drift": 0.50,
            "needless_override_watch": 0.50, "reason_min_rate": 0.80, "require_reasons": 0, "coverage_expected": 0.0, "concentration_watch": 0.60}


def new_role() -> Dict[str, Any]:
    return {"n": 0, "act": {a: 0 for a in ACTIONS}, "rt": [0] * (len(REVIEW_EDGES) + 1), "rt_n": 0, "reason": 0, "shown": 0, "wrong": 0, "wrong_accepted": 0, "right": 0, "right_overridden": 0}


def new_acc() -> Dict[str, Any]:
    return {"n": 0, "roles": {}, "people": {}}


def pseudonym(salt: str, person: str) -> str:
    """A keyed hash, so the same person is the same pseudonym within one monitor and cannot be looked up from a name."""
    return hashlib.sha256((salt + "|" + person.strip().lower()).encode("utf-8")).hexdigest()[:10]


def fold(acc: Dict[str, Any], d: Dict[str, Any], salt: str = "", individuals: bool = False) -> None:
    """Adds one decision. Nothing of it is kept except what these counters hold."""
    role = (str(d.get("role") or "").strip() or "unspecified")[:60]
    if role not in acc["roles"] and len(acc["roles"]) >= MAX_ROLES:
        role = "other"
    r = acc["roles"].setdefault(role, new_role())
    acc["n"] += 1
    r["n"] += 1
    action = d["action"]
    r["act"][action] += 1
    secs = d.get("review_seconds")
    if secs is not None and secs >= 0:
        r["rt"][bisect.bisect_left(REVIEW_EDGES, secs)] += 1
        r["rt_n"] += 1
    if d.get("reason"):
        r["reason"] += 1
    if d.get("confidence_shown"):
        r["shown"] += 1
    correct = d.get("model_correct")
    if correct is True:
        r["right"] += 1
        r["right_overridden"] += 1 if action in ("overridden", "edited") else 0
    elif correct is False:
        r["wrong"] += 1
        r["wrong_accepted"] += 1 if action == "accepted" else 0
    if individuals and d.get("person"):
        p = pseudonym(salt, str(d["person"]))
        if p in acc["people"] or len(acc["people"]) < MAX_PEOPLE:
            acc["people"][p] = acc["people"].get(p, 0) + 1


def _p50(buckets: List[int]) -> Optional[float]:
    return ms.percentile(buckets, 0.5, REVIEW_EDGES)


def _row(name: str, r: Dict[str, Any]) -> Dict[str, Any]:
    n = max(1, r["n"])
    return {"role": name, "n": r["n"], "accepted": round(r["act"]["accepted"] / n, 4), "edited": round(r["act"]["edited"] / n, 4), "overridden": round(r["act"]["overridden"] / n, 4),
            "escalated": round(r["act"]["escalated"] / n, 4), "ignored": round(r["act"]["ignored"] / n, 4), "review_p50": _p50(r["rt"]), "reason_rate": round(r["reason"] / n, 4),
            "shown_rate": round(r["shown"] / n, 4), "wrong": r["wrong"], "wrong_accepted": r["wrong_accepted"], "right": r["right"], "right_overridden": r["right_overridden"]}


def evaluate(acc: Dict[str, Any], thr: Optional[Dict[str, Any]], predictions: int = 0) -> Dict[str, Any]:
    """Judges a window of decisions. `predictions` is how many outputs the model produced in the same period, for the share that any person looked at."""
    t = {**DEFAULTS, **(thr or {})}
    out: Dict[str, Any] = {"n": acc["n"], "reasons": [], "signals": {}, "roles": [], "sufficient": acc["n"] >= t["min_decisions"]}
    if not acc["n"]:
        return out
    total = new_role()
    for r in acc["roles"].values():
        total = ms.merge(total, r)
    n = total["n"]
    out.update({"coverage": round(acc["n"] / predictions, 4) if predictions else None, "accepted": round(total["act"]["accepted"] / n, 4),
                "changed": round((total["act"]["edited"] + total["act"]["overridden"]) / n, 4), "escalated": round(total["act"]["escalated"] / n, 4),
                "ignored": round(total["act"]["ignored"] / n, 4), "review_p50": _p50(total["rt"]), "reason_rate": round(total["reason"] / n, 4), "shown_rate": round(total["shown"] / n, 4),
                "wrong": total["wrong"], "wrong_accepted": total["wrong_accepted"], "right": total["right"], "right_overridden": total["right_overridden"]})
    out["roles"] = sorted((_row(k, v) for k, v in acc["roles"].items()), key=lambda x: -x["n"])
    reasons: List[Dict[str, Any]] = out["reasons"]

    def reason(level: str, kind: str, subject: str, value: float, threshold: float, text: str) -> None:
        reasons.append({"level": level, "kind": kind, "subject": subject, "value": round(value, 4), "threshold": threshold, "text": text})

    harmful = fast = near = False
    scopes = [("all decisions", total)] + [(k, v) for k, v in acc["roles"].items() if len(acc["roles"]) > 1 and v["n"] >= t["min_decisions"]]
    for name, r in scopes:
        who, accept_v = ("People", "accept") if name == "all decisions" else (f"The {name} role", "accepts")
        if r["n"] < t["min_decisions"]:
            continue
        acc_rate, p50 = r["act"]["accepted"] / r["n"], _p50(r["rt"])
        if r["wrong"] >= t["min_wrong"]:
            h = r["wrong_accepted"] / r["wrong"]
            if h >= t["harmful_drift"]:
                harmful = True
                reason("drift", "HUMAN_REVIEW", name, h, t["harmful_drift"], f"{who} accepted {h:.0%} of the {r['wrong']} outputs that turned out to be wrong. Review is not catching the model's mistakes.")
            elif h >= t["harmful_watch"]:
                reason("watch", "HUMAN_REVIEW", name, h, t["harmful_watch"], f"{who} accepted {h:.0%} of the {r['wrong']} outputs that turned out to be wrong.")
        if r["right"] >= t["min_wrong"]:
            o = r["right_overridden"] / r["right"]
            if o >= t["needless_override_watch"]:
                reason("watch", "HUMAN_REVIEW", name, o, t["needless_override_watch"], f"{who} changed or overrode {o:.0%} of the outputs that were right: the model is not trusted, or is not being used as designed.")
        if p50 is not None and r["rt_n"] >= t["min_decisions"] / 2 and p50 < t["perfunctory_seconds"] and acc_rate >= t["perfunctory_accept"]:
            fast = True
            reason("watch", "HUMAN_REVIEW", name, p50, t["perfunctory_seconds"], f"{who} {accept_v} {acc_rate:.0%} of outputs with a median look of {p50:g} seconds. That can be an expert's speed or a rubber stamp: check a sample.")
        elif acc_rate >= t["accept_watch"]:
            near = True
            reason("watch", "HUMAN_REVIEW", name, acc_rate, t["accept_watch"], f"{who} accepted {acc_rate:.0%} of outputs. If the model is that good, fine; if not, review may not be real.")
        if t["require_reasons"] and r["reason"] / r["n"] < t["reason_min_rate"]:
            reason("watch", "HUMAN_REVIEW", name, r["reason"] / r["n"], t["reason_min_rate"], f"A reason was given for {r['reason'] / r['n']:.0%} of decisions; the policy asks for {t['reason_min_rate']:.0%}.")
    cov = out.get("coverage")
    if t["coverage_expected"] > 0 and cov is not None and predictions >= t["min_decisions"]:
        if cov < t["coverage_expected"] * 0.5:
            reason("drift", "HUMAN_REVIEW", "coverage", cov, t["coverage_expected"], f"Only {cov:.0%} of the model's outputs had a person's decision, against the {t['coverage_expected']:.0%} expected. Most outputs are being used unreviewed.")
        elif cov < t["coverage_expected"] * 0.9:
            reason("watch", "HUMAN_REVIEW", "coverage", cov, t["coverage_expected"], f"{cov:.0%} of the model's outputs had a person's decision, against the {t['coverage_expected']:.0%} expected.")
    if acc["people"] and acc["n"] >= t["min_decisions"]:
        top = max(acc["people"].values()) / max(1, sum(acc["people"].values()))
        out["distinct_people"], out["top_person_share"] = len(acc["people"]), round(top, 4)
        if len(acc["people"]) > 1 and top >= t["concentration_watch"]:
            reason("watch", "HUMAN_REVIEW", "concentration", top, t["concentration_watch"], f"One person made {top:.0%} of the decisions: the review depends on them.")
    sig: Dict[str, Any] = {}
    if out["sufficient"]:
        sig["hitl_verified_substantive"] = False if (harmful or fast) else None
        sig["automation_bias_risk"] = "CRITICAL" if harmful else ("HIGH" if (fast and near) or fast else ("MEDIUM" if near or any(r["level"] == "watch" for r in reasons) else "LOW"))
    out["signals"] = {k: v for k, v in sig.items() if v is not None}
    return out
