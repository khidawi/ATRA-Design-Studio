"""
Who decides how sensitive a production monitor is: a floor set by compliance, tuning by the model owner. Pure functions: no database.

The model owner knows the model and can tell when a default fires too easily, so they may tune every threshold. But a threshold is also a control: loosening
it makes a problem harder to see. So compliance can set a **floor** for the organisation, the loosest value any monitor may use for that threshold. An owner
may tighten freely; loosening past the floor needs a compliance sign-off with a written reason (a **waiver**), which is recorded and shown on the page.

If the floor is tightened later, a monitor whose own value is now looser than the floor is held to the floor automatically, unless a waiver covers it.

Only thresholds that decide whether something is flagged are governed. Operational ones (how many records are needed before judging, the length of the window)
are the owner's alone.
"""
from typing import Any, Dict, List, Optional, Set, Tuple

# "lower": a lower value flags more (stricter); "higher": a higher value flags more.
MODEL = {"psi_watch": "lower", "psi_drift": "lower", "perf_drop_watch": "lower", "perf_drop_drift": "lower", "rmse_ratio_watch": "lower", "rmse_ratio_drift": "lower",
         "parity_watch": "higher", "parity_breach": "higher", "error_watch": "lower", "error_drift": "lower", "flag_watch": "lower", "flag_drift": "lower",
         "latency_ratio_watch": "lower", "latency_ratio_drift": "lower", "violation_min": "lower"}
DECISIONS = {"accept_watch": "lower", "perfunctory_seconds": "higher", "perfunctory_accept": "lower", "harmful_watch": "lower", "harmful_drift": "lower",
             "needless_override_watch": "lower", "reason_min_rate": "higher", "require_reasons": "higher", "coverage_expected": "higher", "concentration_watch": "lower"}
SCOPES = {"model": MODEL, "decisions": DECISIONS}


def looser(direction: str, value: float, floor: float) -> bool:
    """True when `value` flags less than `floor` would."""
    return value > floor if direction == "lower" else value < floor


def clean_floors(raw: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    """Validates a floors document: {"model": {...}, "decisions": {...}}. Raises ValueError with a message safe to show."""
    out: Dict[str, Dict[str, float]] = {}
    for scope, vals in (raw or {}).items():
        if scope not in SCOPES:
            raise ValueError(f"Unknown group '{scope}'. Known: {', '.join(SCOPES)}.")
        for k, v in (vals or {}).items():
            if k not in SCOPES[scope]:
                raise ValueError(f"'{k}' cannot have a floor. Governed thresholds: {', '.join(SCOPES[scope])}.")
            try:
                out.setdefault(scope, {})[k] = float(v)
            except (TypeError, ValueError):
                raise ValueError(f"The floor for '{k}' must be a number.")
    return out


def loosened(scope: str, own: Dict[str, float], floors: Dict[str, Dict[str, float]]) -> List[Dict[str, Any]]:
    """The values in `own` that are looser than the floor: each as {key, value, floor}."""
    out = []
    for k, v in (own or {}).items():
        f = (floors.get(scope) or {}).get(k)
        if f is not None and k in SCOPES[scope] and looser(SCOPES[scope][k], float(v), f):
            out.append({"key": k, "value": float(v), "floor": f})
    return out


def effective(scope: str, defaults: Dict[str, float], own: Dict[str, float], floors: Dict[str, Dict[str, float]], waived: Set[str]) -> Dict[str, float]:
    """The thresholds in force: the defaults, then the owner's values, each held to the floor unless waived."""
    t = {**defaults, **{k: float(v) for k, v in (own or {}).items()}}
    for k, f in (floors.get(scope) or {}).items():
        if k in SCOPES[scope] and k in t and k not in waived and looser(SCOPES[scope][k], t[k], f):
            t[k] = f
    return t


def current_waivers(scope: str, waivers: List[Dict[str, Any]], own: Dict[str, float]) -> List[Dict[str, Any]]:
    """The waivers still in effect: one whose recorded value is still the value in use."""
    return [w for w in (waivers or []) if w.get("scope") == scope and w["key"] in (own or {}) and abs(float(own[w["key"]]) - float(w["value"])) < 1e-12]


def apply_change(scope: str, new_own: Dict[str, float], floors: Dict[str, Dict[str, float]], waivers: List[Dict[str, Any]], *, can_waive: bool, reason: Optional[str],
                 by: str, at: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Checks a change of an owner's thresholds against the floors. Returns (new waivers list, the newly waived items).
    Raises PermissionError (names the thresholds, cannot proceed) or ValueError (a reason is needed)."""
    over = loosened(scope, new_own, floors)
    keep = [w for w in (waivers or []) if w.get("scope") != scope]
    if not over:
        return keep, []
    existing = {w["key"]: w for w in current_waivers(scope, waivers, new_own)}
    fresh = [o for o in over if o["key"] not in existing]
    kept = [existing[o["key"]] for o in over if o["key"] in existing]
    if fresh and not can_waive:
        raise PermissionError("Looser than the compliance floor: " + "; ".join(f"{o['key']} {o['value']:g} (floor {o['floor']:g})" for o in fresh) + ". Tighten it, or ask compliance to sign off a waiver.")
    if fresh and len((reason or "").strip()) < 5:
        raise ValueError("A waiver needs a written reason (at least a few words) so the next reader knows why this monitor is looser than the floor.")
    made = [{"scope": scope, "key": o["key"], "value": o["value"], "floor": o["floor"], "reason": reason.strip()[:300], "by": by, "at": at} for o in fresh]
    return keep + kept + made, made
