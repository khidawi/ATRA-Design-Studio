"""
The policy of the ST-AI v2.5 gate: the parameters an accountable authority sets, and that the model refuses to invent.

  independence  for each use that needs it (approval, review, attestation, non-applicability review, accepted-risk approval): a level (PERSON, REPORTING_LINE, UNIT) and a
                mode (AT_ACT: judged when the person acts; CONTINUING: judged again whenever the design is assessed, so a reorganisation that removes independence lapses the act)
  risk          the basis of the quantitative criterion: "legacy_until_intervals" (the legacy score stands in for a design that states no risk intervals) or "intervals" (the
                interval rule alone decides, and a design without intervals or tolerances is unresolved); the confidence level of the intervals (a convention, not a constant)
  tolerances    expected-harm tolerances and severe-event probability tolerances allocated down the organisation: organisation > units > deployments. The allocations to the
                children of a unit sum to at most the unit's own, so if every deployment is within its allocation every unit is within its tolerance.

This module is pure (dicts in, dicts out). Persistence is st_ai_policy_api.py; the published versions are never edited, and a review is bound to the policy version it was
made under (the version number is part of the registry the review fingerprints).
"""
import copy
from typing import Any, Dict, List, Optional, Tuple

USES = ("approval", "review", "attestation", "non_applicability_review", "accepted_risk_approval")
LEVELS = ("PERSON", "REPORTING_LINE", "UNIT")
MODES = ("AT_ACT", "CONTINUING")
BASES = ("legacy_until_intervals", "intervals")
METRICS = ("R", "Q")
SCOPES = ("organisation", "unit", "deployment")
ROOT = "organisation"

DEFAULT_POLICY: Dict[str, Any] = {
    "independence": {u: {"level": "PERSON", "mode": "AT_ACT"} for u in USES},
    "risk": {"basis": "legacy_until_intervals", "confidence_level": 0.95},
    "tolerances": [],
}


def normalise(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The policy with every parameter present: what is not stated takes its default."""
    out = copy.deepcopy(DEFAULT_POLICY)
    p = params or {}
    for u, v in (p.get("independence") or {}).items():
        if u in out["independence"] and isinstance(v, dict):
            out["independence"][u].update({k: v[k] for k in ("level", "mode") if k in v})
    if isinstance(p.get("risk"), dict):
        out["risk"].update({k: p["risk"][k] for k in ("basis", "confidence_level") if k in p["risk"]})
    if isinstance(p.get("tolerances"), list):
        out["tolerances"] = [dict(t) for t in p["tolerances"] if isinstance(t, dict)]
    return out


def validate(params: Optional[Dict[str, Any]]) -> List[str]:
    """What is wrong with a policy (empty: it can be published)."""
    p = normalise(params)
    problems: List[str] = []
    raw_ind = (params or {}).get("independence") or {}
    for u in raw_ind:
        if u not in USES:
            problems.append(f"independence: '{u}' is not a use that needs independence ({', '.join(USES)})")
    for u, v in p["independence"].items():
        if v["level"] not in LEVELS:
            problems.append(f"independence for {u}: the level must be one of {', '.join(LEVELS)}")
        if v["mode"] not in MODES:
            problems.append(f"independence for {u}: the mode must be one of {', '.join(MODES)}")
    r = p["risk"]
    if r["basis"] not in BASES:
        problems.append(f"risk: the basis must be one of {', '.join(BASES)}")
    try:
        if not 0.5 <= float(r["confidence_level"]) < 1:
            problems.append("risk: the confidence level must be at least 0.5 and below 1")
    except (TypeError, ValueError):
        problems.append("risk: the confidence level must be a number")
    problems += _validate_tolerances(p["tolerances"])
    return problems


def _validate_tolerances(rows: List[Dict[str, Any]]) -> List[str]:
    problems: List[str] = []
    seen: Dict[Tuple[str, str, str, str], float] = {}
    for i, t in enumerate(rows, 1):
        where = f"tolerance {i}"
        scope, name, dim, metric = t.get("scope"), str(t.get("name") or "").strip(), str(t.get("dimension") or "").strip(), t.get("metric")
        if scope not in SCOPES:
            problems.append(f"{where}: the scope must be one of {', '.join(SCOPES)}")
            continue
        if not name or not dim:
            problems.append(f"{where}: a name and a harm dimension are required")
            continue
        if metric not in METRICS:
            problems.append(f"{where} ({name}, {dim}): the metric must be R (expected annual harm) or Q (probability of a severe event)")
            continue
        try:
            v = float(t.get("value"))
        except (TypeError, ValueError):
            problems.append(f"{where} ({name}, {dim}): the value must be a number")
            continue
        if v <= 0 or (metric == "Q" and v > 1):
            problems.append(f"{where} ({name}, {dim}): a tolerance must be above 0, and a probability tolerance at most 1")
            continue
        if scope == "organisation" and name != ROOT:
            problems.append(f"{where}: the organisation's own allocation is named '{ROOT}'")
        key = (scope, name, dim, metric)
        if key in seen:
            problems.append(f"{where}: {scope} '{name}' already has a {metric} tolerance for {dim}")
        seen[key] = v
    # allocation: the children of a parent sum to at most the parent's own allocation, per dimension and metric
    parents: Dict[Tuple[str, str, str], float] = {(n, d, m): v for (s, n, d, m), v in seen.items() if s in ("organisation", "unit")}
    sums: Dict[Tuple[str, str, str], float] = {}
    for t in rows:
        if t.get("scope") in ("unit", "deployment"):
            par = str(t.get("parent") or "").strip()
            try:
                v = float(t.get("value"))
            except (TypeError, ValueError):
                continue
            if not par:
                problems.append(f"{t.get('scope')} '{t.get('name')}' ({t.get('dimension')}): the parent unit it is allocated under is missing")
                continue
            if (par, str(t.get("dimension")), t.get("metric")) not in parents:
                problems.append(f"{t.get('scope')} '{t.get('name')}' ({t.get('dimension')}, {t.get('metric')}): its parent '{par}' has no allocation for it to be taken from")
                continue
            k = (par, str(t.get("dimension")), t.get("metric"))
            sums[k] = sums.get(k, 0.0) + v
    for k, total in sums.items():
        if total > parents[k] + 1e-9:
            problems.append(f"allocations under '{k[0]}' for {k[1]} ({k[2]}) add up to {total:g}, more than its own {parents[k]:g}")
    return problems


def independence_requirement(policy: Optional[Dict[str, Any]], use: str) -> Tuple[str, str]:
    """(level, mode) declared for a use."""
    v = normalise(policy)["independence"].get(use) or DEFAULT_POLICY["independence"]["approval"]
    return v["level"], v["mode"]


def tolerance_for(policy: Optional[Dict[str, Any]], deployment_key: Optional[str], dimension: str, metric: str) -> Optional[float]:
    """The tolerance allocated to this deployment for this dimension and metric, or None when none is allocated (the criterion is then unresolved: a missing fact)."""
    if not deployment_key:
        return None
    for t in normalise(policy)["tolerances"]:
        if t.get("scope") == "deployment" and t.get("name") == deployment_key and t.get("dimension") == dimension and t.get("metric") == metric:
            try:
                return float(t["value"])
            except (TypeError, ValueError):
                return None
    return None
