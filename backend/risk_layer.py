"""
The organisation risk layer, pure part (ASTRA phase 2): scales, defaults and validation. No database; risk_api.py stores and serves the declarations.

Three things are declared by the organisation, never computed by ASTRA:

  * the impact tier of each asset, 1 (minor) to 4 (severe): what is lost if it is leaked, altered or unavailable;
  * the tolerance of each department, 0 to 4: the highest tier of an open attack path it accepts (0 accepts none);
  * the response posture: observe, flag, block or halt, for each severity (Medium, High, Critical) and tier. Block and halt are recommendations: a person or the
    control plane enacts them, and the model's verdict does not depend on whether they were.

Fail-closed defaults, because a missing declaration must never make the estate look safer: an asset with no ratified tier counts as tier 4, a department with no
ratified tolerance accepts nothing, and the posture falls back to the default matrix below. The posture must be monotone: a higher tier or a higher severity never
gets a milder response.
"""
from typing import Any, Dict, List, Mapping, Tuple

TIERS = (1, 2, 3, 4)
TOLERANCES = (0, 1, 2, 3, 4)
SEVERITIES = ("Medium", "High", "Critical")
POSTURES = ("observe", "flag", "block", "halt")
POSTURE_RANK = {p: i for i, p in enumerate(POSTURES)}
CIA_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ASSET_KINDS = ("data", "memory")

DEFAULT_TIER = 4
DEFAULT_TOLERANCE = 0
DEFAULT_POSTURE: Dict[int, Dict[str, str]] = {
    1: {"Medium": "observe", "High": "flag", "Critical": "flag"},
    2: {"Medium": "flag", "High": "flag", "Critical": "block"},
    3: {"Medium": "flag", "High": "block", "Critical": "block"},
    4: {"Medium": "flag", "High": "block", "Critical": "halt"},
}
MIN_RATIONALE = 5


def _rationale(d: Mapping[str, Any]) -> List[str]:
    r = d.get("rationale")
    return [] if isinstance(r, str) and len(r.strip()) >= MIN_RATIONALE else ["say why (a short rationale is required)"]


def validate_asset(d: Mapping[str, Any]) -> List[str]:
    p = _rationale(d)
    if d.get("tier") not in TIERS:
        p.append("the impact tier must be 1, 2, 3 or 4")
    for k in ("confidentiality", "integrity", "availability"):
        if d.get(k) not in CIA_LEVELS:
            p.append(f"{k} must be one of {', '.join(CIA_LEVELS)}")
    if d.get("asset_kind") not in ASSET_KINDS:
        p.append("the asset kind must be data or memory")
    if not d.get("asset_ext") or not d.get("department_ext"):
        p.append("the asset and its department are required")
    return p


def validate_tolerance(d: Mapping[str, Any]) -> List[str]:
    p = _rationale(d)
    if d.get("tolerance") not in TOLERANCES:
        p.append("the tolerance must be 0, 1, 2, 3 or 4")
    if not d.get("department_ext"):
        p.append("the department is required")
    return p


def validate_posture(d: Mapping[str, Any]) -> List[str]:
    p = _rationale(d)
    if d.get("tier") not in TIERS:
        p.append("the tier must be 1, 2, 3 or 4")
    if d.get("severity") not in SEVERITIES:
        p.append(f"the severity must be one of {', '.join(SEVERITIES)}")
    if d.get("posture") not in POSTURES:
        p.append(f"the posture must be one of {', '.join(POSTURES)}")
    return p


def posture_matrix(overrides: Mapping[Tuple[int, str], str]) -> Dict[int, Dict[str, str]]:
    """The default matrix with the ratified cells laid over it."""
    m = {t: dict(row) for t, row in DEFAULT_POSTURE.items()}
    for (t, s), v in overrides.items():
        m[t][s] = v
    return m


def posture_problems(m: Mapping[int, Mapping[str, str]]) -> List[str]:
    """Where the matrix is not monotone: a higher tier, or a higher severity, must not get a milder response."""
    out: List[str] = []
    for t in TIERS:
        for i, s in enumerate(SEVERITIES):
            here = POSTURE_RANK[m[t][s]]
            if t < TIERS[-1] and POSTURE_RANK[m[t + 1][s]] < here:
                out.append(f"tier {t + 1} / {s} ({m[t + 1][s]}) is milder than tier {t} / {s} ({m[t][s]})")
            if i < len(SEVERITIES) - 1 and POSTURE_RANK[m[t][SEVERITIES[i + 1]]] < here:
                out.append(f"tier {t} / {SEVERITIES[i + 1]} ({m[t][SEVERITIES[i + 1]]}) is milder than tier {t} / {s} ({m[t][s]})")
    return out
