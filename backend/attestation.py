"""
Declared claims that lapse: a statement about a running model is only as good as its date. Pure functions: no database.

The score of a model rests partly on what people say is true of it: the DPIA is approved, human review is substantive, the fallback has been tested, operators are
trained. Each of those was true when someone said so. A year later nobody knows. So a claim that lowers the risk carries an **attestation**, who confirmed it and
when, and lapses after a period unless someone confirms it again. A claim that raises the risk (drift detected, a breach) never lapses: there is nothing to
re-confirm about bad news.

The server stamps the attestation, never the browser: saving a design records the signed-in person against every governed claim whose value they changed, and
ignores any attestation the client sends. A claim that was already in a design before this existed has no attestation ("never confirmed") until someone confirms
it, so that no one is credited with a statement they did not make.

A lapse is advice, not a verdict. It is shown beside the claim, in the assurance gap and in the assurance pack; it does not change the score. Compliance sets the
validity period of each claim for the organisation.
"""
import math
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

SOON_DAYS = 14
MAX_DAYS = 730

# fact: (what it says, default days of validity, the values that lower the risk: None means "true")
GOVERNED: Dict[str, Dict[str, Any]] = {
    "dpia_approved": {"label": "Data protection impact assessment approved", "days": 365},
    "model_card_approved": {"label": "Model card approved", "days": 365},
    "provider_sla_gdpr_dpa": {"label": "Provider agreement covers GDPR", "days": 365},
    "hitl_formally_specified": {"label": "Human oversight formally specified", "days": 365},
    "policy_hallucination_acknowledged": {"label": "Hallucination risk accepted by policy", "days": 365},
    "liability_boundary_declared": {"label": "Liability boundary declared", "days": 365},
    "right_to_challenge_documented": {"label": "People can challenge a decision", "days": 365},
    "fallback_procedure_exists": {"label": "A fallback procedure exists", "days": 365},
    "fallback_tested": {"label": "The fallback has been tested", "days": 180},
    "output_validation_gate_configured": {"label": "An output validation gate is configured", "days": 180},
    "operator_training_complete": {"label": "Operators are trained", "days": 365},
    "hitl_verified_substantive": {"label": "Human review is substantive", "days": 90, "default_true": True},
    "audit_frequency": {"label": "Audit frequency", "days": 90, "favourable": ["CONTINUOUS", "DAILY"]},
    "rollback_mode": {"label": "Rollback", "days": 180, "favourable": ["AUTOMATED"]},
    "deployment_mode": {"label": "Release approach", "days": 180, "favourable": ["CANARY", "SHADOW", "BLUE_GREEN"]},
}


def relied_on(fact: str, life: Dict[str, Any]) -> bool:
    """Is the model's score leaning on this claim: is it stated in the way that lowers the risk?"""
    g = GOVERNED[fact]
    v = life.get(fact)
    if "favourable" in g:
        return v in g["favourable"]
    if v is None:
        return bool(g.get("default_true"))                    # the framework counts human review as substantive unless it is said not to be
    return v is True


def clean_days(raw: Dict[str, Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for k, v in (raw or {}).items():
        if k not in GOVERNED:
            raise ValueError(f"'{k}' is not a claim that can lapse. Known: {', '.join(GOVERNED)}.")
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"The period for '{k}' must be a whole number of days.")
        if not 7 <= n <= MAX_DAYS:
            raise ValueError(f"The period for '{k}' must be between 7 and {MAX_DAYS} days.")
        out[k] = n
    return out


def days_for(fact: str, policy: Optional[Dict[str, int]]) -> int:
    return int((policy or {}).get(fact, GOVERNED[fact]["days"]))


def stamp(old_doc: Optional[Dict[str, Any]], new_doc: Dict[str, Any], by: str, now_iso: str) -> Dict[str, Any]:
    """The attestations a saved design should carry. They come from what is stored and from what this save changed, never from what the client sent."""
    old_life = (old_doc or {}).get("life") or {}
    old_att = dict((old_doc or {}).get("attest") or {})
    new_life = new_doc.get("life") or {}
    out: Dict[str, Any] = {}
    for fact in GOVERNED:
        if fact not in new_life:
            continue                                                  # no longer stated: nothing to attest
        if fact not in old_life or old_life.get(fact) != new_life.get(fact):
            out[fact] = {"by": by, "at": now_iso, "value": new_life[fact]}
        elif fact in old_att and old_att[fact].get("value") == new_life[fact]:
            out[fact] = old_att[fact]
    return out


def confirm(life: Dict[str, Any], attest: Dict[str, Any], facts: List[str], by: str, now_iso: str) -> Dict[str, Any]:
    """The attestations after `by` confirms `facts` as they stand now. Raises ValueError for a claim that is not stated or cannot lapse."""
    out = dict(attest or {})
    for f in facts:
        if f not in GOVERNED:
            raise ValueError(f"'{f}' is not a claim that can lapse.")
        if f not in life and not (GOVERNED[f].get("default_true") and True):
            raise ValueError(f"'{f}' has not been stated for this model, so there is nothing to confirm.")
        out[f] = {"by": by, "at": now_iso, "value": life.get(f, True if GOVERNED[f].get("default_true") else None)}
    return out


def evaluate(life: Dict[str, Any], attest: Dict[str, Any], policy: Optional[Dict[str, int]], now: datetime) -> List[Dict[str, Any]]:
    """One row per claim the score leans on: who confirmed it, when it lapses, and whether it has."""
    rows: List[Dict[str, Any]] = []
    for fact, g in GOVERNED.items():
        if not relied_on(fact, life or {}):
            continue
        days = days_for(fact, policy)
        a = (attest or {}).get(fact)
        row: Dict[str, Any] = {"fact": fact, "label": g["label"], "value": (life or {}).get(fact), "days": days, "by": None, "at": None, "expires_at": None, "days_left": None, "state": "never"}
        if a and a.get("value") == (life or {}).get(fact, a.get("value")) and a.get("at"):
            at = datetime.fromisoformat(a["at"])
            exp = at + timedelta(days=days)
            left = (exp - now).total_seconds() / 86400
            row.update(by=a.get("by"), at=a["at"], expires_at=exp.isoformat(), days_left=math.floor(left))
            row["state"] = "lapsed" if left < 0 else ("due_soon" if left <= SOON_DAYS else "current")
        rows.append(row)
    return rows


def summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"claims": len(rows), "current": 0, "due_soon": 0, "lapsed": 0, "never": 0}
    for r in rows:
        out[r["state"]] += 1
    return out
