"""
The independence guards of the ST-AI v2.5 model, over the organisation's reporting structure.

Approving, reviewing and attesting need a person who is independent of the people who hold the model's roles, at the level the policy declares for that use:

  PERSON          a different person
  REPORTING_LINE  a different person, and neither supervises the other (neither heads a unit at or above the other's primary unit)
  UNIT            as REPORTING_LINE, and the two have different primary units

The structure is the organisation's own (departments with their parent and head, people with their department: the Organisation screen). Missing or contradictory data
(someone not placed in the structure, a head rule violation, a unit with no head above them) gives UNKNOWN, and an UNKNOWN never meets a requirement: above PERSON level, a
person the organisation does not place cannot approve or review. The mode decides when this is judged: AT_ACT when the person acts, CONTINUING also whenever the design is
assessed again, so a reorganisation that removes the independence makes the review lapse.
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

import st_ai_gate as G
import st_ai_policy as P

ROLES = ("trainer", "validator", "deployer", "operator")


def structure_from_graph(N: Dict[str, Dict[str, Any]]) -> G.Structure:
    """The reporting structure of the organisation graph: a mapping of node id to {type, name, props}."""
    s = G.Structure()
    for i, n in N.items():
        if n["type"] == "department":
            s.parent[i] = n["props"].get("parent") or None
            head = n["props"].get("head")
            s.head[i] = (N.get(head) or {}).get("name") if head else None
    for n in N.values():
        if n["type"] in ("person", "role"):
            dept = n["props"].get("department")
            s.unit_of[n["name"]] = dept if dept in s.parent else None
    return s


def organisation_structure(session: Session) -> G.Structure:
    import company
    N, _ = company._graph(session)
    return structure_from_graph(N)


def role_holders(registry) -> Dict[str, str]:
    return {r: getattr(registry.actors, r).identity for r in ROLES if (getattr(registry.actors, r).identity or "").strip()}


def problems_for(subject: Optional[str], holders: Dict[str, str], level: str, structure: Optional[G.Structure]) -> List[str]:
    """Why `subject` is not independent of the people holding the model's roles at this level (empty: independent of all of them)."""
    out: List[str] = []
    who = (subject or "").strip()
    if not who:
        return ["nobody is named"]
    for role, holder in sorted(holders.items()):
        r = G.independent(who, holder, level, structure)
        if r == G.T:
            continue
        if r == G.F:
            out.append(f"{who} is not independent of the {role} ({holder}) at the level {level}")
        else:
            out.append(f"it cannot be established that {who} is independent of the {role} ({holder}) at the level {level}: the organisation's structure does not place both people, or has no head for a unit above them")
    return out


def check(session: Session, policy: Dict[str, Any], use: str, subject: Optional[str], registry) -> Tuple[List[str], str, str]:
    """(problems, level, mode) for a person acting in `use` (approval, review, attestation) on this model."""
    level, mode = P.independence_requirement(policy, use)
    structure = organisation_structure(session) if level != G.LEVEL_PERSON else None
    return problems_for(subject, role_holders(registry), level, structure), level, mode
