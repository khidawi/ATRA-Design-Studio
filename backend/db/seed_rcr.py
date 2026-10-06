"""
Requirement registries for the agent design-time RCR score, seeded from the two
profiles Sam's Agent design studio carried in its page (payments, healthcare),
with the instruments and weights from RCR_Algorithm_Step_by_Step.

The weights, floors and partial credit are judgement-assigned and not yet
calibrated against assessor ratings (see rcr_engine.py). Applied once; edits made
later are never overwritten. The default declarations are demo content so a new
design starts with something to look at: they are declarations, not facts, and a
veto requirement still needs reviewer sign-off before it counts as Covered.
"""
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AppSetting, RcrProfile, RcrRequirement

log = logging.getLogger("stai.db")
SEED_VERSION = 1
SEED_SETTING = "rcr_seed_version"


def _sel(type_, where=None):
    out = {"type": type_}
    if where:
        out["where"] = where
    return out


def _check(satisfied_if, ok, missing, vars_=None):
    cfg = {"satisfied_if": satisfied_if, "messages": {"satisfied": ok, "unsatisfied": missing}}
    if vars_:
        cfg["vars"] = vars_
    return cfg


APPROVAL = _check({"exists": _sel("approval")}, "Approval step in the design", "No approval step gates the refund tool")
OWNER = _check({"exists": {"type": "agent", "primary": True, "where": {"owner": {"nonempty": True}}}},
               "Owner {owner} assigned in the design", "No owner holds the kill switch",
               {"owner": {"prop": {"select": {"primary": True}, "name": "owner"}}})
RETENTION = _check({"exists": _sel("constraint", {"kind": "retention"})}, "Retention constraint in the design", "Not yet assessed")
DISCLOSURE = _check({"exists": _sel("guardrail", {"kind": "disclosure"})}, "Disclosure guardrail in the design",
                    "Customers not told they are dealing with AI")


def R(key, name, instrument, cls, w, phi=None, check=None, unsat="Gap", default=None):
    return dict(req_key=key, name=name, instrument=instrument, cls=cls, weight=w, phi=phi,
                design_check=check, unsatisfied_declared=unsat, default_declaration=default)


PROFILES = [
    dict(profile_key="payments", name="Payments", requirements=[
        R("dpia", "GDPR Art. 35 — DPIA", "GDPR", "veto", 3, 0.85, default={"status": "Covered", "evidence": "DPIA on file (DOC-114)"}),
        R("approval", "Human approval for refunds (org policy)", "Org policy", "veto", 3, 0.90, APPROVAL),
        R("owner", "OWASP ASI10 — owner and kill switch", "OWASP ASI", "veto", 2, 0.80, OWNER),
        R("lawful", "Lawful basis for customer data", "GDPR", "ordinary", 2, default={"status": "Covered", "evidence": "Contract basis recorded"}),
        R("retention", "Retention limit", "GDPR", "ordinary", 1, check=RETENTION, unsat="Unmapped"),
        R("disclosure", "AI disclosure to customers (org policy)", "Org policy", "ordinary", 1, check=DISCLOSURE),
    ]),
    dict(profile_key="healthcare", name="Healthcare", requirements=[
        R("dpia", "GDPR Art. 35 — DPIA", "GDPR", "veto", 3, 0.85, default={"status": "Gap", "evidence": ""}),
        R("oversight", "EU AI Act Art. 14 — human oversight", "EU AI Act", "veto", 3, 0.90,
          default={"status": "Partial", "evidence": "Reviewer sees flagged emails, not every send"}),
        R("owner", "OWASP ASI10 — owner and kill switch", "OWASP ASI", "veto", 2, 0.80, OWNER),
        R("lawful", "Lawful basis for patient data", "GDPR", "ordinary", 2, default={"status": "Covered", "evidence": "Consent on file"}),
        R("retention", "Retention limit", "GDPR", "ordinary", 1, check=RETENTION, unsat="Unmapped"),
        R("access", "Staff access policy note", "Org policy", "ordinary", 1, default={"status": "Covered", "evidence": "Policy note SAP-07"}),
    ]),
]


def ensure_rcr_profiles(session: Session) -> None:
    current = session.get(AppSetting, SEED_SETTING)
    if current is not None and int(current.value) >= SEED_VERSION:
        return
    existing = {p.profile_key for p in session.scalars(select(RcrProfile))}
    for position, spec in enumerate(PROFILES):
        if spec["profile_key"] in existing:
            continue
        profile = RcrProfile(profile_key=spec["profile_key"], name=spec["name"], position=position)
        session.add(profile)
        session.flush()
        for i, req in enumerate(spec["requirements"]):
            session.add(RcrRequirement(profile_id=profile.id, position=i, **req))
    if current is None:
        session.add(AppSetting(key=SEED_SETTING, value=str(SEED_VERSION)))
    else:
        current.value = str(SEED_VERSION)
    session.commit()
    log.info("Seeded RCR profiles (version %s)", SEED_VERSION)
