"""ST-AI Framework — Assessment Modes
=================================================================

Three assessment modes with progressively stricter evidence requirements,
modelled on ISO 27001's Stage 1 / Stage 2 audit pattern.

SELF       — declarations accepted on trust.
             Suitable for internal risk visibility; not for compliance claims.

VALIDATED  — every "approved" boolean requires an attestor identifier
             (email or staff ID) and a date. Internal sign-off by a named
             individual.

AUDITED    — every "approved" boolean requires a signed evidence object:
             (1) document URL or SHA-256 hash, (2) attestor identifier,
             (3) attestation date, (4) expiry date. Suitable for external
             audit and regulatory submission.

Gate thresholds tighten with mode: under AUDITED, missing evidence is a
hard blocker; under VALIDATED it is a warning; under SELF it is silent.
"""
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from datetime import date


class AssessmentModeEnum(str, Enum):
    SELF      = "SELF"
    VALIDATED = "VALIDATED"
    AUDITED   = "AUDITED"


@dataclass
class Evidence:
    """Optional evidence attachment for a declaration.

    Used in VALIDATED and AUDITED modes to back up "approved" booleans
    with attestor + document references.
    """
    attestor:        Optional[str]  = None   # email or staff ID of approver
    attested_on:     Optional[date] = None   # date of attestation
    expires_on:      Optional[date] = None   # date the evidence ceases to be valid
    document_url:    Optional[str]  = None   # canonical location of the evidence document
    document_sha256: Optional[str]  = None   # SHA-256 hash of the evidence document
    note:            Optional[str]  = None   # free-text supplementary note

    def is_valid_under(self, mode: AssessmentModeEnum, today: Optional[date] = None) -> bool:
        """Whether this evidence is sufficient under the given mode."""
        today = today or date.today()
        if mode == AssessmentModeEnum.SELF:
            return True   # no evidence required
        if mode == AssessmentModeEnum.VALIDATED:
            return bool(self.attestor and self.attested_on)
        if mode == AssessmentModeEnum.AUDITED:
            if not (self.attestor and self.attested_on):
                return False
            if not (self.document_url or self.document_sha256):
                return False
            if self.expires_on is not None and self.expires_on < today:
                return False
            return True
        return False

    def status_text(self, mode: AssessmentModeEnum, today: Optional[date] = None) -> str:
        """Short human-readable status string for the UI."""
        if mode == AssessmentModeEnum.SELF:
            return "Declaration accepted (SELF mode)"
        today = today or date.today()
        if not self.attestor:
            return "⚠ Attestor missing"
        if not self.attested_on:
            return "⚠ Attestation date missing"
        if mode == AssessmentModeEnum.AUDITED:
            if not (self.document_url or self.document_sha256):
                return "⛔ Document reference missing (AUDITED mode)"
            if self.expires_on is not None and self.expires_on < today:
                return f"⛔ Evidence expired on {self.expires_on.isoformat()}"
        return f"✓ {self.attestor} on {self.attested_on.isoformat()}"


_MODE_DESCRIPTIONS = {
    AssessmentModeEnum.SELF: (
        "Self-assessment — declarations accepted on trust. Use for internal "
        "risk visibility only. Not suitable for compliance claims, audits, "
        "or regulatory submissions. Gate decisions are advisory."
    ),
    AssessmentModeEnum.VALIDATED: (
        "Validated assessment — every 'approved' boolean requires an attestor "
        "identifier (email or staff ID) and a date of attestation. Suitable "
        "for internal sign-off by a named individual. Gate decisions carry "
        "the weight of the attestor's authority."
    ),
    AssessmentModeEnum.AUDITED: (
        "Audited assessment — every 'approved' boolean requires a signed "
        "evidence object: document URL or SHA-256 hash, attestor identifier, "
        "attestation date, and (optional) expiry date. Suitable for external "
        "audit and regulatory submission. Gate decisions are auditor-grade."
    ),
}


def mode_description(mode: AssessmentModeEnum) -> str:
    return _MODE_DESCRIPTIONS.get(mode, "")


_MODE_COLOURS = {
    AssessmentModeEnum.SELF:      "#7a8aab",
    AssessmentModeEnum.VALIDATED: "#1976d2",
    AssessmentModeEnum.AUDITED:   "#6a1b9a",
}


def mode_colour(mode: AssessmentModeEnum) -> str:
    return _MODE_COLOURS.get(mode, "#7a8aab")
