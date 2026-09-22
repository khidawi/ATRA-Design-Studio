"""ST-AI Framework — Risk Profiles
=================================================================

Pillar weights for the composite-risk computation are *not* magic
numbers — they are a published policy parameter that adopters may
override. Each profile reflects how a particular industry or
regulatory context prioritises the six risk pillars.

Profiles are normalised so weights sum to exactly 1.000. Composite
score under any profile remains on the 0–100 scale, comparable across
profiles for the same deployment (the same input scored under a
healthcare profile vs a financial profile will differ — that's the
whole point).

Default profile is BALANCED (the original weights from the spec).
"""
from enum import Enum
from typing import Dict


class RiskProfileEnum(str, Enum):
    """Industry / regulatory profiles that adjust pillar weights.

    BALANCED         — default, balanced across all pillars.
    HEALTHCARE       — weights Severity heaviest (patient harm).
    FINANCIAL        — weights Vulnerability heaviest (fraud, manipulation).
    SAFETY_CRITICAL  — weights Autonomy + Severity (avionics, automotive).
    PUBLIC_SECTOR    — weights Uncertainty + Evolution (accountability).
    RESEARCH         — weights Uncertainty heaviest (epistemic risk).
    """
    BALANCED        = "BALANCED"
    HEALTHCARE      = "HEALTHCARE"
    FINANCIAL       = "FINANCIAL"
    SAFETY_CRITICAL = "SAFETY_CRITICAL"
    PUBLIC_SECTOR   = "PUBLIC_SECTOR"
    RESEARCH        = "RESEARCH"


# Each profile = (W_LIKE, W_SEV, W_VULN, W_UNCERT, W_AUTONOMY, W_EVOLUTION)
# Weights must sum to 1.000 exactly.
RISK_PROFILES: Dict[RiskProfileEnum, Dict[str, float]] = {
    RiskProfileEnum.BALANCED: {
        "Likelihood":    0.20,
        "Severity":      0.25,
        "Vulnerability": 0.20,
        "Uncertainty":   0.10,
        "Autonomy":      0.15,
        "Evolution":     0.10,
    },
    RiskProfileEnum.HEALTHCARE: {
        "Likelihood":    0.15,
        "Severity":      0.35,   # patient harm dominates
        "Vulnerability": 0.15,
        "Uncertainty":   0.15,   # diagnostic uncertainty matters
        "Autonomy":      0.15,
        "Evolution":     0.05,
    },
    RiskProfileEnum.FINANCIAL: {
        "Likelihood":    0.20,
        "Severity":      0.20,
        "Vulnerability": 0.30,   # adversarial manipulation is the killer risk
        "Uncertainty":   0.10,
        "Autonomy":      0.10,
        "Evolution":     0.10,
    },
    RiskProfileEnum.SAFETY_CRITICAL: {
        "Likelihood":    0.10,
        "Severity":      0.30,
        "Vulnerability": 0.15,
        "Uncertainty":   0.10,
        "Autonomy":      0.25,   # autonomous action without humans is catastrophic
        "Evolution":     0.10,
    },
    RiskProfileEnum.PUBLIC_SECTOR: {
        "Likelihood":    0.15,
        "Severity":      0.20,
        "Vulnerability": 0.15,
        "Uncertainty":   0.20,   # accountability requires defensible certainty
        "Autonomy":      0.15,
        "Evolution":     0.15,   # policy changes shift risk over time
    },
    RiskProfileEnum.RESEARCH: {
        "Likelihood":    0.15,
        "Severity":      0.15,
        "Vulnerability": 0.15,
        "Uncertainty":   0.30,   # epistemic risk is the central concern
        "Autonomy":      0.10,
        "Evolution":     0.15,
    },
}


# Quick sanity check at import time — every profile sums to 1.000
for _profile_name, _weights in RISK_PROFILES.items():
    _total = sum(_weights.values())
    assert abs(_total - 1.0) < 1e-6, (
        f"Risk profile {_profile_name.value} weights sum to {_total}, must be 1.0"
    )


def get_weights(profile: RiskProfileEnum) -> Dict[str, float]:
    """Return the pillar-weight dict for a profile."""
    return RISK_PROFILES.get(profile, RISK_PROFILES[RiskProfileEnum.BALANCED])


_PROFILE_DESCRIPTIONS = {
    RiskProfileEnum.BALANCED:        "Default profile — balanced weights, suitable when no specialised regulatory context applies.",
    RiskProfileEnum.HEALTHCARE:      "Weights Severity heaviest. Use for clinical decision support, diagnostic imaging, drug-discovery AI, and any system whose output influences patient outcomes.",
    RiskProfileEnum.FINANCIAL:       "Weights Vulnerability heaviest. Use for credit decisions, fraud detection, algorithmic trading, AML/KYC, and any system exposed to adversarial manipulation.",
    RiskProfileEnum.SAFETY_CRITICAL: "Weights Autonomy and Severity. Use for avionics, automotive ADAS/AD, industrial control, robotics, and any AI whose autonomous action can cause physical harm.",
    RiskProfileEnum.PUBLIC_SECTOR:   "Weights Uncertainty and Evolution. Use for government services, benefits decisions, judicial AI, and any system subject to public-accountability requirements.",
    RiskProfileEnum.RESEARCH:        "Weights Uncertainty heaviest. Use for scientific-discovery AI, pre-deployment academic models, and experimental systems where epistemic confidence is the primary concern.",
}


def profile_description(profile: RiskProfileEnum) -> str:
    return _PROFILE_DESCRIPTIONS.get(profile, "")
