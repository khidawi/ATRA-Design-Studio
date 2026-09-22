from typing import Dict, List
from framework.enums import OrganisationSize, Criticality, Importance
from framework.models import Organisation, AISystem, Roles


def compute_residual_risk(
    org: Organisation,
    ai: AISystem,
    roles: Roles,
    security_importance: Dict[str, Importance]
) -> Dict:
    observations: List[str] = []

    # Base risk from AI criticality
    risk_score = {
        Criticality.LOW: 1,
        Criticality.MEDIUM: 2,
        Criticality.HIGH: 3,
        Criticality.CRITICAL: 4
    }[ai.operational_criticality]

    # Organisation size modifier (proportionality)
    size_modifier = {
        OrganisationSize.MICRO: 1.2,
        OrganisationSize.SMALL: 1.1,
        OrganisationSize.MEDIUM: 1.0,
        OrganisationSize.LARGE: 0.9,
        OrganisationSize.ENTERPRISE: 0.8
    }[org.size]

    # Role Concentration Factor
    rcf = roles.role_concentration_factor()
    if rcf == 1:
        risk_score += 1
        observations.append(
            "All AI lifecycle roles are concentrated within a single actor, "
            "increasing governance and assurance risk."
        )

    # Validation importance check
    if (
        security_importance.get("Validation & Testing")
        in (Importance.LOW, Importance.MEDIUM)
        and ai.operational_criticality == Criticality.CRITICAL
    ):
        risk_score += 1
        observations.append(
            "Validation importance may be insufficient given the system criticality."
        )

    adjusted_risk = round(risk_score * size_modifier, 2)

    return {
        "base_risk": risk_score,
        "size_modifier": size_modifier,
        "adjusted_risk": adjusted_risk,
        "observations": observations,
        "rcf": rcf
    }