from typing import List
from framework.enums import Criticality, OrganisationSize, Importance
from framework.models import Organisation, AISystem, Roles


def assess_risk(
    organisation: Organisation,
    ai_system: AISystem,
    roles: Roles,
    security_elements: dict
) -> List[str]:
    """
    Assess contextual and organisational risk factors for an AI deployment.
    Returns a list of qualitative risk observations.
    """

    observations: List[str] = []

    # Role concentration risk
    if (
        roles.role_concentration() == 1
        and ai_system.operational_criticality in
        (Criticality.HIGH, Criticality.CRITICAL)
    ):
        observations.append(
            "Training, deployment, and validation are performed by the same actor "
            "for a high‑criticality AI system, increasing assurance and governance risk."
        )

    # Resource constraints (organisation size)
    if organisation.size in (OrganisationSize.MICRO, OrganisationSize.SMALL):
        observations.append(
            "Organisation size suggests limited resources. Compensating controls "
            "and external assurance mechanisms may be required."
        )

    # Validation importance mismatch
    if (
        security_elements.get("Validation & testing")
        in (Importance.LOW, Importance.MEDIUM)
        and ai_system.operational_criticality == Criticality.CRITICAL
    ):
        observations.append(
            "Validation and testing importance may be insufficient for a "
            "critical AI system."
        )

    return observations
