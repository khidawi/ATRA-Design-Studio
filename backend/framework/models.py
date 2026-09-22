from dataclasses import dataclass
from framework.enums import OrganisationSize, Criticality, ActorType


@dataclass
class Organisation:
    size: OrganisationSize
    sector: str
    security_maturity: str


@dataclass
class AISystem:
    ai_type: str
    deployment_stage: str
    data_criticality: Criticality
    operational_criticality: Criticality


@dataclass
class Roles:
    training: ActorType
    deployment: ActorType
    validation: ActorType

    def role_concentration_factor(self) -> int:
        return len({self.training, self.deployment, self.validation})
