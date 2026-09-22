from dataclasses import dataclass
from framework.enums import Importance


@dataclass
class SecurityElement:
    name: str
    importance: Importance


def default_security_elements():
    return [
        "Data governance",
        "Model integrity",
        "Access control",
        "Monitoring & logging",
        "Validation & testing",
        "Human oversight",
        "Incident response"
    ]