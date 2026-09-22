"""ST-AI Framework — Incident Tracking
=================================================================

Closes the NIST AI RMF "MANAGE" loop. Each Incident is a logged
operational event with classification, severity, time-to-detect,
time-to-resolve, and root cause.

Open incidents feed back into the rule engine:
    • Severity ≥ 4 open incident → L (Likelihood) gets +0.10
    • Recurring same-type incidents (≥3 in 90 days) → ε_b += 0.05
    • Critical-severity incident with no resolution after 72h →
      hard blocker until resolved

This is what makes ST-AI a system rather than a snapshot.
"""
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime, timedelta


class IncidentTypeEnum(str, Enum):
    DRIFT_DETECTION       = "DRIFT_DETECTION"
    BIAS_BREACH           = "BIAS_BREACH"
    SECURITY_EVENT        = "SECURITY_EVENT"
    MODEL_FAILURE         = "MODEL_FAILURE"
    SUPPLY_CHAIN          = "SUPPLY_CHAIN"
    REGULATORY_INQUIRY    = "REGULATORY_INQUIRY"
    DATA_BREACH           = "DATA_BREACH"
    AVAILABILITY_OUTAGE   = "AVAILABILITY_OUTAGE"
    HALLUCINATION_HARM    = "HALLUCINATION_HARM"
    HUMAN_OVERRIDE_FAILED = "HUMAN_OVERRIDE_FAILED"


class IncidentStatusEnum(str, Enum):
    OPEN       = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED  = "MITIGATED"
    RESOLVED   = "RESOLVED"
    POST_MORTEM = "POST_MORTEM"


class IncidentSeverityEnum(int, Enum):
    """1-5 scale, aligned with NIST SP 800-61 incident-handling severities."""
    LOW          = 1
    MODERATE     = 2
    HIGH         = 3
    SEVERE       = 4
    CRITICAL     = 5


@dataclass
class Incident:
    """A single logged incident.

    All datetimes are timezone-naive local. Times-to-X are derived
    properties, not stored.
    """
    incident_id:    str = ""
    incident_type:  IncidentTypeEnum = IncidentTypeEnum.DRIFT_DETECTION
    severity:       IncidentSeverityEnum = IncidentSeverityEnum.MODERATE
    status:         IncidentStatusEnum = IncidentStatusEnum.OPEN
    occurred_at:    Optional[datetime] = None
    detected_at:    Optional[datetime] = None
    mitigated_at:   Optional[datetime] = None
    resolved_at:    Optional[datetime] = None
    title:          str = ""
    description:    str = ""
    root_cause:     str = ""
    lessons_learned: str = ""
    affected_users: int = 0
    reporter:       str = ""
    owner:          str = ""

    @property
    def time_to_detect(self) -> Optional[timedelta]:
        if self.occurred_at and self.detected_at:
            return self.detected_at - self.occurred_at
        return None

    @property
    def time_to_mitigate(self) -> Optional[timedelta]:
        if self.detected_at and self.mitigated_at:
            return self.mitigated_at - self.detected_at
        return None

    @property
    def time_to_resolve(self) -> Optional[timedelta]:
        if self.detected_at and self.resolved_at:
            return self.resolved_at - self.detected_at
        return None

    @property
    def is_open(self) -> bool:
        return self.status in (IncidentStatusEnum.OPEN,
                               IncidentStatusEnum.INVESTIGATING)


@dataclass
class IncidentRegister:
    """Container for all logged incidents on a deployment."""
    incidents: List[Incident] = field(default_factory=list)

    def open_incidents(self) -> List[Incident]:
        return [i for i in self.incidents if i.is_open]

    def open_severe_or_worse(self) -> List[Incident]:
        return [i for i in self.open_incidents()
                if i.severity >= IncidentSeverityEnum.SEVERE]

    def recurring_in_window(
        self,
        type_: IncidentTypeEnum,
        window_days: int = 90,
        now: Optional[datetime] = None
    ) -> int:
        """Count incidents of the given type within the last `window_days`."""
        now = now or datetime.now()
        cutoff = now - timedelta(days=window_days)
        return sum(
            1 for i in self.incidents
            if i.incident_type == type_
            and i.detected_at is not None
            and i.detected_at >= cutoff
        )

    def unresolved_critical_over_72h(self, now: Optional[datetime] = None) -> List[Incident]:
        """Critical incidents open more than 72h — these block the gate."""
        now = now or datetime.now()
        cutoff = now - timedelta(hours=72)
        return [
            i for i in self.incidents
            if i.severity == IncidentSeverityEnum.CRITICAL
            and i.is_open
            and i.detected_at is not None
            and i.detected_at < cutoff
        ]

    @property
    def mean_time_to_resolve(self) -> Optional[timedelta]:
        """Average resolution time across resolved incidents."""
        resolved = [i.time_to_resolve for i in self.incidents
                    if i.time_to_resolve is not None]
        if not resolved:
            return None
        avg = sum(resolved, timedelta()) / len(resolved)
        return avg


_INCIDENT_COLOURS = {
    IncidentSeverityEnum.LOW:      "#1565c0",
    IncidentSeverityEnum.MODERATE: "#2e7d32",
    IncidentSeverityEnum.HIGH:     "#f9a825",
    IncidentSeverityEnum.SEVERE:   "#e65100",
    IncidentSeverityEnum.CRITICAL: "#c62828",
}


def severity_colour(severity: IncidentSeverityEnum) -> str:
    return _INCIDENT_COLOURS.get(severity, "#5a6680")
