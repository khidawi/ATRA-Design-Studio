"""ST-AI Framework — Audit Journal
=================================================================

Append-only JSONL log of every state change, gate transition, and
incident. Each entry is timestamped and stamped with the framework
version. Downloadable from the Export page.

This is the foundation for:
    • Reproducibility (every score can be re-derived from the journal)
    • Inter-assessor reliability studies (compare two journals for the
      same deployment)
    • ISO/IEC 42001 §9.1 monitoring evidence
    • EU AI Act Art 12 record-keeping requirements

Daily Merkle root signing is a planned v1.1 feature; current v1.0
journal is a plain JSONL stream.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Any, Dict, Optional
import json
import hashlib


@dataclass
class JournalEntry:
    """A single immutable log entry.

    Once written, an entry is never modified or deleted. Corrections
    are appended as new entries with `correction_of` pointing to the
    original entry's hash.
    """
    timestamp:      str        # ISO-8601 UTC
    framework_version: str
    event_type:     str        # see EventType class below
    payload:        Dict[str, Any]
    actor:          Optional[str] = None    # user identifier where known
    correction_of:  Optional[str] = None    # hash of entry being corrected

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @property
    def content_hash(self) -> str:
        """Stable SHA-256 of the canonical JSON serialisation."""
        return hashlib.sha256(self.to_jsonl().encode("utf-8")).hexdigest()


class EventType:
    """Standard event type strings — keep these stable across versions."""
    REGISTRY_INITIALISED        = "REGISTRY_INITIALISED"
    REGISTRY_FIELD_CHANGED      = "REGISTRY_FIELD_CHANGED"
    TERMS_DERIVED               = "TERMS_DERIVED"
    GATE_TRANSITION             = "GATE_TRANSITION"
    BLOCKER_RAISED              = "BLOCKER_RAISED"
    BLOCKER_CLEARED             = "BLOCKER_CLEARED"
    INCIDENT_LOGGED             = "INCIDENT_LOGGED"
    INCIDENT_STATUS_CHANGED     = "INCIDENT_STATUS_CHANGED"
    INCIDENT_RESOLVED           = "INCIDENT_RESOLVED"
    EVIDENCE_ATTACHED           = "EVIDENCE_ATTACHED"
    REPORT_GENERATED            = "REPORT_GENERATED"
    PROFILE_CHANGED             = "PROFILE_CHANGED"
    ASSESSMENT_MODE_CHANGED     = "ASSESSMENT_MODE_CHANGED"


class AuditJournal:
    """Append-only journal for a session.

    In v1.0 the journal lives in memory and is dumped to a downloadable
    JSONL file from the Export page. v1.1 will add daily Merkle-root
    signing and persistent storage.
    """

    def __init__(self):
        self._entries: List[JournalEntry] = []

    def append(
        self,
        event_type: str,
        payload: Dict[str, Any],
        actor: Optional[str] = None,
        correction_of: Optional[str] = None,
    ) -> JournalEntry:
        """Append a new entry. Returns the entry (with content hash)."""
        from framework import __version__
        entry = JournalEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            framework_version=__version__,
            event_type=event_type,
            payload=payload,
            actor=actor,
            correction_of=correction_of,
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> List[JournalEntry]:
        return list(self._entries)

    def filter_by_type(self, event_type: str) -> List[JournalEntry]:
        return [e for e in self._entries if e.event_type == event_type]

    def to_jsonl(self) -> str:
        """Serialise the entire journal as JSONL (one JSON object per line)."""
        return "\n".join(e.to_jsonl() for e in self._entries)

    @property
    def merkle_root(self) -> str:
        """SHA-256 of concatenated entry hashes — chain-of-custody fingerprint.

        Two journals with identical entries will share the same root.
        Tampering with any single entry changes the root.
        """
        if not self._entries:
            return ""
        h = hashlib.sha256()
        for e in self._entries:
            h.update(e.content_hash.encode("ascii"))
        return h.hexdigest()

    def summary(self) -> Dict[str, int]:
        """Counts per event type."""
        out: Dict[str, int] = {}
        for e in self._entries:
            out[e.event_type] = out.get(e.event_type, 0) + 1
        return out

    def __len__(self) -> int:
        return len(self._entries)
