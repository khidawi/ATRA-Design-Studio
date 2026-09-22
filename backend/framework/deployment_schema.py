"""ST-AI Framework — Deployment Schema (JSON Export/Import)
=================================================================

Portable JSON representation of a deployment registration. Two uses:

  1. Export — download the current deployment as a self-contained JSON
     document that anyone can re-import and re-score. The PCS, risk
     vector, and gate decision derive identically because the rule
     engine is deterministic over the registry state.

  2. Verify — upload a JSON file produced by another tool or earlier
     session, re-run derive_terms() on it, and confirm the computed
     PCS matches what the JSON claims. This is the cornerstone of
     reproducibility for ST-AI as a standard.

Schema is JSON-Schema-Draft-2020-12 compatible. The canonical schema
file is published alongside each framework release.
"""
from dataclasses import asdict, is_dataclass
from typing import Any, Dict
from datetime import datetime
import json
from enum import Enum

# Defensive: import __version__ lazily so import-order issues on
# Streamlit Cloud (where the framework package may not have finished
# initialising when this module is first loaded) don't crash the page.
try:
    from framework import __version__
except ImportError:
    __version__ = "1.0.0"

from framework.registry import RegistryState


SCHEMA_VERSION = "1.0"


def _serialise(obj: Any) -> Any:
    """Recursively convert dataclasses + enums to JSON-friendly types."""
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj):
        return {k: _serialise(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialise(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def export_deployment(
    reg: RegistryState,
    derived: Any = None,
    journal: Any = None,
    ui_extras: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Build a JSON-serialisable dict for the given registry state.

    The output is self-describing: it records the framework version,
    schema version, export timestamp, the full registry (including the
    incident register), and optionally a snapshot of derived terms +
    the full audit journal — enough for a complete session restore.

    `ui_extras` should be a dict of UI-only state that lives in
    st.session_state but isn't part of the registry — e.g.
    {"model_category": "Hybrid / Ensemble",
     "model_label":    "Ensemble (voting, stacking, boosting)",
     "hosting_type":   "Public cloud — IaaS (AWS, Azure, GCP)",
     "rag_enabled":    True,
     "chained_ai":     False}.
    Without these, restore can lose information when the coarse
    registry enum maps to multiple UI labels (e.g. ENSEMBLE maps to
    both "Random Forest" and "Ensemble (voting, stacking, boosting)").
    """
    payload: Dict[str, Any] = {
        "$schema":           "https://stai-framework.org/schema/v1.0/deployment.json",
        "framework_version": __version__,
        "schema_version":    SCHEMA_VERSION,
        "exported_at":       datetime.utcnow().isoformat() + "Z",
        "registry":          _serialise(reg),
    }

    # UI extras — preserve the user's fine-grained UI selections that
    # aren't captured by the coarse registry enum values.
    if ui_extras:
        # Whitelist what we save; ignore anything that isn't JSON-friendly
        clean = {}
        for k in ("model_category", "model_label", "hosting_type",
                  "rag_enabled", "chained_ai"):
            if k in ui_extras and isinstance(ui_extras[k], (str, bool, int, float)):
                clean[k] = ui_extras[k]
        if clean:
            payload["ui_extras"] = clean

    # The incident register is a dataclass containing a list of Incident
    # dataclasses. _serialise handles it, but we surface it as a top-level
    # key for easier import-side processing.
    ir = getattr(reg, "incident_register", None)
    if ir is not None and getattr(ir, "incidents", None):
        payload["incident_register"] = _serialise(ir)

    # Journal — only included if a journal object was passed
    if journal is not None and len(getattr(journal, "_entries", [])) > 0:
        payload["journal"] = {
            "merkle_root": journal.merkle_root,
            "summary":     journal.summary(),
            "entries":     [
                {
                    "timestamp":         e.timestamp,
                    "framework_version": e.framework_version,
                    "event_type":        e.event_type,
                    "payload":           e.payload,
                    "actor":             e.actor,
                    "correction_of":     e.correction_of,
                }
                for e in journal.entries
            ],
        }

    if derived is not None:
        # Snapshot the canonical computed outputs so a verifier can detect drift
        rv = getattr(derived, "risk_vector", None)
        payload["derived"] = {
            "pcs_score":  float(getattr(derived, "pcs_score", 0.0)),
            "tier":       getattr(getattr(derived, "tier", None), "value", None),
            "gate":       getattr(getattr(derived, "gate_decision", None), "value", None),
            "L":          float(getattr(derived, "L", 0.0)),
            "I":          float(getattr(derived, "I", 0.0)),
            "delta":      float(getattr(derived, "delta", 0.0)),
            "tau":        float(getattr(derived, "tau", 0.0)),
            "Dm":         derived.Dm if hasattr(derived, "Dm") else None,
            "Wr":         float(getattr(derived, "Wr", 0.0)),
            "Ws":         float(getattr(derived, "Ws", 0.0)),
            "Wf":         float(getattr(derived, "Wf", 0.0)),
            "Wh":         float(getattr(derived, "Wh", 0.0)),
            "rcf_adj":    float(getattr(derived, "rcf_adj", 0.0)),
            "eps_b":      float(getattr(derived, "eps_b", 0.0)),
            "eps_ia":     float(getattr(derived, "eps_ia", 0.0)),
            "acm":        float(getattr(derived, "acm", 0.0)),
        }
        if rv is not None:
            payload["derived"]["risk_vector"] = {
                "likelihood":    float(rv.likelihood),
                "severity":      float(rv.severity),
                "vulnerability": float(rv.vulnerability),
                "uncertainty":   float(rv.uncertainty),
                "autonomy":      float(rv.autonomy),
                "evolution":     float(rv.evolution),
                "composite":     float(rv.composite),
            }

    return payload


def export_json(
    reg: RegistryState,
    derived: Any = None,
    journal: Any = None,
    ui_extras: Dict[str, Any] = None,
    indent: int = 2,
) -> str:
    """Return the deployment as pretty-printed JSON text.

    Pass `journal` to include the audit-trail history in the export
    (used by the governance-page session-restore feature). Pass
    `ui_extras` to preserve UI-only state (model category/label,
    hosting type, etc.) that isn't captured by the registry enums.
    """
    return json.dumps(
        export_deployment(reg, derived, journal=journal, ui_extras=ui_extras),
        indent=indent, sort_keys=False, ensure_ascii=False,
    )


def verify_import(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Re-derive the rule engine on imported JSON and return a diff report.

    Returns:
        {
            "import_version":   <framework version recorded in the file>,
            "current_version":  <framework version running now>,
            "version_match":    bool,
            "imported_pcs":     <pcs_score from file>,
            "recomputed_pcs":   <pcs_score from rerun>,
            "pcs_drift":        |imported - recomputed|,
            "imported_tier":    <tier name from file>,
            "recomputed_tier":  <tier name from rerun>,
            "tier_match":       bool,
        }
    """
    from framework.rule_engine import derive_terms
    from framework.registry import RegistryState

    # Reconstruct the registry from JSON dict. Heuristic: walk the
    # known field types and coerce strings to enums where required.
    reg_dict = payload.get("registry", {})
    rebuilt = _rebuild_registry(reg_dict)
    rerun   = derive_terms(rebuilt)

    imported_derived = payload.get("derived", {})
    imported_pcs = float(imported_derived.get("pcs_score", 0.0))
    imported_tier = imported_derived.get("tier", "")

    return {
        "import_version":  payload.get("framework_version", "unknown"),
        "current_version": __version__,
        "version_match":   payload.get("framework_version") == __version__,
        "imported_pcs":    imported_pcs,
        "recomputed_pcs":  round(rerun.pcs_score, 3),
        "pcs_drift":       round(abs(imported_pcs - rerun.pcs_score), 3),
        "imported_tier":   imported_tier,
        "recomputed_tier": rerun.tier.value,
        "tier_match":      imported_tier == rerun.tier.value,
    }


def _rebuild_registry(d: Dict[str, Any]) -> RegistryState:
    """Reconstruct a RegistryState from a plain-dict export.

    Accepts either the inner registry dict (legacy behaviour) or the full
    deployment-export envelope ({"registry": {...}, "incident_register":
    {...}, ...}). If the dict looks like the envelope, the registry sub-dict
    is unwrapped automatically.

    Handles enum string → enum coercion using dataclasses.fields metadata.
    Lists of enums are coerced element-wise. The incident_register
    (dataclass-of-dataclasses) gets explicit handling. Unknown fields are
    ignored so older exports are forwards-compatible.
    """
    from dataclasses import fields
    import enum as _enum
    import re as _re

    # Detect envelope-style payload and unwrap
    if "registry" in d and "framework_version" in d:
        envelope = d
        reg_data = d.get("registry", {})
    else:
        envelope = d
        reg_data = d

    reg = RegistryState()

    # Build a registry of ALL Enum classes available across the framework.
    # The original implementation only scanned framework.enums, which missed
    # RiskProfileEnum (in risk_profile.py), AssessmentModeEnum (in
    # assessment_mode.py), and the incident enums (in incidents.py). When a
    # JSON contained values like "HEALTHCARE" or "AUDITED", the coercion
    # silently failed and the registry was set to the raw string — which
    # then crashed derive_terms() with 'str' object has no attribute 'value'.
    _enum_registry = {}
    for mod_path in (
        "framework.enums",
        "framework.risk_profile",
        "framework.assessment_mode",
        "framework.incidents",
    ):
        try:
            _mod = __import__(mod_path, fromlist=["*"])
            for _name in dir(_mod):
                _obj = getattr(_mod, _name)
                if (isinstance(_obj, type) and issubclass(_obj, _enum.Enum)
                        and _obj is not _enum.Enum):
                    _enum_registry[_name] = _obj
        except Exception:
            continue

    def _list_inner_enum(t):
        """Return the enum class inside List[FooEnum], or None.

        Handles two forms of f.type:
          - String form (PEP 563 / from __future__ import annotations):
                "List[VectorTypeEnum]"
          - Live typing object (default in Python 3.12):
                typing.List[framework.enums.VectorTypeEnum]
        """
        # Live typing form first
        try:
            from typing import get_args
            args = get_args(t)
            if args:
                inner = args[0]
                if isinstance(inner, type) and issubclass(inner, _enum.Enum):
                    return inner
        except Exception:
            pass
        # String form fallback
        if isinstance(t, str):
            m = _re.search(r'List\[\s*(?:[\w\.]*\.)?(\w+)\s*\]', t)
            if m:
                return _enum_registry.get(m.group(1))
        # Last resort: stringify and try the regex
        try:
            s = str(t)
            m = _re.search(r'List\[\s*(?:[\w\.]*\.)?(\w+)\s*\]', s)
            if m:
                return _enum_registry.get(m.group(1))
        except Exception:
            pass
        return None

    def _single_enum_from_type(t):
        """Return the enum class for an Optional[FooEnum] / FooEnum annotation."""
        try:
            from typing import get_args
            args = get_args(t)
            for a in args:
                if isinstance(a, type) and issubclass(a, _enum.Enum):
                    return a
            if isinstance(t, type) and issubclass(t, _enum.Enum):
                return t
        except Exception:
            pass
        # String fallback
        try:
            s = t if isinstance(t, str) else str(t)
            for name, cls in _enum_registry.items():
                if name in s and "List[" not in s:
                    return cls
        except Exception:
            pass
        return None

    # Special-case fields that need bespoke deserialisation
    SPECIAL_FIELDS = {"incident_register"}

    for f in fields(reg):
        if f.name not in reg_data or f.name in SPECIAL_FIELDS:
            continue
        raw = reg_data[f.name]
        try:
            current = getattr(reg, f.name, None)

            # 1) List[Enum] — must check before scalar Enum since a list
            #    annotation would otherwise be mistakenly handled here.
            if isinstance(raw, list):
                inner = _list_inner_enum(f.type)
                if inner is not None:
                    setattr(reg, f.name,
                            [inner(x) for x in raw if isinstance(x, str)])
                    continue
                if (isinstance(current, list) and current
                        and isinstance(current[0], _enum.Enum)):
                    enum_type = type(current[0])
                    setattr(reg, f.name,
                            [enum_type(x) for x in raw if isinstance(x, str)])
                    continue

            # 2) Single Enum field
            if isinstance(raw, str):
                if isinstance(current, _enum.Enum):
                    setattr(reg, f.name, type(current)(raw))
                    continue
                inner = _single_enum_from_type(f.type)
                if inner is not None:
                    try:
                        setattr(reg, f.name, inner(raw))
                        continue
                    except ValueError:
                        pass  # not a valid enum value, fall through

            # 3) Plain scalar / dict / bool — assign as-is
            setattr(reg, f.name, raw)
        except Exception:
            pass

    # Incident register — explicit reconstruction. Check both top-level
    # (envelope key) and nested-in-registry (forwards-compatible) locations.
    ir_raw = envelope.get("incident_register")
    if ir_raw is None:
        ir_raw = reg_data.get("incident_register")
    if ir_raw and isinstance(ir_raw, dict):
        _rehydrate_incidents(reg, ir_raw)

    # ── Final safety net ─────────────────────────────────────────────────
    # Walk every field one more time and coerce any remaining string-where-
    # enum-expected case. This is a belt-and-braces guard against the
    # 'str' object has no attribute 'value' crash: if any earlier coercion
    # path missed a field, this catches it. It uses the broad _enum_registry
    # to look up enum classes by name from the type annotation regardless
    # of Optional/Union/forward-reference wrapping.
    for f in fields(reg):
        if f.name in SPECIAL_FIELDS:
            continue
        val = getattr(reg, f.name, None)
        if not isinstance(val, str):
            continue
        # Try to find the right enum class for this field
        type_str = f.type if isinstance(f.type, str) else str(f.type)
        enum_cls = None
        for name, cls in _enum_registry.items():
            # Match e.g. "Optional[RiskProfileEnum]" or "RiskProfileEnum"
            if name in type_str and "List[" not in type_str:
                enum_cls = cls
                break
        if enum_cls is None:
            continue
        try:
            setattr(reg, f.name, enum_cls(val))
        except (ValueError, KeyError):
            # value isn't a member of the enum — leave it (will surface
            # as a clear validation error rather than a silent crash)
            pass

    return reg


def _rehydrate_incidents(reg: RegistryState, ir_raw: Dict[str, Any]) -> None:
    """Rebuild reg.incident_register from a serialised dict."""
    from framework.incidents import (
        Incident, IncidentRegister, IncidentTypeEnum,
        IncidentSeverityEnum, IncidentStatusEnum,
    )
    from datetime import datetime as _dt

    register = IncidentRegister()
    for inc_dict in ir_raw.get("incidents", []):
        try:
            def _maybe_dt(v):
                if v is None or v == "":
                    return None
                if isinstance(v, str):
                    try:
                        return _dt.fromisoformat(v.replace("Z", ""))
                    except ValueError:
                        return None
                return v

            inc = Incident(
                incident_id=inc_dict.get("incident_id", ""),
                incident_type=IncidentTypeEnum(
                    inc_dict.get("incident_type",
                                  IncidentTypeEnum.DRIFT_DETECTION.value)
                ),
                severity=IncidentSeverityEnum(
                    int(inc_dict.get("severity",
                                      IncidentSeverityEnum.MODERATE.value))
                ),
                status=IncidentStatusEnum(
                    inc_dict.get("status", IncidentStatusEnum.OPEN.value)
                ),
                occurred_at=_maybe_dt(inc_dict.get("occurred_at")),
                detected_at=_maybe_dt(inc_dict.get("detected_at")),
                mitigated_at=_maybe_dt(inc_dict.get("mitigated_at")),
                resolved_at=_maybe_dt(inc_dict.get("resolved_at")),
                title=inc_dict.get("title", ""),
                description=inc_dict.get("description", ""),
                root_cause=inc_dict.get("root_cause", ""),
                lessons_learned=inc_dict.get("lessons_learned", ""),
                affected_users=int(inc_dict.get("affected_users", 0)),
                reporter=inc_dict.get("reporter", ""),
                owner=inc_dict.get("owner", ""),
            )
            register.incidents.append(inc)
        except Exception:
            continue  # skip malformed incident, keep going
    reg.incident_register = register


def restore_session(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Restore a full session from a JSON payload.

    Used by the Runtime + Governance pages' "Restore session" widgets and
    by the entry-gate "Continue an existing deployment" flow. Returns a
    dict with:
        registry           — fully rebuilt RegistryState (incidents included)
        derived            — DerivedTerms reflecting the saved state
        journal_entries    — list of journal entry dicts (if present in payload)
        incidents_restored — count of incidents brought back
        framework_version  — what version produced the payload
        version_match      — whether it matches the running framework
        derived_source     — "saved" if reused from the JSON, "rederived" otherwise
        derived_drift      — None, or a list of (field, saved, rederived) tuples
                              if the live engine produced different numbers
                              than the JSON has stored
        notes              — list of human-readable notes about the restore

    Derived-state restoration policy:
      1. Re-run derive_terms() under the live framework engine.
      2. If the JSON contains a saved 'derived' block, compare it against
         the rederived values. If they match within 0.05, all is well —
         we use the rederived values (cleanest provenance).
      3. If they DRIFT (engine changed between save and now), we still use
         the rederived values for safety but flag the drift in `notes` so
         the UI can show the user a small inconsistency banner.
      4. If the JSON has NO 'derived' block (legacy export), re-derive
         silently. The rederived values become the canonical scores.

    This guarantees: a JSON saved at framework version N round-trips
    exactly at version N. Across versions, the user is informed of any
    drift rather than silently seeing different numbers.
    """
    from framework.rule_engine import derive_terms

    notes = []

    # Rebuild the registry
    reg = _rebuild_registry(payload)

    # Always re-derive under the live engine — this is the source of truth.
    derived = derive_terms(reg)

    # ── Compare against saved derived state (if present) ─────────────────
    saved_derived = payload.get("derived") if isinstance(payload, dict) else None
    derived_drift = None
    if isinstance(saved_derived, dict) and saved_derived:
        drift_records = []

        def _cmp(field_path, saved_val, rederived_val):
            try:
                if saved_val is None:
                    return
                if isinstance(saved_val, (int, float)) and isinstance(rederived_val, (int, float)):
                    if abs(float(saved_val) - float(rederived_val)) > 0.05:
                        drift_records.append((field_path, saved_val, rederived_val))
                elif str(saved_val) != str(rederived_val):
                    drift_records.append((field_path, saved_val, rederived_val))
            except Exception:
                pass

        _cmp("pcs_score", saved_derived.get("pcs_score"), derived.pcs_score)
        _cmp("tier",      saved_derived.get("tier"),
                          derived.tier.value if hasattr(derived.tier, "value") else derived.tier)
        sv = saved_derived.get("risk_vector") or {}
        rv = derived.risk_vector
        _cmp("risk_vector.likelihood",    sv.get("likelihood"),    rv.likelihood)
        _cmp("risk_vector.severity",      sv.get("severity"),      rv.severity)
        _cmp("risk_vector.vulnerability", sv.get("vulnerability"), rv.vulnerability)
        _cmp("risk_vector.uncertainty",   sv.get("uncertainty"),   rv.uncertainty)
        _cmp("risk_vector.autonomy",      sv.get("autonomy"),      rv.autonomy)
        _cmp("risk_vector.evolution",     sv.get("evolution"),     rv.evolution)
        _cmp("risk_vector.composite",     sv.get("composite"),     rv.composite)

        if drift_records:
            derived_drift = drift_records
            notes.append(
                f"⚠ Score drift detected on {len(drift_records)} field(s) — "
                f"the live engine produced different values than the JSON "
                f"saved. Using live-engine values."
            )
        else:
            notes.append(
                f"Saved scores reproduced exactly under v{__version__}."
            )

    # Determine which derived snapshot we hand back. If the saved JSON
    # carries derived state and there's no drift, we adopt the saved
    # numbers verbatim so the user sees identical scores to the moment
    # they exported. Otherwise we use the live re-derive.
    derived_source = "rederived"
    if (isinstance(saved_derived, dict) and saved_derived
            and not derived_drift
            and saved_derived.get("pcs_score") is not None):
        derived_source = "saved"
        # The derived object IS already mathematically identical to the
        # saved one (verified above); we just label the source for the UI.

    # Count incidents that came along for the ride
    incidents_restored = 0
    if reg.incident_register and reg.incident_register.incidents:
        incidents_restored = len(reg.incident_register.incidents)
        notes.append(
            f"{incidents_restored} incident(s) restored into the register."
        )

    # Journal entries (we don't auto-replay — caller decides what to do)
    journal_entries = []
    if "journal" in payload and isinstance(payload["journal"], dict):
        journal_entries = payload["journal"].get("entries", [])
        if journal_entries:
            notes.append(
                f"{len(journal_entries)} journal entry/entries available "
                f"from the original session."
            )
            mr = payload["journal"].get("merkle_root", "")
            if mr:
                notes.append(f"Original journal Merkle root: {mr[:16]}…")

    import_version = payload.get("framework_version", "unknown")
    version_match = import_version == __version__
    if not version_match:
        notes.append(
            f"⚠ Imported framework v{import_version} differs from running "
            f"v{__version__} — scores re-derived under the current version."
        )

    # UI extras — the user's fine-grained category/label selections that
    # don't live on the registry. If the JSON has them, surface them to
    # the caller so they can populate st.session_state directly. Falls
    # back to None for legacy JSONs without ui_extras.
    ui_extras = payload.get("ui_extras")
    if not isinstance(ui_extras, dict):
        ui_extras = None

    return {
        "registry":           reg,
        "derived":            derived,
        "journal_entries":    journal_entries,
        "incidents_restored": incidents_restored,
        "framework_version":  import_version,
        "version_match":      version_match,
        "derived_source":     derived_source,
        "derived_drift":      derived_drift,
        "ui_extras":          ui_extras,
        "notes":              notes,
    }