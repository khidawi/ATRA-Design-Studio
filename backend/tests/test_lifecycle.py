"""
Tests for the lifecycle facts (layers 6-11) and the incident log reaching the ST-AI engine through scoring_bridge.

    docker compose exec backend python -m tests.test_lifecycle
"""
import sys
from datetime import datetime, timedelta, timezone

from schema import IncidentEntry, Lifecycle, RegistryBlock
from scoring_bridge import score_registry

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail) if detail and not ok else ""))
    if not ok:
        fails.append(name)


base, _ = score_registry(RegistryBlock())
tiers = base.raw_breakdown["risk_vector"]["tiers"]
check("per-pillar tiers are returned", set(tiers) == {"likelihood", "severity", "vulnerability", "uncertainty", "autonomy", "evolution", "composite"}, tiers)

# governance facts change the gate: declaring them clears the matching blockers
open_gov, _ = score_registry(RegistryBlock(lifecycle=Lifecycle(dpia_approved=False)))
done_gov, _ = score_registry(RegistryBlock(lifecycle=Lifecycle(
    dpia_approved=True, hitl_formally_specified=True, policy_hallucination_acknowledged=True,
    liability_boundary_declared=True, right_to_challenge_documented=True, model_card_approved=True,
    operator_training_complete=True, output_validation_gate_configured=True)))
check("governance facts reach the engine", len(done_gov.raw_breakdown["blockers"]) <= len(open_gov.raw_breakdown["blockers"]),
      (open_gov.raw_breakdown["blockers"], done_gov.raw_breakdown["blockers"]))

# runtime: a domain violation is a hard blocker
viol, _ = score_registry(RegistryBlock(lifecycle=Lifecycle(domain_violation_occurred=True)))
check("a domain violation blocks the gate", viol.gate == "BLOCKED", viol.gate)

# incidents: an open severe incident raises likelihood, a critical one open for four days blocks
now = datetime.now(tz=timezone.utc)
sev = IncidentEntry(id="I-1", type="MODEL_FAILURE", severity=4, status="OPEN", detected_at=now - timedelta(hours=2))
with_sev, _ = score_registry(RegistryBlock(incident_register=[sev]))
check("an open severe incident raises L", with_sev.raw_breakdown["L"] > base.raw_breakdown["L"], (base.raw_breakdown["L"], with_sev.raw_breakdown["L"]))
crit = IncidentEntry(id="I-2", type="DATA_BREACH", severity=5, status="OPEN", detected_at=now - timedelta(days=4))
with_crit, _ = score_registry(RegistryBlock(incident_register=[crit]))
check("a critical incident open over 72h blocks", any("72" in b for b in with_crit.raw_breakdown["blockers"]), with_crit.raw_breakdown["blockers"])
resolved = IncidentEntry(id="I-3", type="DATA_BREACH", severity=5, status="RESOLVED", detected_at=now - timedelta(days=4), resolved_at=now - timedelta(days=3))
with_res, _ = score_registry(RegistryBlock(incident_register=[resolved]))
check("a resolved critical incident does not block", not any("72" in b for b in with_res.raw_breakdown["blockers"]))

# unknown values are ignored, never fatal
odd, _ = score_registry(RegistryBlock(lifecycle=Lifecycle(drift_type="NOPE", decommissioning_status="???", root_causes=["X"])))
check("unknown enum values fall back to defaults", odd.tier is not None)

sys.exit(1 if fails else 0)
