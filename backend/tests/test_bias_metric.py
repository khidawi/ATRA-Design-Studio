"""
Tests that a design can declare its fairness metric, so the SC-MAP-1 blocker (a critical or special-category model needs a metric and a validation gate) can clear.

    docker compose exec backend python -m tests.test_bias_metric
"""
import sys

from schema import DeploymentContext, Lifecycle, RegistryBlock
from scoring_bridge import score_registry

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + str(detail)[:400] if detail and not ok else ""))
    if not ok:
        fails.append(name)


ctx = DeploymentContext(model_type="NN", ai_criticality="CRITICAL", data_sensitivity="SENSITIVE_PERSONAL", domain="well allocation")


def map1(life):
    res, _ = score_registry(RegistryBlock(deployment_context=ctx, lifecycle=life))
    return [b for b in res.raw_breakdown["blockers"] if "SC-MAP-1" in b]


none = map1(Lifecycle())
check("a critical model with nothing declared is blocked on SC-MAP-1, naming both gaps", len(none) == 1 and "no fairness/bias metric declared" in none[0] and "no OutputValidationGate configured" in none[0], none)
gate_only = map1(Lifecycle(output_validation_gate_configured=True))
check("a validation gate alone does not clear it: the metric is still missing", len(gate_only) == 1 and "no fairness/bias metric declared" in gate_only[0] and "OutputValidationGate" not in gate_only[0].split("gaps:")[1].split(".")[0], gate_only)
metric_only = map1(Lifecycle(bias_metric="DEMOGRAPHIC_PARITY"))
check("a metric alone does not clear it either: the gate is still missing", len(metric_only) == 1 and "no OutputValidationGate configured" in metric_only[0] and "no fairness/bias metric" not in metric_only[0].split("gaps:")[1].split(".")[0], metric_only)
for m in ("DEMOGRAPHIC_PARITY", "EQUALISED_ODDS", "CALIBRATION"):
    check(f"declaring {m} and the gate clears the blocker", map1(Lifecycle(bias_metric=m, output_validation_gate_configured=True)) == [])
check("an unknown metric is ignored, never fatal", len(map1(Lifecycle(bias_metric="NOPE", output_validation_gate_configured=True))) == 1)
sys.exit(1 if fails else 0)
