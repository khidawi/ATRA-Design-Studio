"""
A test case modelled on Lamad LLC (metering consultancy and AI services, Muscat): two models of the kind its products suggest, plugged into ASTRA.

This is illustrative. It is built from what the company says publicly about its products, not from its real models or data; change the names, features and
ranges to match the real ones.

  flow     "lamad-virtual-flow-meter": estimates the oil rate of a well in real time from wellhead pressure, temperature, choke size, gas-oil ratio and water cut
           (a soft sensor: a model standing in for a physical multiphase meter). The true rate is known only when a well test is done, a few times a month.
           People use it for production reporting and hydrocarbon allocation, so a biased estimate becomes a wrong volume on an invoice or a royalty.
  health   "lamad-meter-health": classifies a metering system as healthy, degraded or faulty from diagnostics (noise, alarms, proving factor deviation, calibration
           age). A metering engineer accepts or overrides it. A faulty meter called healthy is mis-measurement nobody is looking for.

Both go wrong in the `drift` phase in ways that matter in this business: a pressure transducer drifts and starts to fail, the wells start producing water, and
the allocation analysts stop checking the estimates.

Set up in the studio: AI Models -> Runtime -> Connect production data, with the record printed by `--show-record`; create an API key of role "collector". Then:

    export ASTRA_URL=http://localhost:5173
    export ASTRA_KEY=astra_xxxxxxxx

    python demo_lamad.py flow --phase normal      python demo_lamad.py health --phase normal
    python demo_lamad.py flow --phase drift       python demo_lamad.py health --phase drift
"""
import argparse
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from astra_runtime import ModelMonitor   # noqa: E402

rng = random.Random(11)
WELLS = [f"W-{i:02d}" for i in range(1, 13)]

FLOW_RECORD = {"inputs": {"well": "W-01", "wellhead_pressure_bar": 85.0, "wellhead_temp_c": 62.0, "choke_size_mm": 24.0, "gas_oil_ratio": 140.0, "water_cut": 0.12}, "output": 310.0}
HEALTH_RECORD = {"inputs": {"meter_type": "coriolis", "dp_noise": 0.4, "alarm_count": 1, "proving_factor_deviation_pct": 0.08, "calibration_age_days": 180}, "output": "healthy"}
FLOW_FIELDS = "Numeric ranges to set (a value outside is a domain violation): wellhead_pressure_bar 5 to 400, wellhead_temp_c 10 to 150, choke_size_mm 0 to 80, gas_oil_ratio 0 and up, water_cut 0 to 1. Make 'well' a category. Output oil_rate_m3d is a number; 'What the model does' is 'Predicts a number'."
HEALTH_FIELDS = "meter_type is a category; the others are numbers. Output is a category (healthy / degraded / faulty)."


def true_oil_rate(p, t, choke, gor, wc):
    return max(0.0, 3.2 * choke ** 1.15 * math.sqrt(max(p, 1.0)) / 10 * (1 - wc) * (1 - 0.0008 * (gor - 100)) * (1 + 0.002 * (t - 60)))


def run_flow(mon: ModelMonitor, phase: str, n: int) -> None:
    for i in range(n):
        well = rng.choice(WELLS)
        choke = rng.gauss(24, 3) if phase == "normal" else rng.gauss(22, 3)
        p_true = rng.gauss(85, 8)
        t = rng.gauss(62, 4)
        gor = rng.gauss(140, 15) if phase == "normal" else rng.gauss(210, 25)             # gas breaking through
        wc = max(0.0, rng.gauss(0.12, 0.03)) if phase == "normal" else min(0.9, max(0.0, rng.gauss(0.38, 0.07)))   # water breakthrough
        p_read = p_true if phase == "normal" else p_true * 1.09 + rng.gauss(0, 3)           # the pressure transducer is drifting
        if phase == "drift" and rng.random() < 0.03:
            p_read = rng.choice([0.0, 450.0, -3.0])                                          # a failing transducer reads rubbish
        truth = true_oil_rate(p_true, t, choke, gor, wc)
        est = true_oil_rate(max(p_read, 1.0), t, choke, 140.0 if phase == "drift" else gor, 0.12 if phase == "drift" else wc) * (1 + rng.gauss(0, 0.03 if phase == "normal" else 0.04))
        has_test = rng.random() < 0.08                                                      # a well test gives the true rate for a few of them
        mon.log(inputs={"well": well, "wellhead_pressure_bar": p_read, "wellhead_temp_c": t, "choke_size_mm": choke, "gas_oil_ratio": gor, "water_cut": wc},
                output=round(est, 2), latency_ms=abs(rng.gauss(35, 8)), label=round(truth * (1 + rng.gauss(0, 0.01)), 2) if has_test else None, error=rng.random() < 0.002)
        review(mon, phase, i, wrong=abs(est - truth) / max(truth, 1) > 0.10)


def run_health(mon: ModelMonitor, phase: str, n: int) -> None:
    for i in range(n):
        mtype = rng.choices(["coriolis", "ultrasonic", "turbine", "orifice"], [0.4, 0.25, 0.2, 0.15])[0]
        faulty = rng.random() < (0.05 if phase == "normal" else 0.18)
        noise = rng.gauss(0.4, 0.1) if not faulty else rng.gauss(1.4, 0.3)
        alarms = max(0, round(rng.gauss(1, 1))) if not faulty else max(1, round(rng.gauss(5, 2)))
        pf = abs(rng.gauss(0.08, 0.04)) if not faulty else abs(rng.gauss(0.45, 0.15))
        age = rng.gauss(150, 60) if phase == "normal" else rng.gauss(420, 90)               # calibrations are overdue
        # the model misses faults more often once its inputs have moved away from where it was validated
        called_faulty = faulty and rng.random() < (0.9 if phase == "normal" else 0.45)
        out = "faulty" if called_faulty else ("degraded" if (noise > 0.7 or pf > 0.2) and rng.random() < 0.8 else "healthy")
        mon.log(inputs={"meter_type": mtype, "dp_noise": noise, "alarm_count": alarms, "proving_factor_deviation_pct": pf, "calibration_age_days": max(0, age)},
                output=out, confidence=rng.uniform(0.7, 0.95) if phase == "normal" else rng.uniform(0.5, 0.8), latency_ms=abs(rng.gauss(25, 6)),
                label=("faulty" if faulty else out) if rng.random() < 0.3 else None)             # an inspection confirms the truth for some
        review(mon, phase, i, wrong=faulty and not called_faulty)


def review(mon: ModelMonitor, phase: str, i: int, wrong: bool) -> None:
    """What the engineers did with the estimate: careful in the normal phase; in the drift phase the allocation analysts accept nearly everything in seconds."""
    if i % 3:
        return
    if phase == "normal":
        accepted = rng.random() < (0.25 if wrong else 0.78)
        mon.decision("accepted" if accepted else rng.choice(["edited", "overridden", "escalated"]), role="metering engineer" if i % 2 else "allocation analyst",
                     review_seconds=abs(rng.gauss(40, 12)), model_correct=not wrong, reason=rng.random() < 0.5, confidence_shown=True)
    else:
        analyst = i % 2 == 0
        accepted = rng.random() < (0.99 if analyst else (0.4 if wrong else 0.75))
        mon.decision("accepted" if accepted else rng.choice(["edited", "overridden"]), role="allocation analyst" if analyst else "metering engineer",
                     review_seconds=abs(rng.gauss(2.5, 0.6)) if analyst else abs(rng.gauss(35, 10)), model_correct=not wrong, confidence_shown=False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("model", choices=["flow", "health"])
    ap.add_argument("--phase", choices=["normal", "drift"], default="normal")
    ap.add_argument("-n", type=int, default=None, help="how many records (default: 1,200 normal, 900 drift)")
    ap.add_argument("--name", default=None, help="the monitor's name (default: lamad-virtual-flow-meter or lamad-meter-health)")
    ap.add_argument("--show-record", action="store_true", help="print the example record to paste into 'Suggest the fields', then stop")
    a = ap.parse_args()
    if a.show_record:
        print(json.dumps(FLOW_RECORD if a.model == "flow" else HEALTH_RECORD, indent=2))
        print("\n" + (FLOW_FIELDS if a.model == "flow" else HEALTH_FIELDS))
        return
    name = a.name or ("lamad-virtual-flow-meter" if a.model == "flow" else "lamad-meter-health")
    mon = ModelMonitor(name, on_error=lambda m: print("ASTRA client:", m, file=sys.stderr))
    if mon.disabled_reason:
        sys.exit(f"Not sending anything: {mon.disabled_reason}")
    n = a.n or (1200 if a.phase == "normal" else 900)
    (run_flow if a.model == "flow" else run_health)(mon, a.phase, n)
    ok = mon.flush(timeout=30)
    print(f"{name}: {n} records ({a.phase}) sent={mon.sent} dropped={mon.dropped} rejected={mon.rejected} platform says: {mon.status}" + ("" if ok else "  (some not delivered yet)"))


if __name__ == "__main__":
    main()
