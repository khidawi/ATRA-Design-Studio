"""Train the temporal graph network on the converted public traces (normal traffic only) and evaluate it as the platform would. Runs in the astra-learned image, scratch only."""
import json
import sys
import time

sys.path.insert(0, "/w")
sys.path.insert(0, "/w/backend")
from learned import real                                   # noqa: E402
from learned.tgn import evaluate as E                      # noqa: E402
from learned.tgn import service as svc                     # noqa: E402

events = json.load(open("/data/hyperagent_events.json"))
ds = real.make_dataset(events, seed=7, episodes=14)
print(real.summary(ds), flush=True)
t0 = time.time()
res = svc.train_and_evaluate(seed=7, ds=ds, configs=((6, 32), (12, 32)))
print(f"trained and evaluated in {time.time() - t0:.0f}s", flush=True)
m = res["metrics"]
print(json.dumps({"selection": m.get("selection"), "budget_fpr": m.get("budget_fpr")}, indent=1))
print(json.dumps({"tgn": m["tgn"], "baseline": m.get("baseline")}, indent=1)[:3500])
print("DECISION:", json.dumps(E.decide(m), indent=1)[:1500])
json.dump(res["metrics"], open("/data/tgn_metrics.json", "w"), indent=1)
