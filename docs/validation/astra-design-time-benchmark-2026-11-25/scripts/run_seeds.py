"""Repeat the TGN evaluation on the converted public traces for several seeds (seed changes the injected episodes and the training). Scratch only."""
import json
import sys
import time

sys.path.insert(0, "/w")
sys.path.insert(0, "/w/backend")
from learned import real                                   # noqa: E402
from learned.tgn import evaluate as E                      # noqa: E402
from learned.tgn import service as svc                     # noqa: E402

events = json.load(open("/data/hyperagent_events.json"))
for seed in [int(s) for s in sys.argv[1:]]:
    t0 = time.time()
    ds = real.make_dataset(events, seed=seed, episodes=14)
    res = svc.train_and_evaluate(seed=seed, ds=ds, configs=((6, 32), (12, 32)))
    m = res["metrics"]
    out = {"seed": seed, "metrics": m, "decision": E.decide(m), "families_skipped": ds["data"]["families_skipped"],
           "victims": {f: len(a["victims"]) for f, a in ds["attacks"].items()}, "seconds": round(time.time() - t0)}
    json.dump(out, open(f"/data/seed_{seed}.json", "w"), indent=1)
    print("seed", seed, "done", out["seconds"], "s; passed:", out["decision"]["passed"], flush=True)
