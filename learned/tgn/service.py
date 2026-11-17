"""
The `learned` service (ASTRA phase 10): trains and evaluates the temporal graph network, and scores live windows with the one the platform has adopted.

    python -m learned.tgn.service evaluate [--seed N] [--out DIR] [--post]    train on simulated normal traffic, evaluate against the baseline, optionally record it on the platform
    python -m learned.tgn.service score    [--out DIR]                        score the complete windows since the last score with the adopted model
    python -m learned.tgn.service loop     [--out DIR] [--every SECONDS]      score on a schedule

The platform is reached with ASTRA_URL and ASTRA_KEY, a key with the collector role: it can read the event stream (names, kinds and times, never content), post an evaluation and post window
scores. It cannot adopt a model, switch anything on, judge a flag or sign anything: that needs a person on the platform, and the platform refuses to adopt a model whose recorded evaluation did
not pass. The service holds the weights (in --out); the platform holds the evaluation, the threshold and the decision.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

import torch

from . import evaluate as E
from . import model as M
from . import schema
from . import simulate as S

WINDOW = int(S.WINDOW)


class Platform:
    def __init__(self, url: str, key: str, timeout: float = 60.0):
        self.url, self.key, self.timeout = url.rstrip("/"), key, timeout

    def call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        req = urllib.request.Request(self.url + path, method=method, data=None if body is None else json.dumps(body).encode("utf-8"),
                                     headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json", "User-Agent": "astra-learned/1"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8") or "null")
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read().decode("utf-8")).get("detail", "")
            except Exception:
                detail = ""
            raise RuntimeError(f"{method} {path} gave HTTP {e.code}: {detail}")


def from_env() -> Platform:
    url, key = os.environ.get("ASTRA_URL", ""), os.environ.get("ASTRA_KEY", "")
    if not (url and key):
        raise SystemExit("learned: ASTRA_URL and ASTRA_KEY are needed")
    return Platform(url, key)


def artefact_path(out: str, checksum: str) -> str:
    return os.path.join(out, f"tgn-{checksum[:16]}.pt")


CONFIGS = ((6, 32), (12, 32), (24, 32))                    # (epochs, width) the settings are chosen among


def train_and_evaluate(seed: int = 7, epochs: Optional[int] = None, d: int = 32, out: Optional[str] = None, configs: Tuple[Tuple[int, int], ...] = CONFIGS, **sim: Any) -> Dict[str, Any]:
    """Simulate, train on normal traffic only, evaluate. The settings are chosen by detection on the DEV attack families only; the TEST families are looked at once, for the chosen model, and
    nothing is tuned afterwards. Saves the weights under their checksum when `out` is given."""
    ds = S.make_dataset(seed=seed, **sim)
    vocab = M.Vocab.of(ds["train"])
    tried = []
    best = None
    for ep, width in ([(epochs, d)] if epochs else list(configs)):
        mdl, crv = M.train(ds["train"], vocab, seed=seed, epochs=ep, d=width)
        met = E.evaluate(ds, mdl, vocab)
        dev = met["tgn"]["macro_dev"]
        tried.append({"epochs": ep, "d": width, "dev_detection": dev, "fpr_val_budget": met["budget_fpr"]})
        if best is None or (dev or 0) > (best[3] or 0) + 1e-9:         # ties keep the smaller setting
            best = (mdl, crv, met, dev, ep, width)
    model, curve, metrics, _, epochs, d = best
    metrics["selection"] = {"chosen_on": "dev families only", "candidates": tried}
    checksum = M.state_dict_checksum(model)
    result = {"checksum": checksum, "metrics": metrics, "vocab": vocab.dump(), "hyper": {"seed": seed, "epochs": epochs, "d": d, "m": model.m, "window_seconds": WINDOW},
              "training": {"events": len(ds["train"]), "loss_curve": [round(x, 4) for x in curve], "schema": schema.SCHEMA_VERSION}}
    if out:
        os.makedirs(out, exist_ok=True)
        torch.save({"state": model.state_dict(), "vocab": vocab.dump(), "hyper": result["hyper"], "checksum": checksum}, artefact_path(out, checksum))
    return result


def load(out: str, checksum: str) -> Tuple[M.TGN, M.Vocab]:
    path = artefact_path(out, checksum)
    if not os.path.exists(path):
        raise RuntimeError(f"the weights of model {checksum[:16]} are not in {out}")
    blob = torch.load(path, weights_only=True)
    vocab = M.Vocab(blob["vocab"]["nodes"], blob["vocab"]["kinds"])
    model = M.TGN(len(vocab.nodes), len(vocab.kinds), d=blob["hyper"]["d"], m=blob["hyper"]["m"])
    model.load_state_dict(blob["state"])
    if M.state_dict_checksum(model) != checksum:
        raise RuntimeError("the weights do not match their checksum")
    return model, vocab


def cmd_evaluate(a: argparse.Namespace) -> int:
    r = train_and_evaluate(seed=a.seed, epochs=a.epochs, out=a.out)
    m = r["metrics"]
    print(f"model {r['checksum'][:16]}  simulated traffic, seed {a.seed}  loss {r['training']['loss_curve'][0]} -> {r['training']['loss_curve'][-1]}")
    for det in ("tgn", "baseline"):
        print(f"  {det:8s} threshold {m[det]['threshold']:>8}  false positives on held-out normal {m[det]['fpr_test']:.3f}  detection on dev {m[det]['macro_dev']}  on held-out families {m[det]['macro_test']}")
        print("           " + "  ".join(f"{f}={m[det]['tpr'][f]}" for f in S.DEV_FAMILIES + S.TEST_FAMILIES))
    print("  settings tried (chosen on dev families only): " + ", ".join(f"{c['epochs']} epochs -> dev {c['dev_detection']}" for c in m["selection"]["candidates"]))
    print("  gate: " + ("PASSED" if m["decision"]["passed"] else "NOT PASSED"))
    for x in m["decision"]["reasons"]:
        print(f"    - {x}")
    if a.post:
        p = from_env()
        try:
            rec = p.call("POST", "/api/astra/learned/tgn/evaluations", {"checksum": r["checksum"], "metrics": m, "vocab": r["vocab"], "hyper": r["hyper"], "training": r["training"]})
        except RuntimeError as e:
            print(f"  not recorded: {e}", file=sys.stderr)
            return 1
        print(f"  recorded on the platform: model {rec['model']['id']}, gate {'passed' if rec['evaluation']['passed'] else 'not passed'}" + (" (the platform disagrees with the service's own verdict)" if rec["disagrees"] else ""))
    return 0


def stream_events(p: Platform, since: float, until: float) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    cursor = since
    while True:
        r = p.call("GET", "/api/astra/learned/stream?" + urllib.parse.urlencode({"since": cursor, "until": until, "limit": 5000}))
        out += r["events"]
        if not r["more"]:
            return out
        cursor = r["events"][-1]["t"] + 1e-6


def cmd_score(a: argparse.Namespace) -> int:
    p = from_env()
    active = p.call("GET", "/api/astra/learned/tgn/active")
    if not active:
        print("learned: no TGN is adopted on the platform: nothing to score")
        return 0
    model, vocab = load(a.out, active["checksum"])
    now = time.time()
    lookback = max(active.get("last_window_end", 0), now - 6 * 3600)
    raw = stream_events(p, lookback, now)
    events = schema.dataset(raw)["events"]
    if not events:
        print("learned: no events to score")
        return 0
    means = E.tgn_window_means(model, vocab, events, active["last_window_end"], (int(now // WINDOW)) * WINDOW)
    norm = active["normalisation"]
    scored = E.z(means, norm)
    counts: Dict[Tuple[str, int], int] = {}
    for e in events:
        counts[(e["agent"], int(e["t"] // WINDOW))] = counts.get((e["agent"], int(e["t"] // WINDOW)), 0) + 1
    windows = [{"agent": k[0], "window_start": k[1] * WINDOW, "events": counts.get(k, 0), "score": round(v, 4)} for k, v in sorted(scored.items())]
    r = p.call("POST", "/api/astra/learned/tgn/scores", {"model_id": active["id"], "windows": windows})
    print(f"learned: scored {r['scored']} windows, {r['flagged']} flagged")
    return 0


def cmd_loop(a: argparse.Namespace) -> int:
    while True:
        try:
            cmd_score(a)
        except Exception as e:                                                       # one bad round must not stop the schedule
            print(f"learned: {e}", file=sys.stderr)
        time.sleep(a.every)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="learned.tgn.service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("evaluate", "score", "loop"):
        sp = sub.add_parser(name)
        sp.add_argument("--out", default=os.environ.get("LEARNED_MODELS", "/models"))
        if name == "evaluate":
            sp.add_argument("--seed", type=int, default=7)
            sp.add_argument("--epochs", type=int, default=None, help="train this many epochs; by default the settings are chosen on the dev families among " + ", ".join(str(c[0]) for c in CONFIGS))
            sp.add_argument("--post", action="store_true")
        if name == "loop":
            sp.add_argument("--every", type=float, default=300.0)
    a = ap.parse_args(argv)
    return {"evaluate": cmd_evaluate, "score": cmd_score, "loop": cmd_loop}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
