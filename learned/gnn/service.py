"""
The graph model in the `learned` service (ASTRA phase 11): trained and evaluated here, scored here once adopted on the platform. Same rules as the temporal network: a collector-role key, the
platform decides, an adopted model is advisory-only and its flags can only mark the baseline control unverified.

    python -m learned.gnn.service evaluate [--seed N] [--out DIR] [--post]
    python -m learned.gnn.service score    [--out DIR]
    python -m learned.gnn.service loop     [--out DIR] [--every SECONDS]
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import torch

from ..tgn import schema
from ..tgn.service import Platform, fetch_real, from_env, stream_events
from . import evaluate as E
from . import graph as G
from . import model as M
from . import real as R
from . import simulate as S

WINDOW = int(S.WINDOW)
CONFIGS = ((40, 6), (80, 6), (80, 10))                   # (epochs, embedding width) the settings are chosen among


def artefact_path(out: str, checksum: str) -> str:
    return os.path.join(out, f"gnn-{checksum[:16]}.pt")


def snapshots(events: List[Dict[str, Any]], lay: G.Layout, lo: float, hi: float) -> List[G.Snapshot]:
    return [G.build(evs, lay) for _, evs in G.by_window(events, S.WINDOW, lo, hi).items()]


def train_and_evaluate(seed: int = 11, epochs: Optional[int] = None, emb: int = 6, out: Optional[str] = None, configs: Tuple[Tuple[int, int], ...] = CONFIGS, ds: Optional[Dict[str, Any]] = None, **sim: Any) -> Dict[str, Any]:
    """Simulate, train on normal training snapshots only, evaluate. Settings are chosen on the DEV families only; the TEST families are judged once, for the chosen model."""
    if ds is None:
        ds = S.make_dataset(seed=seed, **sim)
        lay = G.Layout.of(ds["train"], known_agents=sorted(S.AGENTS))
    else:
        lay = ds["layout"]                                                         # real traces: the company's own slots (learned/gnn/real.py)
    train_snaps = snapshots(ds["train"], lay, 0, ds["spans"]["train"][1])
    best, tried = None, []
    for ep, width in ([(epochs, emb)] if epochs else list(configs)):
        mdl, crv = M.train(train_snaps, lay.dim, seed=seed, epochs=ep, emb=width)
        met = E.evaluate(ds, mdl, lay)
        dev = met["gnn"]["macro_dev"] or 0.0
        tried.append({"epochs": ep, "emb": width, "dev_detection": dev})
        if best is None or dev > best[3] + 1e-9:
            best = (mdl, crv, met, dev, ep, width)
    model, curve, metrics, _, epochs, emb = best
    metrics["selection"] = {"chosen_on": "dev families only", "candidates": tried}
    checksum = M.state_dict_checksum(model)
    result = {"checksum": checksum, "metrics": metrics, "vocab": lay.dump(), "hyper": {"seed": seed, "epochs": epochs, "emb": emb, "hidden": model.hidden, "window_seconds": WINDOW, "dim": lay.dim},
              "training": {"snapshots": len(train_snaps), "events": len(ds["train"]), "loss_curve": [round(x, 5) for x in curve], "schema": schema.SCHEMA_VERSION}}
    if out:
        os.makedirs(out, exist_ok=True)
        torch.save({"state": model.state_dict(), "layout": lay.dump(), "hyper": result["hyper"], "checksum": checksum}, artefact_path(out, checksum))
    return result


def load(out: str, checksum: str) -> Tuple[M.SAGE, G.Layout]:
    path = artefact_path(out, checksum)
    if not os.path.exists(path):
        raise RuntimeError(f"the weights of model {checksum[:16]} are not in {out}")
    blob = torch.load(path, weights_only=True)
    lay = G.Layout.load(blob["layout"])
    model = M.SAGE(lay.dim, blob["hyper"]["hidden"], blob["hyper"]["emb"])
    model.load_state_dict(blob["state"])
    if M.state_dict_checksum(model) != checksum:
        raise RuntimeError("the weights do not match their checksum")
    return model, lay


def fetch_permissions(p: Any, agents: List[str]) -> Dict[str, Any]:
    """What each agent's ACTIVE signed contract permits, from the platform's own contract view (the one the SDK enforces with). An agent without an active contract is left out."""
    out: Dict[str, Any] = {}
    for a in agents:
        c = p.call("GET", "/api/runtime/contract/" + urllib.parse.quote(a, safe=""))
        if c.get("state") == "contract" and c.get("allowed"):
            out[a] = R.permitted_of(c["allowed"])
    return out


def cmd_evaluate(a: argparse.Namespace) -> int:
    ds = None
    if getattr(a, "real", False):                                                  # a company's own events and contracts from the platform, not the simulator
        p = from_env()
        raw = fetch_real(p, a.days)
        try:
            ds = R.make_dataset(raw, fetch_permissions(p, sorted({e["agent"] for e in raw})), seed=a.seed, episodes=a.episodes)
        except R.DataError as e:
            print(f"learned: not enough data to judge a graph model on this company's traffic: {e}", file=sys.stderr)
            return 3
        print(R.summary(ds))
    r = train_and_evaluate(seed=a.seed, epochs=a.epochs, out=a.out, ds=ds)
    m = r["metrics"]
    print(f"model {r['checksum'][:16]}  {'simulated traffic' if m.get('simulated', True) else 'real traces with injected attacks'}, seed {a.seed}  loss {r['training']['loss_curve'][0]} -> {r['training']['loss_curve'][-1]}  ({r['training']['snapshots']} snapshots)")
    fams = [f for f in m["families"]["dev"] + m["families"]["test"] if f in m["gnn"]["tpr"]]
    for det in ("gnn", "baseline"):
        print(f"  {det:9s} false positives on held-out normal {m[det]['fpr_test']:.3f}  detection on dev {m[det]['macro_dev']}  on held-out families {m[det]['macro_test']}")
        print("            " + "  ".join(f"{f}={m[det]['tpr'][f]}" for f in fams))
    print("  reachability check (exact): " + "  ".join(f"{f}={m['reachability']['tpr'][f]}" for f in fams) + f"   attack events outside the estate's permissions: {m['attack_events_not_permitted']}")
    print("  caught by the model but by neither the baseline nor the reachability check: " + "  ".join(f"{f}={m['gnn']['novel'][f]}" for f in fams))
    print("  late-joining agents (no history): model " + "  ".join(f"{f}={m['gnn']['tpr_late'][f]}" for f in fams) + " / baseline " + "  ".join(f"{f}={m['baseline']['tpr_late'][f]}" for f in fams))
    print("  settings tried (chosen on dev families only): " + ", ".join(f"{c['epochs']} epochs, emb {c['emb']} -> dev {c['dev_detection']}" for c in m["selection"]["candidates"]))
    print("  gate: " + ("PASSED" if m["decision"]["passed"] else "NOT PASSED (no-go)"))
    for x in m["decision"]["reasons"]:
        print(f"    - {x}")
    if a.post:
        p = from_env()
        try:
            rec = p.call("POST", "/api/astra/learned/gnn/evaluations", {"checksum": r["checksum"], "metrics": m, "vocab": r["vocab"], "hyper": r["hyper"], "training": r["training"]})
        except RuntimeError as e:
            print(f"  not recorded: {e}", file=sys.stderr)
            return 1
        print(f"  recorded on the platform: model {rec['model']['id']}, gate {'passed' if rec['evaluation']['passed'] else 'not passed'}")
    return 0


def cmd_score(a: argparse.Namespace) -> int:
    p = from_env()
    active = p.call("GET", "/api/astra/learned/gnn/active")
    if not active:
        print("learned: no graph model is adopted on the platform: nothing to score")
        return 0
    model, lay = load(a.out, active["checksum"])
    now = time.time()
    lookback = max(active.get("last_window_end", 0), now - 6 * 3600)
    events = schema.dataset(stream_events(p, lookback, now))["events"]
    if not events:
        print("learned: no events to score")
        return 0
    hi = int(now // WINDOW) * WINDOW
    raw = E.raw_scores(model, lay, events, active["last_window_end"], hi)
    scored = E.z(raw, active["normalisation"])
    counts: Dict[Tuple[str, int], int] = {}
    for e in events:
        k = (e["agent"], int(e["t"] // WINDOW))
        counts[k] = counts.get(k, 0) + 1
    windows = [{"agent": k[0], "window_start": k[1] * WINDOW, "events": counts.get(k, 0), "score": round(v, 4)} for k, v in sorted(scored.items())]
    r = p.call("POST", "/api/astra/learned/gnn/scores", {"model_id": active["id"], "windows": windows})
    print(f"learned: scored {r['scored']} windows, {r['flagged']} flagged")
    return 0


def cmd_loop(a: argparse.Namespace) -> int:
    while True:
        try:
            cmd_score(a)
        except Exception as e:
            print(f"learned: {e}", file=sys.stderr)
        time.sleep(a.every)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="learned.gnn.service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("evaluate", "score", "loop"):
        sp = sub.add_parser(name)
        sp.add_argument("--out", default=os.environ.get("LEARNED_MODELS", "/models"))
        if name == "evaluate":
            sp.add_argument("--seed", type=int, default=11)
            sp.add_argument("--epochs", type=int, default=None, help="train this many epochs; by default the settings are chosen on the dev families")
            sp.add_argument("--post", action="store_true")
            sp.add_argument("--real", action="store_true", help="train and judge on this company's own events and active contracts (read from the platform) with permitted-but-unusual attacks injected into held-out windows")
            sp.add_argument("--days", type=float, default=14.0, help="with --real: how many days of history to read")
            sp.add_argument("--episodes", type=int, default=14, help="with --real: attack episodes injected per family")
        if name == "loop":
            sp.add_argument("--every", type=float, default=300.0)
    a = ap.parse_args(argv)
    return {"evaluate": cmd_evaluate, "score": cmd_score, "loop": cmd_loop}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
