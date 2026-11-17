"""
The entry point of the `learned` service (ASTRA phases 10 and 11).

    python -m learned tgn evaluate [--post]        train and evaluate the temporal graph network
    python -m learned gnn evaluate [--post]        train and evaluate the graph model
    python -m learned tgn score | gnn score        score the complete windows since the last score with the adopted model of that detector
    python -m learned loop [--every SECONDS]       score with every adopted model on a schedule (the default of the container)

A detector that is not adopted on the platform scores nothing: the loop only asks which model is adopted, and does nothing if there is none.
"""
import argparse
import os
import sys
import time
from typing import List, Optional

from .gnn import service as gnn
from .tgn import service as tgn

SERVICES = {"tgn": tgn, "gnn": gnn}


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in SERVICES:
        return SERVICES[argv[0]].main(argv[1:])
    ap = argparse.ArgumentParser(prog="learned")
    ap.add_argument("cmd", choices=["loop"])
    ap.add_argument("--every", type=float, default=300.0)
    ap.add_argument("--out", default=os.environ.get("LEARNED_MODELS", "/models"))
    a = ap.parse_args(argv)
    ns = argparse.Namespace(out=a.out)
    while True:
        for name, svc in SERVICES.items():
            try:
                svc.cmd_score(ns)
            except Exception as e:                                                   # one detector or one round failing must not stop the schedule
                print(f"learned {name}: {e}", file=sys.stderr)
        time.sleep(a.every)


if __name__ == "__main__":
    sys.exit(main())
