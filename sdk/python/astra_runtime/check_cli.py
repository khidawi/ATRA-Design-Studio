"""
astra-check: the admission check of ASTRA Probe, for a build pipeline.

    astra-check --design refund-agent --run          run the Probe on the saved design, then admit or refuse it
    astra-check --design refund-agent                only read the verdict of the newest run

    ASTRA_URL and ASTRA_KEY name the platform and a key (role engineer or higher: a collector key cannot run the Probe).

Exit status: 0 admitted, 1 refused (the reasons are printed, one per line), 2 the check itself could not be made (no key, platform unreachable, unknown design). A pipeline that
treats anything but 0 as a failure is fail-closed: it never admits a change it could not check. The check refuses a design when its newest Probe run is not of this exact version, is older
than the lifetime of its evidence, has a scenario the reconciler missed, or has not run a standing incident scenario approved since.
"""
import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import transport
from .client import Client


def _fail(msg: str) -> int:
    print(f"astra-check: {msg}", file=sys.stderr)
    return 2


def _detail(body: Any) -> Any:
    return body.get("detail", body) if isinstance(body, dict) else body


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="astra-check", description="Admit or refuse a change to an agent design by its ASTRA Probe results.")
    ap.add_argument("--design", required=True, help="the design key of the agent design")
    ap.add_argument("--run", action="store_true", help="run the Probe first (otherwise the newest run is read)")
    ap.add_argument("--url", default=os.environ.get("ASTRA_URL", ""))
    ap.add_argument("--key", default=os.environ.get("ASTRA_KEY", ""))
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for the platform")
    ap.add_argument("--json", action="store_true", help="print the answer of the platform as JSON")
    a = ap.parse_args(argv)
    if not (a.url and a.key):
        return _fail("ASTRA_URL and ASTRA_KEY (or --url and --key) are needed")
    problem = transport.url_problem(a.url)
    if problem:
        return _fail(problem)
    c = Client(a.url, a.key, "astra-check", start=False, timeout=a.timeout)
    c.disabled_reason = None
    summary: Dict[str, Any] = {}
    if a.run:
        status, body = c._http("POST", "/api/astra/probe/run", {"design_key": a.design, "trigger": "admission"})
        if status != 201 or not isinstance(body, dict):
            return _fail(f"the Probe could not be run (HTTP {status}): {_detail(body)}")
        summary = body.get("summary", {})
    status, body = c._http("GET", f"/api/astra/probe/admission?design_key={a.design}")
    if status != 200 or not isinstance(body, dict):
        return _fail(f"the verdict could not be read (HTTP {status}): {_detail(body)}")
    if a.json:
        print(json.dumps(body, indent=2))
    else:
        s = summary or (body.get("run") or {}).get("summary") or {}
        line = f" ({s.get('passed', 0)} of {s.get('applicable', 0)} applicable scenarios passed, {s.get('not_applicable', 0)} not applicable)" if s else ""
        print(("ADMITTED" if body["admit"] else "REFUSED") + f": {a.design}{line}")
        for r in body.get("reasons", []):
            print(f"  - {r}")
    return 0 if body.get("admit") else 1


if __name__ == "__main__":
    sys.exit(main())
