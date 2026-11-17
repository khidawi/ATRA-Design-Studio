"""
The event-stream schema of the temporal graph network (ASTRA phase 10, step 10a), versioned.

An event is a plain dict with exactly these fields, and nothing else is ever read from a runtime event:

    t        seconds since the epoch (float)
    agent    who did it (the agent key)
    kind     what kind of thing (tool_call, data_access, delegation, memory_write, ...)
    target   what it was done to (a tool, a data store, an agent): a name, never a prompt, an argument or a result
    dept     the department of the agent, from the estate
    tier     the highest impact tier the agent can reach, from the estate (1..4)

A dataset is a list of such events in time order, plus the schema version and a hash, so a model can say exactly what it was trained and evaluated on. The version changes when the fields or
their meaning change; a model trained on another version is refused.
"""
import hashlib
import json
from typing import Any, Dict, Iterable, List

SCHEMA_VERSION = "tgn-events-v1"
FIELDS = ("t", "agent", "kind", "target", "dept", "tier")
IGNORED_KINDS = ("heartbeat",)


def clean(e: Dict[str, Any]) -> Dict[str, Any]:
    """The event restricted to the schema: unknown keys are dropped, missing ones refused. This is the only place a runtime event enters the learned service."""
    missing = [f for f in FIELDS if f not in e]
    if missing:
        raise ValueError(f"an event is missing {', '.join(missing)}")
    return {"t": float(e["t"]), "agent": str(e["agent"]), "kind": str(e["kind"]), "target": str(e["target"]), "dept": str(e["dept"]), "tier": int(e["tier"])}


def dataset(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    ev: List[Dict[str, Any]] = sorted((clean(e) for e in events if e.get("kind") not in IGNORED_KINDS), key=lambda x: (x["t"], x["agent"], x["kind"], x["target"]))
    return {"schema": SCHEMA_VERSION, "events": ev, "hash": digest(ev)}


def digest(events: List[Dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps([[e["t"], e["agent"], e["kind"], e["target"], e["dept"], e["tier"]] for e in events], separators=(",", ":")).encode("utf-8")).hexdigest()


def check(ds: Dict[str, Any]) -> None:
    if ds.get("schema") != SCHEMA_VERSION:
        raise ValueError(f"the dataset has schema {ds.get('schema')!r}; this model reads {SCHEMA_VERSION!r}")
    if digest(ds["events"]) != ds.get("hash"):
        raise ValueError("the dataset does not match its hash")
