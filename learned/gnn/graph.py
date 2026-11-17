"""
Interaction-graph snapshots (ASTRA phase 11, step 11a).

For one time window, the graph of what happened: the agents that were active, the tools and data stores they touched, the agents they delegated to and their departments.

    nodes      agent, tool, resource, department (an agent that did nothing in the window has no node)
    edges      agent - tool (invokes), agent - resource (accesses), agent - agent (delegates), agent - department (member of); undirected for message passing
    features   a node type, the impact tier, how much happened, the department, and a log-count over a fixed layout of targets
               (for an agent: how often it touched each tool, store and agent; for a tool or store: how often each agent touched it)

Features say what a node did, never who it is: there is no per-agent identity, so an agent that joined yesterday is scored by what it does against what its neighbours do. The layout (which slots
exist) is fixed when the model is trained and saved with it; a target the layout has never seen goes into one "other" slot.
"""
import math
from typing import Any, Dict, List, Optional, Tuple

TYPES = ("agent", "tool", "resource", "dept")


class Layout:
    def __init__(self, tools: List[str], resources: List[str], agents: List[str], depts: List[str]):
        self.tools, self.resources, self.agents, self.depts = sorted(tools), sorted(resources), sorted(agents), sorted(depts)
        self.t_ix = {x: i for i, x in enumerate(self.tools)}
        self.r_ix = {x: len(self.tools) + i for i, x in enumerate(self.resources)}
        self.a_ix = {x: len(self.tools) + len(self.resources) + i for i, x in enumerate(self.agents)}
        self.other = len(self.tools) + len(self.resources) + len(self.agents)
        self.slots = self.other + 1
        self.d_ix = {x: i for i, x in enumerate(self.depts)}
        self.dim = len(TYPES) + 2 + len(self.depts) + self.slots

    def dump(self) -> Dict[str, List[str]]:
        return {"tools": self.tools, "resources": self.resources, "agents": self.agents, "depts": self.depts}

    @classmethod
    def load(cls, d: Dict[str, List[str]]) -> "Layout":
        return cls(d["tools"], d["resources"], d["agents"], d["depts"])

    @classmethod
    def of(cls, events: List[Dict[str, Any]], known_agents: Optional[List[str]] = None) -> "Layout":
        """The slots a set of events needs. `known_agents` adds agents that exist in the estate but had no events (they still get a slot, so a late joiner can be scored)."""
        return cls([e["target"] for e in events if e["kind"] == "tool_call"], [e["target"] for e in events if e["kind"] == "data_access"],
                   sorted({e["agent"] for e in events} | {e["target"] for e in events if e["kind"] == "delegation"} | set(known_agents or [])), [e["dept"] for e in events])

    def slot(self, kind: str, target: str) -> int:
        table = self.t_ix if kind == "tool_call" else self.r_ix if kind == "data_access" else self.a_ix if kind == "delegation" else {}
        return table.get(target, self.other)


class Snapshot:
    def __init__(self, nodes: List[Tuple[str, str]], x: List[List[float]], edges: List[Tuple[int, int]]):
        self.nodes, self.x, self.edges = nodes, x, edges                 # nodes: (type, name); edges: undirected, listed once
        self.index = {n: i for i, n in enumerate(nodes)}

    def agent_nodes(self) -> List[Tuple[str, int]]:
        return [(n[1], i) for i, n in enumerate(self.nodes) if n[0] == "agent"]


def build(events: List[Dict[str, Any]], lay: Layout) -> Snapshot:
    """The snapshot of the events of one window."""
    nodes: List[Tuple[str, str]] = []
    ix: Dict[Tuple[str, str], int] = {}
    counts: Dict[int, Dict[int, float]] = {}
    tier: Dict[int, int] = {}
    dept: Dict[int, str] = {}
    edges = set()

    def node(t: str, n: str) -> int:
        if (t, n) not in ix:
            ix[(t, n)] = len(nodes)
            nodes.append((t, n))
            counts[ix[(t, n)]] = {}
        return ix[(t, n)]

    for e in sorted(events, key=lambda z: (z["t"], z["agent"], z["kind"], z["target"])):
        a = node("agent", e["agent"])
        tier[a], dept[a] = max(tier.get(a, 0), int(e["tier"])), e["dept"]
        d = node("dept", e["dept"])
        dept[d] = e["dept"]
        edges.add((min(a, d), max(a, d)))
        if e["kind"] == "delegation":
            other = node("agent", e["target"])
            edges.add((min(a, other), max(a, other)))
            counts[a][lay.slot("delegation", e["target"])] = counts[a].get(lay.slot("delegation", e["target"]), 0) + 1
            counts[other][lay.a_ix.get(e["agent"], lay.other)] = counts[other].get(lay.a_ix.get(e["agent"], lay.other), 0) + 1
        else:
            kind = "tool" if e["kind"] == "tool_call" else "resource"
            o = node(kind, e["target"])
            edges.add((min(a, o), max(a, o)))
            s = lay.slot(e["kind"], e["target"])
            counts[a][s] = counts[a].get(s, 0) + 1
            counts[o][lay.a_ix.get(e["agent"], lay.other)] = counts[o].get(lay.a_ix.get(e["agent"], lay.other), 0) + 1
            tier[o] = max(tier.get(o, 0), int(e["tier"]))
    x: List[List[float]] = []
    for i, (t, n) in enumerate(nodes):
        v = [0.0] * lay.dim
        v[TYPES.index(t)] = 1.0
        v[len(TYPES)] = tier.get(i, 0) / 4.0
        total = sum(counts[i].values())
        v[len(TYPES) + 1] = math.log1p(total)
        if t in ("agent", "dept") and dept.get(i) in lay.d_ix:
            v[len(TYPES) + 2 + lay.d_ix[dept[i]]] = 1.0
        base = len(TYPES) + 2 + len(lay.depts)
        for s, c in counts[i].items():
            v[base + s] = math.log1p(c)
        x.append(v)
    return Snapshot(nodes, x, sorted(edges))


def by_window(events: List[Dict[str, Any]], window: float, lo: float, hi: float) -> Dict[int, List[Dict[str, Any]]]:
    out: Dict[int, List[Dict[str, Any]]] = {}
    for e in events:
        if lo <= e["t"] < hi:
            out.setdefault(int(e["t"] // window), []).append(e)
    return dict(sorted(out.items()))
