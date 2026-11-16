"""
The divergence classes of the ASTRA specification (section 8): one row per class.

Each class names the contract element it checks, the Secure Tropos construct behind it, the OWASP agentic risks it signals, how it is detected
(policy lookup, cryptographic check, statistical baseline, semantic judgement) and its default severity. The model adds two things the specification
leaves to the design: the control kind the class protects (so a divergence becomes evidence about a control) and the kind of event it is read from.

Severity is a property of the class; what it means for a department is decided by the gate (gate.py). This table is data, not logic: the predicates
are in events.py.
"""
from dataclasses import dataclass
from typing import Dict, Tuple

POLICY, CRYPTOGRAPHIC, BASELINE, SEMANTIC = "policy", "cryptographic", "baseline", "semantic"


@dataclass(frozen=True)
class DivergenceClass:
    id: str
    name: str
    element: str            # the contract element the class checks
    construct: str          # the Secure Tropos construct behind it
    asi: Tuple[str, ...]    # OWASP agentic risks signalled
    basis: str              # policy | cryptographic | baseline | semantic
    severity: str           # Medium | High | Critical
    control: str            # the control kind it protects
    event: str              # the kind of event it is read from


CLASSES: Dict[str, DivergenceClass] = {c.id: c for c in (
    DivergenceClass('DVG-GOAL-01', 'Goal out of scope', 'permitted_goals', 'Secure goal', ('ASI01',), 'semantic', 'High', 'iso', 'goal_set'),
    DivergenceClass('DVG-GOAL-02', 'Goal integrity violation', 'permitted_goals', 'Secure goal', ('ASI01',), 'semantic', 'Critical', 'iso', 'goal_set'),
    DivergenceClass('DVG-TOOL-01', 'Tool out of scope', 'permitted_tasks', 'Task/plan', ('ASI02',), 'policy', 'High', 'least', 'tool_call'),
    DivergenceClass('DVG-TOOL-02', 'Parameter out of bounds', 'permitted_tasks.scope', 'Task/plan', ('ASI02',), 'policy', 'High', 'least', 'tool_call'),
    DivergenceClass('DVG-TOOL-03', 'Prohibited chain executed', 'prohibited_chains', 'Task/plan', ('ASI02',), 'policy', 'High', 'least', 'tool_call'),
    DivergenceClass('DVG-EXEC-01', 'Execution outside sandbox/egress', 'permitted_tasks', 'Task execution boundary', ('ASI05',), 'policy', 'Critical', 'sandbox', 'exec'),
    DivergenceClass('DVG-RES-01', 'Resource out of scope', 'resource_scopes.data', 'Resource', ('ASI06',), 'policy', 'High', 'least', 'res_access'),
    DivergenceClass('DVG-MEM-01', 'Memory-write violation', 'resource_scopes.memory', 'Resource', ('ASI06',), 'policy', 'High', 'memval', 'mem_write'),
    DivergenceClass('DVG-MEM-02', 'Provenance missing', 'resource_scopes.memory', 'Resource', ('ASI06',), 'policy', 'Medium', 'memval', 'mem_write'),
    DivergenceClass('DVG-DEL-01', 'Delegation to unauthorised target', 'may_delegate_to', 'Secure dependency', ('ASI04', 'ASI07'), 'policy', 'High', 'deleg', 'deleg_out'),
    DivergenceClass('DVG-DEL-02', 'Delegation from unauthorised source', 'accepts_delegation_from', 'Secure dependency', ('ASI07',), 'policy', 'High', 'deleg', 'deleg_in'),
    DivergenceClass('DVG-DEL-03', 'Delegation-mode violation', 'delegation.mode', 'Trust/delegation', ('ASI03', 'ASI07'), 'policy', 'High', 'deleg', 'deleg_out'),
    DivergenceClass('DVG-COMM-01', 'Unauthenticated/unsigned message', 'delegation (channel)', 'Secure dependency', ('ASI07',), 'cryptographic', 'High', 'auth', 'msg'),
    DivergenceClass('DVG-AUT-01', 'Autonomy-boundary breach', 'human_in_the_loop', 'Security constraint', ('ASI09',), 'policy', 'High', 'hitl', 'tool_call'),
    DivergenceClass('DVG-AUT-02', 'Confirmation bypass', 'human_in_the_loop', 'Security constraint', ('ASI09',), 'policy', 'Critical', 'hitl', 'tool_call'),
    DivergenceClass('DVG-AUT-03', 'Presented-vs-executed mismatch', 'autonomy (HITL integrity)', 'Trust relationship', ('ASI09',), 'policy', 'Critical', 'hitl', 'tool_call'),
    DivergenceClass('DVG-ID-01', 'Identity violation', 'agent.id / lifecycle', 'Ownership', ('ASI03',), 'policy', 'High', 'ident', 'id'),
    DivergenceClass('DVG-LIFE-01', 'Lifecycle violation', 'agent.lifecycle', 'Ownership/actor', ('ASI10',), 'policy', 'Medium', 'life', 'life'),
    DivergenceClass('DVG-BASE-01', 'Behavioural-baseline deviation', '(whole contract)', 'Actor behaviour', ('ASI10',), 'baseline', 'Medium', 'base', 'score'),
    DivergenceClass('DVG-SPAWN-01', 'Uninventoried sub-agent spawn', 'estate model', 'Actor', ('ASI10',), 'policy', 'High', 'spawn', 'spawn'),
    DivergenceClass('DVG-SUP-01', 'Unsigned/unprovenanced component', 'supply chain', 'Actor/dependency', ('ASI04',), 'cryptographic', 'Critical', 'supply', 'component'),
    DivergenceClass('DVG-SUP-02', 'Runtime component not in AIBOM', 'supply chain', 'Actor/dependency', ('ASI04',), 'policy', 'High', 'supply', 'component'),
    )}

# Severity becomes evidence about the control the class protects: High and Critical mean the control has been violated, Medium that it is now unverified.
SEVERITY_LEVEL = {"High": "VIO", "Critical": "VIO", "Medium": "UNV"}

# The control kind that each kind of event concerns, used when an event cannot be checked (a required attribute is missing).
EVENT_CONTROL = {"goal_set": "iso", "tool_call": "least", "exec": "sandbox", "res_access": "least", "mem_write": "memval",
                 "deleg_out": "deleg", "deleg_in": "deleg", "msg": "auth", "id": "ident", "life": "life", "spawn": "spawn",
                 "component": "supply"}
