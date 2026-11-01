"""route-based OWASP checks: ASI01 and ASI02 ask whether the guard lies on every route, not whether a guard exists

Revision ID: 0032
Revises: 0031
Create Date: 2026-11-01

Only the seeded rules are changed (origin SEED). An organisation policy or a rule an organisation edited is never touched. The previous check is kept in `downgrade`.
"""
import json

from alembic import op
import sqlalchemy as sa

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None

WRITE = {"type": "tool", "where": {"write": True}}
UNTRUSTED = {"type": "input", "where": {"untrusted": True}}
TO_WRITE = {"from": {"type": "agent", "primary": True}, "to": WRITE, "along": ["delegates", "uses", "connects", "calls"], "guard": {"type": "approval", "label": "gates"}}
FROM_UNTRUSTED = {"from": UNTRUSTED, "to": WRITE, "along": ["feeds", "delegates", "uses", "connects", "calls"],
                  "guard": {"type": "guardrail", "where": {"kind": "injection"}, "label": "limits"}}

NEW = {
    "OWASP-ASI01": (
        "Applies when untrusted input can reach a write-capable tool. Satisfied when a prompt-injection guardrail limits the agent on every route from an untrusted input to a write-capable tool.",
        {"code": "ASI01", "fix_label": "Add injection filter",
         "applies_if": {"all": [{"exists": UNTRUSTED}, {"exists": WRITE}]},
         "satisfied_if": {"no_unguarded_path": FROM_UNTRUSTED}, "flag_unguarded": FROM_UNTRUSTED,
         "flag_nodes": [{"type": "agent", "primary": True}, UNTRUSTED], "vars": {"route": {"route": FROM_UNTRUSTED}},
         "messages": {"not_applicable": "No untrusted input with write tools",
                      "satisfied": "Every route from untrusted input to a write tool passes an injection filter",
                      "unsatisfied": "Untrusted input reaches a write-capable tool without an injection filter: {route}"}}),
    "OWASP-ASI02": (
        "Applies when the agent has a write-capable tool. Satisfied when a human approval lies on every route from the agent to a write-capable tool: an approval drawn beside the route does not count.",
        {"code": "ASI02", "fix_label": "Add approval step", "unsatisfied_status": "AMBER",
         "applies_if": {"exists": WRITE}, "satisfied_if": {"no_unguarded_path": TO_WRITE}, "flag_unguarded": TO_WRITE,
         "vars": {"n": {"unguarded": TO_WRITE}, "route": {"route": TO_WRITE}},
         "inapplicable": [{"when": {"always": True}, "status": "GREEN", "message": "Read-only tools declared"}],
         "messages": {"satisfied": "Every route to a write tool passes a human approval",
                      "unsatisfied": "{n} write tool(s) can be reached without a human approval: {route}"}}),
}

OLD = {
    "OWASP-ASI01": (
        "Applies when untrusted input can reach a write-capable tool. Satisfied by a prompt-injection guardrail.",
        {"code": "ASI01", "fix_label": "Add injection filter",
         "applies_if": {"all": [{"exists": UNTRUSTED}, {"exists": WRITE}]},
         "satisfied_if": {"exists": {"type": "guardrail", "where": {"kind": "injection"}}},
         "flag_nodes": [{"type": "agent", "primary": True}, UNTRUSTED],
         "messages": {"not_applicable": "No untrusted input with write tools", "satisfied": "Injection filter on untrusted input",
                      "unsatisfied": "Untrusted input reaches a write-capable tool"}}),
    "OWASP-ASI02": (
        "Applies when the agent has a write-capable tool. Satisfied by a human approval step.",
        {"code": "ASI02", "fix_label": "Add approval step", "unsatisfied_status": "AMBER",
         "applies_if": {"exists": WRITE}, "satisfied_if": {"exists": {"type": "approval"}}, "flag_nodes": [WRITE],
         "inapplicable": [{"when": {"always": True}, "status": "GREEN", "message": "Read-only tools declared"}],
         "messages": {"satisfied": "Write tools gated by human approval", "unsatisfied": "Write tool has no approval step"}}),
}


def _apply(rules) -> None:
    bind = op.get_bind()
    for key, (description, config) in rules.items():
        bind.execute(sa.text("UPDATE rules SET description = :d, check_config = CAST(:c AS jsonb) WHERE rule_key = :k AND origin = 'SEED'"),
                     {"d": description, "c": json.dumps(config), "k": key})


def upgrade() -> None:
    _apply(NEW)


def downgrade() -> None:
    _apply(OLD)
