"""ASTRA phase 6: typed findings for the divergence classes, runtime bindings and peer keys

Revision ID: 0040
Revises: 0039
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # findings: what a typed divergence record carries beside the legacy columns (all optional, so every existing row and writer stays valid)
    op.add_column("findings", sa.Column("detection_basis", sa.String(14)))                   # policy | cryptographic | semantic
    op.add_column("findings", sa.Column("contract_element", sa.String(60)))
    op.add_column("findings", sa.Column("construct", sa.String(60)))
    op.add_column("findings", sa.Column("asi_signal", JSONB()))
    op.add_column("findings", sa.Column("evidence_refs", JSONB()))
    op.add_column("findings", sa.Column("response_recommended", sa.String(8)))              # filled by the runtime gate (phase 7)
    op.add_column("findings", sa.Column("class_severity", sa.String(8)))                    # the class's own severity; severity keeps the three-level scale of the legacy screens
    op.add_column("findings", sa.Column("adjudication", sa.String(10)))                     # PENDING | CONFIRMED | DISMISSED, for the semantic classes
    op.add_column("findings", sa.Column("adjudicated_by", sa.String(120)))
    op.add_column("findings", sa.Column("adjudicated_at", sa.DateTime(timezone=True)))
    op.add_column("findings", sa.Column("adjudication_note", sa.Text()))
    op.create_check_constraint("ck_findings_adjudication", "findings", "adjudication IS NULL OR adjudication IN ('PENDING', 'CONFIRMED', 'DISMISSED')")
    # runtime events: two more verdicts (an event that cannot be judged, and one waiting for a person)
    op.drop_constraint("ck_runtime_verdict", "runtime_events", type_="check")
    op.create_check_constraint("ck_runtime_verdict", "runtime_events", "verdict IN ('CONFORMING', 'DIVERGENT', 'NO_CONTRACT', 'UNKNOWN_AGENT', 'UNVERIFIED', 'PENDING')")
    op.create_table(
        "astra_bindings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("element", sa.String(12), nullable=False),
        sa.Column("selector", sa.String(200), nullable=False),
        sa.Column("contract_name", sa.String(200), nullable=False),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("element IN ('tool', 'resource', 'delegate', 'component')", name="ck_astra_binding_element"),
    )
    op.create_index("uq_astra_binding", "astra_bindings", ["organisation_id", "agent_key", "element", "selector"], unique=True)
    op.create_table(
        "astra_peer_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("public_key", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("uq_astra_peer_key", "astra_peer_keys", ["organisation_id", "key_id"], unique=True)


def downgrade() -> None:
    op.drop_table("astra_peer_keys")
    op.drop_table("astra_bindings")
    op.execute("DELETE FROM runtime_events WHERE verdict IN ('UNVERIFIED', 'PENDING')")
    op.drop_constraint("ck_runtime_verdict", "runtime_events", type_="check")
    op.create_check_constraint("ck_runtime_verdict", "runtime_events", "verdict IN ('CONFORMING', 'DIVERGENT', 'NO_CONTRACT', 'UNKNOWN_AGENT')")
    op.drop_constraint("ck_findings_adjudication", "findings", type_="check")
    for c in ("adjudication_note", "adjudicated_at", "adjudicated_by", "adjudication", "class_severity", "response_recommended", "evidence_refs", "asi_signal", "construct", "contract_element", "detection_basis"):
        op.drop_column("findings", c)
