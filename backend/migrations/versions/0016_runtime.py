"""runtime observation: events from the SDK, last-seen on agents, runtime drift, collector keys

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-18
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.BigInteger(), sa.Identity(start=1), nullable=False, unique=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),                # when the SDK says it happened (clamped to a sane window)
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("name", sa.String(200), nullable=False, server_default=""),
        sa.Column("attrs", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("verdict", sa.String(14), nullable=False),                         # CONFORMING | DIVERGENT | NO_CONTRACT | UNKNOWN_AGENT
        sa.Column("contract_version", sa.String(16)),
        sa.Column("finding_key", sa.String(12)),
        sa.Column("reported_by", sa.String(200), nullable=False),                    # the key's name
        sa.CheckConstraint("verdict IN ('CONFORMING', 'DIVERGENT', 'NO_CONTRACT', 'UNKNOWN_AGENT')", name="ck_runtime_verdict"),
    )
    op.create_index("ix_runtime_events_agent_at", "runtime_events", ["agent_key", "at"])
    op.create_index("ix_runtime_events_received", "runtime_events", ["received_at"])

    op.add_column("agents", sa.Column("last_seen_at", sa.DateTime(timezone=True)))
    op.drop_constraint("ck_agents_origin", "agents", type_="check")
    op.create_check_constraint("ck_agents_origin", "agents", "origin IN ('DESIGNED', 'REGISTERED', 'DEMO', 'DISCOVERED')")

    op.drop_constraint("ck_drift_source", "drift_items", type_="check")
    op.create_check_constraint("ck_drift_source", "drift_items", "source IN ('DESIGN', 'SIMULATED', 'DEMO', 'IMPORT', 'RUNTIME')")

    op.drop_constraint("ck_api_keys_role", "api_keys", type_="check")
    op.create_check_constraint("ck_api_keys_role", "api_keys", "role IN ('engineer', 'auditor', 'collector')")


def downgrade() -> None:
    op.execute("DELETE FROM api_keys WHERE role = 'collector'")
    op.drop_constraint("ck_api_keys_role", "api_keys", type_="check")
    op.create_check_constraint("ck_api_keys_role", "api_keys", "role IN ('engineer', 'auditor')")
    op.execute("DELETE FROM drift_items WHERE source = 'RUNTIME'")
    op.drop_constraint("ck_drift_source", "drift_items", type_="check")
    op.create_check_constraint("ck_drift_source", "drift_items", "source IN ('DESIGN', 'SIMULATED', 'DEMO', 'IMPORT')")
    op.execute("DELETE FROM agents WHERE origin = 'DISCOVERED'")
    op.drop_constraint("ck_agents_origin", "agents", type_="check")
    op.create_check_constraint("ck_agents_origin", "agents", "origin IN ('DESIGNED', 'REGISTERED', 'DEMO')")
    op.drop_column("agents", "last_seen_at")
    op.drop_table("runtime_events")
