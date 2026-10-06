"""findings and drift items

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.Integer(), sa.Identity(start=1001), nullable=False, unique=True),      # F-1001, F-1002, ...
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("contract_id", sa.String(64)),
        sa.Column("contract_version", sa.String(16)),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("class_code", sa.String(16), nullable=False),
        sa.Column("observed", sa.Text(), nullable=False),
        sa.Column("permitted", sa.Text(), nullable=False),
        sa.Column("element", sa.String(40), nullable=False),
        sa.Column("threat", sa.String(120), nullable=False),
        sa.Column("evidence", sa.String(200), nullable=False),
        sa.Column("event", postgresql.JSONB()),
        sa.Column("source", sa.String(10), nullable=False),                  # SIMULATED | COLLECTED | DEMO
        sa.Column("status", sa.String(14), nullable=False, server_default="OPEN"),
        sa.Column("acknowledged_by", sa.String(120)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("test_spec", sa.Text()),
        sa.Column("halt_requested_by", sa.String(120)),
        sa.Column("halt_requested_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("severity IN ('High', 'Medium', 'Low')", name="ck_findings_severity"),
        sa.CheckConstraint("source IN ('SIMULATED', 'COLLECTED', 'DEMO')", name="ck_findings_source"),
        sa.CheckConstraint("status IN ('OPEN', 'ACKNOWLEDGED')", name="ck_findings_status"),
    )
    op.create_table(
        "drift_items",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("contract_id", sa.String(64)),                              # the ratified contract this is compared with
        sa.Column("design_key", sa.String(40)),
        sa.Column("source", sa.String(10), nullable=False),                  # DESIGN | SIMULATED | DEMO
        sa.Column("source_label", sa.String(200), nullable=False),
        sa.Column("from_version", sa.String(16), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),                    # Widening | Narrowing | Review | Runtime
        sa.Column("policy", sa.String(8), nullable=False, server_default="block"),
        sa.Column("proposed", postgresql.JSONB()),                           # the proposed design document; null for demo rows
        sa.Column("changes", postgresql.JSONB(), nullable=False),
        sa.Column("impact", postgresql.JSONB(), nullable=False),
        sa.Column("rcr_before", sa.Float()),
        sa.Column("rcr_after", sa.Float()),
        sa.Column("gate_after", sa.String(8)),
        sa.Column("status", sa.String(10), nullable=False, server_default="OPEN"),
        sa.Column("decided_by", sa.String(120)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("decision_note", sa.Text()),
        sa.Column("new_contract_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("source IN ('DESIGN', 'SIMULATED', 'DEMO')", name="ck_drift_source"),
        sa.CheckConstraint("status IN ('OPEN', 'APPROVED', 'DECLINED', 'SUPERSEDED')", name="ck_drift_status"),
    )


def downgrade() -> None:
    op.drop_table("drift_items")
    op.drop_table("findings")
