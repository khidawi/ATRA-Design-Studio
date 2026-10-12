"""telemetry discovery: settings, and a record of what each OTLP request became

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "telemetry_settings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False, unique=True),
        sa.Column("agent_from_service", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("discover", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.create_table(
        "telemetry_ingest",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_name", sa.String(200), nullable=False),
        sa.Column("spans", sa.Integer(), nullable=False),
        sa.Column("mapped", sa.Integer(), nullable=False),
        sa.Column("ignored", sa.Integer(), nullable=False),
        sa.Column("unattributed", sa.Integer(), nullable=False),
        sa.Column("agents", sa.Integer(), nullable=False),
        sa.Column("events", sa.Integer(), nullable=False),
        sa.Column("divergent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("invalid", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unknown", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("waiting", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("samples", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_telemetry_ingest_organisation_id", "telemetry_ingest", ["organisation_id"])
    op.create_index("ix_telemetry_ingest_at", "telemetry_ingest", ["at"])


def downgrade() -> None:
    op.drop_table("telemetry_ingest")
    op.drop_table("telemetry_settings")
