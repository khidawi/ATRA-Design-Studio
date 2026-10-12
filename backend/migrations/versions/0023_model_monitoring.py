"""production monitoring of AI models: monitors, hourly aggregates, and the incidents they raise

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "model_monitors",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("key", sa.String(80), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("design_key", sa.String(40)),
        sa.Column("task", sa.String(16), nullable=False),
        sa.Column("spec", postgresql.JSONB(), nullable=False),
        sa.Column("thresholds", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("baseline", postgresql.JSONB()),
        sa.Column("buffer", postgresql.JSONB()),
        sa.Column("baseline_target", sa.Integer(), nullable=False, server_default="1000"),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("status", sa.String(12), nullable=False, server_default="LEARNING"),
        sa.Column("reasons", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("signals", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("records_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("rejected_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_record_at", sa.DateTime(timezone=True)),
        sa.Column("last_eval_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "key", name="uq_model_monitor_key"),
    )
    op.create_table(
        "model_windows",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("monitor_id", sa.Uuid(), sa.ForeignKey("model_monitors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acc", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("monitor_id", "window_start", name="uq_model_window"),
    )
    op.create_index("ix_model_windows_monitor_id", "model_windows", ["monitor_id"])
    op.create_table(
        "model_incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.Integer(), sa.Identity(start=1), unique=True),
        sa.Column("monitor_id", sa.Uuid(), sa.ForeignKey("model_monitors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(14), nullable=False, server_default="OPEN"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recovered_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_by", sa.String(200)),
    )
    op.create_index("ix_model_incidents_monitor_id", "model_incidents", ["monitor_id"])


def downgrade() -> None:
    op.drop_table("model_incidents")
    op.drop_table("model_windows")
    op.drop_table("model_monitors")
