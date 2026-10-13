"""which model version answered, and the decisions people make about a model's outputs

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-13
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("model_monitors", sa.Column("versions", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.add_column("model_monitors", sa.Column("decision_settings", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.create_table(
        "model_decision_windows",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("monitor_id", sa.Uuid(), sa.ForeignKey("model_monitors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acc", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("monitor_id", "window_start", name="uq_model_decision_window"),
    )
    op.create_index("ix_model_decision_windows_monitor_id", "model_decision_windows", ["monitor_id"])


def downgrade() -> None:
    op.drop_table("model_decision_windows")
    op.drop_column("model_monitors", "decision_settings")
    op.drop_column("model_monitors", "versions")
