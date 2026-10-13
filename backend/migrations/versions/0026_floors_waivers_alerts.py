"""threshold floors and waivers for production monitors, and alert channels

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("model_monitors", sa.Column("waivers", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.create_table(
        "threshold_floors",
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), primary_key=True),
        sa.Column("floors", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_by", sa.String(200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "alert_channels",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("url_sealed", sa.String(1500), nullable=False),
        sa.Column("host", sa.String(200), nullable=False),
        sa.Column("min_severity", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_status", sa.String(300)),
        sa.Column("last_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alert_channels_organisation_id", "alert_channels", ["organisation_id"])


def downgrade() -> None:
    op.drop_table("alert_channels")
    op.drop_table("threshold_floors")
    op.drop_column("model_monitors", "waivers")
