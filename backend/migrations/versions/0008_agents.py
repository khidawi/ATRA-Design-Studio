"""agent inventory

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-10
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("owner", sa.String(120)),
        sa.Column("framework", sa.String(80), nullable=False, server_default="Not built yet"),
        sa.Column("tools_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(12), nullable=False),          # ASSURED | TO_RATIFY | DESIGNED | UNOWNED
        sa.Column("mode", sa.String(12), nullable=False, server_default="NOT_RUNNING"),
        sa.Column("origin", sa.String(10), nullable=False),          # DESIGNED | REGISTERED | DEMO
        sa.Column("design_id", sa.Uuid(), sa.ForeignKey("designs.id", ondelete="SET NULL")),
        sa.Column("note", sa.String(200)),                           # shown as the last finding until findings exist (demo rows only)
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "agent_key", name="uq_agents_org_key"),
        sa.CheckConstraint("status IN ('ASSURED', 'TO_RATIFY', 'DESIGNED', 'UNOWNED')", name="ck_agents_status"),
        sa.CheckConstraint("mode IN ('NOT_RUNNING', 'OBSERVE', 'FLAG', 'BLOCK')", name="ck_agents_mode"),
        sa.CheckConstraint("origin IN ('DESIGNED', 'REGISTERED', 'DEMO')", name="ck_agents_origin"),
    )


def downgrade() -> None:
    op.drop_table("agents")
