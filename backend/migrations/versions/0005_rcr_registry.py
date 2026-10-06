"""agent design-time RCR requirement registry

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rcr_profiles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("profile_key", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("partial_credit", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id")),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "rcr_requirements",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("profile_id", sa.Uuid(), sa.ForeignKey("rcr_profiles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("req_key", sa.String(64), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("instrument", sa.String(64), nullable=False),
        sa.Column("cls", sa.String(8), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("phi", sa.Float()),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("design_check", postgresql.JSONB()),
        sa.Column("unsatisfied_declared", sa.String(10), nullable=False, server_default="Gap"),
        sa.Column("default_declaration", postgresql.JSONB()),
        sa.UniqueConstraint("profile_id", "req_key", name="uq_rcr_requirement"),
        sa.CheckConstraint("cls IN ('veto', 'ordinary')", name="ck_rcr_cls"),
    )


def downgrade() -> None:
    op.drop_table("rcr_requirements")
    op.drop_table("rcr_profiles")
