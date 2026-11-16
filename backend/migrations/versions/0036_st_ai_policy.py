"""ST-AI v2.5 policy versions: independence levels and modes, the risk basis and the tolerances allocated down the organisation

Revision ID: 0036
Revises: 0035
Create Date: 2026-11-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "st_ai_policy_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("params", JSONB(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("published_by", sa.String(120), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "number", name="uq_st_ai_policy_number"),
    )


def downgrade() -> None:
    op.drop_table("st_ai_policy_versions")
