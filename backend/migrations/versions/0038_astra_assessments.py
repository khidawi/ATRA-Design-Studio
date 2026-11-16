"""ASTRA phase 4: recorded assessments of an agent design, never edited

Revision ID: 0038
Revises: 0037
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "astra_assessments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("design_key", sa.String(40), nullable=False),
        sa.Column("design_version", sa.Integer(), nullable=False),
        sa.Column("design_hash", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("departments", JSONB(), nullable=False),
        sa.Column("result", JSONB(), nullable=False),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("verdict IN ('INVALID_CONTRACT', 'BLOCKED', 'REQUIRES_REVIEW', 'APPROVED')", name="ck_astra_assessment_verdict"),
    )
    op.create_index("ix_astra_assessments_design", "astra_assessments", ["organisation_id", "design_key", "created_at"])


def downgrade() -> None:
    op.drop_table("astra_assessments")
