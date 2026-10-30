"""design reviews: a person with sign-off permission records that they reviewed one version of a design

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "design_reviews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("design_key", sa.String(40), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("decision", sa.String(8), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("reviewer_name", sa.String(120), nullable=False),
        sa.Column("reviewer_role", sa.String(20), nullable=False),
        sa.Column("pcs_final", sa.Float(), nullable=False),
        sa.Column("tier", sa.String(12), nullable=False),
        sa.Column("gate", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("decision IN ('APPROVED', 'REJECTED')", name="ck_design_reviews_decision"),
    )
    op.create_index("ix_design_reviews_design", "design_reviews", ["design_key", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_design_reviews_design", table_name="design_reviews")
    op.drop_table("design_reviews")
