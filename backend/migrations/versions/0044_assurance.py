"""ASTRA phase 12: regulation mapping reviews and the security role

Revision ID: 0044
Revises: 0043
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "regulation_reviews",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("clause", sa.String(120), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("rules", JSONB(), nullable=False),
        sa.Column("reviewed_by", sa.String(120), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_regulation_reviews_clause", "regulation_reviews", ["organisation_id", "clause", "created_at"])
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint("ck_users_role", "users", "role IN ('admin', 'compliance', 'engineer', 'auditor', 'security')")


def downgrade() -> None:
    op.execute("UPDATE users SET role = 'engineer' WHERE role = 'security'")
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint("ck_users_role", "users", "role IN ('admin', 'compliance', 'engineer', 'auditor')")
    op.drop_table("regulation_reviews")
