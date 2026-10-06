"""coverage assignments: who owns closing a threat check, and by when

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-13
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "coverage_assignments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("code", sa.String(40), nullable=False),
        sa.Column("owner", sa.String(120)),
        sa.Column("due_date", sa.Date()),
        sa.Column("note", sa.Text()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "code", name="uq_coverage_assignment"),
    )


def downgrade() -> None:
    op.drop_table("coverage_assignments")
