"""responsibilities and assignments: who holds a duty, for how long, separate from the employee record and the organisation structure

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "responsibilities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("subject_kind", sa.String(8), nullable=False),
        sa.Column("subject_ref", sa.String(80), nullable=False),
        sa.Column("duty", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "subject_kind", "subject_ref", "duty", name="uq_responsibility"),
        sa.CheckConstraint("subject_kind IN ('agent', 'model')", name="ck_responsibility_kind"),
    )
    op.create_table(
        "assignments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("responsibility_id", sa.Uuid(), sa.ForeignKey("responsibilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("holder_ext_id", sa.String(64), nullable=True),          # the employee record (a person or role of the organisation); null for a holder outside it
        sa.Column("holder_name", sa.String(160), nullable=False),          # what to show if the record is gone, and for a holder outside the organisation
        sa.Column("kind", sa.String(7), nullable=False),
        sa.Column("starts_on", sa.Date(), nullable=False),
        sa.Column("ends_on", sa.Date(), nullable=True),
        sa.Column("reason", sa.String(200), nullable=True),
        sa.Column("created_by", sa.String(160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ended_by", sa.String(160), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.CheckConstraint("kind IN ('PRIMARY', 'COVER')", name="ck_assignment_kind"),
        sa.CheckConstraint("ends_on IS NULL OR ends_on >= starts_on", name="ck_assignment_dates"),
    )
    op.create_index("ix_assignments_responsibility", "assignments", ["responsibility_id", "starts_on"])


def downgrade() -> None:
    op.drop_index("ix_assignments_responsibility", table_name="assignments")
    op.drop_table("assignments")
    op.drop_table("responsibilities")
