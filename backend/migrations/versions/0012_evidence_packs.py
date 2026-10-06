"""evidence packs: immutable, hash-chained snapshots

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_packs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.Integer(), sa.Identity(start=1001), nullable=False, unique=True),     # P-1001, P-1002, ...
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("template", sa.String(10), nullable=False),                                       # TRUST | ASSURANCE
        sa.Column("period_label", sa.String(40), nullable=False),
        sa.Column("generated_by", sa.String(120), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("content", postgresql.JSONB(), nullable=False),                                   # exactly as hashed
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("previous_pack_hash", sa.String(64), nullable=False),                             # "GENESIS" for the first
        sa.Column("pack_hash", sa.String(64), nullable=False),
        sa.Column("claims", sa.Integer(), nullable=False),
        sa.Column("evidenced", sa.Integer(), nullable=False),
        sa.Column("gaps", sa.Integer(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.CheckConstraint("template IN ('TRUST', 'ASSURANCE')", name="ck_packs_template"),
    )


def downgrade() -> None:
    op.drop_table("evidence_packs")
