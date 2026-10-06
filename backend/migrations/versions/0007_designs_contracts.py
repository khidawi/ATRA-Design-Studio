"""saved designs and compiled contracts

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "designs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("design_key", sa.String(40), nullable=False, unique=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("subject", sa.String(8), nullable=False, server_default="MODEL"),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("domain_key", sa.String(64), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("subject IN ('MODEL', 'AGENT')", name="ck_designs_subject"),
    )
    op.create_table(
        "contracts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("contract_id", sa.String(64), nullable=False, unique=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        # A contract outlives the design it came from: deleting the design keeps it, unlinked.
        sa.Column("design_id", sa.Uuid(), sa.ForeignKey("designs.id", ondelete="SET NULL")),
        sa.Column("object_type", sa.String(8), nullable=False, server_default="MODEL"),
        sa.Column("deployment_id", sa.String(80), nullable=False),
        sa.Column("origin", sa.String(10), nullable=False, server_default="COMPILED"),   # COMPILED | IMPORTED
        sa.Column("document", postgresql.JSONB(), nullable=False),                         # exactly as issued
        sa.Column("contract_hash", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("origin IN ('COMPILED', 'IMPORTED')", name="ck_contracts_origin"),
    )


def downgrade() -> None:
    op.drop_table("contracts")
    op.drop_table("designs")
