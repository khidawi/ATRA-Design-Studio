"""ASTRA phase 5: the accepted baseline and the signed behavioural contract

Revision ID: 0039
Revises: 0038
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "astra_baselines",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("design_key", sa.String(40), nullable=False),
        sa.Column("design_hash", sa.String(64), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), sa.ForeignKey("astra_assessments.id"), nullable=False),
        sa.Column("accepted_by", sa.String(120), nullable=False),
        sa.Column("accepted_by_id", sa.Uuid(), nullable=False),
        sa.Column("note", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_astra_baselines_design", "astra_baselines", ["organisation_id", "design_key", "created_at"])
    op.create_table(
        "astra_signed_contracts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("design_key", sa.String(40), nullable=False),
        sa.Column("design_hash", sa.String(64), nullable=False),
        sa.Column("baseline_id", sa.Uuid(), sa.ForeignKey("astra_baselines.id"), nullable=False),
        sa.Column("version", sa.String(20), nullable=False),
        sa.Column("document", JSONB(), nullable=False),
        sa.Column("contract_hash", sa.String(64), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("not_before", sa.String(20), nullable=False),
        sa.Column("expires_at", sa.String(20), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="ACTIVE"),
        sa.Column("signed_by", sa.String(120), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_by", sa.String(120)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.Text()),
        sa.CheckConstraint("status IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')", name="ck_astra_signed_status"),
    )
    op.create_index("uq_astra_signed_active", "astra_signed_contracts", ["organisation_id", "agent_key"], unique=True, postgresql_where=sa.text("status = 'ACTIVE'"))
    op.create_index("ix_astra_signed_agent", "astra_signed_contracts", ["organisation_id", "agent_key", "signed_at"])


def downgrade() -> None:
    op.drop_table("astra_signed_contracts")
    op.drop_table("astra_baselines")
