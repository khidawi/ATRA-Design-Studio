"""agents created from the organisation, and tombstones for contracts removed with their agent or model

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-09
"""
from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_agents_origin", "agents", type_="check")
    op.create_check_constraint("ck_agents_origin", "agents", "origin IN ('DESIGNED', 'REGISTERED', 'DEMO', 'DISCOVERED', 'ORG')")
    op.create_table(
        "removed_contracts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("contract_id", sa.String(64), nullable=False, unique=True),
        sa.Column("object_type", sa.String(8), nullable=False),
        sa.Column("deployment_id", sa.String(80), nullable=False),
        sa.Column("version", sa.String(16), nullable=False, server_default=""),
        sa.Column("contract_hash", sa.String(64), nullable=False),
        sa.Column("removed_by", sa.String(200), nullable=False),
        sa.Column("reason", sa.String(200), nullable=False, server_default=""),
        sa.Column("removed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("removed_contracts")
    op.execute("DELETE FROM agents WHERE origin = 'ORG'")
    op.drop_constraint("ck_agents_origin", "agents", type_="check")
    op.create_check_constraint("ck_agents_origin", "agents", "origin IN ('DESIGNED', 'REGISTERED', 'DEMO', 'DISCOVERED')")
