"""what a first-pass screening of an agent's description found, and the SCREENED origin

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-29
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("screening", postgresql.JSONB(), nullable=True))
    op.drop_constraint("ck_agents_origin", "agents", type_="check")
    op.create_check_constraint("ck_agents_origin", "agents", "origin IN ('DESIGNED', 'REGISTERED', 'DEMO', 'DISCOVERED', 'ORG', 'SCREENED')")


def downgrade() -> None:
    op.execute("UPDATE agents SET origin = 'REGISTERED' WHERE origin = 'SCREENED'")
    op.drop_constraint("ck_agents_origin", "agents", type_="check")
    op.create_check_constraint("ck_agents_origin", "agents", "origin IN ('DESIGNED', 'REGISTERED', 'DEMO', 'DISCOVERED', 'ORG')")
    op.drop_column("agents", "screening")
