"""assurance packs for AI models: a pack says what it is about

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-14
"""
from alembic import op
import sqlalchemy as sa

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence_packs", sa.Column("subject", sa.String(8), nullable=False, server_default="AGENT"))


def downgrade() -> None:
    op.drop_column("evidence_packs", "subject")
