"""evidence records can expire: an attestation that never lapses is how verified turns back into declared unnoticed

Revision ID: 0035
Revises: 0034
Create Date: 2026-11-01
"""
from alembic import op
import sqlalchemy as sa

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("evidence_records", sa.Column("expires_at", sa.Date()))


def downgrade() -> None:
    op.drop_column("evidence_records", "expires_at")
