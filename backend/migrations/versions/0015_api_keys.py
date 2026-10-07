"""API keys for pipelines and collectors

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("name", sa.String(60), nullable=False),
        sa.Column("prefix", sa.String(8), nullable=False),                 # shown in lists so a key can be recognised; not secret
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),  # sha256 of the whole key; the key itself is never stored
        sa.Column("role", sa.String(12), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("revoked_by", sa.String(200)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("role IN ('engineer', 'auditor')", name="ck_api_keys_role"),
    )


def downgrade() -> None:
    op.drop_table("api_keys")
