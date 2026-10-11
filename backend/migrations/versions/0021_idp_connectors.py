"""identity-provider connectors: connections, scans, and what each agent was imported from

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "idp_connections",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("provider", sa.String(12), nullable=False),
        sa.Column("account", sa.String(200), nullable=False, server_default=""),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("secret_enc", sa.Text(), nullable=False),
        sa.Column("rule", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="NEVER"),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(400)),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "name", name="uq_idp_connection_name"),
    )
    op.create_table(
        "idp_scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("connection_id", sa.Uuid(), sa.ForeignKey("idp_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_idp_scans_connection_id", "idp_scans", ["connection_id"])
    op.create_table(
        "idp_imports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("connection_id", sa.Uuid(), sa.ForeignKey("idp_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(10), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("connection_id", "agent_key", name="uq_idp_import"),
    )


def downgrade() -> None:
    op.drop_table("idp_imports")
    op.drop_index("ix_idp_scans_connection_id", table_name="idp_scans")
    op.drop_table("idp_scans")
    op.drop_table("idp_connections")
