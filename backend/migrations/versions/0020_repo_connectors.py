"""repository connectors: connections, scans, and what each agent was imported from

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repo_connections",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("provider", sa.String(12), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("branch", sa.String(120), nullable=False, server_default=""),
        sa.Column("subpath", sa.String(200), nullable=False, server_default=""),
        sa.Column("token_enc", sa.Text()),
        sa.Column("webhook_secret_enc", sa.Text()),
        sa.Column("auto_sync", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("include_tests", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.String(10), nullable=False, server_default="NEVER"),
        sa.Column("last_scan_at", sa.DateTime(timezone=True)),
        sa.Column("last_commit", sa.String(40)),
        sa.Column("last_error", sa.String(400)),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "url", "branch", "subpath", name="uq_repo_connection"),
    )
    op.create_table(
        "repo_scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("connection_id", sa.Uuid(), sa.ForeignKey("repo_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("trigger", sa.String(12), nullable=False),
        sa.Column("result", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_repo_scans_connection_id", "repo_scans", ["connection_id"])
    op.create_table(
        "repo_imports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("connection_id", sa.Uuid(), sa.ForeignKey("repo_connections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("path", sa.String(300), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("outcome", sa.String(10), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("connection_id", "agent_key", name="uq_repo_import"),
    )


def downgrade() -> None:
    op.drop_table("repo_imports")
    op.drop_index("ix_repo_scans_connection_id", table_name="repo_scans")
    op.drop_table("repo_scans")
    op.drop_table("repo_connections")
