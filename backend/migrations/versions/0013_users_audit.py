"""users, sessions and the hash-chained audit log

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("email", sa.String(200), nullable=False, unique=True),
        sa.Column("full_name", sa.String(120), nullable=False),
        sa.Column("role", sa.String(12), nullable=False),
        sa.Column("password_hash", sa.String(300), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("role IN ('admin', 'compliance', 'engineer', 'auditor')", name="ck_users_role"),
    )
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.Integer(), sa.Identity(start=1), nullable=False, unique=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_name", sa.String(200), nullable=False),
        sa.Column("actor_role", sa.String(12)),
        sa.Column("action", sa.String(200), nullable=False),
        sa.Column("outcome", sa.String(12), nullable=False),              # ok | denied | failed
        sa.Column("payload", postgresql.JSONB(), nullable=False),         # exactly what was hashed
        sa.Column("prev_hash", sa.String(64), nullable=False),            # "GENESIS" for the first event
        sa.Column("event_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_audit_events_at", "audit_events", ["at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("user_sessions")
    op.drop_table("users")
