"""regulations, rules, domains

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-06
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "regulations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("instrument", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("source_url", sa.String(500)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("kind IN ('REGULATION', 'STANDARD', 'ORG_POLICY')", name="ck_regulations_kind"),
    )
    op.create_table(
        "rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("rule_key", sa.String(80), nullable=False, unique=True),
        sa.Column("regulation_id", sa.Uuid(), sa.ForeignKey("regulations.id"), nullable=False),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id")),
        sa.Column("citation", sa.String(120), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("maps_to_constraint_id", sa.String(32)),
        sa.Column("status", sa.String(16), nullable=False, server_default="APPROVED"),
        sa.Column("origin", sa.String(16), nullable=False, server_default="SEED"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("severity IN ('REQUIRED', 'RECOMMENDED')", name="ck_rules_severity"),
        sa.CheckConstraint("status IN ('DRAFT', 'APPROVED', 'RETIRED')", name="ck_rules_status"),
    )
    op.create_table(
        "domains",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("domain_key", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id")),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "domain_rules",
        sa.Column("domain_id", sa.Uuid(), sa.ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("rule_id", sa.Uuid(), sa.ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("position", sa.Integer(), nullable=False),
    )
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.String(255), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_table("domain_rules")
    op.drop_table("domains")
    op.drop_table("rules")
    op.drop_table("regulations")
