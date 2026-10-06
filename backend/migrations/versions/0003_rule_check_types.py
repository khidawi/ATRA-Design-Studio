"""rule check types and domain subject

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-06
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

# Rules that had no linked Security Constraint, so they could never be evaluated and
# kept every domain that contained them at amber. They are now attested through a
# Regulatory requirement node. Fresh databases get this from db/seed.py instead.
NOW_ATTESTATION = ("EUAI-ANNEXIII-HEALTH", "OWASP-LLM-TOP10")


def upgrade() -> None:
    op.add_column("rules", sa.Column("check_type", sa.String(16), nullable=False, server_default="CONSTRAINT"))
    op.add_column(
        "rules",
        sa.Column("check_config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.create_check_constraint(
        "ck_rules_check_type", "rules", "check_type IN ('CONSTRAINT', 'ATTESTATION', 'GRAPH')"
    )
    op.add_column("domains", sa.Column("subject", sa.String(8), nullable=False, server_default="MODEL"))
    op.create_check_constraint("ck_domains_subject", "domains", "subject IN ('MODEL', 'AGENT')")

    op.execute(
        sa.text(
            "UPDATE rules SET check_type = 'ATTESTATION', version = version + 1 "
            "WHERE rule_key IN :keys AND maps_to_constraint_id IS NULL AND check_type = 'CONSTRAINT'"
        ).bindparams(sa.bindparam("keys", expanding=True, value=list(NOW_ATTESTATION)))
    )


def downgrade() -> None:
    op.drop_constraint("ck_domains_subject", "domains", type_="check")
    op.drop_column("domains", "subject")
    op.drop_constraint("ck_rules_check_type", "rules", type_="check")
    op.drop_column("rules", "check_config")
    op.drop_column("rules", "check_type")
