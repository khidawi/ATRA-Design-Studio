"""organisation policies: rule subject, applies-to-all, authoring spec

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-06
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("rules", sa.Column("subject", sa.String(8), nullable=False, server_default="MODEL"))
    op.add_column("rules", sa.Column("applies_to_all", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("rules", sa.Column("spec", postgresql.JSONB(), nullable=True))
    op.create_check_constraint("ck_rules_subject", "rules", "subject IN ('MODEL', 'AGENT')")
    # The OWASP Agentic rules added in the previous migration's seed are agent rules.
    op.execute("UPDATE rules SET subject = 'AGENT' WHERE rule_key LIKE 'OWASP-ASI%'")


def downgrade() -> None:
    op.drop_constraint("ck_rules_subject", "rules", type_="check")
    op.drop_column("rules", "spec")
    op.drop_column("rules", "applies_to_all")
    op.drop_column("rules", "subject")
