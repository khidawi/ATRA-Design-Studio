"""contract lifecycle: current status kept beside the immutable document

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-11
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The issued document (and so its hash) never changes. What is true of the contract now lives in these columns.
    op.add_column("contracts", sa.Column("status", sa.String(10), nullable=False, server_default="ACTIVE"))
    op.add_column("contracts", sa.Column("status_reason", sa.Text()))
    op.add_column("contracts", sa.Column("status_by", sa.String(120)))
    op.add_column("contracts", sa.Column("status_at", sa.DateTime(timezone=True)))
    op.add_column("contracts", sa.Column("superseded_by", sa.String(64)))
    op.create_check_constraint("ck_contracts_status", "contracts", "status IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')")
    # Contracts stored before this migration: only the newest per deployment stays in force.
    op.execute("""
        UPDATE contracts c SET status = 'SUPERSEDED', status_at = now(), status_by = 'system',
               status_reason = 'A newer contract for the same deployment exists.',
               superseded_by = (SELECT n.contract_id FROM contracts n
                                WHERE n.object_type = c.object_type AND n.deployment_id = c.deployment_id
                                ORDER BY n.issued_at DESC LIMIT 1)
        WHERE EXISTS (SELECT 1 FROM contracts n WHERE n.object_type = c.object_type AND n.deployment_id = c.deployment_id
                      AND n.issued_at > c.issued_at)
    """)


def downgrade() -> None:
    op.drop_constraint("ck_contracts_status", "contracts", type_="check")
    for col in ("superseded_by", "status_at", "status_by", "status_reason", "status"):
        op.drop_column("contracts", col)
