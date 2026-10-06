"""drift items can come from an imported definition file

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-16
"""
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_drift_source", "drift_items", type_="check")
    op.create_check_constraint("ck_drift_source", "drift_items", "source IN ('DESIGN', 'SIMULATED', 'DEMO', 'IMPORT')")


def downgrade() -> None:
    op.execute("DELETE FROM drift_items WHERE source = 'IMPORT'")
    op.drop_constraint("ck_drift_source", "drift_items", type_="check")
    op.create_check_constraint("ck_drift_source", "drift_items", "source IN ('DESIGN', 'SIMULATED', 'DEMO')")
