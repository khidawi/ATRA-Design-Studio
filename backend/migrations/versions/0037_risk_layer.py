"""ASTRA phase 2: impact tiers, department tolerance and response posture, each proposed by one person and ratified by another

Revision ID: 0037
Revises: 0036
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None

STATUS = "status IN ('PROPOSED', 'RATIFIED', 'SUPERSEDED', 'REJECTED')"


def _common():
    return [
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="PROPOSED"),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("proposed_by", sa.String(120), nullable=False),
        sa.Column("proposed_by_id", sa.Uuid(), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("decided_by", sa.String(120)),
        sa.Column("decided_by_id", sa.Uuid()),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("decision_note", sa.Text()),
    ]


def upgrade() -> None:
    op.create_table(
        "risk_asset_tiers", *_common(),
        sa.Column("asset_ext", sa.String(64), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("department_ext", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False, server_default="data"),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("confidentiality", sa.String(10), nullable=False, server_default="MEDIUM"),
        sa.Column("integrity", sa.String(10), nullable=False, server_default="MEDIUM"),
        sa.Column("availability", sa.String(10), nullable=False, server_default="MEDIUM"),
        sa.CheckConstraint("tier BETWEEN 1 AND 4", name="ck_risk_asset_tier"),
        sa.CheckConstraint(STATUS, name="ck_risk_asset_status"),
    )
    op.create_index("uq_risk_asset_ratified", "risk_asset_tiers", ["organisation_id", "asset_ext"], unique=True, postgresql_where=sa.text("status = 'RATIFIED'"))
    op.create_index("uq_risk_asset_proposed", "risk_asset_tiers", ["organisation_id", "asset_ext"], unique=True, postgresql_where=sa.text("status = 'PROPOSED'"))

    op.create_table(
        "risk_department_tolerance", *_common(),
        sa.Column("department_ext", sa.String(64), nullable=False),
        sa.Column("tolerance", sa.Integer(), nullable=False),
        sa.CheckConstraint("tolerance BETWEEN 0 AND 4", name="ck_risk_tolerance"),
        sa.CheckConstraint(STATUS, name="ck_risk_tolerance_status"),
    )
    op.create_index("uq_risk_tolerance_ratified", "risk_department_tolerance", ["organisation_id", "department_ext"], unique=True, postgresql_where=sa.text("status = 'RATIFIED'"))
    op.create_index("uq_risk_tolerance_proposed", "risk_department_tolerance", ["organisation_id", "department_ext"], unique=True, postgresql_where=sa.text("status = 'PROPOSED'"))

    op.create_table(
        "risk_posture", *_common(),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("posture", sa.String(10), nullable=False),
        sa.CheckConstraint("tier BETWEEN 1 AND 4", name="ck_risk_posture_tier"),
        sa.CheckConstraint("severity IN ('Medium', 'High', 'Critical')", name="ck_risk_posture_severity"),
        sa.CheckConstraint("posture IN ('observe', 'flag', 'block', 'halt')", name="ck_risk_posture_value"),
        sa.CheckConstraint(STATUS, name="ck_risk_posture_status"),
    )
    op.create_index("uq_risk_posture_ratified", "risk_posture", ["organisation_id", "tier", "severity"], unique=True, postgresql_where=sa.text("status = 'RATIFIED'"))
    op.create_index("uq_risk_posture_proposed", "risk_posture", ["organisation_id", "tier", "severity"], unique=True, postgresql_where=sa.text("status = 'PROPOSED'"))


def downgrade() -> None:
    op.drop_table("risk_posture")
    op.drop_table("risk_department_tolerance")
    op.drop_table("risk_asset_tiers")
