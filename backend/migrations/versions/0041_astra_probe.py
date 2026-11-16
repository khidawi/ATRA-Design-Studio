"""ASTRA phase 8: ASTRA Probe runs, results and incident scenarios

Revision ID: 0041
Revises: 0040
Create Date: 2026-11-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "probe_scenarios",                                   # incident scenarios only: the template scenarios are generated from the contract on every run
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("finding_key", sa.String(12), nullable=False),
        sa.Column("class_code", sa.String(16), nullable=False),
        sa.Column("bad_event", JSONB(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="PROPOSED"),
        sa.Column("proposed_by", sa.String(120), nullable=False),
        sa.Column("decided_by", sa.String(120)),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("note", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('PROPOSED', 'STANDING', 'RETIRED')", name="ck_probe_scenario_status"),
    )
    op.create_index("ix_probe_scenarios_agent", "probe_scenarios", ["organisation_id", "agent_key", "status"])
    op.create_table(
        "probe_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("design_key", sa.String(40), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("design_hash", sa.String(64), nullable=False),
        sa.Column("contract_hash", sa.String(64), nullable=False),
        sa.Column("trigger", sa.String(10), nullable=False),
        sa.Column("summary", JSONB(), nullable=False),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("trigger IN ('manual', 'sign', 'nightly', 'admission')", name="ck_probe_run_trigger"),
    )
    op.create_index("ix_probe_runs_design", "probe_runs", ["organisation_id", "design_key", "created_at"])
    op.create_table(
        "probe_results",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("probe_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("class_code", sa.String(16), nullable=False),
        sa.Column("control", sa.String(12), nullable=False),
        sa.Column("basis", sa.String(14), nullable=False),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("scenario_id", sa.Uuid()),
        sa.Column("applicable", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("expected", JSONB(), nullable=False),
        sa.Column("bad_event", JSONB()),
        sa.Column("good_event", JSONB()),
        sa.Column("bad", JSONB()),
        sa.Column("good", JSONB()),
        sa.Column("bad_ok", sa.Boolean()),
        sa.Column("good_ok", sa.Boolean()),
        sa.Column("passed", sa.Boolean()),
    )
    op.create_index("ix_probe_results_run", "probe_results", ["run_id"])


def downgrade() -> None:
    op.drop_table("probe_results")
    op.drop_table("probe_runs")
    op.drop_table("probe_scenarios")
