"""ASTRA phase 10: the temporal graph network: candidate models, adoption and evaluations

Revision ID: 0043
Revises: 0042
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("learned_models", sa.Column("adopted", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("learned_models", sa.Column("adopted_by", sa.String(120)))
    op.add_column("learned_models", sa.Column("adopted_at", sa.DateTime(timezone=True)))
    op.alter_column("learned_models", "status", type_=sa.String(9), existing_type=sa.String(8), existing_nullable=False, existing_server_default="ACTIVE")
    op.drop_constraint("ck_learned_model_status", "learned_models", type_="check")
    op.create_check_constraint("ck_learned_model_status", "learned_models", "status IN ('ACTIVE', 'RETIRED', 'CANDIDATE')")
    # a model that covers every agent (the network) scores many agents in the same window
    op.drop_index("uq_learned_score_window", table_name="learned_scores")
    op.create_index("uq_learned_score_window", "learned_scores", ["model_id", "agent_key", "window_start"], unique=True)
    op.create_table(
        "learned_evaluations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("model_id", sa.Uuid(), sa.ForeignKey("learned_models.id"), nullable=False),
        sa.Column("detector", sa.String(10), nullable=False),
        sa.Column("dataset_hash", sa.String(64), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False),
        sa.Column("budget_fpr", sa.Float(), nullable=False),
        sa.Column("metrics", JSONB(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("reasons", JSONB(), nullable=False),
        sa.Column("recorded_by", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_learned_evaluations_model", "learned_evaluations", ["organisation_id", "model_id", "created_at"])


def downgrade() -> None:
    op.drop_table("learned_evaluations")
    op.drop_index("uq_learned_score_window", table_name="learned_scores")
    op.execute("DELETE FROM learned_scores WHERE detector <> 'baseline'")
    op.create_index("uq_learned_score_window", "learned_scores", ["model_id", "window_start"], unique=True)
    op.execute("DELETE FROM learned_flags WHERE detector <> 'baseline'")
    op.execute("DELETE FROM learned_models WHERE detector <> 'baseline'")
    op.drop_constraint("ck_learned_model_status", "learned_models", type_="check")
    op.create_check_constraint("ck_learned_model_status", "learned_models", "status IN ('ACTIVE', 'RETIRED')")
    op.alter_column("learned_models", "status", type_=sa.String(8), existing_type=sa.String(9), existing_nullable=False, existing_server_default="ACTIVE")
    op.drop_column("learned_models", "adopted_at")
    op.drop_column("learned_models", "adopted_by")
    op.drop_column("learned_models", "adopted")
