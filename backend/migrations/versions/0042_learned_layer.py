"""ASTRA phase 9: the learned layer: models, scores and flags

Revision ID: 0042
Revises: 0041
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "learned_models",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("detector", sa.String(10), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(8), nullable=False, server_default="ACTIVE"),
        sa.Column("trained_on", JSONB(), nullable=False),
        sa.Column("parameters", JSONB(), nullable=False),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("detector IN ('baseline', 'tgn', 'gnn')", name="ck_learned_model_detector"),
        sa.CheckConstraint("status IN ('ACTIVE', 'RETIRED')", name="ck_learned_model_status"),
    )
    op.create_index("uq_learned_model_active", "learned_models", ["organisation_id", "agent_key", "detector"], unique=True, postgresql_where=sa.text("status = 'ACTIVE'"))
    op.create_table(
        "learned_scores",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("model_id", sa.Uuid(), sa.ForeignKey("learned_models.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("detector", sa.String(10), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("events", sa.Integer(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("detail", JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("uq_learned_score_window", "learned_scores", ["model_id", "window_start"], unique=True)
    op.create_index("ix_learned_scores_agent", "learned_scores", ["organisation_id", "agent_key", "window_start"])
    op.create_table(
        "learned_flags",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("model_id", sa.Uuid(), sa.ForeignKey("learned_models.id"), nullable=False),
        sa.Column("score_id", sa.Uuid(), sa.ForeignKey("learned_scores.id"), nullable=False),
        sa.Column("agent_key", sa.String(80), nullable=False),
        sa.Column("detector", sa.String(10), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        # What a learned detector may do to a control (Lemma 3), written into the table: it can only ever say "the baseline control is unverified".
        sa.Column("control", sa.String(8), nullable=False, server_default="base"),
        sa.Column("level", sa.String(3), nullable=False, server_default="UNV"),
        sa.Column("status", sa.String(8), nullable=False, server_default="OPEN"),
        sa.Column("detail", JSONB(), nullable=False),
        sa.Column("adjudicated_by", sa.String(120)),
        sa.Column("adjudicated_at", sa.DateTime(timezone=True)),
        sa.Column("adjudication_note", sa.Text()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("control = 'base' AND level = 'UNV'", name="ck_learned_flag_lemma3"),
        sa.CheckConstraint("status IN ('OPEN', 'BENIGN', 'REAL')", name="ck_learned_flag_status"),
    )
    op.create_index("ix_learned_flags_agent", "learned_flags", ["organisation_id", "agent_key", "status"])


def downgrade() -> None:
    op.drop_table("learned_flags")
    op.drop_table("learned_scores")
    op.drop_table("learned_models")
