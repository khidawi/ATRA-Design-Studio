"""regulation ingestion: runs, rule candidates, rule provenance

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("rules", sa.Column("source_url", sa.String(500), nullable=True))
    op.add_column("rules", sa.Column("source_quote", sa.Text(), nullable=True))
    op.create_table(
        "ingestion_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("regulation_id", sa.Uuid(), sa.ForeignKey("regulations.id"), nullable=False),
        sa.Column("source_url", sa.String(500)),
        sa.Column("source_kind", sa.String(8), nullable=False),          # URL | PASTE
        sa.Column("status", sa.String(10), nullable=False),               # RUNNING | DONE | FAILED
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("fetched_chars", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_sha256", sa.String(64)),
        sa.Column("passages_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passage_offset", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passages_planned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passages_done", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("proposed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kept", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dropped_unverified", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dropped_duplicate", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("source_kind IN ('URL', 'PASTE')", name="ck_ingestion_runs_kind"),
        sa.CheckConstraint("status IN ('RUNNING', 'DONE', 'FAILED')", name="ck_ingestion_runs_status"),
    )
    op.create_table(
        "rule_candidates",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("ingestion_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("regulation_id", sa.Uuid(), sa.ForeignKey("regulations.id"), nullable=False),
        sa.Column("source_url", sa.String(500)),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("citation", sa.String(120), nullable=False),
        sa.Column("quote", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="PENDING"),
        sa.Column("rule_key", sa.String(80)),                             # set when approved
        sa.Column("decision_note", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('PENDING', 'APPROVED', 'REJECTED')", name="ck_rule_candidates_status"),
        sa.CheckConstraint("severity IN ('REQUIRED', 'RECOMMENDED')", name="ck_rule_candidates_severity"),
    )


def downgrade() -> None:
    op.drop_table("rule_candidates")
    op.drop_table("ingestion_runs")
    op.drop_column("rules", "source_quote")
    op.drop_column("rules", "source_url")
