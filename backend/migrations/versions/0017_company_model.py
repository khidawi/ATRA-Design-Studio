"""the organisation model: departments, people, AI systems, data and modelling elements, and their connections

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-20
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

TYPES = "'department', 'person', 'role', 'external', 'agent', 'model', 'data_store', 'goal', 'operation', 'policy', 'threat', 'protection', 'rule', 'environment', 'step', 'decision'"
KINDS = "'works_with', 'task', 'access', 'performs', 'triggers', 'gates', 'achieves', 'governs', 'targets', 'mitigates', 'applies_to', 'next', 'hosts', 'relates'"


def upgrade() -> None:
    op.create_table(
        "company_nodes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("ext_id", sa.String(64), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("props", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "ext_id", name="uq_company_nodes_org_ext"),
        sa.CheckConstraint(f"type IN ({TYPES})", name="ck_company_nodes_type"),
    )
    op.create_table(
        "company_edges",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("from_ext", sa.String(64), nullable=False),
        sa.Column("to_ext", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("label", sa.String(80), nullable=False, server_default=""),
        sa.Column("props", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("organisation_id", "from_ext", "to_ext", "kind", "label", name="uq_company_edges"),
        sa.CheckConstraint(f"kind IN ({KINDS})", name="ck_company_edges_kind"),
    )
    op.create_index("ix_company_edges_from", "company_edges", ["organisation_id", "from_ext"])
    op.create_index("ix_company_edges_to", "company_edges", ["organisation_id", "to_ext"])


def downgrade() -> None:
    op.drop_table("company_edges")
    op.drop_table("company_nodes")
