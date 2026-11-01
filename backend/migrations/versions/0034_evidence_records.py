"""evidence records: files and page snapshots kept as evidence for one control, counted only once attested

Revision ID: 0034
Revises: 0033
Create Date: 2026-11-01
"""
from alembic import op
import sqlalchemy as sa

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organisation_id", sa.Uuid(), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("design_key", sa.String(40), nullable=False),
        sa.Column("subject", sa.String(8), nullable=False),
        sa.Column("control_key", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("filename", sa.String(255)),
        sa.Column("content_type", sa.String(120)),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content", sa.LargeBinary()),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("url", sa.String(500)),
        sa.Column("url_status", sa.Integer()),
        sa.Column("fetched_at", sa.DateTime(timezone=True)),
        sa.Column("uploaded_by", sa.String(120), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="UPLOADED"),
        sa.Column("attested_by", sa.String(120)),
        sa.Column("attested_role", sa.String(20)),
        sa.Column("attested_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by", sa.String(120)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.Text()),
        sa.CheckConstraint("kind IN ('FILE', 'URL')", name="ck_evidence_kind"),
        sa.CheckConstraint("status IN ('UPLOADED', 'ATTESTED', 'REVOKED')", name="ck_evidence_status"),
    )
    op.create_index("ix_evidence_records_design_key", "evidence_records", ["design_key"])


def downgrade() -> None:
    op.drop_index("ix_evidence_records_design_key", table_name="evidence_records")
    op.drop_table("evidence_records")
