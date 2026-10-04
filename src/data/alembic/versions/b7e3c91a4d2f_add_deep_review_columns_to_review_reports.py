"""add deep review columns to review_reports

Revision ID: b7e3c91a4d2f
Revises: d15650c6ecdb
Create Date: 2026-09-24 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7e3c91a4d2f"
down_revision: str | Sequence[str] | None = "d15650c6ecdb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("review_reports", sa.Column("cache_key", sa.String(length=64), nullable=True))
    op.add_column("review_reports", sa.Column("engine_version", sa.String(length=32), nullable=True))
    op.add_column("review_reports", sa.Column("provider", sa.String(length=32), nullable=True))
    op.add_column("review_reports", sa.Column("model", sa.String(length=128), nullable=True))
    op.add_column("review_reports", sa.Column("report_markdown", sa.Text(), nullable=True))
    op.add_column("review_reports", sa.Column("report_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("review_reports", sa.Column("error", sa.Text(), nullable=True))
    op.add_column("review_reports", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f("ix_review_reports_cache_key"), "review_reports", ["cache_key"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_review_reports_cache_key"), table_name="review_reports")
    op.drop_column("review_reports", "completed_at")
    op.drop_column("review_reports", "error")
    op.drop_column("review_reports", "report_data")
    op.drop_column("review_reports", "report_markdown")
    op.drop_column("review_reports", "model")
    op.drop_column("review_reports", "provider")
    op.drop_column("review_reports", "engine_version")
    op.drop_column("review_reports", "cache_key")
