"""add pipeline stage and progress to review_reports

Revision ID: c4d8e2f1a9b3
Revises: 2a3951898fc9
Create Date: 2026-09-24 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c4d8e2f1a9b3'
down_revision: Union[str, Sequence[str], None] = '2a3951898fc9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('review_reports', sa.Column('stage', sa.String(length=32), nullable=True))
    op.add_column('review_reports', sa.Column('progress', postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('review_reports', 'progress')
    op.drop_column('review_reports', 'stage')
