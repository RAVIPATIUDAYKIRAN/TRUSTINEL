"""add_user_facing_verdict_to_trust_reports

Revision ID: e89f12ab34cd
Revises: ad7588b6a024
Create Date: 2026-09-02 15:25:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'e89f12ab34cd'
down_revision: Union[str, None] = 'ad7588b6a024'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    user_verdict_enum = sa.Enum('LEGITIMATE', 'PROBABLY_LEGITIMATE', 'SUSPICIOUS', 'LIKELY_SCAM', 'HIGH_CONFIDENCE_SCAM', 'UNKNOWN', name='userfacingverdict')
    user_verdict_enum.create(op.get_bind(), checkfirst=True)
    op.add_column('trust_reports', sa.Column('user_facing_verdict', user_verdict_enum, nullable=True))
    op.add_column('trust_reports', sa.Column('recommended_user_action', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('trust_reports', 'recommended_user_action')
    op.drop_column('trust_reports', 'user_facing_verdict')
    user_verdict_enum = sa.Enum('LEGITIMATE', 'PROBABLY_LEGITIMATE', 'SUSPICIOUS', 'LIKELY_SCAM', 'HIGH_CONFIDENCE_SCAM', 'UNKNOWN', name='userfacingverdict')
    user_verdict_enum.drop(op.get_bind(), checkfirst=True)
