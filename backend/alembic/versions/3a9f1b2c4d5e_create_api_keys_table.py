"""create_api_keys_table

Revision ID: 3a9f1b2c4d5e
Revises: 28c5d86670f4
Create Date: 2026-08-31 15:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3a9f1b2c4d5e'
down_revision: Union[str, None] = '28c5d86670f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('key_prefix', sa.String(length=16), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('owner', sa.String(length=100), nullable=False),
        sa.Column('tier', sa.String(length=20), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=True)
    op.create_index(op.f('ix_api_keys_is_active'), 'api_keys', ['is_active'], unique=False)
    op.create_index(op.f('ix_api_keys_expires_at'), 'api_keys', ['expires_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_api_keys_expires_at'), table_name='api_keys')
    op.drop_index(op.f('ix_api_keys_is_active'), table_name='api_keys')
    op.drop_index(op.f('ix_api_keys_key_hash'), table_name='api_keys')
    op.drop_table('api_keys')
