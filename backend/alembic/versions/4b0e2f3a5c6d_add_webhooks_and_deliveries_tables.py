"""add_webhooks_and_deliveries_tables

Revision ID: 4b0e2f3a5c6d
Revises: 3a9f1b2c4d5e
Create Date: 2026-08-31 16:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4b0e2f3a5c6d'
down_revision: Union[str, None] = '3a9f1b2c4d5e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create webhooks table
    op.create_table(
        'webhooks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('target_url', sa.String(length=2048), nullable=False),
        sa.Column('secret_hash', sa.String(length=64), nullable=False),
        sa.Column('secret_prefix', sa.String(length=16), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.Column('events', sa.String(length=500), nullable=False),
        sa.Column('owner', sa.String(length=100), nullable=False),
        sa.Column('failure_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_delivery_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_webhooks_is_enabled'), 'webhooks', ['is_enabled'], unique=False)

    # 2. Create webhook_deliveries table
    op.create_table(
        'webhook_deliveries',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('webhook_id', sa.String(length=36), nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('attempt_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='PENDING'),
        sa.Column('response_status_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_retry_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['webhook_id'], ['webhooks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_webhook_deliveries_webhook_id'), 'webhook_deliveries', ['webhook_id'], unique=False)
    op.create_index(op.f('ix_webhook_deliveries_event_id'), 'webhook_deliveries', ['event_id'], unique=False)
    op.create_index(op.f('ix_webhook_deliveries_status'), 'webhook_deliveries', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_webhook_deliveries_status'), table_name='webhook_deliveries')
    op.drop_index(op.f('ix_webhook_deliveries_event_id'), table_name='webhook_deliveries')
    op.drop_index(op.f('ix_webhook_deliveries_webhook_id'), table_name='webhook_deliveries')
    op.drop_table('webhook_deliveries')

    op.drop_index(op.f('ix_webhooks_is_enabled'), table_name='webhooks')
    op.drop_table('webhooks')
