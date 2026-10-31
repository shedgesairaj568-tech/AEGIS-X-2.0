"""create response_actions table for human-in-the-loop incident response

Revision ID: 72e811b0ef55
Revises: 61d900a9dfc4
Create Date: 2026-10-31 17:15:00.000000

"""
from alembic import op
import sqlalchemy as sa
import app.core.db_types


# revision identifiers, used by Alembic.
revision = '72e811b0ef55'
down_revision = '61d900a9dfc4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'response_actions',
        sa.Column('id', app.core.db_types.GUID(), nullable=False),
        sa.Column('alert_id', app.core.db_types.GUID(), nullable=False),
        sa.Column('action_type', sa.String(length=50), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='pending_approval'),
        sa.Column('required_role', sa.String(length=50), nullable=False, server_default='analyst'),
        sa.Column('blast_radius', sa.String(length=20), nullable=False, server_default='LOW'),
        sa.Column('description', sa.String(length=1000), nullable=False),
        sa.Column('rationale', sa.String(length=1000), nullable=True),
        sa.Column('rollback_plan', sa.String(length=1000), nullable=True),
        sa.Column('created_by', sa.String(length=100), nullable=False, server_default='ai_response_agent'),
        sa.Column('approved_by_id', app.core.db_types.GUID(), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('execution_log', app.core.db_types.JSONB_OR_JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['approved_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_response_actions_alert_id'), 'response_actions', ['alert_id'], unique=False)
    op.create_index(op.f('ix_response_actions_status'), 'response_actions', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_response_actions_status'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_alert_id'), table_name='response_actions')
    op.drop_table('response_actions')

