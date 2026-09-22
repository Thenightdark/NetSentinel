"""Store configurable defensive detection thresholds.

Revision ID: 0004_detection_settings
Revises: 0003_collector_agents
"""
from typing import Sequence, Union
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision: str = "0004_detection_settings"
down_revision: Union[str, Sequence[str], None] = "0003_collector_agents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    table = op.create_table(
        "detection_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("port_scan_unique_ports", sa.Integer(), nullable=False),
        sa.Column("port_scan_window_seconds", sa.Integer(), nullable=False),
        sa.Column("bandwidth_spike_megabytes", sa.Integer(), nullable=False),
        sa.Column("bandwidth_spike_window_seconds", sa.Integer(), nullable=False),
        sa.Column("connection_spike_connections", sa.Integer(), nullable=False),
        sa.Column("connection_spike_window_seconds", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.bulk_insert(
        table,
        [
            {
                "id": 1,
                "port_scan_unique_ports": 25,
                "port_scan_window_seconds": 10,
                "bandwidth_spike_megabytes": 500,
                "bandwidth_spike_window_seconds": 300,
                "connection_spike_connections": 500,
                "connection_spike_window_seconds": 60,
                "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
            }
        ],
    )


def downgrade() -> None:
    op.drop_table("detection_settings")
