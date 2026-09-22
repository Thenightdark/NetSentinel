"""Add collector agents and per-agent data attribution.

Revision ID: 0003_collector_agents
Revises: 0002_user_authentication
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_collector_agents"
down_revision: Union[str, Sequence[str], None] = "0002_user_authentication"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "collector_agents",
        sa.Column("agent_id", sa.String(36), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("operating_system", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("version", sa.String(40), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("api_key_hash", sa.String(64), nullable=False),
    )
    op.create_index("ix_collector_agents_hostname", "collector_agents", ["hostname"])
    op.create_index("ix_collector_agents_last_seen", "collector_agents", ["last_seen"])
    op.create_index("ix_collector_agents_status", "collector_agents", ["status"])

    for table in ("network_flows", "hosts", "security_alerts", "dns_observations"):
        op.add_column(table, sa.Column("agent_id", sa.String(36), nullable=True))
        op.create_index(f"ix_{table}_agent_id", table, ["agent_id"])

    op.drop_index("ix_hosts_ip_address", table_name="hosts")
    op.create_index("ix_hosts_ip_address", "hosts", ["ip_address"], unique=False)
    with op.batch_alter_table("hosts") as batch_op:
        batch_op.create_unique_constraint("uq_host_agent_ip", ["agent_id", "ip_address"])

    op.add_column(
        "historical_host_metric_buckets",
        sa.Column("agent_id", sa.String(36), nullable=True),
    )
    op.drop_index("ix_host_metric_bucket_range", table_name="historical_host_metric_buckets")
    with op.batch_alter_table("historical_host_metric_buckets") as batch_op:
        batch_op.drop_constraint("uq_host_metric_bucket_time", type_="unique")
        batch_op.create_unique_constraint(
            "uq_host_metric_bucket_time",
            ["agent_id", "host_ip", "granularity", "bucket_start"],
        )
    op.create_index(
        "ix_host_metric_bucket_range",
        "historical_host_metric_buckets",
        ["agent_id", "host_ip", "granularity", "bucket_start"],
    )


def downgrade() -> None:
    op.drop_index("ix_host_metric_bucket_range", table_name="historical_host_metric_buckets")
    with op.batch_alter_table("historical_host_metric_buckets") as batch_op:
        batch_op.drop_constraint("uq_host_metric_bucket_time", type_="unique")
        batch_op.create_unique_constraint(
            "uq_host_metric_bucket_time", ["host_ip", "granularity", "bucket_start"]
        )
    op.create_index(
        "ix_host_metric_bucket_range",
        "historical_host_metric_buckets",
        ["host_ip", "granularity", "bucket_start"],
    )
    op.drop_column("historical_host_metric_buckets", "agent_id")

    with op.batch_alter_table("hosts") as batch_op:
        batch_op.drop_constraint("uq_host_agent_ip", type_="unique")
    op.drop_index("ix_hosts_ip_address", table_name="hosts")
    op.create_index("ix_hosts_ip_address", "hosts", ["ip_address"], unique=True)

    for table in ("dns_observations", "security_alerts", "hosts", "network_flows"):
        op.drop_index(f"ix_{table}_agent_id", table_name=table)
        op.drop_column(table, "agent_id")

    op.drop_table("collector_agents")
