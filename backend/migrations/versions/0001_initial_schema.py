"""Create the initial NetSentinel schema.

Revision ID: 0001_initial_schema
Revises: None
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001_initial_schema"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column("total_connections", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
    )
    op.create_index("ix_hosts_ip_address", "hosts", ["ip_address"], unique=True)
    op.create_index("ix_hosts_last_seen", "hosts", ["last_seen"])

    op.create_table(
        "network_flows",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("destination_ip", sa.String(45), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(20), nullable=False),
        sa.Column("process_id", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("executable_name", sa.String(255), nullable=True),
        sa.Column("bytes", sa.BigInteger(), nullable=False),
        sa.Column("packet_count", sa.BigInteger(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_flow_endpoints", "network_flows", ["source_ip", "destination_ip"])
    op.create_index("ix_flow_protocol_last_seen", "network_flows", ["protocol", "last_seen"])
    op.create_index("ix_network_flows_source_ip", "network_flows", ["source_ip"])
    op.create_index("ix_network_flows_destination_ip", "network_flows", ["destination_ip"])
    op.create_index("ix_network_flows_protocol", "network_flows", ["protocol"])
    op.create_index("ix_network_flows_first_seen", "network_flows", ["first_seen"])
    op.create_index("ix_network_flows_last_seen", "network_flows", ["last_seen"])

    op.create_table(
        "security_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("alert_type", sa.String(80), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
    )
    for column in ("timestamp", "severity", "alert_type", "source_ip", "destination_ip", "status"):
        op.create_index(f"ix_security_alerts_{column}", "security_alerts", [column])

    op.create_table(
        "ingest_batches",
        sa.Column("batch_id", sa.String(36), primary_key=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
    )
    op.create_table(
        "dns_ingest_batches",
        sa.Column("batch_id", sa.String(36), primary_key=True),
        sa.Column("observation_count", sa.Integer(), nullable=False),
    )
    op.create_table(
        "dns_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("requesting_host", sa.String(45), nullable=False),
        sa.Column("queried_domain", sa.String(253), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("query_type", sa.String(20), nullable=False),
        sa.Column("response_status", sa.String(30), nullable=True),
        sa.Column("is_response", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_dns_domain_timestamp", "dns_observations", ["queried_domain", "timestamp"])
    op.create_index("ix_dns_client_timestamp", "dns_observations", ["requesting_host", "timestamp"])
    for column in ("requesting_host", "queried_domain", "timestamp", "query_type", "response_status", "is_response"):
        op.create_index(f"ix_dns_observations_{column}", "dns_observations", [column])

    op.create_table(
        "historical_metric_buckets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("granularity", sa.String(20), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bytes_uploaded", sa.BigInteger(), nullable=False),
        sa.Column("bytes_downloaded", sa.BigInteger(), nullable=False),
        sa.Column("flow_count", sa.BigInteger(), nullable=False),
        sa.Column("active_hosts", sa.Integer(), nullable=False),
        sa.Column("alerts", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("granularity", "bucket_start", name="uq_metric_bucket_time"),
    )
    op.create_index("ix_metric_bucket_range", "historical_metric_buckets", ["granularity", "bucket_start"])

    op.create_table(
        "historical_host_metric_buckets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_ip", sa.String(45), nullable=False),
        sa.Column("granularity", sa.String(20), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bytes_uploaded", sa.BigInteger(), nullable=False),
        sa.Column("bytes_downloaded", sa.BigInteger(), nullable=False),
        sa.Column("flow_count", sa.BigInteger(), nullable=False),
        sa.UniqueConstraint("host_ip", "granularity", "bucket_start", name="uq_host_metric_bucket_time"),
    )
    op.create_index(
        "ix_host_metric_bucket_range",
        "historical_host_metric_buckets",
        ["host_ip", "granularity", "bucket_start"],
    )


def downgrade() -> None:
    op.drop_table("historical_host_metric_buckets")
    op.drop_table("historical_metric_buckets")
    op.drop_table("dns_observations")
    op.drop_table("dns_ingest_batches")
    op.drop_table("ingest_batches")
    op.drop_table("security_alerts")
    op.drop_table("network_flows")
    op.drop_table("hosts")
