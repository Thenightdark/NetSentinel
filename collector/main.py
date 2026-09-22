"""Command-line entry point for the NetSentinel collector."""

import argparse
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
import logging
import sys
from time import sleep

from .capture import CaptureUnavailable, PassivePacketCapture, available_interfaces
from .agent import AgentClient
from .config import CollectorConfig
from .flows import FlowTracker, NetworkFlow
from .ingest import DNSIngestionClient, FlowIngestionClient
from .models import DNSMetadata, PacketMetadata
from .processes import ProcessConnectionCorrelator
from .stats import CaptureStats

LOGGER = logging.getLogger("netsentinel.collector")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passively capture local network metadata without storing payloads."
    )
    parser.add_argument("--interface", help="Scapy interface name or identifier")
    parser.add_argument("--demo", action="store_true", help="Use synthetic metadata; do not capture")
    parser.add_argument("--no-demo-fallback", action="store_true", help="Fail if capture is unavailable")
    parser.add_argument("--count", type=int, default=None, help="Stop after this many captured packets")
    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Finalize flows inactive for this many seconds (default: 60)",
    )
    parser.add_argument(
        "--process-correlation",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Best-effort local PID/process correlation using safe OS connection metadata",
    )
    parser.add_argument("--debug", action="store_true", help="Enable detailed logging")
    parser.add_argument("--list-interfaces", action="store_true", help="List capture interfaces and exit")
    return parser


def demo_packets(interface: str = "demo0") -> list[PacketMetadata]:
    now = datetime.now(timezone.utc)
    return [
        PacketMetadata(now, "192.0.2.10", "198.51.100.20", 51514, 443, "TCP", 74, "S", interface),
        PacketMetadata(now, "2001:db8::10", "2001:db8::53", 53000, 53, "UDP", 86, None, interface),
    ]


def emit_demo(
    stats: CaptureStats,
    handler: Callable[[PacketMetadata], None],
    interface: str | None = None,
) -> None:
    LOGGER.info("Demo mode uses synthetic metadata and opens no capture socket")
    for metadata in demo_packets(interface or "demo0"):
        stats.record(metadata)
        handler(metadata)
        print(metadata.summary())
        sleep(0.15)


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    environment_config = CollectorConfig.from_environment()
    config = replace(
        environment_config,
        interface=arguments.interface or environment_config.interface,
        demo_mode=arguments.demo or environment_config.demo_mode,
        fallback_to_demo=(
            environment_config.fallback_to_demo and not arguments.no_demo_fallback
        ),
        packet_limit=(
            max(0, arguments.count)
            if arguments.count is not None
            else environment_config.packet_limit
        ),
        flow_inactivity_timeout_seconds=(
            max(0.1, arguments.flow_timeout)
            if arguments.flow_timeout is not None
            else environment_config.flow_inactivity_timeout_seconds
        ),
        process_correlation_enabled=(
            arguments.process_correlation
            if arguments.process_correlation is not None
            else environment_config.process_correlation_enabled
        ),
        log_level="DEBUG" if arguments.debug else environment_config.log_level,
    )
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if arguments.list_interfaces:
        for interface in available_interfaces():
            print(interface)
        return 0

    ingestion_client: FlowIngestionClient | None = None
    dns_ingestion_client: DNSIngestionClient | None = None
    agent_client: AgentClient | None = None
    credentials = None
    try:
        agent_client = AgentClient(
            config.backend_url,
            config.agent_enrollment_key,
            config.agent_state_path,
            heartbeat_interval_seconds=config.agent_heartbeat_interval_seconds,
            timeout_seconds=config.ingest_timeout_seconds,
        )
        credentials = agent_client.ensure_registered()
        agent_client.start(credentials)
    except Exception as exc:
        LOGGER.warning("Agent registration unavailable; local capture will continue: %s", exc)
        if agent_client is not None:
            agent_client.stop()
            agent_client = None

    if credentials is not None:
        ingestion_client = FlowIngestionClient(
            backend_url=config.backend_url,
            agent_id=credentials.agent_id,
            api_key=credentials.api_key,
            batch_size=config.ingest_batch_size,
            flush_interval_seconds=config.ingest_flush_interval_seconds,
            timeout_seconds=config.ingest_timeout_seconds,
            max_retries=config.ingest_max_retries,
            max_queue_size=config.ingest_max_queue_size,
        )
        ingestion_client.start()
        dns_ingestion_client = DNSIngestionClient(
            backend_url=config.backend_url,
            agent_id=credentials.agent_id,
            api_key=credentials.api_key,
            batch_size=config.ingest_batch_size,
            flush_interval_seconds=config.ingest_flush_interval_seconds,
            timeout_seconds=config.ingest_timeout_seconds,
            max_retries=config.ingest_max_retries,
            max_queue_size=config.ingest_max_queue_size,
        )
        dns_ingestion_client.start()
        LOGGER.info("Flow and DNS metadata ingestion enabled for %s", config.backend_url)
    else:
        LOGGER.warning("No collector identity is available; metadata will only be logged")

    def log_finalized_flow(flow: NetworkFlow) -> None:
        LOGGER.info("Finalized flow: %s", flow.summary())
        if ingestion_client is not None:
            ingestion_client.enqueue(flow)

    flow_tracker = FlowTracker(
        inactivity_timeout_seconds=config.flow_inactivity_timeout_seconds,
        on_flow_finalized=log_finalized_flow,
    )
    process_correlator = ProcessConnectionCorrelator(
        enabled=config.process_correlation_enabled,
        refresh_interval_seconds=config.process_refresh_interval_seconds,
    )
    if config.process_correlation_enabled:
        LOGGER.info("Optional local process correlation is enabled")

    def process_packet(packet: PacketMetadata) -> None:
        packet = process_correlator.enrich(packet)
        LOGGER.debug("Packet: %s", packet.summary())
        flow_tracker.observe(packet)

    def process_dns(observation: DNSMetadata) -> None:
        LOGGER.debug("DNS metadata: %s", observation.summary())
        if dns_ingestion_client is not None:
            dns_ingestion_client.enqueue(observation)

    stats = CaptureStats()
    capture = PassivePacketCapture(
        config, process_packet, stats=stats, dns_handler=process_dns
    )
    flow_tracker.start()

    try:
        if config.demo_mode:
            emit_demo(stats, process_packet, config.interface)
        else:
            capture.run()
    except KeyboardInterrupt:
        capture.request_stop()
        LOGGER.info("Capture stopped by user")
    except CaptureUnavailable as exc:
        LOGGER.error("Packet capture is unavailable: %s", exc)
        if not config.fallback_to_demo:
            return 1
        LOGGER.warning("Falling back to demo mode")
        emit_demo(stats, process_packet, config.interface)
    finally:
        flow_tracker.stop(finalize_remaining=True)
        if ingestion_client is not None:
            ingestion_client.stop()
        if dns_ingestion_client is not None:
            dns_ingestion_client.stop()
        if agent_client is not None:
            agent_client.stop()
        LOGGER.info("Collector summary: %s", stats.summary())

    return 0


if __name__ == "__main__":
    sys.exit(main())
