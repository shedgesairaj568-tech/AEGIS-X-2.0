"""
Kafka Multi-Source Security Log Streamer for AEGIS-X 2.0.

Streams synthetic and parsed security telemetry across multi-source Kafka topics:
- security.firewall.events
- security.vpn.events
- security.linux_auth.events
- security.windows_event.events

Provides automatic fallback to a local simulated generator when running without an external Kafka cluster.
"""

import argparse
from datetime import datetime, timezone
import json
import os
import random
import time
from typing import Any

from ai_engine.ingestion.schemas import (
    EventAction,
    EventSeverity,
    HostEntity,
    LogSource,
    NetworkEntity,
    ProcessEntity,
    SecurityEvent,
    UserEntity,
)
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

SAMPLE_USERS = ["root", "admin", "jsmith", "bwayne", "cclark", "deploy_svc", "guest"]
SAMPLE_INTERNAL_IPS = ["192.168.1.10", "192.168.1.55", "192.168.1.100", "10.0.0.12", "10.0.1.45"]
SAMPLE_EXTERNAL_IPS = ["185.220.101.5", "91.240.118.172", "45.154.255.89", "194.26.29.112", "103.145.13.2"]


class MultiSourceKafkaProducer:
    """Publishes security events across source-specific Kafka topics with graceful local fallback."""

    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.bootstrap_servers = bootstrap_servers
        self.producer = None
        self._init_kafka()

    def _init_kafka(self):
        try:
            from kafka import KafkaProducer
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                retries=3,
            )
            logger.info("Connected to Kafka broker at %s", self.bootstrap_servers)
        except Exception as e:
            logger.warning("Kafka broker unreachable at %s: %s (Running in local simulated stream mode)", self.bootstrap_servers, e)
            self.producer = None

    def generate_event(self, source: LogSource | None = None) -> SecurityEvent:
        """Generates a realistic multi-source security event."""
        src = source or random.choice(list(LogSource))
        now = datetime.now(timezone.utc)
        is_attack = random.random() < 0.25

        if src == LogSource.FIREWALL:
            action = EventAction.DROP if is_attack else EventAction.ALLOW
            s_ip = random.choice(SAMPLE_EXTERNAL_IPS) if is_attack else random.choice(SAMPLE_INTERNAL_IPS)
            d_port = 445 if is_attack else random.choice([80, 443, 22])
            raw = f"{now.strftime('%b %d %H:%M:%S')} fw-01 kernel: [UFW {action.value.upper()}] IN=eth0 OUT= SRC={s_ip} DST=192.168.1.100 PROTO=TCP SPT=54321 DPT={d_port} WINDOW=1024 SYN"
            return SecurityEvent(
                source=LogSource.FIREWALL,
                event_type="firewall_rule_match",
                severity=EventSeverity.HIGH if is_attack else EventSeverity.INFO,
                action=action,
                network=NetworkEntity(
                    source_ip=s_ip,
                    destination_ip="192.168.1.100",
                    destination_port=d_port,
                    protocol="TCP",
                ),
                raw_log=raw,
            )

        elif src == LogSource.VPN:
            user = random.choice(SAMPLE_USERS)
            action = EventAction.FAILURE if is_attack else EventAction.SUCCESS
            s_ip = random.choice(SAMPLE_EXTERNAL_IPS)
            raw = f"{now.strftime('%b %d %H:%M:%S')} vpn-gw01 openvpn[1234]: {s_ip}:4433 [AUTH_{action.value.upper()}] username='{user}'"
            return SecurityEvent(
                source=LogSource.VPN,
                event_type="vpn_authentication",
                severity=EventSeverity.MEDIUM if is_attack else EventSeverity.INFO,
                action=action,
                user=UserEntity(username=user),
                network=NetworkEntity(source_ip=s_ip),
                raw_log=raw,
            )

        elif src == LogSource.LINUX_AUTH:
            user = random.choice(SAMPLE_USERS)
            status = "Failed password" if is_attack else "Accepted publickey"
            action = EventAction.FAILURE if is_attack else EventAction.SUCCESS
            s_ip = random.choice(SAMPLE_EXTERNAL_IPS)
            raw = f"{now.strftime('%b %d %H:%M:%S')} srv-auth sshd[5678]: {status} for {user} from {s_ip} port 51234 ssh2"
            return SecurityEvent(
                source=LogSource.LINUX_AUTH,
                event_type="ssh_auth",
                severity=EventSeverity.HIGH if is_attack else EventSeverity.INFO,
                action=action,
                user=UserEntity(username=user),
                network=NetworkEntity(source_ip=s_ip),
                raw_log=raw,
            )

        else:  # WINDOWS_EVENT or NETWORK_FLOW
            event_id = 4625 if is_attack else 4624
            user = random.choice(SAMPLE_USERS)
            action = EventAction.FAILURE if event_id == 4625 else EventAction.SUCCESS
            s_ip = random.choice(SAMPLE_EXTERNAL_IPS)
            raw = json.dumps({
                "EventID": event_id,
                "TimeCreated": now.isoformat(),
                "TargetUserName": user,
                "IpAddress": s_ip,
                "LogonType": 3,
            })
            return SecurityEvent(
                source=LogSource.WINDOWS_EVENT,
                event_type=f"win_logon_{event_id}",
                severity=EventSeverity.HIGH if is_attack else EventSeverity.INFO,
                action=action,
                user=UserEntity(username=user),
                network=NetworkEntity(source_ip=s_ip),
                raw_log=raw,
            )

    def send_event(self, event: SecurityEvent):
        """Sends event to appropriate Kafka topic or outputs to log."""
        topic = f"security.{event.source.value.lower()}.events"
        payload = event.model_dump(mode="json")

        if self.producer:
            try:
                self.producer.send(topic, value=payload)
                logger.info("Published to [%s]: %s (source=%s)", topic, event.event_type, event.source.value)
            except Exception as e:
                logger.error("Failed to publish to Kafka: %s", e)
        else:
            logger.info("[STREAM LOG] -> [%s] | %s | IP: %s | User: %s | Action: %s", topic, event.event_type, event.network.source_ip, event.user.username, event.action.value)

    def stream_continuous(self, rate_per_sec: float = 1.0, max_events: int | None = None):
        """Streams continuous events at specified rate."""
        logger.info("Starting security log stream at %.1f events/sec (max=%s)...", rate_per_sec, max_events or "unlimited")
        delay = 1.0 / max(0.1, rate_per_sec)
        count = 0
        try:
            while max_events is None or count < max_events:
                ev = self.generate_event()
                self.send_event(ev)
                count += 1
                time.sleep(delay)
        except KeyboardInterrupt:
            logger.info("Stream interrupted by user. Total events emitted: %d", count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS-X 2.0 Multi-Source Security Log Streamer")
    parser.add_argument("--rate", type=float, default=1.0, help="Events per second")
    parser.add_argument("--count", type=int, default=None, help="Total events to stream (default: unlimited)")
    parser.add_argument("--broker", type=str, default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"), help="Kafka broker host:port")
    args = parser.parse_args()

    producer = MultiSourceKafkaProducer(bootstrap_servers=args.broker)
    producer.stream_continuous(rate_per_sec=args.rate, max_events=args.count)
