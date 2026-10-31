"""
Source-Aware Feature Extraction: Network & Flow Domain for AEGIS-X 2.0.

Extracts structured numerical and categorical features from Network Flows,
Firewall logs, and VPN session telemetry.
Version: 2.0.0
"""

import ipaddress
import math
from typing import Any

from ai_engine.ingestion.schemas import EventAction, SecurityEvent

FEATURE_SCHEMA_VERSION = "2.0.0-network"

NETWORK_FEATURE_NAMES = [
    "src_port",
    "dst_port",
    "protocol_num",
    "bytes_sent",
    "bytes_received",
    "total_bytes",
    "bytes_ratio",
    "packets_sent",
    "packets_received",
    "total_packets",
    "bytes_per_packet",
    "duration_ms",
    "is_privileged_port",
    "is_ephemeral_port",
    "is_src_private_ip",
    "is_dst_private_ip",
    "action_is_blocked",
    "hour_of_day",
    "day_of_week",
]


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


class NetworkFeatureExtractor:
    """Transforms network-centric SecurityEvents into vectorized numerical features."""

    @classmethod
    def extract_features(cls, event: SecurityEvent) -> dict[str, float]:
        net = event.network
        src_port = float(net.source_port or 0)
        dst_port = float(net.destination_port or 0)

        # Protocol encoding (IANA standard numbers)
        proto_str = (net.protocol or "TCP").upper()
        if "TCP" in proto_str:
            protocol_num = 6.0
        elif "UDP" in proto_str:
            protocol_num = 17.0
        elif "ICMP" in proto_str:
            protocol_num = 1.0
        else:
            protocol_num = 0.0

        bytes_sent = float(net.bytes_sent or 0)
        bytes_recv = float(net.bytes_received or 0)
        total_bytes = bytes_sent + bytes_recv
        bytes_ratio = (bytes_sent / (bytes_recv + 1.0)) if total_bytes > 0 else 1.0

        pkts_sent = float(net.packets_sent or 0)
        pkts_recv = float(net.packets_received or 0)
        total_pkts = pkts_sent + pkts_recv
        bytes_per_pkt = (total_bytes / total_pkts) if total_pkts > 0 else 0.0

        duration_ms = float(net.duration_ms or 0.0)

        is_priv_port = 1.0 if (0 < dst_port <= 1024 or 0 < src_port <= 1024) else 0.0
        is_ephem_port = 1.0 if (src_port >= 49152 or dst_port >= 49152) else 0.0

        is_src_priv = 1.0 if cls._is_private_ip(net.source_ip) else 0.0
        is_dst_priv = 1.0 if cls._is_private_ip(net.destination_ip) else 0.0

        action_blocked = 1.0 if event.action in (EventAction.BLOCK, EventAction.DROP, EventAction.FAILURE) else 0.0

        ts = event.timestamp
        hour = float(ts.hour)
        day_of_week = float(ts.weekday())

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol_num": protocol_num,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_recv,
            "total_bytes": total_bytes,
            "bytes_ratio": round(bytes_ratio, 4),
            "packets_sent": pkts_sent,
            "packets_received": pkts_recv,
            "total_packets": total_pkts,
            "bytes_per_packet": round(bytes_per_pkt, 4),
            "duration_ms": duration_ms,
            "is_privileged_port": is_priv_port,
            "is_ephemeral_port": is_ephem_port,
            "is_src_private_ip": is_src_priv,
            "is_dst_private_ip": is_dst_priv,
            "action_is_blocked": action_blocked,
            "hour_of_day": hour,
            "day_of_week": day_of_week,
        }

    @staticmethod
    def _is_private_ip(ip_str: str | None) -> bool:
        if not ip_str or ip_str in ("-", "localhost"):
            return True
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in RFC1918_NETWORKS)
        except ValueError:
            return False
