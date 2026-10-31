"""
VPN Log Parser for AEGIS-X 2.0.

Parses OpenVPN, WireGuard, and IPsec/AnyConnect tunnel and authentication logs:
- Session authentication (success, bad credentials, expired certs)
- Tunnel establishment and virtual IP address assignment
- Re-keying and TLS handshakes
- Session termination and byte volume telemetry

Gracefully handles unstructured syslog lines and missing identity fields.
"""

from datetime import datetime, timezone
import re
from typing import Any

from ai_engine.ingestion.schemas import (
    EventAction,
    EventSeverity,
    LogSource,
    NetworkEntity,
    SecurityEvent,
    UserEntity,
)
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

# OpenVPN Patterns:
# E.g. openvpn[1234]: 198.51.100.25:52310 TLS: Initial packet from [AF_INET]198.51.100.25:52310, sid=...
_OVPN_INITIAL = re.compile(
    r"openvpn(?:\[\d+\])?:\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+TLS:\s+Initial packet",
    re.IGNORECASE,
)
# E.g. openvpn[1234]: alice/198.51.100.25:52310 MULTI_sva: pool returned IPv4=10.8.0.6, IPv6=(Not enabled)
_OVPN_ASSIGN = re.compile(
    r"openvpn(?:\[\d+\])?:\s+(?P<user>[\w\.\-]+)/(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+MULTI_sva:\s+pool returned IPv4=(?P<assigned_ip>[\d\.]+)",
    re.IGNORECASE,
)
# E.g. openvpn[1234]: 198.51.100.25:52310 TLS Auth Error: Auth Username/Password verification failed for peer
_OVPN_AUTH_FAIL = re.compile(
    r"openvpn(?:\[\d+\])?:\s+(?:(?P<user>[\w\.\-]+)/)?(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+.*?(?:Auth Username/Password verification failed|TLS Error|VERIFY ERROR)",
    re.IGNORECASE,
)
# E.g. openvpn[1234]: alice/198.51.100.25:52310 SIGTERM[soft,delayed-exit] received, client-instance exiting. Bytes: 1245000/3560000
_OVPN_CLOSE = re.compile(
    r"openvpn(?:\[\d+\])?:\s+(?P<user>[\w\.\-]+)/(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+.*?exiting(?:\.\s+Bytes:\s+(?P<bytes_in>\d+)/(?P<bytes_out>\d+))?",
    re.IGNORECASE,
)

# WireGuard Patterns:
# E.g. wireguard: wg0: Handshake for peer 1 (198.51.100.30:51820) did not complete after 5 seconds, retrying...
_WG_HANDSHAKE_FAIL = re.compile(
    r"wireguard:.*?:?\s+Handshake for peer\s+(?P<peer_id>\d+)\s+\((?P<src_ip>[\d\.]+):(?P<src_port>\d+)\)\s+did not complete",
    re.IGNORECASE,
)
# E.g. wireguard: wg0: Receiving handshake initiation from peer 1 (198.51.100.30:51820)
_WG_HANDSHAKE_SUCCESS = re.compile(
    r"wireguard:.*?:?\s+(?:Receiving handshake initiation|Keypair.*?created) for peer\s+(?P<peer_id>\d+)\s+\((?P<src_ip>[\d\.]+):(?P<src_port>\d+)\)",
    re.IGNORECASE,
)


class VpnParser:
    """Parser for OpenVPN, WireGuard, and remote-access VPN events."""

    @classmethod
    def parse_line(cls, line: str, timestamp_override: datetime | None = None) -> SecurityEvent | None:
        if not line or not line.strip():
            return None

        line = line.strip()
        ts = timestamp_override or cls._extract_timestamp(line)

        # 1. OpenVPN Authentication Failure
        match_auth_fail = _OVPN_AUTH_FAIL.search(line)
        if match_auth_fail:
            d = match_auth_fail.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.VPN,
                event_type="vpn_auth_failure",
                severity=EventSeverity.HIGH,
                action=EventAction.FAILURE,
                user=UserEntity(username=d.get("user"), auth_method="vpn_credentials"),
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    protocol="UDP",
                ),
                metadata={"vpn_type": "openvpn", "reason": "credential_or_tls_verification_failed"},
                raw_log=line,
            )

        # 2. OpenVPN Connection & IP Assignment
        match_assign = _OVPN_ASSIGN.search(line)
        if match_assign:
            d = match_assign.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.VPN,
                event_type="vpn_session_start",
                severity=EventSeverity.INFO,
                action=EventAction.SUCCESS,
                user=UserEntity(username=d.get("user"), auth_method="vpn_certificate"),
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    destination_ip=d.get("assigned_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    protocol="UDP",
                ),
                metadata={"vpn_type": "openvpn", "virtual_ip": d.get("assigned_ip")},
                raw_log=line,
            )

        # 3. OpenVPN Session Disconnect
        match_close = _OVPN_CLOSE.search(line)
        if match_close:
            d = match_close.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.VPN,
                event_type="vpn_session_end",
                severity=EventSeverity.INFO,
                action=EventAction.SUCCESS,
                user=UserEntity(username=d.get("user")),
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    bytes_received=int(d["bytes_in"]) if d.get("bytes_in") else None,
                    bytes_sent=int(d["bytes_out"]) if d.get("bytes_out") else None,
                    protocol="UDP",
                ),
                metadata={"vpn_type": "openvpn"},
                raw_log=line,
            )

        # 4. WireGuard Handshake Failure
        match_wg_fail = _WG_HANDSHAKE_FAIL.search(line)
        if match_wg_fail:
            d = match_wg_fail.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.VPN,
                event_type="wireguard_handshake_timeout",
                severity=EventSeverity.LOW,
                action=EventAction.FAILURE,
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    protocol="UDP",
                ),
                metadata={"vpn_type": "wireguard", "peer_id": d.get("peer_id")},
                raw_log=line,
            )

        # 5. WireGuard Handshake Success
        match_wg_ok = _WG_HANDSHAKE_SUCCESS.search(line)
        if match_wg_ok:
            d = match_wg_ok.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.VPN,
                event_type="wireguard_handshake_success",
                severity=EventSeverity.INFO,
                action=EventAction.SUCCESS,
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    protocol="UDP",
                ),
                metadata={"vpn_type": "wireguard", "peer_id": d.get("peer_id")},
                raw_log=line,
            )

        # 6. Generic VPN Initial Packet / Probe
        match_init = _OVPN_INITIAL.search(line)
        if match_init:
            d = match_init.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.VPN,
                event_type="vpn_handshake_init",
                severity=EventSeverity.INFO,
                action=EventAction.ALLOW,
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    protocol="UDP",
                ),
                metadata={"vpn_type": "openvpn"},
                raw_log=line,
            )

        # Fallback generic VPN event
        return SecurityEvent(
            timestamp=ts,
            source=LogSource.VPN,
            event_type="vpn_generic_event",
            severity=EventSeverity.INFO,
            action=EventAction.UNKNOWN,
            metadata={"raw": line},
            raw_log=line,
        )

    @staticmethod
    def _extract_timestamp(line: str) -> datetime:
        iso_match = re.search(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b", line)
        if iso_match:
            try:
                dt_str = iso_match.group(0).replace(" ", "T")
                if not dt_str.endswith("Z") and "+" not in dt_str and "-" not in dt_str[10:]:
                    dt_str += "Z"
                return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        bsd_match = re.search(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b", line)
        if bsd_match:
            try:
                month, day, time_str = bsd_match.groups()
                now = datetime.now(timezone.utc)
                parsed = datetime.strptime(f"{now.year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        return datetime.now(timezone.utc)

