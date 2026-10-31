"""
Firewall Log Parser for AEGIS-X 2.0.

Parses structured and semi-structured firewall logs from common enterprise formats:
- Cisco ASA syslogs (%ASA-6-302013, %ASA-4-106023, %ASA-2-106001)
- Palo Alto Networks traffic logs (CSV or key-value format)
- Linux iptables/nftables logs (prefix log format)
- CEF (Common Event Format) firewall events

Gracefully handles malformed lines, missing fields, and irregular timestamps.
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
)
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Cisco ASA regex patterns:
# E.g. %ASA-4-106023: Deny tcp src outside:198.51.100.15/44321 dst inside:10.0.0.5/80 by access-group "acl_in"
_CISCO_DENY_PATTERN = re.compile(
    r"%ASA-\d+-(?P<code>\d+):\s+(?P<action>Deny|Drop)\s+(?P<proto>\w+)\s+src\s+(?:\w+:)?(?P<src_ip>[\d\.]+)/(?P<src_port>\d+)\s+dst\s+(?:\w+:)?(?P<dst_ip>[\d\.]+)/(?P<dst_port>\d+)(?:\s+by\s+access-group\s+\"(?P<rule>[^\"]+)\")?",
    re.IGNORECASE,
)
# E.g. %ASA-6-302013: Built inbound TCP connection 12345 for outside:203.0.113.10/54321 (203.0.113.10/54321) to inside:10.0.0.10/443 (10.0.0.10/443)
_CISCO_BUILT_PATTERN = re.compile(
    r"%ASA-\d+-(?P<code>\d+):\s+Built\s+(?P<dir>inbound|outbound)?\s*(?P<proto>\w+)\s+connection\s+\d+\s+for\s+(?:\w+:)?(?P<src_ip>[\d\.]+)/(?P<src_port>\d+)(?:\s+\([^\)]+\))?\s+to\s+(?:\w+:)?(?P<dst_ip>[\d\.]+)/(?P<dst_port>\d+)",
    re.IGNORECASE,
)

# iptables prefix regex:
# E.g. iptables-DROP: IN=eth0 OUT= MAC=... SRC=192.168.1.50 DST=10.0.0.1 LEN=60 ... PROTO=TCP SPT=49152 DPT=22 ...
_IPTABLES_PATTERN = re.compile(
    r"(?P<prefix>[\w\-]+):\s+.*?SRC=(?P<src_ip>[\d\.]+)\s+DST=(?P<dst_ip>[\d\.]+).*?PROTO=(?P<proto>\w+)(?:.*?SPT=(?P<src_port>\d+))?(?:.*?DPT=(?P<dst_port>\d+))?",
    re.IGNORECASE,
)

# Key-Value / CEF pattern (e.g., action=block proto=tcp src=... dst=...)
_KV_PAIR_PATTERN = re.compile(r"(\w+)=([^\s]+|\"[^\"]*\")")


class FirewallParser:
    """Parser for diverse enterprise firewall log streams."""

    @classmethod
    def parse_line(cls, line: str, timestamp_override: datetime | None = None) -> SecurityEvent | None:
        """
        Parses a single firewall log line into a normalized SecurityEvent.
        Returns None if line is empty or purely whitespace.
        Never raises an uncaught exception on malformed logs.
        """
        if not line or not line.strip():
            return None

        line = line.strip()
        ts = timestamp_override or cls._extract_timestamp(line)

        # 1. Try Cisco ASA Deny / Drop
        match_deny = _CISCO_DENY_PATTERN.search(line)
        if match_deny:
            data = match_deny.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.FIREWALL,
                event_type="firewall_deny",
                severity=EventSeverity.MEDIUM,
                action=EventAction.DROP if "drop" in data.get("action", "").lower() else EventAction.BLOCK,
                network=NetworkEntity(
                    source_ip=data.get("src_ip"),
                    destination_ip=data.get("dst_ip"),
                    source_port=int(data["src_port"]) if data.get("src_port") else None,
                    destination_port=int(data["dst_port"]) if data.get("dst_port") else None,
                    protocol=data.get("proto", "TCP").upper(),
                ),
                metadata={
                    "vendor": "cisco_asa",
                    "cisco_code": data.get("code"),
                    "rule": data.get("rule"),
                },
                raw_log=line,
            )

        # 2. Try Cisco ASA Built / Permitted Connection
        match_built = _CISCO_BUILT_PATTERN.search(line)
        if match_built:
            data = match_built.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.FIREWALL,
                event_type="firewall_permit",
                severity=EventSeverity.INFO,
                action=EventAction.ALLOW,
                network=NetworkEntity(
                    source_ip=data.get("src_ip"),
                    destination_ip=data.get("dst_ip"),
                    source_port=int(data["src_port"]) if data.get("src_port") else None,
                    destination_port=int(data["dst_port"]) if data.get("dst_port") else None,
                    protocol=data.get("proto", "TCP").upper(),
                ),
                metadata={"vendor": "cisco_asa", "cisco_code": data.get("code")},
                raw_log=line,
            )

        # 3. Try Linux iptables
        match_iptables = _IPTABLES_PATTERN.search(line)
        if match_iptables:
            data = match_iptables.groupdict()
            raw_prefix = data.get("prefix", "").lower()
            clean_prefix = raw_prefix.replace("-", "_")
            event_type = clean_prefix if "iptables" in clean_prefix else f"iptables_{clean_prefix}"
            action = EventAction.DROP if "drop" in raw_prefix else (
                EventAction.BLOCK if "reject" in raw_prefix else EventAction.ALLOW
            )
            severity = EventSeverity.MEDIUM if action in (EventAction.DROP, EventAction.BLOCK) else EventSeverity.INFO
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.FIREWALL,
                event_type=event_type,
                severity=severity,
                action=action,
                network=NetworkEntity(
                    source_ip=data.get("src_ip"),
                    destination_ip=data.get("dst_ip"),
                    source_port=int(data["src_port"]) if data.get("src_port") else None,
                    destination_port=int(data["dst_port"]) if data.get("dst_port") else None,
                    protocol=data.get("proto", "TCP").upper(),
                ),
                metadata={"vendor": "iptables", "rule_prefix": raw_prefix},
                raw_log=line,
            )

        # 4. Generic Key-Value / CEF / PAN-OS fallback
        return cls._parse_key_value(line, ts)

    @classmethod
    def _parse_key_value(cls, line: str, ts: datetime) -> SecurityEvent:
        """Parses key-value formatted log lines (e.g. CEF, Palo Alto, Fortinet)."""
        kv_pairs: dict[str, str] = {}
        for k, v in _KV_PAIR_PATTERN.findall(line):
            kv_pairs[k.lower()] = v.strip('"')

        src_ip = kv_pairs.get("src") or kv_pairs.get("srcip") or kv_pairs.get("source_ip") or kv_pairs.get("suser_ip")
        dst_ip = kv_pairs.get("dst") or kv_pairs.get("dstip") or kv_pairs.get("destination_ip")
        spt = kv_pairs.get("spt") or kv_pairs.get("srcport") or kv_pairs.get("source_port")
        dpt = kv_pairs.get("dpt") or kv_pairs.get("dstport") or kv_pairs.get("destination_port")
        proto = kv_pairs.get("proto") or kv_pairs.get("protocol") or "TCP"
        act_str = (kv_pairs.get("act") or kv_pairs.get("action") or "").lower()

        action = EventAction.UNKNOWN
        severity = EventSeverity.INFO
        if act_str in ("deny", "drop", "block", "reject"):
            action = EventAction.BLOCK if act_str != "drop" else EventAction.DROP
            severity = EventSeverity.MEDIUM
        elif act_str in ("allow", "permit", "pass", "accept"):
            action = EventAction.ALLOW
            severity = EventSeverity.INFO

        # Bytes & packets if present
        bytes_out = int(kv_pairs.get("bytes_out", 0)) if kv_pairs.get("bytes_out") else None
        bytes_in = int(kv_pairs.get("bytes_in", 0)) if kv_pairs.get("bytes_in") else None

        return SecurityEvent(
            timestamp=ts,
            source=LogSource.FIREWALL,
            event_type=f"firewall_{action.value}",
            severity=severity,
            action=action,
            network=NetworkEntity(
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=int(spt) if spt and spt.isdigit() else None,
                destination_port=int(dpt) if dpt and dpt.isdigit() else None,
                protocol=proto.upper(),
                bytes_sent=bytes_out,
                bytes_received=bytes_in,
            ),
            metadata={"parsed_kv": kv_pairs},
            raw_log=line,
        )

    @staticmethod
    def _extract_timestamp(line: str) -> datetime:
        """Attempts to extract timestamp from syslog header or returns current UTC."""
        # Check ISO timestamp e.g. 2026-10-31T12:00:00Z
        iso_match = re.search(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b", line)
        if iso_match:
            try:
                dt_str = iso_match.group(0).replace(" ", "T")
                if not dt_str.endswith("Z") and "+" not in dt_str and "-" not in dt_str[10:]:
                    dt_str += "Z"
                return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Check standard BSD syslog e.g. Oct 31 12:00:00
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
