"""
Multi-Source Log Loader and Stream Simulator for AEGIS-X 2.0.

Loads, streams, and normalizes logs from local files or streaming queues:
- Firewall logs (.log, .txt)
- VPN logs (.log)
- Linux auth/syslog (.log, auth.log, secure)
- Windows Event Logs (.json, .evtx)

Features deduplication, error logging, and malformed line fault tolerance.
"""

from collections.abc import Generator
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from ai_engine.ingestion.parsers.firewall_parser import FirewallParser
from ai_engine.ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ai_engine.ingestion.parsers.vpn_parser import VpnParser
from ai_engine.ingestion.parsers.windows_event_parser import WindowsEventParser
from ai_engine.ingestion.schemas import LogSource, SecurityEvent
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


class MultiSourceLogLoader:
    """Ingests multi-source logs with deduplication and fault-tolerant parsing."""

    def __init__(self, enable_dedup: bool = True):
        self.enable_dedup = enable_dedup
        self._seen_hashes: set[str] = set()

    def parse_file(
        self,
        file_path: str | Path,
        source: LogSource | None = None,
    ) -> list[SecurityEvent]:
        """Parses an entire file and returns a list of valid SecurityEvents."""
        events: list[SecurityEvent] = []
        for event in self.stream_file(file_path, source):
            events.append(event)
        return events

    def stream_file(
        self,
        file_path: str | Path,
        source: LogSource | None = None,
    ) -> Generator[SecurityEvent, None, None]:
        """Yields SecurityEvents sequentially from a log file."""
        path = Path(file_path)
        if not path.exists():
            logger.error("Log file not found: %s", path)
            return

        inferred_source = source or self._infer_source(path)

        if inferred_source == LogSource.WINDOWS_EVENT and path.suffix.lower() == ".json":
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                try:
                    data = json.load(f)
                    records = data if isinstance(data, list) else [data]
                    for rec in records:
                        ev = WindowsEventParser.parse_record(rec)
                        if ev and self._is_new_event(ev):
                            yield ev
                except json.JSONDecodeError as exc:
                    logger.warning("JSON decode error in %s: %s", path, exc)
            return

        # Line-by-line parsing for syslog/firewall/vpn/linux auth
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    ev = self._parse_single_line(clean_line, inferred_source)
                    if ev and self._is_new_event(ev):
                        yield ev
                except Exception as exc:
                    logger.warning("Error parsing %s line %d: %s", path, line_no, exc)

    def _parse_single_line(self, line: str, source: LogSource) -> SecurityEvent | None:
        if source == LogSource.FIREWALL:
            return FirewallParser.parse_line(line)
        elif source == LogSource.VPN:
            return VpnParser.parse_line(line)
        elif source == LogSource.LINUX_AUTH:
            return LinuxAuthParser.parse_line(line)
        elif source == LogSource.WINDOWS_EVENT:
            return WindowsEventParser.parse_record(line)
        else:
            return FirewallParser.parse_line(line)

    def _is_new_event(self, event: SecurityEvent) -> bool:
        """Deduplicates events based on source and raw log payload signature."""
        if not self.enable_dedup:
            return True
        h = hashlib.sha256(
            f"{event.source}:{event.raw_log.strip()}".encode()
        ).hexdigest()
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        return True

    @staticmethod
    def _infer_source(path: Path) -> LogSource:
        name = path.name.lower()
        if "firewall" in name or "asa" in name or "iptables" in name:
            return LogSource.FIREWALL
        elif "vpn" in name or "wireguard" in name or "openvpn" in name:
            return LogSource.VPN
        elif "auth" in name or "secure" in name or "linux" in name or "syslog" in name:
            return LogSource.LINUX_AUTH
        elif "windows" in name or "event" in name or "evtx" in name:
            return LogSource.WINDOWS_EVENT
        return LogSource.NETWORK_FLOW
