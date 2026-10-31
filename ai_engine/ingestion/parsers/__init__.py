"""
Parsers package for multi-source log ingestion in AEGIS-X 2.0.
"""

from ai_engine.ingestion.parsers.firewall_parser import FirewallParser
from ai_engine.ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ai_engine.ingestion.parsers.vpn_parser import VpnParser
from ai_engine.ingestion.parsers.windows_event_parser import WindowsEventParser

__all__ = [
    "FirewallParser",
    "VpnParser",
    "LinuxAuthParser",
    "WindowsEventParser",
]

