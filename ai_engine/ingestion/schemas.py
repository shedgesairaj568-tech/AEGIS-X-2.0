"""
Universal SecurityEvent Schema for AEGIS-X 2.0.

Provides a unified, source-aware data representation for all ingested security logs:
- Firewall logs (Cisco ASA, Palo Alto, iptables, pfSense)
- VPN logs (OpenVPN, WireGuard, IPsec)
- Linux authentication and system logs (auth.log, secure, syslog, auditd)
- Windows Event Logs (Security.evtx, Sysmon)
- Network flow logs (NetFlow, IPFIX, Zeek, CIC-IDS)

Normalizes common entity fields while preserving raw event payloads and source-specific
metadata for explainability and forensic evidence preservation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid

from pydantic import BaseModel, Field, field_validator


class LogSource(str, Enum):
    FIREWALL = "firewall"
    VPN = "vpn"
    LINUX_AUTH = "linux_auth"
    WINDOWS_EVENT = "windows_event"
    NETWORK_FLOW = "network_flow"


class EventSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    DROP = "drop"
    SUCCESS = "success"
    FAILURE = "failure"
    ALERT = "alert"
    UNKNOWN = "unknown"


class NetworkEntity(BaseModel):
    """Network-level contextual entities."""

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None  # TCP, UDP, ICMP, etc.
    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)
    packets_sent: int | None = Field(default=None, ge=0)
    packets_received: int | None = Field(default=None, ge=0)
    duration_ms: float | None = Field(default=None, ge=0)


class UserEntity(BaseModel):
    """Identity and authentication contextual entities."""

    username: str | None = None
    domain: str | None = None
    user_id: str | None = None
    auth_method: str | None = None  # password, publickey, mfa, kerberos, ntlm
    privilege_level: str | None = None  # user, admin, root, SYSTEM
    session_id: str | None = None


class HostEntity(BaseModel):
    """Host/Endpoint contextual entities."""

    hostname: str | None = None
    ip_address: str | None = None
    os: str | None = None
    device_id: str | None = None


class ProcessEntity(BaseModel):
    """Process execution contextual entities."""

    process_id: int | None = None
    process_name: str | None = None
    process_path: str | None = None
    command_line: str | None = None
    parent_process_id: int | None = None
    parent_process_name: str | None = None
    file_hash: str | None = None


class SecurityEvent(BaseModel):
    """
    Universal SecurityEvent schema adhering to SIEM/ECS normalization standards.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: LogSource
    event_type: str  # e.g., "ssh_login_failure", "fw_drop", "process_spawn", "vpn_connect"
    severity: EventSeverity = EventSeverity.INFO
    action: EventAction = EventAction.UNKNOWN

    # Normalized Entities
    network: NetworkEntity = Field(default_factory=NetworkEntity)
    user: UserEntity = Field(default_factory=UserEntity)
    host: HostEntity = Field(default_factory=HostEntity)
    process: ProcessEntity = Field(default_factory=ProcessEntity)

    # Source-Specific Metadata & Raw Log Preservation
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_log: str = Field(min_length=1)

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            # Parse ISO or standard timestamp string
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                # Fallback to current UTC time if unparseable
                return datetime.now(timezone.utc)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        elif isinstance(v, (int, float)):
            # Epoch timestamp
            return datetime.fromtimestamp(v, tz=timezone.utc)
        elif isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        return datetime.now(timezone.utc)

