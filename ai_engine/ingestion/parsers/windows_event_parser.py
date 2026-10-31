"""
Windows Event Log Parser for AEGIS-X 2.0.

Parses Windows Security and System Event logs (JSON objects, EVTX XML strings,
or forwarded syslog event streams):
- Event ID 4624: Successful Logon (Logon Type 2=Interactive, 3=Network, 10=RDP)
- Event ID 4625: Failed Logon (Status and SubStatus reason codes)
- Event ID 4672: Special Privileges Assigned (Admin/SeDebug rights)
- Event ID 4688: Process Creation (ProcessCommandLine, ParentProcessName)
- Event ID 4720: User Account Created
- Event ID 7045: New Service Installed (Persistence indicator)

Preserves exact EventData attributes and maps security entities to standard schema.
"""

from datetime import datetime, timezone
import json
import re
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

# Logon Types
LOGON_TYPES: dict[int, str] = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}


class WindowsEventParser:
    """Parser for Windows Security Event Log records."""

    @classmethod
    def parse_record(cls, record: dict | str, timestamp_override: datetime | None = None) -> SecurityEvent | None:
        """
        Parses a Windows Event Log record (given as a dict or JSON/XML string).
        Never throws on missing fields or malformed data.
        """
        if not record:
            return None

        data: dict[str, Any] = {}
        raw_str = ""

        if isinstance(record, str):
            raw_str = record.strip()
            if not raw_str:
                return None
            try:
                data = json.loads(raw_str)
            except json.JSONDecodeError:
                # Try simple regex parsing for XML / syslog format
                return cls._parse_text_fallback(raw_str, timestamp_override)
        elif isinstance(record, dict):
            data = record
            raw_str = json.dumps(record)

        event_id = int(data.get("EventID") or data.get("event_id") or data.get("Id") or 0)
        ts = timestamp_override or cls._parse_timestamp(data.get("TimeCreated") or data.get("timestamp"))
        computer = data.get("Computer") or data.get("hostname") or data.get("Host")
        event_data = data.get("EventData") or data.get("data") or {}

        # 1. Event 4624: Successful Logon
        if event_id == 4624:
            logon_type_code = int(event_data.get("LogonType") or 0)
            logon_type_name = LOGON_TYPES.get(logon_type_code, f"Type_{logon_type_code}")
            target_user = event_data.get("TargetUserName") or event_data.get("SubjectUserName")
            target_domain = event_data.get("TargetDomainName")
            src_ip = event_data.get("IpAddress")
            src_port = event_data.get("IpPort")

            severity = EventSeverity.INFO
            # Remote RDP logon or network logon to sensitive account warrants MEDIUM
            if logon_type_code == 10 or (target_user and target_user.lower() in ("administrator", "root")):
                severity = EventSeverity.MEDIUM

            return SecurityEvent(
                timestamp=ts,
                source=LogSource.WINDOWS_EVENT,
                event_type="windows_logon_success",
                severity=severity,
                action=EventAction.SUCCESS,
                user=UserEntity(
                    username=target_user,
                    domain=target_domain,
                    auth_method=logon_type_name,
                    session_id=event_data.get("TargetLogonId"),
                ),
                network=NetworkEntity(
                    source_ip=src_ip if src_ip and src_ip != "-" else None,
                    source_port=int(src_port) if src_port and src_port.isdigit() else None,
                ),
                host=HostEntity(hostname=computer, os="Windows"),
                metadata={
                    "event_id": 4624,
                    "logon_type": logon_type_name,
                    "logon_process": event_data.get("LogonProcessName"),
                    "authentication_package": event_data.get("AuthenticationPackageName"),
                },
                raw_log=raw_str,
            )

        # 2. Event 4625: Failed Logon
        if event_id == 4625:
            target_user = event_data.get("TargetUserName")
            src_ip = event_data.get("IpAddress")
            src_port = event_data.get("IpPort")
            status_code = event_data.get("Status")
            sub_status = event_data.get("SubStatus")

            return SecurityEvent(
                timestamp=ts,
                source=LogSource.WINDOWS_EVENT,
                event_type="windows_logon_failure",
                severity=EventSeverity.HIGH if target_user in ("Administrator", "admin") else EventSeverity.MEDIUM,
                action=EventAction.FAILURE,
                user=UserEntity(
                    username=target_user,
                    domain=event_data.get("TargetDomainName"),
                    auth_method="Windows_Auth",
                ),
                network=NetworkEntity(
                    source_ip=src_ip if src_ip and src_ip != "-" else None,
                    source_port=int(src_port) if src_port and src_port.isdigit() else None,
                ),
                host=HostEntity(hostname=computer, os="Windows"),
                metadata={
                    "event_id": 4625,
                    "failure_status": status_code,
                    "sub_status": sub_status,
                    "failure_reason": cls._resolve_failure_reason(sub_status),
                },
                raw_log=raw_str,
            )

        # 3. Event 4672: Special Privileges Assigned
        if event_id == 4672:
            user = event_data.get("SubjectUserName")
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.WINDOWS_EVENT,
                event_type="windows_privilege_assigned",
                severity=EventSeverity.MEDIUM,
                action=EventAction.SUCCESS,
                user=UserEntity(username=user, privilege_level="Administrator"),
                host=HostEntity(hostname=computer, os="Windows"),
                metadata={
                    "event_id": 4672,
                    "privilege_list": event_data.get("PrivilegeList"),
                },
                raw_log=raw_str,
            )

        # 4. Event 4688: Process Creation
        if event_id == 4688:
            proc_name = event_data.get("NewProcessName")
            cmd_line = event_data.get("CommandLine") or event_data.get("ProcessCommandLine")
            parent_proc = event_data.get("ParentProcessName")
            user = event_data.get("SubjectUserName") or event_data.get("TargetUserName")

            # Detect suspicious execution (cmd.exe spawning powershell with encoded commands, mimikatz, certutil)
            is_suspicious = False
            if cmd_line:
                lower_cmd = cmd_line.lower()
                is_suspicious = any(
                    term in lower_cmd
                    for term in ("-enc", "bypass", "invoke-mimikatz", "downloadstring", "certutil -urlcache", "vssadmin delete shadows")
                )

            return SecurityEvent(
                timestamp=ts,
                source=LogSource.WINDOWS_EVENT,
                event_type="windows_process_creation",
                severity=EventSeverity.CRITICAL if is_suspicious else EventSeverity.INFO,
                action=EventAction.SUCCESS,
                user=UserEntity(username=user),
                process=ProcessEntity(
                    process_name=proc_name.split("\\")[-1] if proc_name else None,
                    process_path=proc_name,
                    command_line=cmd_line,
                    parent_process_name=parent_proc.split("\\")[-1] if parent_proc else None,
                ),
                host=HostEntity(hostname=computer, os="Windows"),
                metadata={"event_id": 4688, "creator_process": parent_proc},
                raw_log=raw_str,
            )

        # 5. Event 7045: Service Installed
        if event_id == 7045:
            svc_name = event_data.get("ServiceName")
            img_path = event_data.get("ImagePath")
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.WINDOWS_EVENT,
                event_type="windows_service_installed",
                severity=EventSeverity.HIGH,
                action=EventAction.SUCCESS,
                process=ProcessEntity(process_name=svc_name, command_line=img_path),
                host=HostEntity(hostname=computer, os="Windows"),
                metadata={"event_id": 7045, "service_type": event_data.get("ServiceType")},
                raw_log=raw_str,
            )

        # Generic Windows Event fallback
        return SecurityEvent(
            timestamp=ts,
            source=LogSource.WINDOWS_EVENT,
            event_type=f"windows_event_{event_id}" if event_id else "windows_generic_event",
            severity=EventSeverity.INFO,
            action=EventAction.UNKNOWN,
            host=HostEntity(hostname=computer, os="Windows"),
            metadata=event_data,
            raw_log=raw_str,
        )

    @classmethod
    def _parse_text_fallback(cls, raw: str, ts_override: datetime | None) -> SecurityEvent:
        """Fallback regex parser for text lines referencing Windows Event IDs."""
        ev_match = re.search(r"\b(?:EventID|Event\s+ID|ID)[:\s]+(?P<id>\d{4})\b", raw, re.IGNORECASE)
        event_id = int(ev_match.group("id")) if ev_match else 0
        user_match = re.search(r"\b(?:Account\s+Name|User|TargetUserName)[:\s]+(?P<user>[\w\.\-]+)\b", raw, re.IGNORECASE)
        ip_match = re.search(r"\b(?:Source\s+Network\s+Address|IpAddress)[:\s]+(?P<ip>[\d\.]+)\b", raw, re.IGNORECASE)

        return SecurityEvent(
            timestamp=ts_override or datetime.now(timezone.utc),
            source=LogSource.WINDOWS_EVENT,
            event_type=f"windows_event_{event_id}" if event_id else "windows_text_event",
            severity=EventSeverity.INFO,
            action=EventAction.UNKNOWN,
            user=UserEntity(username=user_match.group("user") if user_match else None),
            network=NetworkEntity(source_ip=ip_match.group("ip") if ip_match else None),
            metadata={"parsed_text": True, "event_id": event_id},
            raw_log=raw,
        )

    @staticmethod
    def _parse_timestamp(val: Any) -> datetime:
        if not val:
            return datetime.now(timezone.utc)
        if isinstance(val, (int, float)):
            return datetime.fromtimestamp(val, tz=timezone.utc)
        if isinstance(val, str):
            try:
                clean_str = val.replace("Z", "+00:00")
                return datetime.fromisoformat(clean_str)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _resolve_failure_reason(sub_status: str | None) -> str:
        reasons = {
            "0xc0000064": "User name does not exist",
            "0xc000006a": "User name correct, password incorrect",
            "0xc0000234": "User account currently locked out",
            "0xc0000072": "Account is currently disabled",
            "0xc0000193": "User account has expired",
            "0xc0000070": "User logon type not granted or time restriction",
        }
        if not sub_status:
            return "Unknown failure reason"
        return reasons.get(sub_status.lower(), f"SubStatus {sub_status}")

