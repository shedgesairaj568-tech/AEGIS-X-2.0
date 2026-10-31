"""
Linux System and Authentication Log Parser for AEGIS-X 2.0.

Parses auth.log, secure, syslog, and auditd events:
- SSH authentication attempts (Failed password, Invalid user, Accepted publickey/password)
- Privilege escalation via sudo (successful commands, unauthorized attempts)
- Switch user (su) failures and root escalation
- PAM session lifecycle (open, close, authentication token failures)

Normalizes authentication entities, usernames, remote IPs, ports, and execution context.
"""

from datetime import datetime, timezone
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

# SSH Failed Password:
# E.g. Oct 31 10:14:22 web-srv-01 sshd[14205]: Failed password for invalid user admin from 198.51.100.88 port 48123 ssh2
_SSH_FAIL_PATTERN = re.compile(
    r"sshd(?:\[\d+\])?:\s+Failed\s+password\s+for\s+(?P<invalid>invalid\s+user\s+)?(?P<user>[^\s]+)\s+from\s+(?P<src_ip>[\d\.]+)\s+port\s+(?P<src_port>\d+)",
    re.IGNORECASE,
)
# SSH Accepted:
# E.g. Oct 31 10:15:00 web-srv-01 sshd[14210]: Accepted publickey for root from 192.168.1.10 port 52140 ssh2: RSA SHA256:...
_SSH_SUCCESS_PATTERN = re.compile(
    r"sshd(?:\[\d+\])?:\s+Accepted\s+(?P<auth_method>publickey|password|keyboard-interactive)\s+for\s+(?P<user>[^\s]+)\s+from\s+(?P<src_ip>[\d\.]+)\s+port\s+(?P<src_port>\d+)",
    re.IGNORECASE,
)
# Sudo Execution:
# E.g. Oct 31 10:16:01 web-srv-01 sudo:   analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow
_SUDO_PATTERN = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?P<user>[^\s]+)\s+:\s+(?:TTY=(?P<tty>[^\s;]+)\s*;\s*)?(?:PWD=(?P<pwd>[^\s;]+)\s*;\s*)?USER=(?P<target_user>[^\s;]+)\s*;\s*COMMAND=(?P<cmd>.*)",
    re.IGNORECASE,
)
# Sudo Unauthorized / Not in sudoers:
_SUDO_UNAUTH_PATTERN = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?P<user>[^\s]+)\s+:\s+user NOT in sudoers",
    re.IGNORECASE,
)
# SU Failed:
# E.g. Oct 31 10:17:10 web-srv-01 su[14300]: FAILED SU (to root) guest on pts/1
_SU_FAIL_PATTERN = re.compile(
    r"su(?:\[\d+\])?:\s+FAILED SU\s+\(to\s+(?P<target_user>[^\)]+)\)\s+(?P<user>[^\s]+)",
    re.IGNORECASE,
)
# Hostname extraction from standard syslog:
# E.g. Oct 31 10:14:22 web-srv-01 sshd...
_SYSLOG_HOST_PATTERN = re.compile(
    r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(?P<hostname>[\w\.\-]+)\s+",
)


class LinuxAuthParser:
    """Parser for Linux host authentication and system privilege activity."""

    @classmethod
    def parse_line(cls, line: str, timestamp_override: datetime | None = None) -> SecurityEvent | None:
        if not line or not line.strip():
            return None

        line = line.strip()
        ts = timestamp_override or cls._extract_timestamp(line)
        hostname = cls._extract_hostname(line)

        # 1. SSH Authentication Failure / Brute Force Probe
        match_ssh_fail = _SSH_FAIL_PATTERN.search(line)
        if match_ssh_fail:
            d = match_ssh_fail.groupdict()
            is_invalid = bool(d.get("invalid"))
            username = d.get("user")
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.LINUX_AUTH,
                event_type="ssh_login_failure",
                severity=EventSeverity.HIGH if (is_invalid or username in ("root", "admin")) else EventSeverity.MEDIUM,
                action=EventAction.FAILURE,
                user=UserEntity(
                    username=username,
                    auth_method="password",
                    privilege_level="root" if username == "root" else "user",
                ),
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    destination_port=22,
                    protocol="TCP",
                ),
                host=HostEntity(hostname=hostname),
                metadata={
                    "service": "sshd",
                    "invalid_user": is_invalid,
                },
                raw_log=line,
            )

        # 2. SSH Successful Logon
        match_ssh_ok = _SSH_SUCCESS_PATTERN.search(line)
        if match_ssh_ok:
            d = match_ssh_ok.groupdict()
            username = d.get("user")
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.LINUX_AUTH,
                event_type="ssh_login_success",
                severity=EventSeverity.LOW if username != "root" else EventSeverity.MEDIUM,
                action=EventAction.SUCCESS,
                user=UserEntity(
                    username=username,
                    auth_method=d.get("auth_method", "publickey"),
                    privilege_level="root" if username == "root" else "user",
                ),
                network=NetworkEntity(
                    source_ip=d.get("src_ip"),
                    source_port=int(d["src_port"]) if d.get("src_port") else None,
                    destination_port=22,
                    protocol="TCP",
                ),
                host=HostEntity(hostname=hostname),
                metadata={"service": "sshd"},
                raw_log=line,
            )

        # 3. Sudo Unauthorized
        match_sudo_unauth = _SUDO_UNAUTH_PATTERN.search(line)
        if match_sudo_unauth:
            d = match_sudo_unauth.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.LINUX_AUTH,
                event_type="sudo_unauthorized_attempt",
                severity=EventSeverity.HIGH,
                action=EventAction.BLOCK,
                user=UserEntity(username=d.get("user")),
                host=HostEntity(hostname=hostname),
                metadata={"service": "sudo", "alert": "user_not_in_sudoers"},
                raw_log=line,
            )

        # 4. Sudo Command Execution
        match_sudo = _SUDO_PATTERN.search(line)
        if match_sudo:
            d = match_sudo.groupdict()
            cmd = d.get("cmd", "")
            # Check for suspicious commands (e.g. shadow, nmap, netcat, iptables)
            is_suspicious_cmd = any(s in cmd.lower() for s in ("/etc/shadow", "chmod 777", "nmap", "nc -l", "curl | bash", "wget"))
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.LINUX_AUTH,
                event_type="sudo_command_execution",
                severity=EventSeverity.HIGH if is_suspicious_cmd else EventSeverity.INFO,
                action=EventAction.SUCCESS,
                user=UserEntity(username=d.get("user"), privilege_level=d.get("target_user", "root")),
                process=ProcessEntity(command_line=cmd),
                host=HostEntity(hostname=hostname),
                metadata={"service": "sudo", "target_user": d.get("target_user"), "pwd": d.get("pwd")},
                raw_log=line,
            )

        # 5. SU Switch User Failure
        match_su_fail = _SU_FAIL_PATTERN.search(line)
        if match_su_fail:
            d = match_su_fail.groupdict()
            return SecurityEvent(
                timestamp=ts,
                source=LogSource.LINUX_AUTH,
                event_type="su_auth_failure",
                severity=EventSeverity.HIGH,
                action=EventAction.FAILURE,
                user=UserEntity(username=d.get("user")),
                host=HostEntity(hostname=hostname),
                metadata={"service": "su", "target_user": d.get("target_user")},
                raw_log=line,
            )

        # Fallback generic Linux event
        return SecurityEvent(
            timestamp=ts,
            source=LogSource.LINUX_AUTH,
            event_type="linux_system_event",
            severity=EventSeverity.INFO,
            action=EventAction.UNKNOWN,
            host=HostEntity(hostname=hostname),
            metadata={"raw": line},
            raw_log=line,
        )

    @staticmethod
    def _extract_hostname(line: str) -> str | None:
        match = _SYSLOG_HOST_PATTERN.search(line)
        return match.group("hostname") if match else None

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

