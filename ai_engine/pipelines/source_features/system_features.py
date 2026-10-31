"""
Source-Aware Feature Extraction: System & Process Execution Domain for AEGIS-X 2.0.

Extracts structured features for process lineage, command execution, and service installations
(Windows 4688, 7045, 4672, and Linux sudo/auditd events).
Version: 2.0.0
"""

import math
from typing import Any

from ai_engine.ingestion.schemas import SecurityEvent

FEATURE_SCHEMA_VERSION = "2.0.0-system"

SYSTEM_FEATURE_NAMES = [
    "event_id_code",
    "is_shell_process",
    "cmd_length",
    "cmd_entropy",
    "has_obfuscation_keywords",
    "is_privilege_escalation",
    "path_depth",
    "has_suspicious_parent",
    "hour_of_day",
]

SHELL_BINARIES = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "zsh", "wscript.exe", "cscript.exe", "mshta.exe"}
SUSPICIOUS_PARENTS = {"w3wp.exe", "httpd.exe", "nginx.exe", "winword.exe", "excel.exe", "acrobat.exe", "spoolsv.exe"}
OBFUSCATION_PATTERNS = ["-enc", "-e ", "base64", "bypass", "downloadstring", "invoke-expression", "iex", "certutil", "curl |", "wget |"]


class SystemFeatureExtractor:
    """Transforms process execution and OS system events into vectorized numerical features."""

    @classmethod
    def extract_features(cls, event: SecurityEvent) -> dict[str, float]:
        proc = event.process
        user = event.user
        meta = event.metadata

        # 1. Event ID
        event_id = float(meta.get("event_id") or 0.0)

        # 2. Shell Binary Detection
        proc_name = (proc.process_name or "").lower()
        is_shell = 1.0 if any(sh in proc_name for sh in SHELL_BINARIES) else 0.0

        # 3. Command Line Length & Shannon Entropy
        cmd = proc.command_line or ""
        cmd_len = float(len(cmd))
        cmd_entropy = round(cls._shannon_entropy(cmd), 4)

        # 4. Obfuscation / Execution Keywords
        lower_cmd = cmd.lower()
        has_obfuscation = 1.0 if any(p in lower_cmd for p in OBFUSCATION_PATTERNS) else 0.0

        # 5. Privilege Escalation
        priv_user = (user.privilege_level or "").lower()
        is_priv_esc = 1.0 if (
            "root" in priv_user
            or "admin" in priv_user
            or "sudo" in event.event_type
            or event_id in (4672.0, 7045.0)
        ) else 0.0

        # 6. Path Depth
        path = proc.process_path or ""
        path_depth = float(path.count("\\") + path.count("/"))

        # 7. Suspicious Parent Process (e.g. web server spawning a shell)
        parent_name = (proc.parent_process_name or "").lower()
        has_susp_parent = 1.0 if (parent_name in SUSPICIOUS_PARENTS and is_shell) else 0.0

        # 8. Hour of Day
        hour = float(event.timestamp.hour)

        return {
            "event_id_code": event_id,
            "is_shell_process": is_shell,
            "cmd_length": cmd_len,
            "cmd_entropy": cmd_entropy,
            "has_obfuscation_keywords": has_obfuscation,
            "is_privilege_escalation": is_priv_esc,
            "path_depth": path_depth,
            "has_suspicious_parent": has_susp_parent,
            "hour_of_day": hour,
        }

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

