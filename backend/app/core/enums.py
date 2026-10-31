"""
Shared value sets for Alert-related string columns.

Deliberately implemented as plain Python string constants + Literal types
rather than a native Postgres ENUM column. Native enums are painful to
migrate (ALTER TYPE ... ADD VALUE has restrictions, can't run in a
transaction on older PG versions) — a plain VARCHAR validated by Pydantic
at the API boundary gives the same safety with much easier evolution as
new attack types are added in Module 6 (AI models).
"""

from typing import Literal

AlertStatus = Literal["open", "investigating", "resolved", "false_positive"]
ALERT_STATUSES: tuple[str, ...] = ("open", "investigating", "resolved", "false_positive")

AlertSeverity = Literal["info", "low", "medium", "high", "critical"]
ALERT_SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# Matches the XGBoost classifier's output classes from the project spec.
AttackType = Literal[
    "normal",
    "brute_force",
    "ddos",
    "botnet",
    "port_scan",
    "sql_injection",
    "web_attack",
    "other",
]
ATTACK_TYPES: tuple[str, ...] = (
    "normal",
    "brute_force",
    "ddos",
    "botnet",
    "port_scan",
    "sql_injection",
    "web_attack",
    "other",
)

AlertSource = Literal[
    "network_flow",
    "auth_log",
    "firewall",
    "ids_ips",
    "endpoint",
    "cloud_audit",
    "user_behaviour",
    "threat_intel",
]
ALERT_SOURCES: tuple[str, ...] = (
    "network_flow",
    "auth_log",
    "firewall",
    "ids_ips",
    "endpoint",
    "cloud_audit",
    "user_behaviour",
    "threat_intel",
)

ThreatHistoryEventType = Literal[
    "detected", "status_change", "note", "assignment", "correlation", "report_generated"
]
THREAT_HISTORY_EVENT_TYPES: tuple[str, ...] = (
    "detected",
    "status_change",
    "note",
    "assignment",
    "correlation",
    "report_generated",
)

SettingScope = Literal["user", "system"]
SETTING_SCOPES: tuple[str, ...] = ("user", "system")

# Human-In-The-Loop Containment Actions
ActionStatus = Literal["pending_approval", "approved", "executed", "rejected", "failed"]
ACTION_STATUSES: tuple[str, ...] = ("pending_approval", "approved", "executed", "rejected", "failed")

ActionType = Literal["block_ip", "isolate_host", "disable_user", "terminate_process", "revoke_session"]
ACTION_TYPES: tuple[str, ...] = ("block_ip", "isolate_host", "disable_user", "terminate_process", "revoke_session")
