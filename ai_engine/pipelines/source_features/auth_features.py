"""
Source-Aware Feature Extraction: Authentication Domain for AEGIS-X 2.0.

Extracts structured features for host authentication events (Linux SSH/PAM/sudo,
Windows Event 4624/4625, and VPN logon events).
Version: 2.0.0
"""

import ipaddress
import math
from typing import Any

from ai_engine.ingestion.schemas import EventAction, SecurityEvent

FEATURE_SCHEMA_VERSION = "2.0.0-auth"

AUTH_FEATURE_NAMES = [
    "is_failed_attempt",
    "is_root_or_admin",
    "username_length",
    "username_entropy",
    "is_invalid_user",
    "auth_method_code",
    "has_remote_ip",
    "is_external_ip",
    "is_night_time",
    "is_weekend",
    "hour_of_day",
    "target_port",
]


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


class AuthFeatureExtractor:
    """Transforms authentication-centric SecurityEvents into vectorized numerical features."""

    @classmethod
    def extract_features(cls, event: SecurityEvent) -> dict[str, float]:
        user = event.user
        net = event.network
        meta = event.metadata

        # 1. Failure vs Success
        is_failure = 1.0 if (event.action in (EventAction.FAILURE, EventAction.BLOCK, EventAction.DROP) or "fail" in event.event_type) else 0.0

        # 2. Privileged Account Check
        uname = (user.username or "").lower()
        is_priv = 1.0 if any(p in uname for p in ("root", "admin", "administrator", "system", "deploy")) else 0.0

        # 3. Username length and character entropy (helps detect randomly generated usernames)
        u_len = float(len(uname))
        u_entropy = round(cls._shannon_entropy(uname), 4)

        # 4. Invalid User flag
        is_invalid = 1.0 if meta.get("invalid_user") or "invalid" in event.raw_log.lower() else 0.0

        # 5. Auth Method Code
        method = (user.auth_method or "").lower()
        if "pass" in method:
            method_code = 1.0
        elif "pub" in method or "cert" in method:
            method_code = 2.0
        elif "kerb" in method or "ntlm" in method:
            method_code = 3.0
        elif "rdp" in method or "remote" in method:
            method_code = 4.0
        else:
            method_code = 0.0

        # 6. Network Origin
        src_ip = net.source_ip
        has_remote = 1.0 if src_ip and src_ip not in ("-", "127.0.0.1", "::1", "localhost") else 0.0
        is_external = 1.0 if (has_remote and not cls._is_private_ip(src_ip)) else 0.0

        # 7. Temporal Indicators
        ts = event.timestamp
        hour = float(ts.hour)
        is_night = 1.0 if (hour >= 22.0 or hour <= 6.0) else 0.0
        is_wknd = 1.0 if ts.weekday() >= 5 else 0.0

        target_port = float(net.destination_port or (22.0 if "ssh" in event.event_type else 0.0))

        return {
            "is_failed_attempt": is_failure,
            "is_root_or_admin": is_priv,
            "username_length": u_len,
            "username_entropy": u_entropy,
            "is_invalid_user": is_invalid,
            "auth_method_code": method_code,
            "has_remote_ip": has_remote,
            "is_external_ip": is_external,
            "is_night_time": is_night,
            "is_weekend": is_wknd,
            "hour_of_day": hour,
            "target_port": target_port,
        }

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    @staticmethod
    def _is_private_ip(ip_str: str | None) -> bool:
        if not ip_str or ip_str in ("-", "localhost"):
            return True
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in RFC1918_NETWORKS)
        except ValueError:
            return False
