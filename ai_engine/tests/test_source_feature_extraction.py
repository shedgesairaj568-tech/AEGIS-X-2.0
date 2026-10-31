"""
Comprehensive Unit Tests for AEGIS-X 2.0 Source-Aware Feature Extractors.
"""

from datetime import datetime, timezone
import pytest

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
from ai_engine.pipelines.source_features.auth_features import (
    AUTH_FEATURE_NAMES,
    AuthFeatureExtractor,
)
from ai_engine.pipelines.source_features.network_features import (
    NETWORK_FEATURE_NAMES,
    NetworkFeatureExtractor,
)
from ai_engine.pipelines.source_features.system_features import (
    SYSTEM_FEATURE_NAMES,
    SystemFeatureExtractor,
)


class TestNetworkFeatureExtractor:
    def test_extract_all_features(self):
        event = SecurityEvent(
            timestamp=datetime(2026, 10, 31, 14, 30, tzinfo=timezone.utc),
            source=LogSource.FIREWALL,
            event_type="firewall_deny",
            action=EventAction.BLOCK,
            network=NetworkEntity(
                source_ip="198.51.100.20",
                destination_ip="10.0.0.5",
                source_port=52340,
                destination_port=443,
                protocol="TCP",
                bytes_sent=1500,
                bytes_received=3000,
                packets_sent=10,
                packets_received=20,
                duration_ms=250.0,
            ),
            raw_log="sample fw raw",
        )
        feats = NetworkFeatureExtractor.extract_features(event)

        # Check all declared feature names are present
        assert set(feats.keys()) == set(NETWORK_FEATURE_NAMES)
        assert feats["src_port"] == 52340.0
        assert feats["dst_port"] == 443.0
        assert feats["protocol_num"] == 6.0
        assert feats["total_bytes"] == 4500.0
        assert feats["total_packets"] == 30.0
        assert feats["bytes_per_packet"] == 150.0
        assert feats["is_privileged_port"] == 1.0  # dst_port 443 <= 1024
        assert feats["is_src_private_ip"] == 0.0  # 198.51.100.20 is public
        assert feats["is_dst_private_ip"] == 1.0  # 10.0.0.5 is RFC 1918 private
        assert feats["action_is_blocked"] == 1.0
        assert feats["hour_of_day"] == 14.0

    def test_zero_packets_safe_division(self):
        event = SecurityEvent(
            source=LogSource.NETWORK_FLOW,
            event_type="flow_zero",
            network=NetworkEntity(),
            raw_log="zero",
        )
        feats = NetworkFeatureExtractor.extract_features(event)
        assert feats["bytes_per_packet"] == 0.0
        assert feats["bytes_ratio"] == 1.0


class TestAuthFeatureExtractor:
    def test_extract_auth_features(self):
        event = SecurityEvent(
            timestamp=datetime(2026, 10, 31, 23, 15, tzinfo=timezone.utc),
            source=LogSource.LINUX_AUTH,
            event_type="ssh_login_failure",
            action=EventAction.FAILURE,
            user=UserEntity(username="administrator", auth_method="password"),
            network=NetworkEntity(source_ip="203.0.113.5", destination_port=22),
            metadata={"invalid_user": True},
            raw_log="sample auth raw",
        )
        feats = AuthFeatureExtractor.extract_features(event)

        assert set(feats.keys()) == set(AUTH_FEATURE_NAMES)
        assert feats["is_failed_attempt"] == 1.0
        assert feats["is_root_or_admin"] == 1.0
        assert feats["username_length"] == 13.0
        assert feats["username_entropy"] > 0.0
        assert feats["is_invalid_user"] == 1.0
        assert feats["auth_method_code"] == 1.0  # password
        assert feats["has_remote_ip"] == 1.0
        assert feats["is_external_ip"] == 1.0  # public IP
        assert feats["is_night_time"] == 1.0  # 23:15
        assert feats["target_port"] == 22.0


class TestSystemFeatureExtractor:
    def test_extract_process_features(self):
        event = SecurityEvent(
            timestamp=datetime(2026, 10, 31, 3, 0, tzinfo=timezone.utc),
            source=LogSource.WINDOWS_EVENT,
            event_type="windows_process_creation",
            action=EventAction.SUCCESS,
            user=UserEntity(username="svc_account", privilege_level="Administrator"),
            process=ProcessEntity(
                process_name="powershell.exe",
                process_path="C:\\Windows\\System32\\powershell.exe",
                command_line="powershell.exe -ExecutionPolicy Bypass -enc AAAA...",
                parent_process_name="w3wp.exe",  # IIS web server spawning powershell!
            ),
            metadata={"event_id": 4688},
            raw_log="sample proc raw",
        )
        feats = SystemFeatureExtractor.extract_features(event)

        assert set(feats.keys()) == set(SYSTEM_FEATURE_NAMES)
        assert feats["event_id_code"] == 4688.0
        assert feats["is_shell_process"] == 1.0
        assert feats["has_obfuscation_keywords"] == 1.0
        assert feats["is_privilege_escalation"] == 1.0
        assert feats["has_suspicious_parent"] == 1.0  # w3wp.exe -> powershell
        assert feats["cmd_entropy"] > 0.0
        assert feats["path_depth"] == 3.0

