"""
Comprehensive Unit Tests for AEGIS-X 2.0 Ingestion Parsers & SecurityEvent Schema.
"""

from datetime import datetime, timezone
import json
import pytest

from ai_engine.ingestion.log_loader import MultiSourceLogLoader
from ai_engine.ingestion.schemas import (
    EventAction,
    EventSeverity,
    LogSource,
    SecurityEvent,
)
from ai_engine.ingestion.parsers.firewall_parser import FirewallParser
from ai_engine.ingestion.parsers.vpn_parser import VpnParser
from ai_engine.ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ai_engine.ingestion.parsers.windows_event_parser import WindowsEventParser


class TestSecurityEventSchema:
    def test_security_event_defaults(self):
        event = SecurityEvent(
            source=LogSource.NETWORK_FLOW,
            event_type="test_flow",
            raw_log="test raw log line",
        )
        assert event.event_id is not None
        assert isinstance(event.timestamp, datetime)
        assert event.severity == EventSeverity.INFO
        assert event.action == EventAction.UNKNOWN
        assert event.network.source_ip is None

    def test_timestamp_normalization(self):
        # ISO string
        event1 = SecurityEvent(
            timestamp="2026-10-31T12:00:00Z",
            source=LogSource.FIREWALL,
            event_type="fw_test",
            raw_log="raw",
        )
        assert event1.timestamp.tzinfo == timezone.utc
        assert event1.timestamp.year == 2026

        # Epoch float
        event2 = SecurityEvent(
            timestamp=1700000000.0,
            source=LogSource.FIREWALL,
            event_type="fw_test",
            raw_log="raw",
        )
        assert event2.timestamp.tzinfo == timezone.utc


class TestFirewallParser:
    def test_parse_cisco_asa_deny(self):
        line = '%ASA-4-106023: Deny tcp src outside:198.51.100.15/44321 dst inside:10.0.0.5/80 by access-group "acl_in"'
        ev = FirewallParser.parse_line(line)
        assert ev is not None
        assert ev.source == LogSource.FIREWALL
        assert ev.event_type == "firewall_deny"
        assert ev.action == EventAction.BLOCK
        assert ev.network.source_ip == "198.51.100.15"
        assert ev.network.source_port == 44321
        assert ev.network.destination_ip == "10.0.0.5"
        assert ev.network.destination_port == 80
        assert ev.network.protocol == "TCP"
        assert ev.metadata["vendor"] == "cisco_asa"

    def test_parse_cisco_asa_built(self):
        line = "%ASA-6-302013: Built inbound TCP connection 12345 for outside:203.0.113.10/54321 to inside:10.0.0.10/443"
        ev = FirewallParser.parse_line(line)
        assert ev is not None
        assert ev.action == EventAction.ALLOW
        assert ev.network.source_ip == "203.0.113.10"
        assert ev.network.destination_port == 443

    def test_parse_iptables_drop(self):
        line = "iptables-DROP: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.50 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=49152 DPT=22"
        ev = FirewallParser.parse_line(line)
        assert ev is not None
        assert ev.action == EventAction.DROP
        assert ev.severity == EventSeverity.MEDIUM
        assert ev.network.source_ip == "192.168.1.50"
        assert ev.network.destination_port == 22

    def test_parse_key_value_firewall(self):
        line = "action=block proto=udp src=198.51.100.99 dst=10.0.0.8 spt=61234 dpt=53 bytes_out=120 bytes_in=0"
        ev = FirewallParser.parse_line(line)
        assert ev is not None
        assert ev.action == EventAction.BLOCK
        assert ev.network.protocol == "UDP"
        assert ev.network.bytes_sent == 120

    def test_parse_malformed_firewall_line(self):
        assert FirewallParser.parse_line("") is None
        assert FirewallParser.parse_line("   \n") is None
        ev = FirewallParser.parse_line("GARBAGE TEXT WITHOUT ANY FIREWALL SYNTAX")
        assert ev is not None
        assert ev.source == LogSource.FIREWALL
        assert ev.action == EventAction.UNKNOWN


class TestVpnParser:
    def test_parse_openvpn_auth_failure(self):
        line = "openvpn[4521]: 203.0.113.88:41235 TLS Auth Error: Auth Username/Password verification failed for peer"
        ev = VpnParser.parse_line(line)
        assert ev is not None
        assert ev.source == LogSource.VPN
        assert ev.event_type == "vpn_auth_failure"
        assert ev.action == EventAction.FAILURE
        assert ev.severity == EventSeverity.HIGH
        assert ev.network.source_ip == "203.0.113.88"
        assert ev.network.source_port == 41235

    def test_parse_openvpn_ip_assignment(self):
        line = "openvpn[4521]: alice/198.51.100.25:52310 MULTI_sva: pool returned IPv4=10.8.0.6, IPv6=(Not enabled)"
        ev = VpnParser.parse_line(line)
        assert ev is not None
        assert ev.event_type == "vpn_session_start"
        assert ev.action == EventAction.SUCCESS
        assert ev.user.username == "alice"
        assert ev.network.destination_ip == "10.8.0.6"

    def test_parse_wireguard_handshake(self):
        line = "wireguard: wg0: Handshake for peer 1 (198.51.100.30:51820) did not complete after 5 seconds, retrying..."
        ev = VpnParser.parse_line(line)
        assert ev is not None
        assert ev.event_type == "wireguard_handshake_timeout"
        assert ev.action == EventAction.FAILURE
        assert ev.network.source_ip == "198.51.100.30"


class TestLinuxAuthParser:
    def test_parse_ssh_failed_password(self):
        line = "Oct 31 10:14:22 web-srv-01 sshd[14205]: Failed password for invalid user admin from 198.51.100.88 port 48123 ssh2"
        ev = LinuxAuthParser.parse_line(line)
        assert ev is not None
        assert ev.source == LogSource.LINUX_AUTH
        assert ev.event_type == "ssh_login_failure"
        assert ev.action == EventAction.FAILURE
        assert ev.severity == EventSeverity.HIGH
        assert ev.user.username == "admin"
        assert ev.network.source_ip == "198.51.100.88"
        assert ev.network.source_port == 48123
        assert ev.metadata["invalid_user"] is True
        assert ev.host.hostname == "web-srv-01"

    def test_parse_ssh_accepted(self):
        line = "Oct 31 10:15:00 web-srv-01 sshd[14210]: Accepted publickey for sarah from 192.168.1.10 port 52140 ssh2"
        ev = LinuxAuthParser.parse_line(line)
        assert ev is not None
        assert ev.event_type == "ssh_login_success"
        assert ev.action == EventAction.SUCCESS
        assert ev.user.username == "sarah"
        assert ev.user.auth_method == "publickey"

    def test_parse_sudo_command(self):
        line = "Oct 31 10:16:01 web-srv-01 sudo:   analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow"
        ev = LinuxAuthParser.parse_line(line)
        assert ev is not None
        assert ev.event_type == "sudo_command_execution"
        assert ev.user.username == "analyst"
        assert ev.user.privilege_level == "root"
        assert "/etc/shadow" in ev.process.command_line
        assert ev.severity == EventSeverity.HIGH  # suspicious shadow access

    def test_parse_sudo_unauthorized(self):
        line = "Oct 31 10:16:15 web-srv-01 sudo:   intruder : user NOT in sudoers ; TTY=pts/2"
        ev = LinuxAuthParser.parse_line(line)
        assert ev is not None
        assert ev.event_type == "sudo_unauthorized_attempt"
        assert ev.severity == EventSeverity.HIGH


class TestWindowsEventParser:
    def test_parse_event_4624_success(self):
        rec = {
            "EventID": 4624,
            "TimeCreated": "2026-10-31T10:20:00Z",
            "Computer": "DC01.corp.internal",
            "EventData": {
                "TargetUserName": "Administrator",
                "LogonType": "10",
                "IpAddress": "198.51.100.44",
                "IpPort": "54120",
            },
        }
        ev = WindowsEventParser.parse_record(rec)
        assert ev is not None
        assert ev.source == LogSource.WINDOWS_EVENT
        assert ev.event_type == "windows_logon_success"
        assert ev.action == EventAction.SUCCESS
        assert ev.user.username == "Administrator"
        assert "RDP" in ev.user.auth_method
        assert ev.network.source_ip == "198.51.100.44"

    def test_parse_event_4625_failure(self):
        rec = {
            "EventID": 4625,
            "TimeCreated": "2026-10-31T10:21:15Z",
            "Computer": "DC01.corp.internal",
            "EventData": {
                "TargetUserName": "finance_user",
                "SubStatus": "0xC000006A",
                "IpAddress": "203.0.113.99",
            },
        }
        ev = WindowsEventParser.parse_record(rec)
        assert ev is not None
        assert ev.event_type == "windows_logon_failure"
        assert ev.action == EventAction.FAILURE
        assert ev.metadata["failure_reason"] == "User name correct, password incorrect"

    def test_parse_event_4688_powershell_encoded(self):
        rec = {
            "EventID": 4688,
            "EventData": {
                "SubjectUserName": "jsmith",
                "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -enc JABzACAAPQ...",
                "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            },
        }
        ev = WindowsEventParser.parse_record(rec)
        assert ev is not None
        assert ev.event_type == "windows_process_creation"
        assert ev.severity == EventSeverity.CRITICAL
        assert ev.process.process_name == "powershell.exe"
        assert ev.process.parent_process_name == "cmd.exe"

    def test_parse_windows_raw_string_and_invalid(self):
        assert WindowsEventParser.parse_record("") is None
        ev = WindowsEventParser.parse_record("EventID: 4624 User: alice IpAddress: 10.0.0.5")
        assert ev is not None
        assert ev.metadata["event_id"] == 4624
        assert ev.user.username == "alice"


class TestMultiSourceLogLoader:
    def test_load_sample_firewall_file(self):
        loader = MultiSourceLogLoader()
        events = loader.parse_file("datasets/sample_logs/firewall_sample.log")
        assert len(events) >= 6
        assert any(e.event_type == "firewall_deny" for e in events)
        assert any(e.event_type == "iptables_drop" for e in events)

    def test_load_sample_vpn_file(self):
        loader = MultiSourceLogLoader()
        events = loader.parse_file("datasets/sample_logs/vpn_sample.log")
        assert len(events) >= 5
        assert any(e.event_type == "vpn_auth_failure" for e in events)
        assert any(e.event_type == "vpn_session_start" for e in events)

    def test_load_sample_linux_auth_file(self):
        loader = MultiSourceLogLoader()
        events = loader.parse_file("datasets/sample_logs/linux_auth_sample.log")
        assert len(events) >= 6
        assert any(e.event_type == "ssh_login_failure" for e in events)
        assert any(e.event_type == "sudo_command_execution" for e in events)

    def test_load_sample_windows_events_file(self):
        loader = MultiSourceLogLoader()
        events = loader.parse_file("datasets/sample_logs/windows_events_sample.json")
        assert len(events) == 5
        assert any(e.event_type == "windows_logon_success" for e in events)
        assert any(e.event_type == "windows_logon_failure" for e in events)
        assert any(e.event_type == "windows_process_creation" for e in events)

    def test_event_deduplication(self):
        loader = MultiSourceLogLoader(enable_dedup=True)
        line = '%ASA-4-106023: Deny tcp src outside:198.51.100.15/44321 dst inside:10.0.0.5/80 by access-group "acl_in"'
        ev1 = FirewallParser.parse_line(line)
        ev2 = FirewallParser.parse_line(line)
        assert loader._is_new_event(ev1) is True
        assert loader._is_new_event(ev2) is False

