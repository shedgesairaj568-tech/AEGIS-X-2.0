"""
Comprehensive unit and behavioral tests for the AEGIS-X 2.0 CorrelationEngine.
"""

from datetime import datetime, timedelta, timezone
import pytest

from ai_engine.correlation.correlation_engine import AttackStage, CorrelationEngine


def test_isolated_event_correlation():
    """An alert with no matching candidate events remains isolated."""
    engine = CorrelationEngine(time_window_seconds=3600)
    now = datetime.now(timezone.utc)

    focal = {
        "id": "alert-001",
        "attack_type": "port_scan",
        "source_ip": "198.51.100.5",
        "destination_ip": "10.0.0.15",
        "detected_at": now.isoformat(),
        "severity": "low",
        "title": "Port Scan Detected",
    }

    incident = engine.correlate(focal, candidate_events=[])

    assert incident.correlated_event_count == 0
    assert not incident.is_multi_stage_attack
    assert incident.confidence_score == 0.50
    assert "Isolated" in incident.evidence_summary
    assert len(incident.timeline) == 1
    assert incident.timeline[0].is_focal_event


def test_shared_entity_correlation_and_timeline():
    """Events sharing external adversary IP are correlated and ordered chronologically."""
    engine = CorrelationEngine(time_window_seconds=3600)
    base_time = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

    focal = {
        "id": "alert-002",
        "attack_type": "brute_force",
        "source_ip": "203.0.113.88",
        "destination_ip": "10.0.1.50",
        "username": "admin",
        "detected_at": (base_time + timedelta(minutes=15)).isoformat(),
        "severity": "high",
        "title": "SSH Brute Force",
    }

    candidates = [
        # Earlier event with same source IP (port scan)
        {
            "id": "cand-001",
            "attack_type": "port_scan",
            "source_ip": "203.0.113.88",
            "destination_ip": "10.0.1.50",
            "detected_at": base_time.isoformat(),
            "severity": "low",
            "title": "Initial Port Scan",
        },
        # Unrelated event from different IP
        {
            "id": "cand-002",
            "attack_type": "web_attack",
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.2.99",
            "detected_at": (base_time + timedelta(minutes=5)).isoformat(),
            "severity": "medium",
            "title": "Unrelated Web Attack",
        },
    ]

    incident = engine.correlate(focal, candidates)

    assert incident.correlated_event_count == 1
    assert incident.primary_attacker_ip == "203.0.113.88"
    assert "admin" in incident.targeted_users
    assert len(incident.timeline) == 2
    # Verify strict chronological order
    assert incident.timeline[0].event_id == "cand-001"
    assert incident.timeline[1].event_id == "alert-002"
    assert incident.timeline[1].is_focal_event


def test_time_window_boundary_exclusion():
    """Candidate events outside the sliding time window are excluded."""
    engine = CorrelationEngine(time_window_seconds=1800)  # 30 min window
    focal_time = datetime(2026, 10, 31, 14, 0, 0, tzinfo=timezone.utc)

    focal = {
        "id": "alert-focal",
        "attack_type": "ddos",
        "source_ip": "198.51.100.99",
        "detected_at": focal_time.isoformat(),
        "severity": "high",
    }

    candidates = [
        # 45 minutes prior -> outside 30 min window
        {
            "id": "old-event",
            "attack_type": "ddos",
            "source_ip": "198.51.100.99",
            "detected_at": (focal_time - timedelta(minutes=45)).isoformat(),
            "severity": "medium",
        },
        # 10 minutes prior -> inside window
        {
            "id": "recent-event",
            "attack_type": "ddos",
            "source_ip": "198.51.100.99",
            "detected_at": (focal_time - timedelta(minutes=10)).isoformat(),
            "severity": "high",
        },
    ]

    incident = engine.correlate(focal, candidates)
    assert incident.correlated_event_count == 1
    assert incident.timeline[0].event_id == "recent-event"


def test_brute_force_burst_pattern_detection():
    """Burst of 5+ authentication failures triggers burst pattern flag."""
    engine = CorrelationEngine(brute_force_failure_threshold=4)
    base_time = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc)

    focal = {
        "id": "focal-auth-fail",
        "attack_type": "brute_force",
        "username": "root",
        "source_ip": "198.51.100.22",
        "description": "Failed password for root",
        "detected_at": (base_time + timedelta(minutes=3)).isoformat(),
        "severity": "high",
    }

    candidates = [
        {
            "id": f"fail-{i}",
            "attack_type": "brute_force",
            "username": "root",
            "source_ip": "198.51.100.22",
            "description": f"Failed password attempt {i}",
            "detected_at": (base_time + timedelta(seconds=i * 20)).isoformat(),
            "severity": "medium",
        }
        for i in range(4)
    ]

    incident = engine.correlate(focal, candidates)
    assert incident.correlated_event_count == 4
    assert any("burst threshold met" in reason for reason in incident.correlation_reasons)


def test_multi_stage_attack_chain_detection():
    """Detects progression through kill-chain stages (Recon -> Credential Access -> Privilege Escalation)."""
    engine = CorrelationEngine(time_window_seconds=7200)
    t0 = datetime(2026, 10, 31, 8, 0, 0, tzinfo=timezone.utc)

    # Focal alert: Sudo unauthorized (Privilege Escalation)
    focal = {
        "id": "alert-privesc",
        "attack_type": "sudo_unauthorized",
        "username": "service_account",
        "hostname": "prod-app-01",
        "detected_at": (t0 + timedelta(minutes=40)).isoformat(),
        "severity": "critical",
        "title": "Unauthorized Sudo Execution",
    }

    candidates = [
        # Stage 1: Port scan (Reconnaissance) targeting the same host
        {
            "id": "stage1-scan",
            "attack_type": "port_scan",
            "hostname": "prod-app-01",
            "detected_at": t0.isoformat(),
            "severity": "low",
            "title": "Port Scan",
        },
        # Stage 2: Brute force (Credential Access) against the same account
        {
            "id": "stage2-auth",
            "attack_type": "brute_force",
            "username": "service_account",
            "hostname": "prod-app-01",
            "detected_at": (t0 + timedelta(minutes=15)).isoformat(),
            "severity": "high",
            "title": "SSH Password Guessing",
        },
    ]

    incident = engine.correlate(focal, candidates)

    assert incident.correlated_event_count == 2
    assert incident.is_multi_stage_attack is True
    assert AttackStage.RECONNAISSANCE in incident.stages_detected
    assert AttackStage.CREDENTIAL_ACCESS in incident.stages_detected
    assert AttackStage.PRIVILEGE_ESCALATION in incident.stages_detected
    assert "sustained" in incident.evidence_summary.lower() or "campaign" in incident.evidence_summary.lower()


def test_prevention_of_false_fusion():
    """Strictly prevents fusing unrelated security alerts that share no entity."""
    engine = CorrelationEngine(time_window_seconds=3600)
    now = datetime.now(timezone.utc)

    focal = {
        "id": "focal-sql",
        "attack_type": "sql_injection",
        "source_ip": "198.51.100.11",
        "destination_ip": "10.0.0.8",
        "detected_at": now.isoformat(),
        "severity": "high",
    }

    # Different attack, different IP, different destination, different host, different user
    candidates = [
        {
            "id": "unrelated-vpn",
            "attack_type": "vpn_failure",
            "source_ip": "203.0.113.99",
            "destination_ip": "10.0.5.50",
            "username": "marketing_user",
            "detected_at": (now - timedelta(minutes=5)).isoformat(),
            "severity": "low",
        }
    ]

    incident = engine.correlate(focal, candidates)
    assert incident.correlated_event_count == 0
    assert not incident.is_multi_stage_attack

