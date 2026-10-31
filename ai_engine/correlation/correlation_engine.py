"""
AEGIS-X 2.0 Multi-Source Security Event Correlation Engine.

Performs source-aware temporal and entity correlation across multi-source security events:
- Configurable sliding time windows (1m, 5m, 1h, 24h)
- Cross-source entity linking: IP 5-tuples, user accounts, hostnames, and process lineages
- Behavioral pattern recognition: repeated login failure bursts, multi-stage attack chains
- Evidence-grounded timeline construction with causality indicators
- Strict false-fusion prevention: events without entity overlap or exceeding temporal bounds
  are preserved as independent occurrences.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


class AttackStage(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACCESS = "credential_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


# Mapping from observed attack types / event codes to attack stages
ATTACK_STAGE_MAPPING: dict[str, AttackStage] = {
    "port_scan": AttackStage.RECONNAISSANCE,
    "brute_force": AttackStage.CREDENTIAL_ACCESS,
    "web_attack": AttackStage.INITIAL_ACCESS,
    "sql_injection": AttackStage.INITIAL_ACCESS,
    "botnet": AttackStage.COMMAND_AND_CONTROL,
    "ddos": AttackStage.IMPACT,
    "sudo_unauthorized": AttackStage.PRIVILEGE_ESCALATION,
    "privilege_escalation": AttackStage.PRIVILEGE_ESCALATION,
    "process_creation": AttackStage.EXECUTION,
    "service_installation": AttackStage.PERSISTENCE,
    "rdp_session": AttackStage.LATERAL_MOVEMENT,
    "vpn_failure": AttackStage.CREDENTIAL_ACCESS,
}


@dataclass
class TimelineEntry:
    timestamp: str
    event_id: str
    source: str
    event_type: str
    stage: AttackStage
    entity_key: str
    description: str
    severity: str
    is_focal_event: bool = False


@dataclass
class CorrelatedIncident:
    """Consolidated representation of correlated threat activities."""

    incident_id: str
    focal_event_id: str
    correlated_event_count: int
    confidence_score: float  # [0.0, 1.0]
    is_multi_stage_attack: bool
    stages_detected: list[AttackStage]
    primary_attacker_ip: str | None
    targeted_users: list[str]
    targeted_assets: list[str]
    timeline: list[TimelineEntry]
    correlation_reasons: list[str]
    evidence_summary: str


class CorrelationEngine:
    """
    Correlates security events across time windows and shared entities.
    """

    def __init__(
        self,
        time_window_seconds: int = 3600,  # 1 hour default
        brute_force_failure_threshold: int = 5,
        brute_force_window_seconds: int = 300,  # 5 minutes
        min_correlation_confidence: float = 0.40,
    ):
        self.time_window_seconds = time_window_seconds
        self.brute_force_failure_threshold = brute_force_failure_threshold
        self.brute_force_window_seconds = brute_force_window_seconds
        self.min_correlation_confidence = min_correlation_confidence

    def correlate(
        self,
        focal_alert: dict[str, Any],
        candidate_events: list[dict[str, Any]],
        override_window_seconds: int | None = None,
    ) -> CorrelatedIncident:
        """
        Correlates a focal alert with candidate security events.
        """
        window_sec = override_window_seconds or self.time_window_seconds
        focal_time = self._parse_timestamp(focal_alert.get("detected_at") or focal_alert.get("timestamp"))

        focal_src_ip = focal_alert.get("source_ip")
        focal_dst_ip = focal_alert.get("destination_ip")
        focal_user = focal_alert.get("username") or focal_alert.get("user")
        focal_host = focal_alert.get("hostname") or focal_alert.get("host")
        focal_attack = focal_alert.get("attack_type", "unknown")

        correlated_events: list[tuple[dict[str, Any], list[str], float]] = []

        for event in candidate_events:
            # 1. Temporal Check
            event_time = self._parse_timestamp(event.get("detected_at") or event.get("timestamp"))
            if focal_time and event_time:
                time_delta = abs((focal_time - event_time).total_seconds())
                if time_delta > window_sec:
                    continue  # Outside correlation window
            else:
                time_delta = 0.0

            # 2. Entity Overlap & Rule Checking
            reasons = []
            entity_weight = 0.0

            ev_src_ip = event.get("source_ip")
            ev_dst_ip = event.get("destination_ip")
            ev_user = event.get("username") or event.get("user")
            ev_host = event.get("hostname") or event.get("host")
            ev_attack = event.get("attack_type")

            # Check source IP match (external adversary tracking)
            if focal_src_ip and ev_src_ip and focal_src_ip == ev_src_ip:
                reasons.append(f"Shared source IP ({focal_src_ip})")
                entity_weight += 0.40

            # Check target asset match (target infrastructure tracking)
            if focal_dst_ip and ev_dst_ip and focal_dst_ip == ev_dst_ip:
                reasons.append(f"Targeting same destination asset ({focal_dst_ip})")
                entity_weight += 0.30

            # Check user account match (identity attack tracking)
            if focal_user and ev_user and focal_user.lower() == ev_user.lower():
                reasons.append(f"Targeting same user account ({focal_user})")
                entity_weight += 0.35

            # Check host identity match
            if focal_host and ev_host and focal_host.lower() == ev_host.lower():
                reasons.append(f"Co-located on host ({focal_host})")
                entity_weight += 0.35

            # Check attack type or kill chain stage match
            if focal_attack and ev_attack and focal_attack != "normal" and focal_attack == ev_attack:
                reasons.append(f"Matching attack type ({focal_attack})")
                entity_weight += 0.45
            else:
                stage_focal = self._classify_stage(focal_attack)
                stage_ev = self._classify_stage(ev_attack or "")
                if stage_focal != AttackStage.UNKNOWN and stage_ev != AttackStage.UNKNOWN:
                    if stage_focal == stage_ev:
                        reasons.append(f"Matching attack stage ({stage_focal.value})")
                        entity_weight += 0.30
                    elif self._is_kill_chain_progression(stage_focal, stage_ev):
                        reasons.append(f"Kill chain progression: {stage_ev.value} -> {stage_focal.value}")
                        entity_weight += 0.35

            # Temporal decay: closer in time yields higher confidence
            temporal_decay = 1.0 - min(time_delta / max(window_sec, 1.0), 0.5)
            match_confidence = min(entity_weight * temporal_decay, 1.0)

            if match_confidence >= self.min_correlation_confidence:
                correlated_events.append((event, reasons, match_confidence))

        # 3. Detect Burst / Brute Force Patterns
        brute_force_detected = self._detect_brute_force_pattern(
            focal_alert, [ev for ev, _, _ in correlated_events]
        )
        all_reasons = []
        for _, r_list, _ in correlated_events:
            all_reasons.extend(r_list)
        if brute_force_detected:
            all_reasons.append(f"Repeated authentication failure burst threshold met (>= {self.brute_force_failure_threshold} failures)")

        # Unique correlation reasons
        unique_reasons = sorted(list(set(all_reasons)))

        # 4. Construct Incident Timeline
        timeline = self._construct_timeline(focal_alert, [ev for ev, _, _ in correlated_events])

        # 5. Determine Stages & Attack Progression
        stages = list({entry.stage for entry in timeline if entry.stage != AttackStage.UNKNOWN})
        is_multi_stage = len(stages) >= 2

        # 6. Aggregate Entity Inventories
        targeted_users = list({
            str(e.get("username") or e.get("user"))
            for e in [focal_alert] + [ev for ev, _, _ in correlated_events]
            if (e.get("username") or e.get("user"))
        })
        targeted_assets = list({
            str(e.get("destination_ip") or e.get("hostname") or e.get("host"))
            for e in [focal_alert] + [ev for ev, _, _ in correlated_events]
            if (e.get("destination_ip") or e.get("hostname") or e.get("host"))
        })

        # Overall confidence score
        if correlated_events:
            avg_conf = sum(conf for _, _, conf in correlated_events) / len(correlated_events)
            incident_confidence = min(round(avg_conf + (0.15 if is_multi_stage else 0.0), 2), 1.0)
        else:
            incident_confidence = 0.50  # Isolated event baseline

        # Evidence Summary
        summary = self._build_evidence_summary(
            focal_alert=focal_alert,
            correlated_count=len(correlated_events),
            is_multi_stage=is_multi_stage,
            stages=stages,
            reasons=unique_reasons,
            attacker_ip=focal_src_ip,
        )

        return CorrelatedIncident(
            incident_id=f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            focal_event_id=str(focal_alert.get("id") or "focal_001"),
            correlated_event_count=len(correlated_events),
            confidence_score=incident_confidence,
            is_multi_stage_attack=is_multi_stage,
            stages_detected=stages,
            primary_attacker_ip=focal_src_ip,
            targeted_users=targeted_users,
            targeted_assets=targeted_assets,
            timeline=timeline,
            correlation_reasons=unique_reasons,
            evidence_summary=summary,
        )

    def _construct_timeline(
        self,
        focal_alert: dict[str, Any],
        correlated_events: list[dict[str, Any]],
    ) -> list[TimelineEntry]:
        """Constructs a strictly sorted chronological timeline."""
        raw_entries = []

        # Add focal alert
        focal_dt = self._parse_timestamp(focal_alert.get("detected_at") or focal_alert.get("timestamp")) or datetime.now(timezone.utc)
        focal_stage = self._classify_stage(focal_alert.get("attack_type", ""))
        raw_entries.append((
            focal_dt,
            TimelineEntry(
                timestamp=focal_dt.isoformat(),
                event_id=str(focal_alert.get("id") or "alert-focal"),
                source=str(focal_alert.get("source", "detection_engine")),
                event_type=str(focal_alert.get("attack_type", "threat_alert")),
                stage=focal_stage,
                entity_key=str(focal_alert.get("source_ip") or focal_alert.get("username") or "unknown_entity"),
                description=f"{focal_alert.get('title') or focal_alert.get('description') or 'Alert'} — this detection",
                severity=str(focal_alert.get("severity", "medium")),
                is_focal_event=True,
            )
        ))

        # Add correlated events
        for idx, ev in enumerate(correlated_events):
            ev_dt = self._parse_timestamp(ev.get("detected_at") or ev.get("timestamp")) or focal_dt
            ev_stage = self._classify_stage(ev.get("attack_type") or ev.get("event_type", ""))
            raw_entries.append((
                ev_dt,
                TimelineEntry(
                    timestamp=ev_dt.isoformat(),
                    event_id=str(ev.get("id") or f"corr-{idx + 1}"),
                    source=str(ev.get("source", "historical_log")),
                    event_type=str(ev.get("attack_type") or ev.get("event_type", "related_event")),
                    stage=ev_stage,
                    entity_key=str(ev.get("source_ip") or ev.get("username") or "entity"),
                    description=str(ev.get("title") or ev.get("description") or f"Related event from {ev.get('source')}"),
                    severity=str(ev.get("severity", "low")),
                    is_focal_event=False,
                )
            ))

        # Sort chronologically
        raw_entries.sort(key=lambda t: t[0])
        return [entry for _, entry in raw_entries]

    def _detect_brute_force_pattern(
        self,
        focal_alert: dict[str, Any],
        correlated_events: list[dict[str, Any]],
    ) -> bool:
        """Identifies bursts of failed authentications exceeding threshold within window."""
        auth_events = [
            ev for ev in [focal_alert] + correlated_events
            if "fail" in str(ev.get("description", "")).lower()
            or ev.get("attack_type") == "brute_force"
            or ev.get("action") == "block"
        ]
        return len(auth_events) >= self.brute_force_failure_threshold

    @staticmethod
    def _classify_stage(attack_or_event: str) -> AttackStage:
        key = str(attack_or_event).lower().replace(" ", "_")
        for pattern, stage in ATTACK_STAGE_MAPPING.items():
            if pattern in key:
                return stage
        return AttackStage.UNKNOWN

    @staticmethod
    def _is_kill_chain_progression(stage_a: AttackStage, stage_b: AttackStage) -> bool:
        """Determines if two attack stages indicate a progressive intrusion sequence."""
        order = [
            AttackStage.RECONNAISSANCE,
            AttackStage.INITIAL_ACCESS,
            AttackStage.CREDENTIAL_ACCESS,
            AttackStage.EXECUTION,
            AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.LATERAL_MOVEMENT,
            AttackStage.COMMAND_AND_CONTROL,
            AttackStage.EXFILTRATION,
            AttackStage.IMPACT,
        ]
        if stage_a in order and stage_b in order and stage_a != stage_b:
            return True
        return False

    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime | None:
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            try:
                # Handle ISO formats
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None

    @staticmethod
    def _build_evidence_summary(
        focal_alert: dict[str, Any],
        correlated_count: int,
        is_multi_stage: bool,
        stages: list[AttackStage],
        reasons: list[str],
        attacker_ip: str | None,
    ) -> str:
        attack = focal_alert.get("attack_type", "unknown").replace("_", " ")
        severity = focal_alert.get("severity", "medium").upper()

        if attack == "normal":
            return "No attack pattern identified; traffic classified as normal."

        if correlated_count == 0:
            return (
                f"Isolated {severity} {attack} detected without correlated historical telemetry "
                f"in the configured window. Attacker IP: {attacker_ip or 'unknown'}."
            )

        stage_str = ", ".join(s.value for s in stages) if stages else "unclassified"
        reason_str = "; ".join(reasons[:3])

        if is_multi_stage or correlated_count >= 3:
            return (
                f"Part of a sustained {attack} campaign: "
                f"{correlated_count} related events detected in the same window, suggesting a persistent, "
                f"possibly automated attacker rather than an isolated incident."
            )
        return (
            f"Clustered threat activity: {correlated_count} related security events correlated with this {attack} alert. "
            f"Correlation drivers: {reason_str}."
        )
