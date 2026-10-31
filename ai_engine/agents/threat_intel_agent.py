"""
Agent 2 — Threat Intelligence Agent for AEGIS-X 2.0.

Responsibilities:
- Map detected threat behaviors to formal MITRE ATT&CK Tactics, Techniques, and Sub-techniques.
- Identify known adversarial attack patterns based on telemetry signals.
- Provide calibrated confidence scores with concrete evidence justifications.
- STRICT ETHICAL/SECURITY GUARD: Prevent ungrounded or speculative threat actor attribution.
  Clearly delineate observed adversary TTPs from nation-state or group attribution unless
  authenticated threat intel feeds substantiate the link.
"""

from dataclasses import dataclass
from typing import Any

from ai_engine.inference.mitre_mapping import get_mitre_mapping
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


# Enriched MITRE ATT&CK Knowledge Base for Threat Intelligence Context
TACTIC_CATALOG: dict[str, dict[str, Any]] = {
    "brute_force": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "sub_technique": "T1110.001 - Password Guessing",
        "pattern": "Systematic credential guessing targeting authentication endpoints (SSH, RDP, Web).",
        "common_actors": ["APT28", "FIN7", "Volt Typhoon"],
        "telemetry_indicators": ["Repeated EventID 4625", "SSH Failed Password bursts", "High failure/success ratio"],
    },
    "port_scan": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "sub_technique": "T1046 - Port Scanning",
        "pattern": "High-volume sequential or SYN-sweep probes across common service ports.",
        "common_actors": ["Various Threat Actors", "Automated Scanners (Shodan, Censys)"],
        "telemetry_indicators": ["SYN-ACK drops on firewall", "Short-lived TCP connections", "Low byte-to-packet ratio"],
    },
    "ddos": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "sub_technique": "T1498.001 - Direct Network Flood",
        "pattern": "High-bandwidth volumetric packet flooding intended to exhaust network or service capacity.",
        "common_actors": ["DDoS-for-Hire Services", "Mirai Botnet Variants", "Killnet"],
        "telemetry_indicators": ["Abnormal flow packets/sec", "Symmetric high forward packet rate", "Interface saturation"],
    },
    "botnet": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "sub_technique": "T1071.001 - Web Protocols",
        "pattern": "Periodic beaconing and external command execution via standardized web channels.",
        "common_actors": ["Emotet", "Qakbot", "Cobalt Strike Operators"],
        "telemetry_indicators": ["Periodic beacon interval", "Known malicious external IP", "Uncommon user-agent strings"],
    },
    "web_attack": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "sub_technique": "T1190 - Web Application Exploitation",
        "pattern": "Path traversal, remote code execution payloads, or header tampering targeting HTTP services.",
        "common_actors": ["Opportunistic Web Exploiters", "Lazarus Group", "FIN8"],
        "telemetry_indicators": ["HTTP 4xx/5xx error clusters", "Suspicious URI query parameters", "Encoded command strings"],
    },
    "sql_injection": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "sub_technique": "T1190 - SQL Injection",
        "pattern": "Input manipulation designed to alter backend database queries and extract sensitive schemas.",
        "common_actors": ["Database Scrapers", "Initial Access Brokers"],
        "telemetry_indicators": ["SQL syntax keywords in URI/POST", "Abnormal database error rates", "High response payload size"],
    },
    "sudo_unauthorized": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "sub_technique": "T1548.003 - Sudo and Sudo Caching",
        "pattern": "Unauthorized execution attempts of privileged binaries by non-wheel/sudoers accounts.",
        "common_actors": ["Local Attackers", "Post-Compromise Operators"],
        "telemetry_indicators": ["PAM audit failure", "Sudoers security log entry", "Terminal command failure"],
    },
    "powershell_obfuscated": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "sub_technique": "T1059.001 - PowerShell",
        "pattern": "Execution of encoded, hidden, or non-interactive PowerShell commands.",
        "common_actors": ["BlackCat / ALPHV", "MuddyWater", "LockBit"],
        "telemetry_indicators": ["Windows EventID 4688", "-EncodedCommand flag", "High entropy command arguments"],
    },
}


class ThreatIntelAgent:
    """
    Synthesizes actionable threat intelligence and maps observed behaviors to ATT&CK tactics.
    """

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        detection = state.get("detection", {})
        investigation = state.get("investigation", {})

        attack_type = detection.get("attack_type", "normal")
        confidence = float(detection.get("confidence", 0.0))
        risk_score = float(detection.get("risk_score", 0.0))
        is_anomaly = bool(detection.get("is_anomaly", False))

        intel_record = self._resolve_threat_intel(attack_type, is_anomaly, confidence, risk_score, investigation)

        logger.info(
            "ThreatIntelAgent: Mapped %s to MITRE Tactic=%s, Technique=%s (Confidence=%.2f)",
            attack_type,
            intel_record["mitre_tactic_name"],
            intel_record["mitre_technique_id"],
            intel_record["confidence"],
        )

        return {"threat_intel": intel_record}

    def _resolve_threat_intel(
        self,
        attack_type: str,
        is_anomaly: bool,
        confidence: float,
        risk_score: float,
        investigation: dict[str, Any],
    ) -> dict[str, Any]:
        catalog_entry = TACTIC_CATALOG.get(attack_type)

        if catalog_entry:
            tactic_id = catalog_entry["tactic_id"]
            tactic_name = catalog_entry["tactic_name"]
            tech_id = catalog_entry["technique_id"]
            tech_name = catalog_entry["technique_name"]
            sub_tech = catalog_entry["sub_technique"]
            pattern = catalog_entry["pattern"]
            actors = catalog_entry["common_actors"]
            indicators = catalog_entry["telemetry_indicators"]
            intel_conf = round(min(confidence * 0.70 + (risk_score / 100.0) * 0.30, 0.98), 2)
        elif is_anomaly:
            # Unclassified anomaly / potential zero-day or novelty
            tactic_id = "TA0043"
            tactic_name = "Defense Evasion / Anomaly"
            tech_id = "T1027"
            tech_name = "Obfuscated / Anomalous Traffic"
            sub_tech = "T1027 - Anomalous Telemetry"
            pattern = "Observed anomalous telemetry deviates significantly from baseline traffic models but does not match known attack signatures."
            actors = ["Unattributed Threat Entity"]
            indicators = ["High Autoencoder Reconstruction Error", "Isolation Forest Tree Anomaly"]
            intel_conf = round(min(risk_score / 100.0, 0.85), 2)
        else:
            # Normal or unclassified benign traffic
            return {
                "mitre_tactic_id": None,
                "mitre_tactic_name": None,
                "mitre_technique_id": None,
                "mitre_technique_name": None,
                "sub_technique": None,
                "attack_pattern": "Benign / Baseline operational activity.",
                "confidence": 0.0,
                "attribution_statement": "No malicious indicators detected.",
                "known_associated_actors": [],
                "telemetry_indicators": [],
                "threat_intel_summary": "Traffic conforms to normal organizational baseline parameters.",
            }

        # Attribution Guard: Strictly prevent unsubstantiated attribution
        attribution_stmt = (
            f"Adversary activity conforms to TTPs documented in {tech_id} ({tech_name}). "
            f"While actors such as {', '.join(actors[:2])} frequently utilize these techniques, "
            f"specific threat group attribution is NOT supported by local telemetry alone. "
            f"Activity is classified as un-attributed opportunistic or adversary-controlled probing."
        )

        timeline = investigation.get("timeline", [])
        is_campaign = investigation.get("is_multi_stage_attack", False) or len(timeline) >= 3

        summary = (
            f"Observed telemetry maps to MITRE ATT&CK tactic '{tactic_name}' [{tactic_id}], "
            f"specifically technique '{tech_name}' [{tech_id}]. {pattern} "
            f"Pattern confidence: {int(intel_conf * 100)}%. "
            + ("Part of a multi-stage intrusion sequence." if is_campaign else "Current indicators reflect a discrete activity cluster.")
        )

        return {
            "mitre_tactic_id": tactic_id,
            "mitre_tactic_name": tactic_name,
            "mitre_technique_id": tech_id,
            "mitre_technique_name": tech_name,
            "sub_technique": sub_tech,
            "attack_pattern": pattern,
            "confidence": intel_conf,
            "attribution_statement": attribution_stmt,
            "known_associated_actors": actors,
            "telemetry_indicators": indicators,
            "threat_intel_summary": summary,
        }
