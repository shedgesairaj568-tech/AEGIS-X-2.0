"""
Agent 4 — Response Agent for AEGIS-X 2.0.

Responsibilities:
- Suggest actionable incident containment actions (network, account, endpoint).
- Generate standardized investigation recommendations for SOC tier analysts.
- Synthesize comprehensive incident reports (via LLM or grounded deterministic template).
- Provide concrete remediation and hardening guidance.

CRITICAL SECURITY AND HITL SAFEGUARDS:
- Unrestricted autonomous execution of destructive actions is STRICTLY PROHIBITED.
- Every proposed containment action is instantiated with status="PENDING_APPROVAL".
- Each action specifies:
  - Required authorization role (SOC_ANALYST vs SECURITY_ADMIN)
  - Estimated operational blast radius (LOW, MEDIUM, HIGH)
  - Concrete step-by-step rollback procedures
"""

import uuid
from typing import Any

from ai_engine.agents.llm_client import USE_LLM_FOR_SEVERITIES, LLMClient
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


class ResponseAgent:
    def __init__(self, llm_client: LLMClient | None = None):
        self._llm = llm_client or LLMClient()

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        detection = state.get("detection", {})
        investigation = state.get("investigation", {})
        threat_intel = state.get("threat_intel", {})
        knowledge = state.get("knowledge", {})

        severity = detection.get("severity", "low")
        should_try_llm = self._llm.is_configured and severity in USE_LLM_FOR_SEVERITIES

        report = None
        if should_try_llm:
            report = self._generate_with_llm(detection, investigation, threat_intel, knowledge)

        if report is None:
            report = self._generate_from_template(detection, investigation, threat_intel, knowledge)

        # Generate Human-In-The-Loop Containment Actions
        containment_actions = self._generate_containment_actions(detection, investigation)
        investigation_steps = self._generate_investigation_recommendations(detection, investigation)

        report["containment_actions"] = containment_actions
        report["investigation_steps"] = investigation_steps
        report["human_in_the_loop_required"] = True
        report["containment_status"] = "PENDING_APPROVAL"

        logger.info(
            "ResponseAgent: Report generated via %s with %d pending containment actions.",
            report["generated_by"],
            len(containment_actions),
        )
        return {"response": report}

    def _generate_containment_actions(
        self,
        detection: dict[str, Any],
        investigation: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Synthesizes structured, auditable containment actions requiring human authorization.
        """
        actions = []
        attack_type = detection.get("attack_type", "normal")
        severity = detection.get("severity", "low")
        source_ip = detection.get("source_ip") or investigation.get("primary_attacker_ip")
        raw_event = detection.get("raw_event", {})
        dest_ip = detection.get("destination_ip") or raw_event.get("destination_ip")
        user = raw_event.get("username") or (investigation.get("targeted_users") or [None])[0]

        # 1. External Adversary IP Blocking
        if source_ip and attack_type != "normal" and not self._is_private_ip(source_ip):
            actions.append({
                "action_id": f"ACT-{uuid.uuid4().hex[:8].upper()}",
                "action_type": "BLOCK_IP",
                "target": source_ip,
                "status": "PENDING_APPROVAL",
                "required_role": "SOC_ANALYST",
                "blast_radius": "LOW",
                "description": f"Block inbound traffic from attacker IP {source_ip} at perimeter firewall.",
                "rollback_plan": f"Execute 'iptables -D INPUT -s {source_ip} -j DROP' or remove firewall rule.",
                "approval_required": True,
            })

        # 2. Targeted Account Quarantine (for Brute Force / Credential Theft)
        if user and attack_type in ("brute_force", "sudo_unauthorized") and severity in ("high", "critical"):
            actions.append({
                "action_id": f"ACT-{uuid.uuid4().hex[:8].upper()}",
                "action_type": "DISABLE_USER",
                "target": user,
                "status": "PENDING_APPROVAL",
                "required_role": "SECURITY_ADMIN",
                "blast_radius": "MEDIUM",
                "description": f"Temporarily suspend account '{user}' and invalidate active Kerberos/OAuth sessions.",
                "rollback_plan": f"Re-enable account '{user}' in Identity Provider / Active Directory and issue password reset.",
                "approval_required": True,
            })

        # 3. Endpoint Isolation (for Post-Compromise / Botnet / High Severity)
        if dest_ip and severity in ("high", "critical") and attack_type in ("botnet", "web_attack"):
            actions.append({
                "action_id": f"ACT-{uuid.uuid4().hex[:8].upper()}",
                "action_type": "ISOLATE_HOST",
                "target": dest_ip,
                "status": "PENDING_APPROVAL",
                "required_role": "SECURITY_ADMIN",
                "blast_radius": "HIGH",
                "description": f"Isolate internal asset {dest_ip} from local network segment (allowing SOC management only).",
                "rollback_plan": f"Restore network interface routing and remove containment VLAN for {dest_ip}.",
                "approval_required": True,
            })

        return actions

    @staticmethod
    def _generate_investigation_recommendations(
        detection: dict[str, Any],
        investigation: dict[str, Any],
    ) -> dict[str, list[str]]:
        """Provides concrete triage guidance categorized by operational domain."""
        attack_type = detection.get("attack_type", "normal")

        account_steps = [
            "Query Active Directory / IdP audit logs for concurrent logins from disparate geolocations.",
            "Verify whether MFA was successfully prompted and completed during the session.",
            "Inspect recent credential updates or self-service password resets.",
        ]

        endpoint_steps = [
            "Collect process creation telemetry (Sysmon Event ID 1 / Windows 4688) around the detection window.",
            "Inspect PowerShell ScriptBlock logs (Event ID 4104) for encoded or obfuscated payloads.",
            "Verify persistence locations: scheduled tasks, Windows services, or systemd units.",
        ]

        network_steps = [
            "Query NetFlow/VPC flow logs for abnormal outbound data volume to external IPs.",
            "Inspect DNS resolution history for domain generation algorithms (DGA) or newly registered domains.",
            "Verify firewall perimeter logs for egress connection attempts on non-standard ports.",
        ]

        if attack_type == "port_scan":
            network_steps.insert(0, "Identify all internal destination ports scanned to establish attacker reconnaissance scope.")
        elif attack_type == "brute_force":
            account_steps.insert(0, "Enumerate all accounts targeted from this source IP to assess horizontal password spraying.")

        return {
            "account_investigation": account_steps,
            "endpoint_investigation": endpoint_steps,
            "network_investigation": network_steps,
        }

    # --- LLM Path -------------------------------------------------------------

    def _generate_with_llm(
        self,
        detection: dict[str, Any],
        investigation: dict[str, Any],
        threat_intel: dict[str, Any],
        knowledge: dict[str, Any],
    ) -> dict[str, Any] | None:
        system_prompt = (
            "You are an expert SOC Incident Commander. Given structured detection, "
            "correlation, threat intelligence, and RAG knowledge, compose a rigorous incident report. "
            "Respond with exactly three sections, each on its own line: "
            "'SUMMARY:', 'ROOT_CAUSE:', and 'MITIGATION:'. "
            "Cite relevant MITRE techniques and CVEs when present. Be concise, evidence-based, "
            "and strictly avoid fabricating facts."
        )
        user_prompt = self._build_context_prompt(detection, investigation, threat_intel, knowledge)

        raw_text = self._llm.generate(system_prompt, user_prompt)
        if raw_text is None:
            return None

        parsed = self._parse_llm_sections(raw_text)
        if parsed is None:
            logger.warning("LLM response did not match expected section format; falling back to template.")
            return None

        return {
            "incident_title": detection.get("title", "Security Incident"),
            "summary": parsed["summary"],
            "root_cause": parsed["root_cause"],
            "mitigation": parsed["mitigation"],
            "generated_by": "llm",
        }

    @staticmethod
    def _build_context_prompt(
        detection: dict[str, Any],
        investigation: dict[str, Any],
        threat_intel: dict[str, Any],
        knowledge: dict[str, Any],
    ) -> str:
        lines = [
            f"Attack type: {detection.get('attack_type')}",
            f"Severity: {detection.get('severity')} (Calibrated risk score: {detection.get('risk_score')}/100)",
            f"Anomaly score: {detection.get('anomaly_score')}, Classification confidence: {detection.get('confidence')}",
            f"Detection explanation: {detection.get('explanation')}",
            f"MITRE Tactic: {threat_intel.get('mitre_tactic_name')} [{threat_intel.get('mitre_tactic_id')}]",
            f"MITRE Technique: {threat_intel.get('mitre_technique_name')} [{threat_intel.get('mitre_technique_id')}]",
            f"Pattern description: {threat_intel.get('attack_pattern')}",
            f"Correlated events: {investigation.get('correlated_event_count', 0)}",
            f"Multi-stage campaign: {investigation.get('is_multi_stage_attack', False)}",
            f"Timeline: {'; '.join(investigation.get('timeline', [])[:3])}",
            f"Root cause hypothesis: {investigation.get('root_cause_hypothesis')}",
        ]
        mitre = knowledge.get("mitre_attck", [])
        if mitre:
            lines.append(f"Retrieved MITRE context: {mitre[0].get('text', '')[:300]}")
        policies = knowledge.get("security_policies", [])
        if policies:
            lines.append(f"Retrieved Policy context: {policies[0].get('text', '')[:300]}")

        return "\n".join(lines)

    @staticmethod
    def _parse_llm_sections(text: str) -> dict[str, str] | None:
        sections = {"summary": None, "root_cause": None, "mitigation": None}
        prefix_map = {"SUMMARY:": "summary", "ROOT_CAUSE:": "root_cause", "MITIGATION:": "mitigation"}

        for line in text.splitlines():
            stripped = line.strip()
            for prefix, key in prefix_map.items():
                if stripped.upper().startswith(prefix):
                    sections[key] = stripped[len(prefix):].strip()

        if all(sections.values()):
            return sections
        return None

    # --- Grounded Template Fallback -------------------------------------------

    def _generate_from_template(
        self,
        detection: dict[str, Any],
        investigation: dict[str, Any],
        threat_intel: dict[str, Any],
        knowledge: dict[str, Any],
    ) -> dict[str, Any]:
        attack_type = detection.get("attack_type", "unknown").replace("_", " ")
        severity = detection.get("severity", "low").upper()
        risk_score = detection.get("risk_score", 0)

        # Grounded Summary
        summary = (
            f"A {severity}-severity {attack_type} threat was detected with a calibrated risk score of "
            f"{risk_score}/100. {detection.get('explanation', '')}"
        )

        # Grounded Root Cause
        root_cause = investigation.get(
            "root_cause_hypothesis",
            f"Event detected via multi-model hybrid classification as {attack_type}."
        )
        tech_id = threat_intel.get("mitre_technique_id") or detection.get("mitre_technique_id")
        tech_name = threat_intel.get("mitre_technique_name") or detection.get("mitre_technique_name")
        if tech_id:
            root_cause += f" Aligns with MITRE ATT&CK technique {tech_id} ({tech_name})."

        # Grounded Mitigation
        mitigation = self._build_mitigation_text(knowledge, threat_intel)

        return {
            "incident_title": detection.get("title", f"{severity} Incident - {attack_type.title()}"),
            "summary": summary.strip(),
            "root_cause": root_cause.strip(),
            "mitigation": mitigation.strip(),
            "generated_by": "template_fallback",
        }

    @staticmethod
    def _build_mitigation_text(knowledge: dict[str, Any], threat_intel: dict[str, Any]) -> str:
        mitre = knowledge.get("mitre_attck", [])
        policies = knowledge.get("security_policies", [])

        parts = []
        if mitre and mitre[0].get("mitigation"):
            parts.append(f"MITRE-recommended mitigation: {mitre[0]['mitigation']}")
        if policies and (policies[0].get("content") or policies[0].get("title")):
            parts.append(f"Per company policy '{policies[0].get('title', '')}': {policies[0].get('content', '')}")

        recs = knowledge.get("defensive_recommendations", [])
        if recs and not parts:
            parts.extend(recs[:2])

        if not parts:
            return "No specific mitigation guidance found; escalate to a Tier 2 analyst for manual review."
        return " ".join(parts)

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        if not ip_str:
            return True
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private
                or ip.is_loopback
                or ip in ipaddress.ip_network("10.0.0.0/8")
                or ip in ipaddress.ip_network("172.16.0.0/12")
                or ip in ipaddress.ip_network("192.168.0.0/16")
            )
        except ValueError:
            return True
