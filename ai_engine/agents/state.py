"""
Shared state definitions for the AEGIS-X 2.0 multi-agent investigation system.

Threaded through LangGraph across all 4 specialized agent nodes:
1. ThreatDetectionAgent (hybrid ML detection, calibrated scoring, dual explainability)
2. InvestigationAgent (temporal correlation, entity linking, timeline construction)
3. ThreatIntelAgent (MITRE ATT&CK tactical mapping, pattern recognition, attribution guard)
4. KnowledgeAgent (RAG retrieval over Qdrant, document citations, fact-vs-interpretation)
5. ResponseAgent (HITL containment action proposals, triage recommendations, report synthesis)
"""

from typing import Any, TypedDict


class DetectionState(TypedDict, total=False):
    title: str
    source: str
    attack_type: str
    severity: str
    anomaly_score: float
    risk_score: float
    confidence: float
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    explanation: str
    is_anomaly: bool
    reconstruction_error: float
    is_ae_anomaly: bool
    calibrated_probability: float
    model_contributions: dict[str, float]
    autoencoder_attributions: dict[str, float]
    source_ip: str | None
    destination_ip: str | None
    raw_event: dict[str, Any]


class InvestigationState(TypedDict, total=False):
    correlated_event_count: int
    timeline: list[str]
    structured_timeline: list[dict[str, Any]]
    root_cause_hypothesis: str
    confidence_score: float
    is_multi_stage_attack: bool
    stages_detected: list[str]
    primary_attacker_ip: str | None
    targeted_users: list[str]
    targeted_assets: list[str]
    correlation_reasons: list[str]


class ThreatIntelState(TypedDict, total=False):
    mitre_tactic_id: str | None
    mitre_tactic_name: str | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    sub_technique: str | None
    attack_pattern: str
    confidence: float
    attribution_statement: str
    known_associated_actors: list[str]
    telemetry_indicators: list[str]
    threat_intel_summary: str


class KnowledgeState(TypedDict, total=False):
    mitre_attck: list[dict[str, Any]]
    cve: list[dict[str, Any]]
    security_policies: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    verified_facts: list[str]
    defensive_recommendations: list[str]
    provenance_disclaimer: str


class ResponseState(TypedDict, total=False):
    incident_title: str
    summary: str
    root_cause: str
    mitigation: str
    generated_by: str
    containment_actions: list[dict[str, Any]]
    investigation_steps: dict[str, list[str]]
    human_in_the_loop_required: bool
    containment_status: str


class AgentState(TypedDict, total=False):
    """The full unified state threaded through the LangGraph pipeline."""

    # Input telemetry
    raw_features: dict[str, Any]
    related_events: list[dict[str, Any]]

    # Populated incrementally by each specialized agent
    detection: DetectionState
    investigation: InvestigationState
    threat_intel: ThreatIntelState
    knowledge: KnowledgeState
    response: ResponseState

    # Control flow & diagnostics
    skip_full_investigation: bool
    error: str | None
