"""
Multi-agent investigation graph for AEGIS-X 2.0, built with LangGraph.

Architecture & Controlled Communication:

      ThreatDetectionAgent (Hybrid ML, Calibrated Risk, Dual Explainability)
                 |
      [Router: Is this anomalous or malicious?]
         /                              \\
    Confidently Normal              Anomalous / Classified Attack
    (Skip straight to END)                 |
                                    InvestigationAgent (CorrelationEngine, Entity Linking, Timeline)
                                           |
                                    ThreatIntelAgent (MITRE ATT&CK Mapping, TTPs, Attribution Guard)
                                           |
                                    KnowledgeAgent (RAG over Qdrant, Citations, Fact-vs-Interpretation)
                                           |
                                    ResponseAgent (HITL Containment Actions, Investigation Steps, Report)
                                           |
                                          END
"""

from typing import Any
from langgraph.graph import END, StateGraph

from ai_engine.agents.investigation_agent import InvestigationAgent
from ai_engine.agents.knowledge_agent import KnowledgeAgent
from ai_engine.agents.response_agent import ResponseAgent
from ai_engine.agents.state import AgentState
from ai_engine.agents.threat_detection_agent import ThreatDetectionAgent
from ai_engine.agents.threat_intel_agent import ThreatIntelAgent
from ai_engine.correlation.correlation_engine import CorrelationEngine
from ai_engine.inference.detection_service import DetectionService
from ai_engine.utils.logging_utils import get_logger
from rag.retrieval.retrieval_service import RetrievalService

logger = get_logger(__name__)


def _route_after_detection(state: AgentState) -> str:
    detection = state.get("detection", {})
    is_confidently_normal = (
        detection.get("attack_type") == "normal"
        and not detection.get("is_anomaly", False)
        and float(detection.get("risk_score", 0.0)) < 30.0
    )

    if is_confidently_normal:
        logger.info("Router: Confidently benign traffic (risk < 30), terminating graph early.")
        return "skip"
    return "investigate"


def build_investigation_graph(
    detection_service: DetectionService | None = None,
    retrieval_service: RetrievalService | None = None,
    correlation_engine: CorrelationEngine | None = None,
):
    """
    Builds and compiles the AEGIS-X 2.0 multi-agent LangGraph workflow.
    All underlying services are dependency-injected to ensure fast, isolated unit testing.
    """
    detection_service = detection_service or DetectionService()
    retrieval_service = retrieval_service or RetrievalService()
    correlation_engine = correlation_engine or CorrelationEngine()

    threat_detection_agent = ThreatDetectionAgent(detection_service)
    investigation_agent = InvestigationAgent(correlation_engine)
    threat_intel_agent = ThreatIntelAgent()
    knowledge_agent = KnowledgeAgent(retrieval_service)
    response_agent = ResponseAgent()

    graph = StateGraph(AgentState)

    # Register all 4 specialized agent nodes + detection node
    graph.add_node("threat_detection", threat_detection_agent.run)
    graph.add_node("investigation", investigation_agent.run)
    graph.add_node("threat_intel", threat_intel_agent.run)
    graph.add_node("knowledge", knowledge_agent.run)
    graph.add_node("response", response_agent.run)

    # Entry point & conditional routing
    graph.set_entry_point("threat_detection")
    graph.add_conditional_edges(
        "threat_detection",
        _route_after_detection,
        {"skip": END, "investigate": "investigation"},
    )

    # Sequential traceable investigation pipeline
    graph.add_edge("investigation", "threat_intel")
    graph.add_edge("threat_intel", "knowledge")
    graph.add_edge("knowledge", "response")
    graph.add_edge("response", END)

    return graph.compile()


class InvestigationPipeline:
    """
    High-level convenience orchestrator for the multi-agent investigation pipeline.
    """

    def __init__(
        self,
        detection_service: DetectionService | None = None,
        retrieval_service: RetrievalService | None = None,
        correlation_engine: CorrelationEngine | None = None,
    ):
        self.graph = build_investigation_graph(
            detection_service=detection_service,
            retrieval_service=retrieval_service,
            correlation_engine=correlation_engine,
        )

    def investigate(
        self,
        raw_features: dict[str, Any],
        related_events: list[dict[str, Any]] | None = None,
        source: str = "network_flow",
    ) -> AgentState:
        initial_state: AgentState = {
            "raw_features": raw_features,
            "related_events": related_events or [],
            "source": source,
        }
        return self.graph.invoke(initial_state)
