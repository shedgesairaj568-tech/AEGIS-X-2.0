"""
Agent 3 — Knowledge Agent for AEGIS-X 2.0.

Responsibilities:
- Implement Retrieval-Augmented Generation (RAG) over vector databases (Qdrant).
- Retrieve verified knowledge from authoritative cybersecurity collections:
  - MITRE ATT&CK tactics, techniques, and mitigation controls
  - Common Vulnerabilities and Exposures (CVE) definitions
  - Internal corporate Security Policies
- Synthesize actionable defensive recommendations.
- STRICT EXPLAINABILITY & PROVENANCE GUARD:
  - Explicitly cite retrieved documents with doc IDs and match scores.
  - Formally distinguish verified retrieved facts from model-generated interpretations.
"""

from typing import Any

from ai_engine.utils.logging_utils import get_logger
from rag.retrieval.retrieval_service import RetrievalService

logger = get_logger(__name__)


class KnowledgeAgent:
    def __init__(self, retrieval_service: RetrievalService):
        self._service = retrieval_service

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        detection = state.get("detection", {})
        threat_intel = state.get("threat_intel", {})
        attack_type = detection.get("attack_type", "other")

        # Build query context using MITRE technique name or threat intel context
        mitre_context = (
            threat_intel.get("mitre_technique_name")
            or detection.get("mitre_technique_name")
            or ""
        )

        results = self._service.enrich_alert(attack_type, mitre_context)

        # Build formal citations
        citations: list[dict[str, Any]] = []
        retrieved_facts: list[str] = []
        defensive_recommendations: list[str] = []

        # 1. Process MITRE ATT&CK documents
        for doc in results.get("mitre_attck", []):
            title = doc.payload.get("name") or doc.payload.get("title") or doc.doc_id
            citations.append({
                "collection": "mitre_attck",
                "doc_id": doc.doc_id,
                "title": title,
                "relevance_score": round(doc.score, 3),
            })
            text_snippet = doc.payload.get("text") or doc.payload.get("description", "")
            if text_snippet:
                retrieved_facts.append(f"[Fact: MITRE {doc.doc_id}] {text_snippet[:250].strip()}...")
            mitigation = doc.payload.get("mitigation")
            if mitigation:
                defensive_recommendations.append(f"MITRE Guidance ({doc.doc_id}): {mitigation}")

        # 2. Process CVE documents
        for doc in results.get("cve", []):
            cve_id = doc.payload.get("cve_id") or doc.doc_id
            citations.append({
                "collection": "cve",
                "doc_id": cve_id,
                "title": doc.payload.get("title") or cve_id,
                "relevance_score": round(doc.score, 3),
            })
            desc = doc.payload.get("description") or doc.payload.get("text", "")
            if desc:
                retrieved_facts.append(f"[Fact: CVE {cve_id}] {desc[:250].strip()}...")

        # 3. Process Security Policy documents
        for doc in results.get("security_policies", []):
            policy_id = doc.payload.get("policy_id") or doc.doc_id
            title = doc.payload.get("title") or policy_id
            citations.append({
                "collection": "security_policies",
                "doc_id": policy_id,
                "title": title,
                "relevance_score": round(doc.score, 3),
            })
            content = doc.payload.get("content") or doc.payload.get("text", "")
            if content:
                defensive_recommendations.append(f"Internal Policy ({title}): {content[:250].strip()}...")

        logger.info(
            "KnowledgeAgent: retrieved %d MITRE, %d CVE, %d policies (total citations: %d)",
            len(results["mitre_attck"]),
            len(results["cve"]),
            len(results["security_policies"]),
            len(citations),
        )

        return {
            "knowledge": {
                "mitre_attck": [self._doc_to_dict(d) for d in results["mitre_attck"]],
                "cve": [self._doc_to_dict(d) for d in results["cve"]],
                "security_policies": [self._doc_to_dict(d) for d in results["security_policies"]],
                "citations": citations,
                "verified_facts": retrieved_facts,
                "defensive_recommendations": defensive_recommendations,
                "provenance_disclaimer": (
                    "Verified facts and defensive controls were retrieved directly from authenticated "
                    "knowledge stores (Qdrant). Model predictions represent probabilistic risk assessments."
                ),
            }
        }

    @staticmethod
    def _doc_to_dict(doc) -> dict:
        return {"doc_id": doc.doc_id, "score": doc.score, **doc.payload}
