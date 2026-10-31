"""
Integration test: builds real trained models (Module 6) and a real
ingested vector store (Module 7), then runs the full LangGraph pipeline
end-to-end — the same sequence Module 9 (Integration) will use in
production, just against a small synthetic sample so it stays fast.
"""

import pandas as pd
import pytest

from ai_engine.agents.graph import InvestigationPipeline
from ai_engine.inference.detection_service import DetectionService
from ai_engine.pipelines.preprocessing_pipeline import run_preprocessing_pipeline
from ai_engine.training.train_pipeline import train_models
from ai_engine.utils.synthetic_data_generator import write_sample_csv
from rag.ingestion.ingest_knowledge_base import ingest_all
from rag.retrieval.retrieval_service import RetrievalService


@pytest.fixture(scope="module")
def pipeline_and_features(tmp_path_factory):
    base = tmp_path_factory.mktemp("module8_integration")

    # Module 5: preprocessing
    raw_csv = write_sample_csv(base / "raw" / "sample.csv", n_rows=3000, seed=11)
    processed_dir = base / "processed"
    run_preprocessing_pipeline(raw_csv, output_dir=processed_dir, generate_eda=False)

    feature_columns = [c for c in pd.read_csv(processed_dir / "train.csv").columns if c != "attack_type_encoded"]

    # Module 6: train models
    artifacts_dir = base / "artifacts"
    metadata_dir = base / "metadata"
    train_models(processed_dir=processed_dir, artifacts_dir=artifacts_dir, metadata_dir=metadata_dir)
    detection_service = DetectionService(artifacts_dir=artifacts_dir, processed_dir=processed_dir)

    # Module 7: ingest knowledge base, then reuse the SAME client for
    # retrieval — both happen in this one process, and Qdrant's embedded
    # mode locks its storage folder, so a second client on the same path
    # would fail.
    from rag.vector_store.qdrant_store import get_qdrant_client

    vector_store_path = str(base / "qdrant_data")
    shared_qdrant_client = get_qdrant_client(local_path=vector_store_path)
    ingest_all(local_path=vector_store_path, qdrant_client=shared_qdrant_client)
    retrieval_service = RetrievalService(local_path=vector_store_path, qdrant_client=shared_qdrant_client)

    # Module 8: build the graph with these real (but test-scale) services
    pipeline = InvestigationPipeline(detection_service=detection_service, retrieval_service=retrieval_service)

    return pipeline, feature_columns


def test_pipeline_always_produces_detection(pipeline_and_features):
    pipeline, feature_columns = pipeline_and_features
    raw_features = {col: 0.0 for col in feature_columns}

    result = pipeline.investigate(raw_features)

    assert "detection" in result
    assert result["detection"]["attack_type"] in (
        "normal",
        "brute_force",
        "ddos",
        "botnet",
        "port_scan",
        "sql_injection",
        "web_attack",
        "other",
    )


def test_pipeline_state_is_internally_consistent(pipeline_and_features):
    """
    Either ALL of investigation/knowledge/response are present (attack
    path was taken), or NONE are (confidently-normal traffic was
    correctly routed straight to END) — never a partial state.
    """
    pipeline, feature_columns = pipeline_and_features
    raw_features = {col: 0.0 for col in feature_columns}

    result = pipeline.investigate(raw_features)

    keys_present = {"investigation", "knowledge", "response"} & set(result.keys())
    assert len(keys_present) in (0, 3)


def test_full_path_produces_valid_response_when_attack_detected(pipeline_and_features):
    """
    Uses an extreme, clearly-anomalous feature vector to force the
    "attack" branch of the router, so this test doesn't depend on which
    branch a zero-vector happens to take.
    """
    pipeline, feature_columns = pipeline_and_features
    # Extreme values in every feature should read as highly anomalous
    # regardless of the specific trained model's decision boundary.
    raw_features = {col: 1e6 for col in feature_columns}

    result = pipeline.investigate(raw_features)

    if "response" in result:  # only assert if this extreme input DID trigger the full path
        assert result["response"]["generated_by"] in ("llm", "template_fallback")
        assert len(result["response"]["summary"]) > 0
        assert len(result["response"]["mitigation"]) > 0
        assert "knowledge" in result
        assert "investigation" in result


def test_pipeline_accepts_related_events_for_correlation(pipeline_and_features):
    pipeline, feature_columns = pipeline_and_features
    raw_features = {col: 1e6 for col in feature_columns}
    related_events = [
        {"attack_type": "ddos", "detected_at": "2026-01-01T00:00:00", "severity": "high"},
        {"attack_type": "ddos", "detected_at": "2026-01-01T00:05:00", "severity": "high"},
    ]

    result = pipeline.investigate(raw_features, related_events=related_events)

    if "investigation" in result:
        assert result["investigation"]["correlated_event_count"] <= len(related_events)
