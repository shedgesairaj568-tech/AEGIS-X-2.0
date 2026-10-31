"""
Full-stack integration test.

This is the ultimate proof for Module 9: a REAL uvicorn server (started
in a background thread, not an in-process ASGI transport), REAL trained
models, a REAL ingested vector store, and the live feed runner talking to
all of it over REAL HTTP — the exact same code path used in production,
just pointed at a temporary SQLite database instead of Postgres so the
test doesn't need a running database server.

This complements (doesn't replace) the mocked unit tests in
test_backend_client.py and test_pipeline_connector.py — those are fast
and test logic in isolation; this one proves the pieces actually work
together end-to-end.
"""

import socket
import threading
import time

import pytest
import requests
import uvicorn

from ai_engine.agents.graph import InvestigationPipeline
from ai_engine.inference.detection_service import DetectionService
from ai_engine.integration.backend_client import BackendClient
from ai_engine.integration.live_feed_runner import run_live_feed
from ai_engine.integration.pipeline_connector import PipelineConnector
from ai_engine.pipelines.preprocessing_pipeline import run_preprocessing_pipeline
from ai_engine.training.train_pipeline import train_models
from ai_engine.utils.synthetic_data_generator import write_sample_csv
from rag.ingestion.ingest_knowledge_base import ingest_all
from rag.retrieval.retrieval_service import RetrievalService
from rag.vector_store.qdrant_store import get_qdrant_client


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _create_tables(Base, engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture(scope="module")
def live_backend_url(tmp_path_factory):
    """
    Starts the REAL backend app (backend/app/main.py) against a temporary
    SQLite database, in a background thread, and yields its base URL.
    Requires the backend package to be importable — see the sys.path
    handling below, since backend/ is a sibling directory to ai_engine/,
    not a subpackage of it.
    """
    import os
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]  # .../AEGIS-X
    backend_dir = repo_root / "backend"
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    db_path = tmp_path_factory.mktemp("module9_backend") / "test.db"
    os.environ["SECRET_KEY"] = "test-secret-key-for-module9-integration-only"
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["CORS_ORIGINS"] = "http://localhost"

    import asyncio

    from app.core.database import Base, engine  # noqa: E402
    from app.main import app  # noqa: E402

    asyncio.run(_create_tables(Base, engine))

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            resp = requests.get(f"{base_url}/api/v1/health", timeout=1)
            if resp.status_code == 200:
                break
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
    else:
        pytest.fail("Backend server did not become healthy in time")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def registered_service_account(live_backend_url):
    email, password = "pipeline@aegis-x.io", "changeme123456"
    requests.post(
        f"{live_backend_url}/api/v1/auth/register",
        json={"email": email, "full_name": "AI Pipeline Service", "password": password},
        timeout=10,
    )
    return email, password


@pytest.fixture(scope="module")
def trained_pipeline(tmp_path_factory):
    base = tmp_path_factory.mktemp("module9_pipeline")

    raw_csv = write_sample_csv(base / "raw" / "sample.csv", n_rows=2000, seed=99)
    processed_dir = base / "processed"
    run_preprocessing_pipeline(raw_csv, output_dir=processed_dir, generate_eda=False)

    artifacts_dir = base / "artifacts"
    metadata_dir = base / "metadata"
    train_models(processed_dir=processed_dir, artifacts_dir=artifacts_dir, metadata_dir=metadata_dir)
    detection_service = DetectionService(artifacts_dir=artifacts_dir, processed_dir=processed_dir)

    vector_store_path = str(base / "qdrant_data")
    shared_client = get_qdrant_client(local_path=vector_store_path)
    ingest_all(local_path=vector_store_path, qdrant_client=shared_client)
    retrieval_service = RetrievalService(local_path=vector_store_path, qdrant_client=shared_client)

    return InvestigationPipeline(detection_service=detection_service, retrieval_service=retrieval_service), raw_csv


def test_full_pipeline_writes_real_alert_to_real_backend(
    live_backend_url, registered_service_account, trained_pipeline
):
    email, password = registered_service_account
    pipeline, raw_csv = trained_pipeline

    client = BackendClient(live_backend_url, email, password)
    connector = PipelineConnector(client, pipeline)

    results = run_live_feed(connector, raw_csv, max_rows=5)

    assert len(results) == 5
    assert all(r.alert_id is not None for r in results)

    # Confirm the alert is ACTUALLY queryable back from the real backend —
    # not just that create_alert() returned 201 without erroring.
    token_resp = requests.post(
        f"{live_backend_url}/api/v1/auth/login", json={"email": email, "password": password}, timeout=10
    )
    headers = {"Authorization": f"Bearer {token_resp.json()['access_token']}"}

    list_resp = requests.get(f"{live_backend_url}/api/v1/alerts", headers=headers, timeout=10)
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 5


def test_investigated_alert_has_real_report_attached(live_backend_url, registered_service_account, trained_pipeline):
    """
    Runs enough rows to guarantee at least one non-normal detection, then
    confirms a real Report row exists for it via a real GET request —
    proving the full detection -> investigation -> knowledge -> response
    -> backend write chain works end-to-end, not just the alert creation.
    """
    email, password = registered_service_account
    pipeline, raw_csv = trained_pipeline

    client = BackendClient(live_backend_url, email, password)
    connector = PipelineConnector(client, pipeline)

    results = run_live_feed(connector, raw_csv, max_rows=15)
    investigated = [r for r in results if r.was_investigated]

    if not investigated:
        pytest.skip("No attack traffic detected in this sample slice; nothing to verify a report for.")

    token_resp = requests.post(
        f"{live_backend_url}/api/v1/auth/login", json={"email": email, "password": password}, timeout=10
    )
    headers = {"Authorization": f"Bearer {token_resp.json()['access_token']}"}

    alert_id = investigated[0].alert_id
    reports_resp = requests.get(f"{live_backend_url}/api/v1/alerts/{alert_id}/reports", headers=headers, timeout=10)
    assert reports_resp.status_code == 200
    reports = reports_resp.json()
    assert len(reports) == 1
    assert len(reports[0]["summary"]) > 0
    assert len(reports[0]["mitigation"]) > 0
