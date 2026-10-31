"""
AEGIS-X system health check.

Verifies the project is actually set up correctly — dependencies
installed, models trained, vector store ingested, backend configured —
BEFORE someone tries to run the live feed and gets a confusing stack
trace three layers deep. This is the first thing to run after a fresh
clone/setup, or when something isn't working and it's unclear why.

Usage:
    python tests/health_check.py
"""

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class CheckResult:
    def __init__(self, name: str, ok: bool, detail: str = "", fix_hint: str = ""):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.fix_hint = fix_hint


def _check_package_installed(package_name: str) -> bool:
    return importlib.util.find_spec(package_name) is not None


def check_backend_dependencies() -> CheckResult:
    required = ["fastapi", "sqlalchemy", "jose", "passlib", "pydantic"]
    missing = [p for p in required if not _check_package_installed(p)]
    if missing:
        return CheckResult(
            "Backend dependencies",
            False,
            f"Missing: {', '.join(missing)}",
            "pip install -r backend/requirements.txt (see README if psycopg2/asyncpg fail to compile — SQLite-only setups can skip those two)",
        )
    return CheckResult("Backend dependencies", True, "All core packages importable.")


def check_ai_engine_dependencies() -> CheckResult:
    required = ["pandas", "numpy", "sklearn", "xgboost", "shap", "matplotlib"]
    missing = [p for p in required if not _check_package_installed(p)]
    if missing:
        return CheckResult(
            "AI engine dependencies", False, f"Missing: {', '.join(missing)}", "pip install -r ai_engine/requirements.txt"
        )
    return CheckResult("AI engine dependencies", True, "All core packages importable.")


def check_rag_dependencies() -> CheckResult:
    if not _check_package_installed("qdrant_client"):
        return CheckResult("RAG dependencies", False, "Missing: qdrant-client", "pip install -r rag/requirements.txt")
    sentence_transformers_available = _check_package_installed("sentence_transformers")
    detail = "qdrant-client OK." + (
        " sentence-transformers OK (real embeddings)."
        if sentence_transformers_available
        else " sentence-transformers NOT installed — will use the offline fallback embedder (reduced semantic quality, but functional). See rag/README.md."
    )
    return CheckResult("RAG dependencies", True, detail)


def check_agents_dependencies() -> CheckResult:
    if not _check_package_installed("langgraph"):
        return CheckResult(
            "Agents dependencies", False, "Missing: langgraph", "pip install -r ai_engine/agents/requirements.txt"
        )
    return CheckResult("Agents dependencies", True, "langgraph importable.")


def check_trained_models() -> CheckResult:
    artifacts_dir = REPO_ROOT / "models" / "artifacts"
    required_files = ["isolation_forest.joblib", "xgboost_classifier.joblib"]
    missing = [f for f in required_files if not (artifacts_dir / f).exists()]
    if missing:
        return CheckResult(
            "Trained models (Module 6)",
            False,
            f"Missing in {artifacts_dir}: {', '.join(missing)}",
            "python -m ai_engine.training.train_pipeline (after running Module 5 preprocessing first)",
        )
    return CheckResult("Trained models (Module 6)", True, f"Found in {artifacts_dir}.")


def check_preprocessing_artifacts() -> CheckResult:
    processed_dir = REPO_ROOT / "datasets" / "processed"
    required_files = ["scaler.joblib", "label_encoder.joblib"]
    missing = [f for f in required_files if not (processed_dir / f).exists()]
    if missing:
        return CheckResult(
            "Preprocessing artifacts (Module 5)",
            False,
            f"Missing in {processed_dir}: {', '.join(missing)}",
            "python -m ai_engine.pipelines.preprocessing_pipeline <path-to-csv-or-directory>",
        )
    return CheckResult("Preprocessing artifacts (Module 5)", True, f"Found in {processed_dir}.")


def check_vector_store_ingested() -> CheckResult:
    vector_store_dir = REPO_ROOT / "rag" / "vector_store" / "qdrant_data"
    if not vector_store_dir.exists() or not any(vector_store_dir.iterdir()):
        return CheckResult(
            "RAG vector store (Module 7)",
            False,
            f"'{vector_store_dir}' is empty or missing.",
            "python -m rag.ingestion.ingest_knowledge_base",
        )
    return CheckResult("RAG vector store (Module 7)", True, f"Data present in {vector_store_dir}.")


def check_backend_env_file() -> CheckResult:
    env_file = REPO_ROOT / "backend" / ".env"
    env_example = REPO_ROOT / "backend" / ".env.example"
    if not env_file.exists():
        return CheckResult(
            "Backend .env file",
            False,
            f"'{env_file}' not found.",
            f"cp backend/.env.example backend/.env, then set a real SECRET_KEY (see {env_example.name}).",
        )
    content = env_file.read_text()
    if "CHANGE_ME" in content:
        return CheckResult(
            "Backend .env file",
            False,
            "SECRET_KEY still has the placeholder value.",
            'Generate one: python -c "import secrets; print(secrets.token_hex(32))" and paste it into backend/.env',
        )
    return CheckResult("Backend .env file", True, "Present and SECRET_KEY looks configured.")


def check_anthropic_api_key() -> CheckResult:
    """Informational only — not a failure, since the template fallback works fine without it."""
    import os

    if os.environ.get("ANTHROPIC_API_KEY"):
        return CheckResult(
            "LLM API key (optional)",
            True,
            "ANTHROPIC_API_KEY is set — Response Agent will use real LLM generation for high/critical alerts.",
        )
    return CheckResult(
        "LLM API key (optional)",
        True,
        "ANTHROPIC_API_KEY not set — Response Agent will use its deterministic template fallback (fully functional, see ai_engine/agents/README.md).",
    )


ALL_CHECKS = [
    check_backend_dependencies,
    check_ai_engine_dependencies,
    check_rag_dependencies,
    check_agents_dependencies,
    check_backend_env_file,
    check_preprocessing_artifacts,
    check_trained_models,
    check_vector_store_ingested,
    check_anthropic_api_key,
]


def main() -> int:
    print("=" * 70)
    print("AEGIS-X — System Health Check")
    print("=" * 70)
    print()

    results = [check() for check in ALL_CHECKS]

    for r in results:
        status = "OK  " if r.ok else "FAIL"
        print(f"[{status}] {r.name}")
        if r.detail:
            print(f"        {r.detail}")
        if not r.ok and r.fix_hint:
            print(f"        Fix: {r.fix_hint}")
        print()

    failed = [r for r in results if not r.ok]
    print("=" * 70)
    if failed:
        print(f"{len(results) - len(failed)}/{len(results)} checks passed. {len(failed)} issue(s) to fix (see above).")
        return 1
    print(f"All {len(results)} checks passed. System looks ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
