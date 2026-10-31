"""
Live feed runner.

Since we don't have real network capture hardware, this simulates a live
feed by replaying rows from the CIC-IDS2017 dataset (or the synthetic
sample) through the full pipeline -> backend connector, one at a time —
exactly what would happen if a real packet-capture agent were streaming
flows in. This is the script you'd point at a real backend to actually
populate it with realistic-looking traffic for a demo, or to
load-test/sanity-check the whole system end-to-end.

Also assigns each row a synthetic source_ip (the CIC-IDS2017 feature
subset Module 5 selected doesn't include source IP as a model feature —
see ai_engine/pipelines/feature_engineering.py — since a real
packet-capture agent would supply this as separate connection metadata
alongside the statistical flow features fed to the model, not as
something the model itself predicts from).
"""

import time
from pathlib import Path

from ai_engine.integration.backend_client import BackendClient
from ai_engine.integration.pipeline_connector import PipelineConnector
from ai_engine.pipelines.data_cleaner import clean_data
from ai_engine.pipelines.data_loader import load_cic_ids2017
from ai_engine.pipelines.feature_engineering import engineer_features, select_features
from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Deterministic per-row synthetic source IP, grouped by attack type so
# related events from the "same attacker" actually correlate in the demo
# (real deployments get this from the actual packet capture instead).
_SOURCE_IP_BY_LABEL = {
    "BENIGN": "10.0.0.{}",
    "DDoS": "203.0.113.{}",
    "PortScan": "198.51.100.{}",
    "FTP-Patator": "192.0.2.{}",
    "SSH-Patator": "192.0.2.{}",
    "Bot": "185.220.101.{}",
    "Web Attack - Brute Force": "203.0.113.{}",
    "Web Attack - XSS": "203.0.113.{}",
    "Web Attack - Sql Injection": "203.0.113.{}",
}


def run_live_feed(
    connector: PipelineConnector,
    source_csv: str | Path,
    max_rows: int = 20,
    delay_seconds: float = 0.0,
    labels_to_include: list[str] | None = None,
) -> list:
    """
    Replays up to max_rows from source_csv through the connector.
    delay_seconds > 0 simulates real-time pacing between events; 0 (the
    default) runs as fast as possible for testing/demo purposes.
    """
    df = load_cic_ids2017(source_csv)
    df = clean_data(df)
    df = select_features(df)
    df = engineer_features(df)

    if labels_to_include:
        df = df[df["Label"].isin(labels_to_include)]

    df = df.head(max_rows)
    results = []

    for i, (_, row) in enumerate(df.iterrows()):
        label = row["Label"]
        raw_features = row.drop("Label").to_dict()

        ip_template = _SOURCE_IP_BY_LABEL.get(label, "10.0.0.{}")
        source_ip = ip_template.format((i % 5) + 1)  # cycle through 5 IPs per label to create some correlation

        try:
            result = connector.process_flow(raw_features, source="network_flow", source_ip=source_ip)
            logger.info(
                "[%d/%d] true_label=%s -> alert_id=%s attack_type=%s severity=%s investigated=%s",
                i + 1,
                len(df),
                label,
                result.alert_id,
                result.attack_type,
                result.severity,
                result.was_investigated,
            )
            results.append(result)
        except Exception as exc:
            logger.error("[%d/%d] Failed to process row (true_label=%s): %s", i + 1, len(df), label, exc)

        if delay_seconds > 0:
            time.sleep(delay_seconds)

    return results


if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Replay dataset rows through the full AEGIS-X pipeline into a live backend.")
    parser.add_argument("--source-csv", default="datasets/cic_ids2017/raw/synthetic_sample.csv")
    parser.add_argument("--backend-url", default=os.environ.get("AEGIS_BACKEND_URL", "http://localhost:8000"))
    parser.add_argument("--email", default=os.environ.get("AEGIS_SERVICE_EMAIL", "pipeline@aegis-x.io"))
    parser.add_argument("--password", default=os.environ.get("AEGIS_SERVICE_PASSWORD", "changeme123"))
    parser.add_argument("--max-rows", type=int, default=20)
    parser.add_argument("--delay-seconds", type=float, default=0.0)
    args = parser.parse_args()

    from ai_engine.agents.graph import InvestigationPipeline

    client = BackendClient(base_url=args.backend_url, email=args.email, password=args.password)
    pipeline = InvestigationPipeline()
    connector = PipelineConnector(client, pipeline)

    results = run_live_feed(connector, args.source_csv, max_rows=args.max_rows, delay_seconds=args.delay_seconds)
    print(f"Processed {len(results)} flows. {sum(r.was_investigated for r in results)} triggered full investigation.")
