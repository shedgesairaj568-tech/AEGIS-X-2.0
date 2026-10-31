"""
Synthetic CIC-IDS2017-like sample generator.

IMPORTANT: this does NOT replace the real dataset. It exists purely so
the preprocessing pipeline (and its tests) can run end-to-end in an
environment without network access to the official CIC-IDS2017 hosting
server. It generates statistically plausible values per attack type
(e.g. port scans get many tiny packets; DDoS gets high packet rates) so
the pipeline's cleaning/feature/EDA logic has realistic patterns to work
with, but the actual numbers are NOT real captured traffic.

Run directly to regenerate the sample file:
    python -m ai_engine.utils.synthetic_data_generator
"""

from pathlib import Path

import numpy as np
import pandas as pd

# Roughly mirrors CIC-IDS2017's real class imbalance: benign traffic
# dominates, attacks are a minority, and among attacks some types
# (DoS Hulk, PortScan) are far more common than rare ones (Heartbleed).
CLASS_WEIGHTS: dict[str, float] = {
    "BENIGN": 0.55,
    "DoS Hulk": 0.12,
    "PortScan": 0.10,
    "DDoS": 0.08,
    "DoS GoldenEye": 0.04,
    "FTP-Patator": 0.03,
    "SSH-Patator": 0.03,
    "DoS slowloris": 0.02,
    "DoS Slowhttptest": 0.015,
    "Bot": 0.01,
    "Web Attack - Brute Force": 0.008,
    "Web Attack - XSS": 0.004,
    "Infiltration": 0.002,
    "Web Attack - Sql Injection": 0.0009,
    "Heartbleed": 0.0001,
}


def _generate_rows_for_label(label: str, n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Generate n rows with distributions loosely characteristic of this attack type."""
    if label == "BENIGN":
        flow_duration = rng.exponential(scale=500_000, size=n)
        fwd_packets = rng.poisson(lam=15, size=n) + 1
        bwd_packets = rng.poisson(lam=12, size=n) + 1
        fwd_len = rng.normal(loc=500, scale=200, size=n).clip(min=0)
        bwd_len = rng.normal(loc=600, scale=250, size=n).clip(min=0)
        syn_flags = rng.integers(0, 2, size=n)
    elif label == "PortScan":
        flow_duration = rng.exponential(scale=1_000, size=n)  # very short flows
        fwd_packets = rng.poisson(lam=2, size=n) + 1  # few packets
        bwd_packets = rng.poisson(lam=1, size=n)
        fwd_len = rng.normal(loc=40, scale=10, size=n).clip(min=0)  # tiny packets
        bwd_len = rng.normal(loc=20, scale=10, size=n).clip(min=0)
        syn_flags = np.ones(n, dtype=int)  # SYN scans
    elif label == "DDoS":
        # Distributed = much higher aggregate packet volume than a
        # single-source DoS attack, and a higher, tighter packet rate
        # (many bots flooding in near-unison) — deliberately distinct
        # from the single-source DoS branch below so the classifier has
        # a real signal to separate these two classes on.
        flow_duration = rng.exponential(scale=30_000, size=n)
        fwd_packets = rng.poisson(lam=600, size=n) + 50
        bwd_packets = rng.poisson(lam=3, size=n)
        fwd_len = rng.normal(loc=1200, scale=60, size=n).clip(min=0)  # tight, uniform size
        bwd_len = rng.normal(loc=40, scale=15, size=n).clip(min=0)
        syn_flags = rng.integers(0, 2, size=n)
    elif label in ("DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"):
        flow_duration = rng.exponential(scale=50_000, size=n)
        fwd_packets = rng.poisson(lam=200, size=n) + 10  # flood of packets, single source
        bwd_packets = rng.poisson(lam=5, size=n)  # target barely responds
        fwd_len = rng.normal(loc=800, scale=100, size=n).clip(min=0)
        bwd_len = rng.normal(loc=50, scale=20, size=n).clip(min=0)
        syn_flags = rng.integers(0, 2, size=n)
    elif label in ("FTP-Patator", "SSH-Patator"):
        flow_duration = rng.exponential(scale=200_000, size=n)
        fwd_packets = rng.poisson(lam=20, size=n) + 5  # repeated login attempts
        bwd_packets = rng.poisson(lam=18, size=n) + 5
        fwd_len = rng.normal(loc=100, scale=30, size=n).clip(min=0)
        bwd_len = rng.normal(loc=100, scale=30, size=n).clip(min=0)
        syn_flags = rng.integers(0, 2, size=n)
    elif label == "Bot":
        flow_duration = rng.exponential(scale=300_000, size=n)
        fwd_packets = rng.poisson(lam=8, size=n) + 1
        bwd_packets = rng.poisson(lam=8, size=n) + 1
        fwd_len = rng.normal(loc=200, scale=80, size=n).clip(min=0)
        bwd_len = rng.normal(loc=200, scale=80, size=n).clip(min=0)
        syn_flags = rng.integers(0, 2, size=n)
    else:  # web attacks, infiltration, heartbleed, and any other rare class
        flow_duration = rng.exponential(scale=100_000, size=n)
        fwd_packets = rng.poisson(lam=10, size=n) + 1
        bwd_packets = rng.poisson(lam=10, size=n) + 1
        fwd_len = rng.normal(loc=300, scale=150, size=n).clip(min=0)
        bwd_len = rng.normal(loc=300, scale=150, size=n).clip(min=0)
        syn_flags = rng.integers(0, 2, size=n)

    total_fwd_bytes = fwd_len * fwd_packets
    total_bwd_bytes = bwd_len * bwd_packets
    total_packets = fwd_packets + bwd_packets
    total_bytes = total_fwd_bytes + total_bwd_bytes

    # Occasionally produce a zero flow_duration, to exercise the
    # Flow Bytes/s divide-by-zero -> Infinity quirk that data_cleaner.py
    # is specifically designed to handle (matches a real dataset quirk).
    zero_duration_mask = rng.random(n) < 0.01
    flow_duration_safe = flow_duration.copy()
    flow_duration_safe[zero_duration_mask] = 0

    with np.errstate(divide="ignore", invalid="ignore"):
        flow_bytes_per_s = np.where(
            flow_duration_safe > 0, total_bytes / (flow_duration_safe / 1_000_000), np.inf
        )
        flow_packets_per_s = np.where(
            flow_duration_safe > 0, total_packets / (flow_duration_safe / 1_000_000), np.inf
        )

    df = pd.DataFrame(
        {
            " Destination Port": rng.choice([80, 443, 22, 21, 3389, 8080, 53], size=n),
            " Flow Duration": flow_duration_safe,
            " Total Fwd Packets": fwd_packets,
            " Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": total_fwd_bytes,
            " Total Length of Bwd Packets": total_bwd_bytes,
            " Fwd Packet Length Max": fwd_len * rng.uniform(1.0, 1.3, size=n),
            " Fwd Packet Length Min": (fwd_len * rng.uniform(0.5, 0.9, size=n)).clip(min=0),
            " Fwd Packet Length Mean": fwd_len,
            "Bwd Packet Length Max": bwd_len * rng.uniform(1.0, 1.3, size=n),
            " Bwd Packet Length Min": (bwd_len * rng.uniform(0.5, 0.9, size=n)).clip(min=0),
            " Bwd Packet Length Mean": bwd_len,
            "Flow Bytes/s": flow_bytes_per_s,
            "Flow Packets/s": flow_packets_per_s,
            " Flow IAT Mean": rng.exponential(scale=1000, size=n),
            " Flow IAT Std": rng.exponential(scale=500, size=n),
            "Fwd IAT Mean": rng.exponential(scale=800, size=n),
            " Bwd IAT Mean": rng.exponential(scale=800, size=n),
            " Fwd PSH Flags": rng.integers(0, 2, size=n),
            " SYN Flag Count": syn_flags,
            " ACK Flag Count": rng.integers(0, 2, size=n),
            "Average Packet Size": (total_bytes / total_packets.clip(min=1)),
            " Label": label,
        }
    )
    return df


def generate_sample_dataset(n_rows: int = 15_000, seed: int = 42) -> pd.DataFrame:
    """Generate a synthetic CIC-IDS2017-shaped sample with n_rows total rows."""
    rng = np.random.default_rng(seed)

    frames = []
    for label, weight in CLASS_WEIGHTS.items():
        n = max(1, int(round(n_rows * weight)))
        frames.append(_generate_rows_for_label(label, n, rng))

    df = pd.concat(frames, ignore_index=True)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)  # shuffle rows
    return df


def write_sample_csv(output_path: str | Path, n_rows: int = 15_000, seed: int = 42) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df = generate_sample_dataset(n_rows=n_rows, seed=seed)
    df.to_csv(output_path, index=False)
    return output_path


if __name__ == "__main__":
    path = write_sample_csv("datasets/cic_ids2017/raw/synthetic_sample.csv")
    print(f"Wrote synthetic sample to: {path}")
