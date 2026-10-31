"""
Unit and integration tests for DeepAutoencoderDetector (Module 6 / Phase 2).
"""

import numpy as np
import pandas as pd
import pytest
import torch

from ai_engine.models.autoencoder.model import AutoencoderNet, DeepAutoencoderDetector


def test_autoencoder_net_shapes():
    """Verifies PyTorch net preserves input dimensions and produces correct latent dimension."""
    input_dim = 10
    latent_dim = 4
    batch_size = 16

    net = AutoencoderNet(input_dim=input_dim, latent_dim=latent_dim, h1=8, h2=6)
    x = torch.randn(batch_size, input_dim)

    recon = net(x)
    assert recon.shape == (batch_size, input_dim), f"Expected {(batch_size, input_dim)}, got {recon.shape}"

    latent = net.get_latent(x)
    assert latent.shape == (batch_size, latent_dim), f"Expected {(batch_size, latent_dim)}, got {latent.shape}"


def test_autoencoder_training_loss_decreases():
    """Verifies that autoencoder fits normal baseline data and loss decreases."""
    np.random.seed(42)
    # Generate 500 samples around a known subspace
    normal_data = np.random.normal(loc=0.0, scale=0.5, size=(500, 8))
    feature_names = [f"f_{i}" for i in range(8)]
    df_normal = pd.DataFrame(normal_data, columns=feature_names)

    detector = DeepAutoencoderDetector(input_dim=8, latent_dim=4, learning_rate=0.01, feature_names=feature_names)
    history = detector.fit(df_normal, epochs=15, batch_size=32, random_seed=42)

    assert len(history["train_loss"]) == 15
    assert history["train_loss"][-1] < history["train_loss"][0], "Training loss should decrease over training"


def test_autoencoder_anomaly_detection_and_attribution():
    """Verifies anomalies produce significantly higher reconstruction errors and per-feature attribution works."""
    np.random.seed(42)
    normal_data = np.random.normal(loc=0.0, scale=0.2, size=(400, 6))
    feature_names = [f"feat_{i}" for i in range(6)]
    df_normal = pd.DataFrame(normal_data, columns=feature_names)

    detector = DeepAutoencoderDetector(input_dim=6, latent_dim=3, feature_names=feature_names)
    detector.fit(df_normal, epochs=20, batch_size=32, random_seed=42)

    # Calibrate threshold at 95th percentile of normal data
    normal_errors = detector.reconstruction_error(df_normal)
    detector.threshold = float(np.percentile(normal_errors, 95))

    # Test on a normal sample
    sample_normal = pd.Series([0.05, -0.02, 0.01, 0.04, -0.03, 0.02], index=feature_names)
    err_norm, is_anom_norm, attr_norm = detector.predict_one(sample_normal)
    assert not is_anom_norm, "Normal sample should not be flagged as anomaly"
    assert len(attr_norm) == min(5, len(feature_names))

    # Test on an extreme anomaly (e.g., massive value in feat_3)
    sample_anom = pd.Series([0.0, 0.0, 0.0, 25.0, 0.0, 0.0], index=feature_names)
    err_anom, is_anom_flag, attr_anom = detector.predict_one(sample_anom)
    assert is_anom_flag, "Extreme deviation should be flagged as anomaly"
    assert err_anom > err_norm * 5, "Reconstruction error must be much higher for anomaly"

    # Verify per-feature attribution points to feat_3 as primary driver
    top_driver = max(attr_anom.items(), key=lambda kv: kv[1])[0]
    assert top_driver == "feat_3", f"Expected feat_3 to be top anomaly driver, got {top_driver}"


def test_autoencoder_save_load_roundtrip(tmp_path):
    """Verifies that model state, threshold, and feature names persist accurately across save/load."""
    feature_names = ["p1", "p2", "p3", "p4"]
    detector = DeepAutoencoderDetector(input_dim=4, latent_dim=2, feature_names=feature_names)
    detector.threshold = 0.4285

    save_file = tmp_path / "autoencoder.pt"
    detector.save(save_file)
    assert save_file.exists()

    loaded = DeepAutoencoderDetector.load(save_file)
    assert loaded.input_dim == 4
    assert loaded.latent_dim == 2
    assert loaded.feature_names == feature_names
    assert pytest.approx(loaded.threshold, 1e-4) == 0.4285

    # Check identical inference
    sample = pd.Series([0.5, 0.2, -0.1, 0.8], index=feature_names)
    err1, is_anom1, attr1 = detector.predict_one(sample)
    err2, is_anom2, attr2 = loaded.predict_one(sample)

    assert pytest.approx(err1, 1e-5) == err2
    assert is_anom1 == is_anom2
    assert attr1 == attr2
