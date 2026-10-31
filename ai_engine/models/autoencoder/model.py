"""
Deep Autoencoder for Unsupervised Anomaly Detection in AEGIS-X 2.0.

Learns a compressed latent representation of benign baseline traffic/events
and flags anomalous patterns via reconstruction error:
    e_i = || x_i - \\hat{x}_i ||_2^2

Features:
- Symmetric feed-forward architecture with bottleneck compression.
- LayerNorm and Dropout for robust regularization.
- Empirical validation-based threshold tuning (percentile / Youden's J index).
- Per-feature reconstruction error attribution for explainability.
- Torch serialization and reproducible inference.
"""

from pathlib import Path
from typing import Any
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)


class AutoencoderNet(nn.Module):
    """Symmetric Autoencoder PyTorch neural network."""

    def __init__(
        self,
        input_dim: int,
        latent_dim: int = 16,
        dropout: float = 0.1,
        h1: int | None = None,
        h2: int | None = None,
    ):
        super().__init__()
        # Ensure hidden dimensions scale with input_dim
        h1 = h1 or max(latent_dim * 4, 32)
        h2 = h2 or max(latent_dim * 2, 24)

        # Encoder: input_dim -> h1 -> h2 -> latent_dim
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h1),
            nn.LayerNorm(h1),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(h1, h2),
            nn.LayerNorm(h2),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(h2, latent_dim),
            nn.LeakyReLU(0.1),
        )

        # Decoder: latent_dim -> h2 -> h1 -> input_dim
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, h2),
            nn.LayerNorm(h2),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(h2, h1),
            nn.LayerNorm(h1),
            nn.LeakyReLU(0.1),
            nn.Dropout(dropout),
            nn.Linear(h1, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

    def get_latent(self, x: torch.Tensor) -> torch.Tensor:
        return self.encoder(x)


class DeepAutoencoderDetector:
    """Wrapper managing training, evaluation, threshold tuning, and inference."""

    def __init__(
        self,
        input_dim: int,
        latent_dim: int = 16,
        learning_rate: float = 1e-3,
        threshold: float | None = None,
        feature_names: list[str] | None = None,
    ):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.learning_rate = learning_rate
        self.threshold = threshold
        self.feature_names = feature_names or []
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.net = AutoencoderNet(input_dim, latent_dim).to(self.device)

    def fit(
        self,
        X_train: pd.DataFrame | np.ndarray,
        epochs: int = 25,
        batch_size: int = 64,
        val_split: float = 0.1,
        random_seed: int = 42,
    ) -> dict[str, list[float]]:
        """
        Trains autoencoder on normal training samples.
        """
        torch.manual_seed(random_seed)
        np.random.seed(random_seed)

        if isinstance(X_train, pd.DataFrame):
            if not self.feature_names:
                self.feature_names = list(X_train.columns)
            X_arr = X_train.values.astype(np.float32)
        else:
            X_arr = np.asarray(X_train, dtype=np.float32)

        n_samples = len(X_arr)
        val_size = int(n_samples * val_split)
        indices = np.random.permutation(n_samples)
        train_idx, val_idx = indices[val_size:], indices[:val_size]

        train_tensor = torch.tensor(X_arr[train_idx], dtype=torch.float32)
        val_tensor = torch.tensor(X_arr[val_idx], dtype=torch.float32)

        train_loader = DataLoader(
            TensorDataset(train_tensor, train_tensor),
            batch_size=batch_size,
            shuffle=True,
        )

        optimizer = torch.optim.Adam(self.net.parameters(), lr=self.learning_rate, weight_decay=1e-5)
        criterion = nn.MSELoss()

        history: dict[str, list[float]] = {"train_loss": [], "val_loss": []}

        self.net.train()
        for epoch in range(epochs):
            batch_losses = []
            for batch_x, _ in train_loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                recon = self.net(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                batch_losses.append(loss.item())

            train_loss = float(np.mean(batch_losses))

            # Validation loss
            self.net.eval()
            with torch.no_grad():
                val_recon = self.net(val_tensor.to(self.device))
                val_loss = float(criterion(val_recon, val_tensor.to(self.device)).item())
            self.net.train()

            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_loss)

        self.net.eval()

        # If threshold not tuned yet, default to 95th percentile of normal validation errors
        if self.threshold is None and len(val_tensor) > 0:
            val_errors = self.compute_reconstruction_errors(X_arr[val_idx])
            self.threshold = float(np.percentile(val_errors, 95))
            logger.info("Autoencoder baseline threshold tuned to: %.6f (95th pct)", self.threshold)

        return history

    def tune_threshold(
        self,
        X_val: pd.DataFrame | np.ndarray,
        y_val: np.ndarray,
        normal_label: int = 0,
        percentile: float = 95.0,
    ) -> float:
        """
        Tunes reconstruction threshold using validation data.
        If ground truth y_val is available, finds threshold maximizing Youden's J statistic
        (Sensitivity + Specificity - 1); otherwise uses normal samples percentile.
        """
        val_errors = self.compute_reconstruction_errors(X_val)
        y_binary = (y_val != normal_label).astype(int)

        if len(np.unique(y_binary)) > 1:
            # Grid search candidate percentiles on errors
            candidates = np.percentile(val_errors, np.linspace(80, 99.5, 40))
            best_j = -1.0
            best_thresh = float(candidates[0])

            for th in candidates:
                preds = (val_errors >= th).astype(int)
                tp = np.sum((preds == 1) & (y_binary == 1))
                fn = np.sum((preds == 0) & (y_binary == 1))
                tn = np.sum((preds == 0) & (y_binary == 0))
                fp = np.sum((preds == 1) & (y_binary == 0))

                tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                j_stat = tpr - fpr

                if j_stat > best_j:
                    best_j = j_stat
                    best_thresh = float(th)

            self.threshold = best_thresh
            logger.info("Autoencoder threshold optimized via Youden J (%.4f): %.6f", best_j, self.threshold)
        else:
            self.threshold = float(np.percentile(val_errors, percentile))
            logger.info("Autoencoder threshold tuned to %.1fth percentile: %.6f", percentile, self.threshold)

        return self.threshold

    def compute_reconstruction_errors(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Computes sample-wise mean squared reconstruction error."""
        self.net.eval()
        if isinstance(X, pd.DataFrame):
            X_arr = X.values.astype(np.float32)
        else:
            X_arr = np.asarray(X, dtype=np.float32)

        with torch.no_grad():
            tensor_x = torch.tensor(X_arr, dtype=torch.float32).to(self.device)
            recon = self.net(tensor_x)
            mse_per_sample = torch.mean((tensor_x - recon) ** 2, dim=1).cpu().numpy()

        return mse_per_sample

    def reconstruction_errors(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Alias for compute_reconstruction_errors."""
        return self.compute_reconstruction_errors(X)

    def reconstruction_error(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Alias for compute_reconstruction_errors."""
        return self.compute_reconstruction_errors(X)

    def compute_feature_contributions(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """
        Computes squared reconstruction error per individual feature dimension:
            (x_ij - \\hat{x}_ij)^2
        """
        self.net.eval()
        if isinstance(X, pd.DataFrame):
            X_arr = X.values.astype(np.float32)
        else:
            X_arr = np.asarray(X, dtype=np.float32)

        with torch.no_grad():
            tensor_x = torch.tensor(X_arr, dtype=torch.float32).to(self.device)
            recon = self.net(tensor_x)
            feat_errors = ((tensor_x - recon) ** 2).cpu().numpy()

        return feat_errors

    def predict_one(self, sample: pd.Series | np.ndarray | dict) -> tuple[float, bool, dict[str, float]]:
        """
        Evaluates a single sample.
        Returns:
            (reconstruction_error, is_anomaly, top_feature_attributions)
        """
        if isinstance(sample, dict):
            X_arr = np.array([[sample[col] for col in self.feature_names]], dtype=np.float32)
        elif isinstance(sample, pd.Series):
            X_arr = sample.values.reshape(1, -1).astype(np.float32)
        else:
            X_arr = np.asarray(sample, dtype=np.float32).reshape(1, -1)

        error = float(self.compute_reconstruction_errors(X_arr)[0])
        th = self.threshold if self.threshold is not None else 1.0
        is_anomaly = bool(error >= th)

        # Calculate per-feature contributions
        feat_errs = self.compute_feature_contributions(X_arr)[0]
        attributions: dict[str, float] = {}
        if self.feature_names and len(self.feature_names) == len(feat_errs):
            # Sort top 5 contributing features
            top_indices = np.argsort(feat_errs)[::-1][:5]
            for idx in top_indices:
                attributions[self.feature_names[idx]] = round(float(feat_errs[idx]), 4)

        return error, is_anomaly, attributions

    def save(self, file_path: str | Path) -> None:
        """Persists model architecture, weights, threshold, and feature metadata."""
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "state_dict": self.net.state_dict(),
        }
        torch.save(payload, file_path)
        logger.info("Saved DeepAutoencoder to %s", file_path)

    @classmethod
    def load(cls, file_path: str | Path) -> "DeepAutoencoderDetector":
        """Loads a saved DeepAutoencoder artifact."""
        file_path = Path(file_path)
        payload = torch.load(file_path, map_location=torch.device("cpu"), weights_only=False)

        detector = cls(
            input_dim=payload["input_dim"],
            latent_dim=payload["latent_dim"],
            threshold=payload.get("threshold"),
            feature_names=payload.get("feature_names", []),
        )
        detector.net.load_state_dict(payload["state_dict"])
        detector.net.eval()
        logger.info("Loaded DeepAutoencoder from %s (threshold=%.6f)", file_path, detector.threshold or 0.0)
        return detector
