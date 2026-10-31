"""
Source-Aware Feature Extraction Package for AEGIS-X 2.0.
"""

from ai_engine.pipelines.source_features.auth_features import (
    AUTH_FEATURE_NAMES,
    AuthFeatureExtractor,
)
from ai_engine.pipelines.source_features.network_features import (
    NETWORK_FEATURE_NAMES,
    NetworkFeatureExtractor,
)
from ai_engine.pipelines.source_features.system_features import (
    SYSTEM_FEATURE_NAMES,
    SystemFeatureExtractor,
)

__all__ = [
    "NetworkFeatureExtractor",
    "NETWORK_FEATURE_NAMES",
    "AuthFeatureExtractor",
    "AUTH_FEATURE_NAMES",
    "SystemFeatureExtractor",
    "SYSTEM_FEATURE_NAMES",
]

