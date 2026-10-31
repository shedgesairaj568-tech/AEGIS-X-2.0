"""
LLM client — used by the Response Agent to generate the final
human-readable incident report (root cause explanation, mitigation).

Calls the Anthropic Messages API when ANTHROPIC_API_KEY is set in the
environment. When it isn't (or the call fails for any reason — network
issue, rate limit, etc.), falls back to a deterministic, template-based
generator that assembles a report directly from the structured data
already gathered by the other three agents (SHAP explanation, MITRE
technique, CVE, and policy context) — the SAME graceful-degradation
pattern used for the embedding model in Module 7
(rag/vector_store/embedding_model.py).

This fallback is a legitimate design choice, not just a workaround: some
deployments deliberately want a fast, free, deterministic path for
low-severity alerts and only spend an LLM call on higher-severity ones —
see `USE_LLM_FOR_SEVERITIES` below.

Model name is read from the ANTHROPIC_MODEL env var (default is a
reasonable current choice, but check
https://docs.claude.com/en/docs/about-claude/models for the latest
recommended model string, since these change over time).
"""

import os
from typing import Any

import requests

from ai_engine.utils.logging_utils import get_logger

logger = get_logger(__name__)

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-5"

_UNSET = object()

# Only spend a real LLM call on alerts severe enough to warrant it; lower
# severities use the free, instant template fallback by design, not just
# as a degraded mode. Override by passing force_llm=True to generate().
USE_LLM_FOR_SEVERITIES = {"high", "critical"}


class LLMClient:
    def __init__(self, api_key: Any = _UNSET, model: str | None = None):
        if api_key is _UNSET:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        else:
            self.api_key = api_key
        self.model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
        self.is_configured = bool(self.api_key)

        if not self.is_configured:
            logger.warning(
                "ANTHROPIC_API_KEY not set — LLMClient will report unavailable and "
                "ResponseAgent will use its deterministic template fallback instead. "
                "Set ANTHROPIC_API_KEY in the environment to enable real LLM-generated reports."
            )

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 500) -> str | None:
        """
        Returns the generated text, or None if the LLM is unavailable or
        the call failed — callers (ResponseAgent) must handle None by
        falling back to their own template logic, never crash on it.
        """
        if not self.is_configured:
            return None

        try:
            response = requests.post(
                ANTHROPIC_API_URL,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            text_blocks = [block["text"] for block in data.get("content", []) if block.get("type") == "text"]
            return "\n".join(text_blocks).strip() or None
        except Exception as exc:
            logger.warning("LLM call failed (%s); falling back to template generation.", exc)
            return None
