"""
Tests for ai_engine.agents.llm_client.
"""

from unittest.mock import MagicMock, patch

from ai_engine.agents.llm_client import LLMClient


def test_no_api_key_means_not_configured():
    client = LLMClient(api_key=None)
    assert client.is_configured is False


def test_generate_returns_none_when_not_configured():
    client = LLMClient(api_key=None)
    result = client.generate("system prompt", "user prompt")
    assert result is None


def test_configured_with_explicit_api_key():
    client = LLMClient(api_key="fake-key-123")
    assert client.is_configured is True


@patch("ai_engine.agents.llm_client.requests.post")
def test_generate_returns_text_on_successful_call(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {"content": [{"type": "text", "text": "Generated report text."}]}
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    client = LLMClient(api_key="fake-key-123")
    result = client.generate("system", "user")

    assert result == "Generated report text."


@patch("ai_engine.agents.llm_client.requests.post")
def test_generate_returns_none_on_api_error(mock_post):
    mock_post.side_effect = Exception("network error")

    client = LLMClient(api_key="fake-key-123")
    result = client.generate("system", "user")

    assert result is None


@patch("ai_engine.agents.llm_client.requests.post")
def test_generate_sends_correct_request_shape(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {"content": [{"type": "text", "text": "ok"}]}
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    client = LLMClient(api_key="fake-key-123", model="test-model")
    client.generate("sys prompt", "user prompt", max_tokens=100)

    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["headers"]["x-api-key"] == "fake-key-123"
    assert call_kwargs["json"]["model"] == "test-model"
    assert call_kwargs["json"]["system"] == "sys prompt"
    assert call_kwargs["json"]["messages"][0]["content"] == "user prompt"
    assert call_kwargs["json"]["max_tokens"] == 100
