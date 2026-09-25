import socket
import urllib.error
import pytest
from unittest.mock import patch, MagicMock

from local_ai.providers import OllamaProvider, FakeLocalAIProvider
from local_ai.exceptions import AIProviderError, AITimeoutError, AIModelNotFoundError


def test_fake_provider_success():
    """1. Test FakeLocalAIProvider returns deterministic JSON response."""
    provider = FakeLocalAIProvider()
    assert provider.name == "fake"
    assert provider.health_check() is True
    assert provider.is_model_available("qwen3:4b-instruct") is True

    messages = [{"role": "user", "content": "hello"}]
    res = provider.generate(messages)
    assert isinstance(res, str)
    assert "summary" in res


def test_ollama_provider_health_check_online():
    """2. Test OllamaProvider health_check when local server is online."""
    provider = OllamaProvider(base_url="http://localhost:11434")
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        assert provider.health_check() is True


def test_ollama_provider_health_check_offline():
    """3. Test OllamaProvider health_check when local server is offline."""
    provider = OllamaProvider(base_url="http://localhost:11434")

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        assert provider.health_check() is False


def test_ollama_provider_is_model_available():
    """4. Test OllamaProvider model discovery via /api/tags."""
    provider = OllamaProvider(base_url="http://localhost:11434")
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = b'{"models": [{"name": "qwen3:4b-instruct"}, {"name": "llama3:latest"}]}'

    with patch("urllib.request.urlopen", return_value=mock_resp):
        assert provider.is_model_available("qwen3:4b-instruct") is True
        assert provider.is_model_available("llama3") is True
        assert provider.is_model_available("nonexistent-model") is False


def test_ollama_provider_generate_success():
    """5. Test OllamaProvider generate sends correct JSON payload to /api/chat."""
    provider = OllamaProvider(base_url="http://localhost:11434", default_model="qwen3:4b-instruct")
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = b'{"message": {"role": "assistant", "content": "{\\"summary\\": \\"OK\\"}"}}'

    messages = [{"role": "user", "content": "hi"}]

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = provider.generate(messages, temperature=0.1, max_tokens=256, timeout=5.0)
        assert res == '{"summary": "OK"}'


def test_ollama_provider_model_not_found_error():
    """6. Test OllamaProvider raises AIModelNotFoundError on HTTP 404."""
    provider = OllamaProvider()
    http_err = urllib.error.HTTPError(
        url="http://localhost:11434/api/chat", code=404, msg="Not Found", hdrs={}, fp=None
    )

    with patch("urllib.request.urlopen", side_effect=http_err):
        with pytest.raises(AIModelNotFoundError):
            provider.generate([{"role": "user", "content": "hi"}])


def test_ollama_provider_timeout_error():
    """7. Test OllamaProvider raises AITimeoutError on timeout."""
    provider = OllamaProvider()

    with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
        with pytest.raises(AITimeoutError):
            provider.generate([{"role": "user", "content": "hi"}], timeout=0.1)
