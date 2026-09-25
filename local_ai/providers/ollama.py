import json
import socket
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

from local_ai.exceptions import AIProviderError, AITimeoutError, AIModelNotFoundError
from .base import LocalAIProvider


class OllamaProvider(LocalAIProvider):
    """Model-agnostic adapter for local Ollama server chat/instruction interface."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        default_model: str = "qwen3:4b-instruct",
    ):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    @property
    def name(self) -> str:
        return "ollama"

    def health_check(self) -> bool:
        """Ping local Ollama server to check if online and reachable."""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                headers={"User-Agent": "AegisBackend/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return resp.status == 200
        except Exception:
            return False

    def is_model_available(self, model_name: str) -> bool:
        """Check whether the specified model is installed in the local Ollama instance."""
        target = model_name.strip().lower()
        if not target:
            return False

        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                headers={"User-Agent": "AegisBackend/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status != 200:
                    return False
                data = json.loads(resp.read().decode("utf-8"))
                installed_models = [
                    m.get("name", "").lower() for m in data.get("models", [])
                ]

                # Match exact name, latest tag, or base model name prefix
                for installed in installed_models:
                    if target == installed:
                        return True
                    if target + ":latest" == installed:
                        return True
                    if installed.startswith(target + ":"):
                        return True
                    if target.split(":")[0] == installed.split(":")[0]:
                        return True
                return False
        except Exception:
            return False

    def generate(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 512,
        timeout: float = 10.0,
        model_override: Optional[str] = None,
    ) -> str:
        """Send chat messages to local Ollama API and return model's text response."""
        target_model = model_override or self.default_model

        payload = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        json_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json_data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AegisBackend/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status != 200:
                    raise AIProviderError(
                        f"Ollama API returned HTTP status {response.status}"
                    )
                resp_bytes = response.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))

                # Extract completion string
                msg_data = resp_json.get("message", {})
                content = msg_data.get("content", "").strip()
                if not content:
                    raise AIProviderError("Ollama API returned empty content string")
                return content

        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise AIModelNotFoundError(
                    f"Configured model '{target_model}' not found in Ollama runtime"
                ) from e
            raise AIProviderError(
                f"Ollama HTTP error {e.code}: {e.reason}"
            ) from e
        except (socket.timeout, TimeoutError) as e:
            raise AITimeoutError(
                f"Ollama API request timed out after {timeout}s"
            ) from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                raise AITimeoutError(
                    f"Ollama API request timed out after {timeout}s"
                ) from e
            raise AIProviderError(
                f"Failed to connect to Ollama at {self.base_url}: {str(e.reason)}"
            ) from e
        except Exception as e:
            if isinstance(e, (AITimeoutError, AIModelNotFoundError, AIProviderError)):
                raise
            raise AIProviderError(
                f"Unexpected Ollama provider error: {str(e)}"
            ) from e
