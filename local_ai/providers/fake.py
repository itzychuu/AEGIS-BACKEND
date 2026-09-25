import json
from typing import List, Dict, Any, Optional

from local_ai.exceptions import AIProviderError, AITimeoutError, AIModelNotFoundError
from .base import LocalAIProvider

DEFAULT_FAKE_RESPONSE = {
    "summary": "Deterministic test security correlation summary.",
    "risk_assessment": "The evidence supports the classification based on ML probability and security signals.",
    "key_findings": [
        "ML probability evaluated for target URL",
        "Cybersecurity signals analyzed"
    ],
    "supporting_signals": [
        "ml_probability",
        "dns_resolution"
    ],
    "conflicting_signals": [],
    "uncertainties": [
        "No threat intelligence match recorded"
    ]
}


class FakeLocalAIProvider(LocalAIProvider):
    """Deterministic mock provider for unit testing without local LLM or network calls."""

    def __init__(
        self,
        response_dict: Optional[Dict[str, Any]] = None,
        raw_response: Optional[str] = None,
        simulated_error: Optional[Exception] = None,
        is_healthy: bool = True,
        installed_models: Optional[List[str]] = None,
    ):
        self.response_dict = response_dict or DEFAULT_FAKE_RESPONSE
        self.raw_response = raw_response
        self.simulated_error = simulated_error
        self.is_healthy = is_healthy
        self.installed_models = installed_models or ["qwen3:4b-instruct", "test-model"]

    @property
    def name(self) -> str:
        return "fake"

    def health_check(self) -> bool:
        return self.is_healthy

    def is_model_available(self, model_name: str) -> bool:
        if not self.is_healthy:
            return False
        m = model_name.strip().lower()
        return any(m in installed.lower() for installed in self.installed_models)

    def generate(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 512,
        timeout: float = 10.0,
        model_override: Optional[str] = None,
    ) -> str:
        if self.simulated_error:
            raise self.simulated_error

        if self.raw_response is not None:
            return self.raw_response

        return json.dumps(self.response_dict, indent=2)
