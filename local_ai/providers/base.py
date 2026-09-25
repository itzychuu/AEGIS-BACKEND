from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class LocalAIProvider(ABC):
    """Abstract base provider interface for model-agnostic local AI execution."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name identifier of the provider (e.g., 'ollama', 'fake')."""
        pass

    @abstractmethod
    def generate(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: float = 0.1,
        max_tokens: int = 512,
        timeout: float = 10.0,
        model_override: Optional[str] = None,
    ) -> str:
        """Generate text completion from standardized system/user chat messages."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Determine whether the local AI runtime server is online and reachable."""
        pass

    @abstractmethod
    def is_model_available(self, model_name: str) -> bool:
        """Check whether the specified model is installed in the local runtime."""
        pass
