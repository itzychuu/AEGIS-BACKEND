import os
from dataclasses import dataclass, field

DEFAULT_AI_ENABLED = False
DEFAULT_AI_PROVIDER = "ollama"
DEFAULT_AI_MODEL = "qwen3:4b-instruct"
DEFAULT_AI_BASE_URL = "http://localhost:11434"
DEFAULT_AI_TIMEOUT = 10.0
DEFAULT_AI_TEMPERATURE = 0.1
DEFAULT_AI_MAX_TOKENS = 512
DEFAULT_AI_MAX_FINDINGS = 8
DEFAULT_AI_MAX_TEXT_LENGTH = 1000


@dataclass
class AIConfig:
    """Centralized, model-agnostic configuration for the Local AI module."""
    enabled: bool = field(
        default_factory=lambda: os.getenv("AEGIS_AI_ENABLED", "false").lower() == "true"
    )
    provider: str = field(
        default_factory=lambda: os.getenv("AEGIS_AI_PROVIDER", DEFAULT_AI_PROVIDER)
    )
    model: str = field(
        default_factory=lambda: os.getenv("AEGIS_AI_MODEL", DEFAULT_AI_MODEL)
    )
    base_url: str = field(
        default_factory=lambda: os.getenv("AEGIS_AI_BASE_URL", DEFAULT_AI_BASE_URL)
    )
    timeout: float = field(
        default_factory=lambda: float(os.getenv("AEGIS_AI_TIMEOUT", str(DEFAULT_AI_TIMEOUT)))
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv("AEGIS_AI_TEMPERATURE", str(DEFAULT_AI_TEMPERATURE)))
    )
    max_tokens: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_AI_MAX_TOKENS", str(DEFAULT_AI_MAX_TOKENS)))
    )
    max_findings: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_AI_MAX_FINDINGS", str(DEFAULT_AI_MAX_FINDINGS)))
    )
    max_text_length: int = field(
        default_factory=lambda: int(os.getenv("AEGIS_AI_MAX_TEXT_LENGTH", str(DEFAULT_AI_MAX_TEXT_LENGTH)))
    )
