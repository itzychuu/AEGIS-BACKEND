import os
from dataclasses import dataclass, field

DEFAULT_TTL_SECONDS = 3600
DEFAULT_MAX_ENTRIES = 1000
DEFAULT_MODEL_VERSION = "xgboost_v6"


@dataclass
class CachePolicy:
    """Configurable policy settings for the in-memory trust cache."""
    ttl_seconds: int = field(
        default_factory=lambda: int(
            os.getenv("AEGIS_CACHE_TTL_SECONDS", str(DEFAULT_TTL_SECONDS))
        )
    )
    max_entries: int = field(
        default_factory=lambda: int(
            os.getenv("AEGIS_CACHE_MAX_ENTRIES", str(DEFAULT_MAX_ENTRIES))
        )
    )
    active_model_version: str = DEFAULT_MODEL_VERSION

    def __post_init__(self):
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        if self.max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
