from typing import Optional
from aegis_engine import AegisEngine

_engine_instance: Optional[AegisEngine] = None


def get_aegis_engine() -> AegisEngine:
    """FastAPI dependency providing a reusable, thread-safe AegisEngine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AegisEngine()
    return _engine_instance


def reset_aegis_engine() -> None:
    """Reset the global AegisEngine singleton (useful for isolated unit testing)."""
    global _engine_instance
    _engine_instance = None
