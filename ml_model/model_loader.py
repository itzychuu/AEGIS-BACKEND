from pathlib import Path
import threading
from typing import Dict, Any, Optional

import joblib

from .exceptions import (
    ModelNotFoundError,
    CorruptModelError,
    InvalidArtifactError,
)

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent
    / "existing_model"
    / "phishguard_xgb_v6.joblib"
)

REQUIRED_ARTIFACT_KEYS = {
    "model",
    "selector",
    "feature_names",
    "threshold",
}

_cached_artifact: Optional[Dict[str, Any]] = None
_model_lock = threading.Lock()


def validate_artifact(artifact: Any) -> Dict[str, Any]:
    """Validate that the loaded artifact is a dictionary with all required keys and methods."""
    if not isinstance(artifact, dict):
        raise InvalidArtifactError(
            f"Expected model artifact to be a dict, got {type(artifact).__name__}"
        )

    missing_keys = REQUIRED_ARTIFACT_KEYS - set(artifact.keys())
    if missing_keys:
        raise InvalidArtifactError(
            f"Model artifact is missing required keys: {sorted(missing_keys)}"
        )

    if not hasattr(artifact["model"], "predict_proba"):
        raise InvalidArtifactError(
            "Model object inside artifact lacks 'predict_proba' method."
        )

    if not hasattr(artifact["selector"], "transform"):
        raise InvalidArtifactError(
            "Selector object inside artifact lacks 'transform' method."
        )

    if not isinstance(artifact["feature_names"], list) or not artifact["feature_names"]:
        raise InvalidArtifactError(
            "Artifact 'feature_names' must be a non-empty list."
        )

    return artifact


def load_model(model_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and validate the XGBoost V6 joblib artifact from disk."""
    target_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH

    if not target_path.exists():
        raise ModelNotFoundError(
            f"Model artifact file not found at: {target_path}"
        )

    try:
        artifact = joblib.load(target_path)
    except Exception as e:
        raise CorruptModelError(
            f"Failed to deserialise model artifact from {target_path}: {str(e)}"
        ) from e

    return validate_artifact(artifact)


def get_loaded_model(
    model_path: Optional[Path] = None, force_reload: bool = False
) -> Dict[str, Any]:
    """Retrieve the cached model artifact, loading it lazily if not already cached."""
    global _cached_artifact

    if _cached_artifact is not None and not force_reload and model_path is None:
        return _cached_artifact

    with _model_lock:
        if _cached_artifact is None or force_reload or model_path is not None:
            loaded = load_model(model_path)
            if model_path is None:
                _cached_artifact = loaded
            return loaded
        return _cached_artifact


def clear_model_cache() -> None:
    """Clear cached model artifact (used for testing)."""
    global _cached_artifact
    with _model_lock:
        _cached_artifact = None