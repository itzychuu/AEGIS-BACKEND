from typing import Dict, Any, Optional
from pathlib import Path

from .model_loader import get_loaded_model
from .feature_extractor import feature_frame
from .exceptions import (
    InvalidURLError,
    IncompatibleSchemaError,
    PredictionError,
)

MODEL_VERSION = "xgboost_v6"


def predict_url(url: str, model_path: Optional[Path] = None) -> Dict[str, Any]:
    """Predict whether a URL is BENIGN or PHISHING using XGBoost V6.

    Args:
        url: The URL string to evaluate.
        model_path: Optional custom path to model artifact (used for testing).

    Returns:
        Dict containing prediction (0/1), label ("BENIGN"/"PHISHING"),
        probability (float), threshold (float), and model_version.

    Raises:
        InvalidURLError: If the input URL is empty, None, or invalid.
        IncompatibleSchemaError: If feature extraction schema does not align with model.
        PredictionError: If inference fails unexpectedly.
    """
    artifact = get_loaded_model(model_path=model_path)

    feature_names = artifact["feature_names"]
    selector = artifact["selector"]
    model = artifact["model"]
    threshold = float(artifact["threshold"])

    try:
        features = feature_frame(url)
    except InvalidURLError:
        raise
    except Exception as e:
        raise PredictionError(f"Failed to extract features for URL: {str(e)}") from e

    missing_features = set(feature_names) - set(features.columns)
    if missing_features:
        raise IncompatibleSchemaError(
            f"Extracted features are missing expected columns: {sorted(missing_features)}"
        )

    # Reindex columns to ensure exact feature ordering expected by saved selector/model
    aligned_features = features.reindex(columns=feature_names, fill_value=0)

    try:
        selected_features = selector.transform(aligned_features)
        proba_array = model.predict_proba(selected_features)
        probability = float(proba_array[0][1])
    except Exception as e:
        raise PredictionError(f"Model prediction inference failed: {str(e)}") from e

    prediction = int(probability >= threshold)
    label = "PHISHING" if prediction == 1 else "BENIGN"

    return {
        "prediction": prediction,
        "label": label,
        "probability": probability,
        "threshold": threshold,
        "model_version": MODEL_VERSION,
    }