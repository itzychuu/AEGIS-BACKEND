import math
import pytest
from pathlib import Path
import pandas as pd
import joblib

from ml_model.model_loader import (
    load_model,
    get_loaded_model,
    clear_model_cache,
    DEFAULT_MODEL_PATH,
)
from ml_model.feature_extractor import (
    normalize_url,
    extract_features,
    feature_frame,
    entropy,
)
from ml_model.predictor import predict_url, MODEL_VERSION
from ml_model.exceptions import (
    MLError,
    ModelNotFoundError,
    CorruptModelError,
    InvalidArtifactError,
    InvalidURLError,
    IncompatibleSchemaError,
    PredictionError,
)


@pytest.fixture(autouse=True)
def reset_cache():
    clear_model_cache()
    yield
    clear_model_cache()


def test_model_loading():
    """1. Test that model artifact loads successfully from default path."""
    artifact = load_model()
    assert isinstance(artifact, dict)
    assert "model" in artifact
    assert "selector" in artifact
    assert "feature_names" in artifact
    assert "threshold" in artifact


def test_artifact_structure():
    """2. Test that model artifact keys and types match V6 requirements."""
    artifact = get_loaded_model()
    assert artifact["feature_version"] == 6
    assert isinstance(artifact["threshold"], (float, int))
    assert artifact["threshold"] > 0.0 and artifact["threshold"] < 1.0
    assert hasattr(artifact["model"], "predict_proba")
    assert hasattr(artifact["selector"], "transform")
    assert isinstance(artifact["feature_names"], list)
    assert len(artifact["feature_names"]) == 51
    assert isinstance(artifact["selected_features"], list)
    assert len(artifact["selected_features"]) == 32


def test_feature_extraction():
    """3. Test feature extraction generates expected dictionary structure and types."""
    feats = extract_features("https://example.com/login?user=admin")
    assert isinstance(feats, dict)
    assert len(feats) == 51

    # Check specific feature values for known input
    assert feats["has_https"] == 1
    assert feats["has_http"] == 0
    assert feats["hostname_length"] == len("example.com")
    assert feats["suspicious_word_count"] >= 1  # 'login' is present
    assert feats["has_suspicious_word"] == 1
    assert feats["query_parameter_count"] == 1
    assert feats["tld_is_common"] == 1

    # Ensure no NaN or Inf in feature dictionary
    for k, v in feats.items():
        assert not math.isnan(v), f"Feature {k} returned NaN"
        assert not math.isinf(v), f"Feature {k} returned Inf"


def test_feature_names():
    """4. Test that extracted feature names match the saved artifact feature names exactly."""
    artifact = get_loaded_model()
    feats = extract_features("https://google.com")
    extracted_names = list(feats.keys())
    assert extracted_names == artifact["feature_names"]


def test_feature_ordering():
    """5. Test that feature_frame produces columns in exact training feature order."""
    artifact = get_loaded_model()
    frame = feature_frame("https://google.com")
    assert isinstance(frame, pd.DataFrame)
    assert list(frame.columns) == artifact["feature_names"]


def test_url_normalization():
    """6. Test canonical URL normalization rules."""
    assert normalize_url("google.com") == "https://google.com"
    assert normalize_url("http://google.com") == "http://google.com"
    assert normalize_url("HTTPS://GOOGLE.COM") == "https://google.com"
    assert normalize_url("  example.org/path  ") == "https://example.org/path"


def test_malformed_url_handling():
    """7. Test input validation and malformed URL handling."""
    # Invalid inputs must raise InvalidURLError
    with pytest.raises(InvalidURLError):
        predict_url("")

    with pytest.raises(InvalidURLError):
        predict_url("   ")

    with pytest.raises(InvalidURLError):
        predict_url(None)

    with pytest.raises(InvalidURLError):
        predict_url(12345)

    # Unusual / complex URLs should be handled safely without crashing
    unusual_urls = [
        "http://192.168.1.1/admin",
        "https://user:pass@example.com:8080/path?query=1#frag",
        "http://xn--fsqu00a.xn--0zwm56d.com/",
        "http://very-long-subdomain.test.example.co.uk/a/b/c/d/e/f/g?x=1&y=2&z=3",
        "https://domain.com/path//with///multiple////slashes",
    ]
    for url in unusual_urls:
        result = predict_url(url)
        assert "prediction" in result
        assert result["prediction"] in (0, 1)


def test_prediction_output_structure():
    """8. Test prediction structure returned by predict_url."""
    result = predict_url("https://example.com")
    assert isinstance(result, dict)
    assert "prediction" in result
    assert "label" in result
    assert "probability" in result
    assert "threshold" in result
    assert "model_version" in result

    assert result["prediction"] in (0, 1)
    assert result["label"] in ("BENIGN", "PHISHING")
    assert isinstance(result["probability"], float)
    assert 0.0 <= result["probability"] <= 1.0
    assert isinstance(result["threshold"], float)
    assert result["model_version"] == MODEL_VERSION


def test_threshold_usage():
    """9. Test that label decision respects saved threshold strictly."""
    artifact = get_loaded_model()
    threshold = artifact["threshold"]

    res_benign = predict_url("https://www.google.com")
    assert res_benign["threshold"] == threshold

    if res_benign["probability"] >= threshold:
        assert res_benign["prediction"] == 1
        assert res_benign["label"] == "PHISHING"
    else:
        assert res_benign["prediction"] == 0
        assert res_benign["label"] == "BENIGN"


def test_selector_usage():
    """10. Test that the saved selector transforms features to selected size."""
    artifact = get_loaded_model()
    frame = feature_frame("https://example.com")
    selector = artifact["selector"]

    # Transform without fit
    selected = selector.transform(frame)
    assert selected.shape[1] == len(artifact["selected_features"])
    assert selected.shape[1] == 32


def test_repeated_predictions():
    """11. Test multiple consecutive predictions for performance and consistency."""
    urls = [
        "https://google.com",
        "https://github.com",
        "https://wikipedia.org",
        "https://python.org",
        "https://amazon.com",
    ]
    results = [predict_url(u) for u in urls]
    assert len(results) == len(urls)
    for r in results:
        assert r["prediction"] in (0, 1)

    # Identical input produces identical output
    r1 = predict_url("https://google.com")
    r2 = predict_url("https://google.com")
    assert r1 == r2


def test_model_reuse():
    """12. Test singleton model loading behavior (model loaded once)."""
    m1 = get_loaded_model()
    m2 = get_loaded_model()
    assert m1 is m2  # Exact same memory object


def test_missing_model_file(tmp_path):
    """13a. Test exception when model file is missing."""
    non_existent = tmp_path / "does_not_exist.joblib"
    with pytest.raises(ModelNotFoundError):
        load_model(non_existent)


def test_corrupt_model_file(tmp_path):
    """13b. Test exception when model file is corrupt."""
    corrupt_file = tmp_path / "corrupt.joblib"
    corrupt_file.write_bytes(b"NOT_A_VALID_JOBLIB_FILE")
    with pytest.raises(CorruptModelError):
        load_model(corrupt_file)


def test_invalid_artifact_structure(tmp_path):
    """13c. Test exception when joblib file contains invalid artifact dictionary."""
    invalid_file = tmp_path / "invalid.joblib"
    joblib.dump({"incomplete": "dict"}, invalid_file)
    with pytest.raises(InvalidArtifactError):
        load_model(invalid_file)


def test_schema_mismatch_error(monkeypatch):
    """13d. Test exception when feature schema is missing required columns."""
    artifact = get_loaded_model()
    # Mock feature_frame to return missing columns
    empty_frame = pd.DataFrame([{"url_length": 10}])
    monkeypatch.setattr("ml_model.predictor.feature_frame", lambda url: empty_frame)
    with pytest.raises(IncompatibleSchemaError):
        predict_url("https://example.com")


def test_local_test_url_suite():
    """14. Local test set evaluation covering benign and suspicious URLs."""
    test_urls = [
        # Benign URLs
        "https://www.wikipedia.org",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://github.com/torvalds/linux",
        "http://example.org",
        "https://stackoverflow.com/questions/12345/example",
        # Synthetic / suspicious-looking URLs
        "http://secure-login-verify-account-update-billing.bank-alert-claim.com/signin/credential.php?user=123&session=abc&auth=xyz",
        "http://paypal.com.verify-login-update-security-account.info/login.php",
        "http://192.168.1.1/login/verify.asp?account=update",
    ]

    for url in test_urls:
        res = predict_url(url)
        assert isinstance(res["prediction"], int)
        assert res["label"] in ("BENIGN", "PHISHING")
        assert 0.0 <= res["probability"] <= 1.0
        assert res["threshold"] > 0.0
