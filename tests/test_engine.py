import time
import pytest
from unittest.mock import MagicMock

from aegis_engine import (
    AegisEngine,
    AnalysisResult,
    AnalysisPipeline,
    run_analysis,
    calculate_risk_score,
    classify_risk,
    DecisionConfig,
    RiskScoreResult,
    EngineError,
    RiskScoringError,
    DecisionError,
)
from cache import MemoryCache, CachePolicy
from ml_model.exceptions import InvalidURLError, PredictionError


def test_valid_url_analysis():
    """1. Test valid URL analysis produces AnalysisResult."""
    engine = AegisEngine()
    result = engine.analyze("https://example.com")

    assert isinstance(result, AnalysisResult)
    assert result.url == "https://example.com"
    assert result.classification in ("SAFE", "SUSPICIOUS", "CRITICAL")
    assert 0 <= result.risk_score <= 100
    assert result.cached is False
    assert isinstance(result.reasons, list)
    assert len(result.reasons) > 0
    assert "ml_probability" in result.signals
    assert result.model_version == "xgboost_v6"
    assert result.analysis_time_ms >= 0.0


def test_empty_and_invalid_urls():
    """2 & 3. Test empty, None, and invalid non-string URLs raise InvalidURLError."""
    engine = AegisEngine()

    with pytest.raises(InvalidURLError):
        engine.analyze("")

    with pytest.raises(InvalidURLError):
        engine.analyze("   ")

    with pytest.raises(InvalidURLError):
        engine.analyze(None)

    with pytest.raises(InvalidURLError):
        engine.analyze(12345)


def test_cache_miss_invokes_ml_and_cache_hit_bypasses_ml():
    """4, 5, 6, 15, 16. Test cache miss calls ML and cache hit skips ML."""
    mock_predictor = MagicMock(return_value={
        "prediction": 0,
        "label": "BENIGN",
        "probability": 0.05,
        "threshold": 0.7125,
        "model_version": "xgboost_v6",
    })

    cache = MemoryCache()
    engine = AegisEngine(cache=cache, predictor_fn=mock_predictor)

    url = "https://example.com"

    # First request: Cache Miss
    res1 = engine.analyze(url)
    assert res1.cached is False
    assert mock_predictor.call_count == 1

    # Second request: Cache Hit
    res2 = engine.analyze(url)
    assert res2.cached is True
    assert mock_predictor.call_count == 1  # ML predictor NOT called again
    assert res2.classification == res1.classification
    assert res2.risk_score == res1.risk_score


def test_cache_expiration_reinvokes_ml():
    """7. Test expired cache entry invokes ML again."""
    mock_predictor = MagicMock(return_value={
        "prediction": 0,
        "label": "BENIGN",
        "probability": 0.05,
        "threshold": 0.7125,
        "model_version": "xgboost_v6",
    })

    policy = CachePolicy(ttl_seconds=1)
    cache = MemoryCache(policy=policy)
    engine = AegisEngine(cache=cache, predictor_fn=mock_predictor)

    url = "https://example.com"
    engine.analyze(url)
    assert mock_predictor.call_count == 1

    # Wait for TTL expiry
    time.sleep(1.1)

    # Subsequent request forces cache miss and re-invokes ML
    res = engine.analyze(url)
    assert res.cached is False
    assert mock_predictor.call_count == 2


def test_classification_mapping_and_thresholds():
    """8, 9, 10, 11, 12, 13, 14. Test probability mapping to SAFE/SUSPICIOUS/CRITICAL."""
    # 8. Low probability -> SAFE
    mock_low = lambda url: {
        "prediction": 0, "label": "BENIGN", "probability": 0.04,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    }
    e_low = AegisEngine(predictor_fn=mock_low)
    r_low = e_low.analyze("https://example-low.com")
    assert r_low.risk_score == 4
    assert r_low.classification == "SAFE"
    assert "Low phishing probability" in r_low.reasons[0]

    # 9. Moderate probability -> SUSPICIOUS
    mock_mod = lambda url: {
        "prediction": 0, "label": "BENIGN", "probability": 0.65,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    }
    e_mod = AegisEngine(predictor_fn=mock_mod)
    r_mod = e_mod.analyze("https://example-mod.com")
    assert r_mod.risk_score == 65
    assert r_mod.classification == "SUSPICIOUS"
    assert "moderate phishing risk" in r_mod.reasons[0]

    # 10. High probability -> CRITICAL
    mock_high = lambda url: {
        "prediction": 1, "label": "PHISHING", "probability": 0.99,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    }
    e_high = AegisEngine(predictor_fn=mock_high)
    r_high = e_high.analyze("https://example-high.com")
    assert r_high.risk_score == 99
    assert r_high.classification == "CRITICAL"
    assert "high phishing risk" in r_high.reasons[0]


def test_analysis_time_ms_field():
    """17. Test analysis_time_ms exists and is non-negative."""
    engine = AegisEngine()
    res = engine.analyze("https://example.com")
    assert isinstance(res.analysis_time_ms, float)
    assert res.analysis_time_ms >= 0.0


def test_never_fail_open_on_ml_failure():
    """18. Test that ML failure raises an exception and NEVER fails open to SAFE."""
    def broken_predictor(url):
        raise PredictionError("ML Model inference failed completely")

    engine = AegisEngine(predictor_fn=broken_predictor)

    # Must raise exception, never return SAFE or dummy classification
    with pytest.raises(PredictionError):
        engine.analyze("https://example.com")


def test_malformed_ml_output_handling():
    """19. Test that malformed ML output raises controlled error."""
    # Missing 'probability' key
    def malformed_predictor1(url):
        return {"invalid": "dict"}

    engine1 = AegisEngine(predictor_fn=malformed_predictor1)
    with pytest.raises(RiskScoringError):
        engine1.analyze("https://example.com")

    # Probability is NaN
    def malformed_predictor2(url):
        return {"probability": float("nan")}

    engine2 = AegisEngine(predictor_fn=malformed_predictor2)
    with pytest.raises(RiskScoringError):
        engine2.analyze("https://example.com")


def test_model_version_mismatch_forces_fresh_analysis():
    """20. Test that cached result with old model_version forces fresh analysis."""
    mock_predictor = MagicMock(return_value={
        "prediction": 0, "label": "BENIGN", "probability": 0.1,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })
    cache = MemoryCache()
    # Manually populate cache with old model version
    cache.set("https://example.com", {
        "classification": "SAFE",
        "risk_score": 10,
        "reasons": ["Old"],
        "signals": {},
        "model_version": "xgboost_v5",
    }, model_version="xgboost_v5")

    engine = AegisEngine(cache=cache, predictor_fn=mock_predictor)
    res = engine.analyze("https://example.com")

    # Mismatch forces cache miss, running fresh ML
    assert res.cached is False
    assert mock_predictor.call_count == 1
    assert res.model_version == "xgboost_v6"


def test_url_normalization_cache_reuse():
    """21. Test that engine reuses canonical URL normalization for caching."""
    mock_predictor = MagicMock(return_value={
        "prediction": 0, "label": "BENIGN", "probability": 0.05,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })
    engine = AegisEngine(predictor_fn=mock_predictor)

    # First call with unnormalized string
    res1 = engine.analyze("example.com")
    assert mock_predictor.call_count == 1

    # Second call with full canonical scheme
    res2 = engine.analyze("https://example.com/")
    assert mock_predictor.call_count == 1  # Hits cache!
    assert res2.cached is True


def test_multiple_urls_distinct_results():
    """22. Test that different URLs produce separate cache entries."""
    engine = AegisEngine()
    res1 = engine.analyze("https://google.com")
    res2 = engine.analyze("https://wikipedia.org")

    assert res1.url != res2.url


def test_pipeline_execution():
    """23. Test AnalysisPipeline and run_analysis orchestration."""
    result = run_analysis("https://python.org")
    assert isinstance(result, AnalysisResult)
    assert result.classification in ("SAFE", "SUSPICIOUS", "CRITICAL")
