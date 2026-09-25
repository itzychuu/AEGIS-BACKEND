import pytest
from unittest.mock import MagicMock

from aegis_engine import AegisEngine, AnalysisResult
from local_ai import LocalAIAnalyzer, AIConfig, AIStatus
from local_ai.providers import FakeLocalAIProvider
from local_ai.exceptions import AITimeoutError


def test_engine_integration_ai_disabled():
    """1. Test AegisEngine with AI disabled does not populate res.ai."""
    cfg = AIConfig(enabled=False)
    ai_analyzer = LocalAIAnalyzer(config=cfg, provider=FakeLocalAIProvider())

    mock_predictor = MagicMock(return_value={
        "prediction": 0, "label": "BENIGN", "probability": 0.05,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })

    engine = AegisEngine(predictor_fn=mock_predictor, ai_analyzer=ai_analyzer, enable_ai=False)
    res = engine.analyze("https://example.com")

    assert isinstance(res, AnalysisResult)
    assert res.ai is None
    assert res.risk_score == 5
    assert res.classification == "SAFE"


def test_engine_integration_ai_enabled_success():
    """2 & 8 & 9. Test AegisEngine with AI enabled attaches res.ai while preserving deterministic risk/classification."""
    cfg = AIConfig(enabled=True)
    ai_analyzer = LocalAIAnalyzer(config=cfg, provider=FakeLocalAIProvider())

    mock_predictor = MagicMock(return_value={
        "prediction": 0, "label": "BENIGN", "probability": 0.05,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })

    engine = AegisEngine(predictor_fn=mock_predictor, ai_analyzer=ai_analyzer, enable_ai=True)
    res = engine.analyze("https://example.com")

    assert res.ai is not None
    assert res.ai["available"] is True
    assert res.ai["status"] == AIStatus.SUCCESS
    assert "summary" in res.ai

    # Deterministic authority check: risk score and classification MUST NOT change
    assert res.risk_score == 5
    assert res.classification == "SAFE"


def test_engine_integration_ai_failure_isolation():
    """3 & 4. Test that AI failure does NOT crash AegisEngine or fail open."""
    cfg = AIConfig(enabled=True)
    provider = FakeLocalAIProvider(simulated_error=AITimeoutError("AI request timed out"))
    ai_analyzer = LocalAIAnalyzer(config=cfg, provider=provider)

    mock_predictor = MagicMock(return_value={
        "prediction": 1, "label": "PHISHING", "probability": 0.95,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })

    engine = AegisEngine(predictor_fn=mock_predictor, ai_analyzer=ai_analyzer, enable_ai=True)
    res = engine.analyze("https://phishing-site.com")

    assert res.ai is not None
    assert res.ai["available"] is False
    assert res.ai["status"] == AIStatus.TIMEOUT

    # Deterministic score & classification preserved!
    assert res.risk_score == 95
    assert res.classification == "CRITICAL"


def test_engine_integration_cache_preserves_ai_output():
    """5. Test that Trust Cache preserves res.ai dictionary on cache hit."""
    cfg = AIConfig(enabled=True)
    ai_analyzer = LocalAIAnalyzer(config=cfg, provider=FakeLocalAIProvider())

    mock_predictor = MagicMock(return_value={
        "prediction": 0, "label": "BENIGN", "probability": 0.05,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })

    engine = AegisEngine(predictor_fn=mock_predictor, ai_analyzer=ai_analyzer, enable_ai=True)

    # First call (Cache miss)
    res1 = engine.analyze("https://example.com")
    assert res1.cached is False
    assert res1.ai is not None
    assert res1.ai["available"] is True

    # Second call (Cache hit)
    res2 = engine.analyze("https://example.com")
    assert res2.cached is True
    assert res2.ai is not None
    assert res2.ai["summary"] == res1.ai["summary"]
