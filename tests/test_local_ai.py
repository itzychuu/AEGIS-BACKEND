import pytest

from local_ai.analyzer import LocalAIAnalyzer
from local_ai.config import AIConfig
from local_ai.models import AIStatus, AIAnalysisResult
from local_ai.providers import FakeLocalAIProvider
from local_ai.prompts import build_ai_context, build_prompt_messages
from aegis_engine import AnalysisResult


def test_local_ai_disabled():
    """1. Test LocalAIAnalyzer when AI is disabled in config."""
    cfg = AIConfig(enabled=False)
    analyzer = LocalAIAnalyzer(config=cfg, provider=FakeLocalAIProvider())

    res = analyzer.analyze(AnalysisResult(
        url="https://example.com", classification="SAFE", risk_score=5,
        cached=False, reasons=[], signals={}, model_version="xgboost_v6", analysis_time_ms=1.0
    ))

    assert res.available is False
    assert res.status == AIStatus.DISABLED


def test_local_ai_analyzer_success():
    """2. Test LocalAIAnalyzer with enabled FakeLocalAIProvider."""
    cfg = AIConfig(enabled=True)
    provider = FakeLocalAIProvider()
    analyzer = LocalAIAnalyzer(config=cfg, provider=provider)

    analysis_res = AnalysisResult(
        url="https://example.com", classification="SAFE", risk_score=5,
        cached=False, reasons=["Low ML risk"], signals={"ml_probability": 0.05},
        model_version="xgboost_v6", analysis_time_ms=10.0
    )

    res = analyzer.analyze(analysis_res)

    assert isinstance(res, AIAnalysisResult)
    assert res.available is True
    assert res.status == AIStatus.SUCCESS
    assert "summary" in res.to_dict()
    assert res.provider == "fake"


def test_local_ai_unavailable_runtime():
    """3. Test LocalAIAnalyzer when AI server is offline (health check fails)."""
    cfg = AIConfig(enabled=True)
    provider = FakeLocalAIProvider(is_healthy=False)
    analyzer = LocalAIAnalyzer(config=cfg, provider=provider)

    res = analyzer.analyze(AnalysisResult(
        url="https://example.com", classification="SAFE", risk_score=5,
        cached=False, reasons=[], signals={}, model_version="xgboost_v6", analysis_time_ms=1.0
    ))

    assert res.available is False
    assert res.status == AIStatus.UNAVAILABLE
    assert "offline" in res.error.lower()


def test_local_ai_model_not_found():
    """4. Test LocalAIAnalyzer when model is missing in local runtime."""
    cfg = AIConfig(enabled=True, model="missing-model-xyz")
    provider = FakeLocalAIProvider(installed_models=["qwen3:4b-instruct"])
    analyzer = LocalAIAnalyzer(config=cfg, provider=provider)

    res = analyzer.analyze(AnalysisResult(
        url="https://example.com", classification="SAFE", risk_score=5,
        cached=False, reasons=[], signals={}, model_version="xgboost_v6", analysis_time_ms=1.0
    ))

    assert res.available is False
    assert res.status == AIStatus.MODEL_NOT_FOUND


def test_prompt_messages_sanitization():
    """5. Test build_ai_context and build_prompt_messages structure."""
    analysis_res = AnalysisResult(
        url="https://example.com/login",
        classification="CRITICAL",
        risk_score=95,
        cached=False,
        reasons=["High ML probability", "Blocklist match"],
        signals={
            "ml_probability": 0.95,
            "cyber_analysis": {
                "dns": {"data": {"resolved": True, "a_records": ["93.184.216.34"]}},
                "threat_intel": {"data": {"is_blocked": True, "matched": True}}
            }
        },
        model_version="xgboost_v6",
        analysis_time_ms=50.0
    )

    ctx = build_ai_context(analysis_res)
    assert ctx.url == "https://example.com/login"
    assert ctx.risk_score == 95
    assert ctx.classification == "CRITICAL"
    assert ctx.dns_signals["resolved"] is True
    assert ctx.threat_intel_signals["is_blocked"] is True

    messages = build_prompt_messages(ctx)
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "target_url" in messages[1]["content"]
