import pytest
from unittest.mock import MagicMock

from cyber_analysis import (
    CyberOrchestrator,
    CyberAnalysisResult,
    AnalyzerResult,
    SecuritySignal,
    SecuritySeverity,
)
from aegis_engine import AegisEngine, AnalysisResult, calculate_risk_score, classify_risk


def test_cyber_orchestrator_parallel_execution():
    """1, 5, 6, 7, 8. Test CyberOrchestrator runs all analyzers and aggregates signals and timings."""
    mock_dns = MagicMock()
    mock_dns.analyze.return_value = AnalyzerResult(
        available=True,
        status="success",
        data={"hostname": "example.com"},
        signals=[SecuritySignal("dns", "direct_ip_host", "medium", "Direct IP host")],
        execution_time_ms=10.0,
    )

    mock_http = MagicMock()
    mock_http.analyze.return_value = AnalyzerResult(
        available=True,
        status="success",
        data={"status_code": 200},
        signals=[SecuritySignal("http", "plain_http", "low", "Plain HTTP")],
        execution_time_ms=15.0,
    )

    mock_tls = MagicMock()
    mock_tls.analyze.return_value = AnalyzerResult(available=True, status="success", execution_time_ms=5.0)

    mock_redirects = MagicMock()
    mock_redirects.analyze.return_value = AnalyzerResult(available=True, status="success", execution_time_ms=8.0)

    mock_intel = MagicMock()
    mock_intel.lookup_url.return_value = AnalyzerResult(
        available=True,
        status="success",
        signals=[SecuritySignal("threat_intel", "known_malicious_match", "critical", "Blocklist match")],
        execution_time_ms=2.0,
    )

    orchestrator = CyberOrchestrator(
        dns_analyzer=mock_dns,
        http_analyzer=mock_http,
        tls_analyzer=mock_tls,
        redirect_analyzer=mock_redirects,
        threat_intel_provider=mock_intel,
    )

    res = orchestrator.analyze("http://example.com")

    assert isinstance(res, CyberAnalysisResult)
    assert res.dns.available is True
    assert res.http.available is True
    assert len(res.signals) == 3
    assert res.total_time_ms >= 0.0


def test_cyber_orchestrator_error_isolation():
    """2, 3. Test that failure in one analyzer does not crash remaining analyzers."""
    mock_dns = MagicMock()
    mock_dns.analyze.side_effect = RuntimeError("DNS socket failure")

    mock_http = MagicMock()
    mock_http.analyze.return_value = AnalyzerResult(available=True, status="success")

    orchestrator = CyberOrchestrator(
        dns_analyzer=mock_dns,
        http_analyzer=mock_http,
        tls_analyzer=MagicMock(),
        redirect_analyzer=MagicMock(),
        threat_intel_provider=MagicMock(),
    )

    res = orchestrator.analyze("https://example.com")

    assert res.dns.available is False
    assert res.dns.status == "error"
    assert "failed unexpectedly" in res.dns.errors[0]
    assert res.http.available is True


def test_aegis_engine_integrated_cyber_risk():
    """9, 10, 11. Test AegisEngine integrating ML + Cyber signals into final classification."""
    mock_predictor = MagicMock(return_value={
        "prediction": 0, "label": "BENIGN", "probability": 0.15,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })

    # Base ML score = 15
    # Cyber signals: known_malicious_match (+50) -> Integrated risk = 65 -> SUSPICIOUS
    mock_orchestrator = MagicMock()
    mock_orchestrator.analyze.return_value = CyberAnalysisResult(
        signals=[
            SecuritySignal("threat_intel", "known_malicious_match", "critical", "Domain matched threat blocklist")
        ],
        total_time_ms=12.0,
    )

    engine = AegisEngine(predictor_fn=mock_predictor, cyber_orchestrator=mock_orchestrator)
    res = engine.analyze("http://suspicious-domain.com")

    assert res.cached is False
    assert res.risk_score == 65
    assert res.classification == "SUSPICIOUS"
    assert len(res.reasons) >= 2
    assert "Domain matched threat blocklist" in res.reasons
    assert "cyber_analysis" in res.signals


def test_aegis_engine_allowlist_risk_discount():
    """Test AegisEngine applying trust discount for allowlisted domains."""
    mock_predictor = MagicMock(return_value={
        "prediction": 0, "label": "BENIGN", "probability": 0.25,
        "threshold": 0.7125, "model_version": "xgboost_v6"
    })

    # Base ML score = 25
    # Cyber signals: allowlisted_domain (-30) -> Integrated risk = 0 -> SAFE
    mock_orchestrator = MagicMock()
    mock_orchestrator.analyze.return_value = CyberAnalysisResult(
        signals=[
            SecuritySignal("threat_intel", "allowlisted_domain", "info", "Domain matched allowlist")
        ],
        total_time_ms=5.0,
    )

    engine = AegisEngine(predictor_fn=mock_predictor, cyber_orchestrator=mock_orchestrator)
    res = engine.analyze("https://google.com")

    assert res.risk_score == 0
    assert res.classification == "SAFE"
