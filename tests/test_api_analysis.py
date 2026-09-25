import pytest
from fastapi.testclient import TestClient
from api.app import app
from api.dependencies import get_aegis_engine, reset_aegis_engine
from aegis_engine import AegisEngine, AnalysisResult
from aegis_engine.decision_engine import DecisionConfig
from cache import MemoryCache


@pytest.fixture
def client():
    reset_aegis_engine()
    with TestClient(app) as c:
        yield c
    reset_aegis_engine()


def fake_predictor_safe(url: str):
    return {
        "url": url,
        "prediction": 0,
        "probability": 0.05,
        "label": "legitimate",
        "model_version": "xgboost_v6",
    }


def fake_predictor_suspicious(url: str):
    return {
        "url": url,
        "prediction": 1,
        "probability": 0.50,
        "label": "phishing",
        "model_version": "xgboost_v6",
    }


def fake_predictor_critical(url: str):
    return {
        "url": url,
        "prediction": 1,
        "probability": 0.95,
        "label": "phishing",
        "model_version": "xgboost_v6",
    }


def test_analyze_valid_url_safe(client):
    cache = MemoryCache()
    engine = AegisEngine(
        cache=cache,
        predictor_fn=fake_predictor_safe,
        enable_cyber_analysis=False,
        enable_ai=False,
    )
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    response = client.post("/api/v1/analyze", json={"url": "https://google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://google.com"
    assert data["classification"] == "SAFE"
    assert 0 <= data["risk_score"] <= 100
    assert data["cached"] is False
    assert isinstance(data["reasons"], list)
    assert isinstance(data["signals"], dict)
    assert data["model_version"] == "xgboost_v6"
    assert "analysis_time_ms" in data

    app.dependency_overrides.clear()


def test_analyze_suspicious(client):
    cache = MemoryCache()
    engine = AegisEngine(
        cache=cache,
        predictor_fn=fake_predictor_suspicious,
        enable_cyber_analysis=False,
        enable_ai=False,
    )
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    response = client.post("/api/v1/analyze", json={"url": "http://suspicious-test-site.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "SUSPICIOUS"
    assert data["risk_score"] >= 30

    app.dependency_overrides.clear()


def test_analyze_critical(client):
    cache = MemoryCache()
    engine = AegisEngine(
        cache=cache,
        predictor_fn=fake_predictor_critical,
        enable_cyber_analysis=False,
        enable_ai=False,
    )
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    response = client.post("/api/v1/analyze", json={"url": "http://phishing-critical-site.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "CRITICAL"
    assert data["risk_score"] >= 70

    app.dependency_overrides.clear()


def test_analyze_cache_hit(client):
    cache = MemoryCache()
    engine = AegisEngine(
        cache=cache,
        predictor_fn=fake_predictor_safe,
        enable_cyber_analysis=False,
        enable_ai=False,
    )
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    # First request -> cache miss
    res1 = client.post("/api/v1/analyze", json={"url": "https://example.org"})
    assert res1.status_code == 200
    assert res1.json()["cached"] is False

    # Second request -> cache hit
    res2 = client.post("/api/v1/analyze", json={"url": "https://example.org"})
    assert res2.status_code == 200
    assert res2.json()["cached"] is True

    app.dependency_overrides.clear()


def test_analyze_missing_url_field(client):
    response = client.post("/api/v1/analyze", json={})
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_analyze_empty_url(client):
    response = client.post("/api/v1/analyze", json={"url": ""})
    assert response.status_code in [400, 422]
    data = response.json()
    assert "error" in data


def test_analyze_whitespace_url(client):
    response = client.post("/api/v1/analyze", json={"url": "   "})
    assert response.status_code in [400, 422]
    data = response.json()
    assert "error" in data


def test_analyze_oversized_url(client):
    oversized = "https://example.com/" + "a" * 10000
    response = client.post("/api/v1/analyze", json={"url": oversized})
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert "length exceeds maximum" in data["error"]["message"].lower()


def test_analyze_invalid_url_format(client):
    response = client.post("/api/v1/analyze", json={"url": "http://[invalid-ipv6"})
    assert response.status_code in [400, 422]
    data = response.json()
    assert "error" in data
