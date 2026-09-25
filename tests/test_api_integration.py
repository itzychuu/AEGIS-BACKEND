import pytest
import concurrent.futures
from fastapi.testclient import TestClient
from api.app import app
from api.dependencies import get_aegis_engine, reset_aegis_engine
from aegis_engine import AegisEngine
from local_ai.providers import FakeLocalAIProvider
from local_ai import LocalAIAnalyzer
from local_ai.config import AIConfig
from cache import MemoryCache


@pytest.fixture
def client():
    reset_aegis_engine()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    reset_aegis_engine()


def fake_predictor(url: str):
    return {
        "url": url,
        "prediction": 0,
        "probability": 0.10,
        "label": "legitimate",
        "model_version": "xgboost_v6",
    }


def test_full_pipeline_integration(client):
    fake_provider = FakeLocalAIProvider(
        response_dict={
            "summary": "Synthetic AI summary for test",
            "risk_assessment": "The evidence supports the classification based on ML probability.",
            "key_findings": ["ML probability evaluated for target URL"],
            "supporting_signals": ["ml_probability"],
            "conflicting_signals": [],
            "uncertainties": []
        }
    )
    ai_analyzer = LocalAIAnalyzer(
        config=AIConfig(enabled=True, model="qwen3:4b-instruct"),
        provider=fake_provider,
    )
    cache = MemoryCache()
    engine = AegisEngine(
        cache=cache,
        predictor_fn=fake_predictor,
        enable_cyber_analysis=False,
        ai_analyzer=ai_analyzer,
        enable_ai=True,
    )
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    response = client.post(
        "/api/v1/analyze",
        json={"url": "https://secure-login-example.org"},
        headers={"X-Request-ID": "test-req-12345"}
    )
    assert response.status_code == 200
    data = response.json()

    # Verify response structure
    assert data["url"] == "https://secure-login-example.org"
    assert data["classification"] == "SAFE"
    assert 0 <= data["risk_score"] <= 100
    assert data["cached"] is False
    assert data["model_version"] == "xgboost_v6"
    assert "reasons" in data
    assert "signals" in data
    assert "ai" in data
    assert data["ai"]["available"] is True
    assert data["ai"]["summary"] == "Synthetic AI summary for test"

    # Verify request ID header
    assert response.headers.get("X-Request-ID") == "test-req-12345"

    app.dependency_overrides.clear()


def test_ssrf_url_protection_via_api(client):
    """Verify that localhost/internal IPs trigger SSRF protection inside Aegis pipeline."""
    cache = MemoryCache()
    engine = AegisEngine(
        cache=cache,
        predictor_fn=fake_predictor,
        enable_cyber_analysis=True,
        enable_ai=False,
    )
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    response = client.post("/api/v1/analyze", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert response.status_code == 200
    data = response.json()

    # Check if SSRF status is reported inside cyber_analysis http result
    signals = data.get("signals", {})
    cyber_res = signals.get("cyber_analysis", {})
    http_res = cyber_res.get("http", {})
    dns_res = cyber_res.get("dns", {})

    is_blocked = (http_res.get("status") == "ssrf_blocked") or (dns_res.get("status") == "ssrf_blocked")
    assert is_blocked, "SSRF protection should mark status as ssrf_blocked for metadata IP"

    app.dependency_overrides.clear()


def test_cors_headers(client):
    response = client.options(
        "/api/v1/analyze",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        }
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") in ["http://localhost:3000", "*"]


def test_concurrent_api_requests(client):
    cache = MemoryCache()
    engine = AegisEngine(
        cache=cache,
        predictor_fn=fake_predictor,
        enable_cyber_analysis=False,
        enable_ai=False,
    )
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    urls = [f"https://example{i}.org" for i in range(10)]

    def make_req(target_url):
        return client.post("/api/v1/analyze", json={"url": target_url})

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(make_req, u) for u in urls]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 10
    for res in results:
        assert res.status_code == 200
        assert res.json()["classification"] == "SAFE"

    app.dependency_overrides.clear()
