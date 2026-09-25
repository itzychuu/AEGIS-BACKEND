import pytest
from fastapi.testclient import TestClient
from api.app import app
from api.dependencies import get_aegis_engine, reset_aegis_engine
from aegis_engine import AegisEngine, AnalysisResult
from aegis_engine.exceptions import EngineError


@pytest.fixture
def client():
    reset_aegis_engine()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    reset_aegis_engine()


def test_invalid_json_body(client):
    response = client.post(
        "/api/v1/analyze",
        content="invalid json content",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_engine_exception_handling(client):
    class BrokenEngine:
        def analyze(self, url: str):
            raise EngineError("Simulated engine failure")

    app.dependency_overrides[get_aegis_engine] = lambda: BrokenEngine()

    response = client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert response.status_code == 500
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "ENGINE_ERROR"
    assert "Simulated engine failure" not in data["error"]["message"]  # Controlled output
    assert "stack" not in data["error"]

    app.dependency_overrides.clear()


def test_unexpected_exception_handling(client):
    class CrashingEngine:
        def analyze(self, url: str):
            raise RuntimeError("Unexpected internal crash with sensitive /var/secret/path")

    app.dependency_overrides[get_aegis_engine] = lambda: CrashingEngine()

    response = client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert response.status_code == 500
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INTERNAL_ERROR"
    assert "sensitive" not in data["error"]["message"]
    assert data["error"]["message"] == "An internal server error occurred."

    app.dependency_overrides.clear()


def test_invalid_risk_score_out_of_bounds(client):
    class BadScoreEngine:
        def analyze(self, url: str):
            return AnalysisResult(
                url=url,
                classification="SAFE",
                risk_score=999,  # Invalid risk score > 100
                cached=False,
                reasons=[],
                signals={},
                model_version="xgboost_v6",
                analysis_time_ms=10.0,
            )

    app.dependency_overrides[get_aegis_engine] = lambda: BadScoreEngine()

    response = client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert response.status_code == 500
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "ENGINE_ERROR"

    app.dependency_overrides.clear()
