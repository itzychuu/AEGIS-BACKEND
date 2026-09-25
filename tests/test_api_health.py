import pytest
from fastapi.testclient import TestClient
from api.app import app
from api.dependencies import get_aegis_engine, reset_aegis_engine
from aegis_engine import AegisEngine
from cache import MemoryCache
from local_ai.models import AIStatus


@pytest.fixture
def client():
    reset_aegis_engine()
    with TestClient(app) as c:
        yield c
    reset_aegis_engine()


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "aegis-backend"
    assert data["version"] == "1.0.0"


def test_api_v1_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "aegis-backend"
    assert data["version"] == "1.0.0"


def test_readiness_endpoint_default(client):
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert "checks" in data
    assert data["checks"]["ml_model"] == "ready"
    assert data["checks"]["cyber_analysis"] in ["ready", "disabled"]
    assert data["checks"]["local_ai"] in ["disabled", "unavailable", "available", "model_not_found"]


def test_readiness_with_mocked_engine(client):
    # Test readiness behavior when AI is explicitly disabled
    engine = AegisEngine(enable_cyber_analysis=False, enable_ai=False)
    app.dependency_overrides[get_aegis_engine] = lambda: engine

    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["checks"]["ml_model"] == "ready"
    assert data["checks"]["cyber_analysis"] == "disabled"
    assert data["checks"]["local_ai"] == "disabled"

    app.dependency_overrides.clear()
