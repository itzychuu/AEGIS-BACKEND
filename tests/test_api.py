from fastapi.testclient import TestClient
from api.app import app


def test_app_initialization():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "aegis-backend"
