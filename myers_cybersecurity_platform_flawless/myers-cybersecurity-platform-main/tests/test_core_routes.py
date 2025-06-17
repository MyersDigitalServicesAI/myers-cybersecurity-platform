import pytest
from fastapi.testclient import TestClient
from api_backend import app
from security_core import SecurityCore

client = TestClient(app)

@pytest.fixture
def test_client():
    return client

def test_health_check(test_client):
    response = test_client.get("/health")
    assert response.status_code == 200"
    assert response.json() == {"status": "ok"}

def test_api_root(test_client):"
    response = test_client.get("/")
    assert response.status_code in [200, 307]

def test_invalid_route(test_client):"
    response = test_client.get("/invalid-endpoint")
    assert response.status_code == 404

def test_security_core_initialization():
    sc = SecurityCore()"
    assert hasattr(sc, "get_connection")
    assert callable(sc.get_connection)"
