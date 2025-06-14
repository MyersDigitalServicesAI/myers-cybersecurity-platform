from fastapi.testclient import TestClient
from api_backend import app  # Adjust if your FastAPI app is elsewhere

client = TestClient(app)

def test_health_check():
    response = client.get("/health")  # Replace with actual endpoint if needed
    assert response.status_code == 200

def test_api_root():
    response = client.get("/")
    assert response.status_code in [200, 307]  # Depending on redirect behavior

def test_invalid_route():
    response = client.get("/invalid-endpoint")
    assert response.status_code == 404

from security_core import SecurityCore

def test_security_core_initialization():
    sc = SecurityCore()
    assert hasattr(sc, "get_connection")
    assert callable(sc.get_connection)
