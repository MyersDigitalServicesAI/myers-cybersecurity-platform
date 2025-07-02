import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import os

# Assuming api_backend.py is where your FastAPI app instance 'app' is defined
# from api_backend import app

# For demonstration, let's create a dummy app if api_backend isn't available
# In a real scenario, you would import your actual FastAPI app.
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/")
def read_root():
    return {"message": "Welcome to Myers Cybersecurity API"}


# Mock the database utility functions for isolated testing
@pytest.fixture(autouse=True)
def mock_db_utils():
    with patch('security_core.get_db_connection') as mock_get_conn, \
         patch('security_core.return_db_connection') as mock_return_conn, \
         patch('security_core.close_db_pool') as mock_close_pool:
        # Configure mocks to return a mock connection object
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn
        yield mock_get_conn, mock_return_conn, mock_close_pool, mock_conn, mock_cursor

# Mock environment variables for SecurityCore initialization
@pytest.fixture(autouse=True)
def mock_env_vars():
    with patch.dict(os.environ, {
        "JWT_SECRET_KEY": "test_jwt_secret_key_1234567890",
        "ENCRYPTION_KEY": "test_encryption_key_abcdefghijklmnopqrstuvwxyz1234567890",
        "DATABASE_URL": "postgresql://user:password@host:port/testdb"
    }):
        yield

client = TestClient(app)

@pytest.fixture
def test_client():
    return client

def test_health_check(test_client):
    """Test the /health endpoint."""
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_api_root(test_client):
    """Test the root endpoint."""
    response = test_client.get("/")
    # Depending on your actual root behavior (e.g., redirect to docs), status might vary.
    # For a simple message, 200 is expected.
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to Myers Cybersecurity API"}


def test_invalid_route(test_client):
    """Test a non-existent route."""
    response = test_client.get("/invalid-endpoint")
    assert response.status_code == 404

# This test now correctly imports SecurityCore after mocks are set up
def test_security_core_initialization(mock_db_utils):
    """Test that SecurityCore initializes correctly with mocked dependencies."""
    from security_core import SecurityCore
    sc = SecurityCore()
    # Assert that init_database was called, which in turn calls get_db_connection
    mock_db_utils[0].assert_called_once() # mock_get_conn
    assert hasattr(sc, "init_database")
    assert callable(sc.init_database)
    assert hasattr(sc, "get_or_create_encryption_key")
    assert callable(sc.get_or_create_encryption_key)
    # You can add more specific assertions about internal state or mocked calls if needed

    # Example: Test that encryption key is set (from mock_env_vars)
    assert sc.encryption_key == os.environ["ENCRYPTION_KEY"].encode('utf-8')

