import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
import os

# --- Hardened Module Imports ---
# This test file assumes it can import the main 'app' instance from your API backend.
from api_backend import app
from security_core import SecurityCore
# The database utilities are patched, so direct import for use isn't strictly necessary
# but it's good practice to know what's being mocked.
from utils.database import init_db_pool, close_db_pool

# Use pytest fixtures to manage the application lifecycle for tests.
@pytest.fixture(scope="module")
def test_client():
    """
    Creates a TestClient instance for the FastAPI app.
    This fixture will be used by all tests in this module.
    It also handles the application startup and shutdown events.
    """
    # --- Setup ---
    # Mock environment variables required for the app to start
    with patch.dict(os.environ, {
        "DATABASE_URL": "postgresql://test:test@localhost/testdb", # Mock DB URL
        "JWT_SECRET_KEY": "test-jwt-secret",
        "ENCRYPTION_KEY": "a_valid_fernet_key_for_testing_must_be_32_bytes_url_safe_base64=",
        "STRIPE_SECRET_KEY": "sk_test_mock",
        "STRIPE_WEBHOOK_SECRET": "whsec_mock"
    }):
        # Mock the database pool initialization so it doesn't try to connect
        with patch("utils.database.init_db_pool") as mock_init_pool, \
             patch("utils.database.close_db_pool") as mock_close_pool:
            
            # The TestClient context manager handles startup and shutdown events
            with TestClient(app) as client:
                yield client
    
    # Teardown is handled automatically by the TestClient context manager

def test_health_check(test_client: TestClient):
    """
    Tests the /healthz endpoint to ensure the API is running and healthy.
    This is the most basic sanity check.
    """
    response = test_client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_invalid_route(test_client: TestClient):
    """
    Tests that accessing a non-existent route returns a 404 Not Found error.
    """
    response = test_client.get("/this/route/does/not/exist")
    assert response.status_code == 404

def test_security_core_instantiates_successfully():
    """
    Tests that the SecurityCore class can be instantiated without errors,
    assuming the necessary environment variables are set (which they are by the fixture).
    This is a sanity check for a critical component.
    """
    # This test runs within the patched environment created by the test_client fixture
    try:
        sc = SecurityCore()
        # Check that essential attributes are set from the mocked environment variables
        assert sc.jwt_secret_key == "test-jwt-secret"
        assert sc.encryption_key == "a_valid_fernet_key_for_testing_must_be_32_bytes_url_safe_base64="
    except Exception as e:
        pytest.fail(f"SecurityCore failed to instantiate: {e}")
