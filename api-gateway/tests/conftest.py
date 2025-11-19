import pytest
from app import create_app

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    app = create_app()
    
    # Set config for testing purposes
    app.config.update({
        "TESTING": True,
        "AUTH_SERVICE_URL": "http://mock-auth-service",
        "TRANSLATION_SERVICE_URL": "http://mock-translation-service",
    })

    yield app

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()