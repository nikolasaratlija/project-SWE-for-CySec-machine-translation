import pytest
from app import create_app

@pytest.fixture(scope='module')
def app():
    """Instance of Main Flask App configured for testing."""
    # Pass the test config directly to the factory
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:" 
    })
    
    yield app

@pytest.fixture(scope='module')
def client(app):
    """A test client for the app."""
    return app.test_client()