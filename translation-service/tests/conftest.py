import pytest
from app import create_app, db

@pytest.fixture
def app():
    """Instance of Main Flask App configured for testing."""
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False
    })

    # Create an application context to access the database
    with app.app_context():
        # Create tables for the real in-memory DB
        db.create_all()
        yield app
        # Cleanup: remove session and drop tables
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()