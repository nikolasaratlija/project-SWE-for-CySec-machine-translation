import pytest
import os
from unittest.mock import patch
from app import create_app
from auth.models import db, User

@pytest.fixture(scope='function')
def test_app():
    """Create and configure a new app instance for each test."""
    
    # Define the test configuration
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", # Forces SQLite
        "JWT_SECRET_KEY": "super-secret-test-key",
        "WTF_CSRF_ENABLED": False
    }

    # Pass it directly to the factory
    app = create_app(test_config)

    # Create tables and context
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='function')
def client(test_app):
    return test_app.test_client()

@pytest.fixture(scope='function')
def init_database(test_app):
    """Create default users for testing."""
    user = User(username="testuser", password="password123")
    admin = User(username="adminuser", password="password123", is_admin=True)
    
    # User with 2FA
    two_fa_user = User(
        username="2fauser", 
        password="password123", 
        is_2fa_enabled=True,
        totp_secret="JBSWY3DPEHPK3PXP" # Valid Base32 secret
    )

    db.session.add_all([user, admin, two_fa_user])
    db.session.commit()

    return db