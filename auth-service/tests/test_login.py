def test_login_successful(client, init_database):
    """Test standard login with correct credentials."""
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json


def test_login_invalid_credentials(client, init_database):
    """Test login with wrong password."""
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert response.json['message'] == "Invalid credentials"


def test_login_triggers_2fa(client, init_database):
    """Test that a 2FA enabled user gets a specific response, not a token."""
    response = client.post('/login', json={
        'username': '2fauser',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert response.json.get('2fa_required') is True
    assert 'access_token' not in response.json
    assert 'user_id' in response.json


def test_login_validation_missing_json(client):
    """No JSON body."""
    response = client.post('/login')
    assert response.status_code == 415
    # assert "Invalid JSON body" in response.json['message']


def test_login_validation_missing_fields(client):
    """Missing username or password keys."""
    response = client.post('/login', json={'username': 'testuser'})
    assert response.status_code == 400
    assert "Missing 'username' or 'password'" in response.json['message']


def test_login_validation_types(client):
    """Wrong types (e.g. int instead of str)."""
    response = client.post('/login', json={
        'username': 12345,
        'password': 'password'
    })
    assert response.status_code == 400
    assert "must be strings" in response.json['message']


def test_login_validation_empty_strings(client):
    """Empty strings."""
    response = client.post('/login', json={
        'username': '   ',
        'password': ''
    })
    assert response.status_code == 400
    assert "cannot be empty" in response.json['message']