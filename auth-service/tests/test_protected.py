# unit test
def test_validate_token_missing(client):
    """Test accessing protected route without token."""
    response = client.get('/validate')
    assert response.status_code == 401
    # Flask-JWT-Extended default message usually contains "Missing Authorization Header"


# unit test
def test_validate_token_invalid(client):
    """Test accessing protected route with garbage token."""
    response = client.get('/validate', headers={
        'Authorization': 'Bearer invalid.token.here'
    })
    # Can be 422 (Unprocessable Entity) or 401 depending on JWT config
    # Flask-JWT-Extended usually returns 422 for malformed tokens
    assert response.status_code in [401, 422]


# integration test
def test_validate_token_valid(client, init_database):
    """Test token validation endpoint with valid token."""
    # Login
    login_res = client.post('/login', json={
        'username': 'testuser',
        'password': 'password123'
    })
    token = login_res.json['access_token']
    
    # Validate
    response = client.get('/validate', headers={
        'Authorization': f'Bearer {token}'
    })
    
    assert response.status_code == 200
    assert response.json['valid'] is True
    

# integration test
def test_logout(client, init_database):
    """Test logout endpoint."""
    # todo implement token invalidation
    pass