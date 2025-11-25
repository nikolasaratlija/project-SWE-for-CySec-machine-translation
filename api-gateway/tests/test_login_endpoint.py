from unittest.mock import patch, MagicMock
import requests


def test_login_success(client):
    """Test successful login."""
    # Mock the response from the auth service
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"token": "a_valid_token"}

    with patch('gateway.routes.requests.request', return_value=mock_response) as mock_post:
        response = client.post('/login', json={"username": "test", "password": "pw"})
        
        # Assert that the correct response is returned
        assert response.status_code == 200
        assert response.json == {"token": "a_valid_token"}
        
        # Assert that the request was forwarded correctly
        mock_post.assert_called_once_with(
            'POST',
            'http://mock-auth-service/login',
            json={"username": "test", "password": "pw"}
        )


def test_login_missing_json(client):
    """Test login with no JSON body."""
    response = client.post('/login', data="not json")
    assert response.status_code == 415


def test_login_auth_service_error(client):
    """Test login when the downstream auth service returns a 500 error."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal auth error"

    with patch('gateway.routes.requests.request', return_value=mock_response):
        response = client.post('/login', json={"username": "test", "password": "pw"})
        assert response.status_code == 500
        assert response.json['error'] == "Internal Server Error"


def test_login_auth_service_unavailable(client):
    """Test login when the downstream auth service is unreachable."""
    with patch('gateway.routes.requests.request', side_effect=requests.exceptions.ConnectionError):
        response = client.post('/login', json={"username": "test", "password": "pw"})
        assert response.status_code == 503
        assert response.json['error'] == "Service Unavailable"

