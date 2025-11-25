from unittest.mock import patch, MagicMock
import requests

@patch('gateway.routes.requests.get')
def test_translate_success(mock_validate, client):
    """Test successful translation request."""
    # Mock the token validation response
    mock_validate_response = MagicMock()
    mock_validate_response.status_code = 200
    mock_validate_response.json.return_value = {'user_id': 'user-123'}
    mock_validate.return_value = mock_validate_response

    # Mock the translation service response
    mock_translate_response = MagicMock()
    mock_translate_response.status_code = 200
    mock_translate_response.json.return_value = {'translated_text': 'Hola'}

    with patch('gateway.routes.requests.request', return_value=mock_translate_response) as mock_forward:
        response = client.post(
            '/translate',
            json={"text": "Hello", "language": "es"},
            headers={'Authorization': 'Bearer valid_token'}
        )

        assert response.status_code == 200
        assert response.json == {'translated_text': 'Hola'}
        
        # Verify token validation was called
        mock_validate.assert_called_once_with(
            'http://mock-auth-service/validate',
            headers={'Authorization': 'Bearer valid_token'}
        )
        
        # Verify the request was forwarded to the translation service
        mock_forward.assert_called_once()
        call_args = mock_forward.call_args
        assert call_args[0][0] == 'POST' # Method
        assert call_args[0][1] == 'http://mock-translation-service/translate' # URL
        assert call_args[1]['headers']['X-User-ID'] == 'user-123'
        assert call_args[1]['json'] == {"text": "Hello", "language": "es"}


def test_translate_no_auth_header(client):
    """Test translate endpoint without an Authorization header."""
    response = client.post('/translate', json={"text": "Hello"})
    assert response.status_code == 401
    assert "Authorization header is required" in response.json['message']


@patch('gateway.routes.requests.get')
def test_translate_invalid_token(mock_validate, client):
    """Test translate with an invalid token (auth service returns 401)."""
    # Simulate a 401 response from the validation endpoint
    mock_validate.side_effect = requests.exceptions.HTTPError(
        response=MagicMock(status_code=401)
    )

    response = client.post(
        '/translate',
        json={"text": "Hello"},
        headers={'Authorization': 'Bearer invalid_token'}
    )
    assert response.status_code == 401
    assert "Invalid or expired token" in response.json['message']


@patch('gateway.routes.requests.get')
def test_translate_auth_service_down(mock_validate, client):
    """Test translate when the auth service is down during validation."""
    mock_validate.side_effect = requests.exceptions.RequestException

    response = client.post(
        '/translate',
        json={"text": "Hello"},
        headers={'Authorization': 'Bearer any_token'}
    )
    assert response.status_code == 503
    assert "Authentication service is unavailable" in response.json['message']
