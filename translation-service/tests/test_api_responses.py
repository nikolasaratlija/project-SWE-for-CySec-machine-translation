import requests
from unittest.mock import patch

# unit tests

def test_translate_missing_user_id_header(client):
    """Test for 400 error when X-User-ID header is missing."""
    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'nl'
    })
    assert response.status_code == 400
    assert response.json['message'] == "X-User-ID header is required"


def test_translate_unsupported_language(client):
    """Test for 400 error with an unsupported target language."""
    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'fr'
    }, headers={'X-User-ID': 'test-user'})
    assert response.status_code == 400
    assert response.json['message'] == "Target language must be 'nl' or 'bg'"


def test_translate_no_source_text(client):
    """Test for 400 error when source text is missing."""
    response = client.post('/translate', json={
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})
    assert response.status_code == 400
    assert response.json['message'] == "Text to translate is required"


@patch('translation.routes.requests.post')
def test_translate_ollama_api_error(mock_post, client):
    """Test the route's behavior when the Ollama API call fails."""
    mock_post.side_effect = requests.exceptions.RequestException("Connection timed out")

    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})

    assert response.status_code == 500
    assert "Could not connect to translation model" in response.json['message']


@patch('translation.routes.db.session')
@patch('translation.routes.requests.post')
def test_translate_database_error(mock_post, mock_db_session, client):
    """
    Test the route's behavior when the database commit fails.
    We mock db here because we intentionally want to simulate a crash.
    """
    mock_response = mock_post.return_value
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'response': 'Hallo'}

    # Force the commit to fail
    mock_db_session.commit.side_effect = Exception("Database is locked")

    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})

    assert response.status_code == 500
    assert "Database error" in response.json['message']
    mock_db_session.rollback.assert_called_once()