import requests
from unittest.mock import patch

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
        'target_language': 'fr' # Invalid language
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


# We patch the objects in the module where they are looked up/used
@patch('translation.routes.db.session')
@patch('translation.routes.requests.post')
def test_translate_success(mock_post, mock_db_session, client):
    """Test the successful translation path with mocks."""
    # Configure the mock for requests.post
    mock_response = mock_post.return_value
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'response': 'Hallo'}

    # Make the request
    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})

    # Assertions
    assert response.status_code == 200
    assert response.json['translated_text'] == 'Hallo'
    mock_post.assert_called_once()
    mock_db_session.add.assert_called_once()
    mock_db_session.commit.assert_called_once()


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
    """Test the route's behavior when the database commit fails."""
    mock_response = mock_post.return_value
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'response': 'Hallo'}

    mock_db_session.commit.side_effect = Exception("Database is locked")

    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})

    assert response.status_code == 500
    assert "Database error" in response.json['message']
    mock_db_session.rollback.assert_called_once()


def test_translate_text_is_not_a_string(client):
    """Test for 400 error when 'text' is not a string."""
    response = client.post('/translate', json={
        'text': 12345,  # Non-string type
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})
    assert response.status_code == 400
    assert response.json['message'] == "'text' must be a string"


def test_translate_text_exceeds_max_length(client):
    """Test for 400 error when the source text is too long."""
    long_text = "a" * 2001  # Exceeds the 2000 character limit
    response = client.post('/translate', json={
        'text': long_text,
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})
    assert response.status_code == 400
    assert response.json['message'] == "Text to translate is too long (max 2000 characters)"


@patch('translation.routes.db.session')
@patch('translation.routes.requests.post')
def test_translate_strips_whitespace(mock_post, mock_db_session, client):
    """Test if leading/trailing whitespace is stripped from the source text."""
    # Configure the mock for requests.post
    mock_response = mock_post.return_value
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'response': 'Hallo'}

    # Make the request
    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})

    # Assertions
    assert response.status_code == 200
    assert response.json['translated_text'] == 'Hallo'
