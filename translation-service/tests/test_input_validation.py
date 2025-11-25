from unittest.mock import patch
from translation.models import Translation
from app import db 


# Unit tests
def test_translate_text_exceeds_max_length(client):
    long_text = "a" * 2001
    response = client.post('/translate', json={
        'text': long_text,
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})
    assert response.status_code == 400


def test_translate_text_is_not_a_string(client):
    response = client.post('/translate', json={
        'text': 12345,
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})
    assert response.status_code == 400


# integration tests
@patch('translation.routes.requests.post')
def test_translate_strips_whitespace(mock_post, client, app):
    """Test if leading/trailing whitespace is stripped and saved correctly."""
    mock_response = mock_post.return_value
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'response': 'Hallo'}

    response = client.post('/translate', json={
        'text': '  Hello  ', # Input with spaces
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})

    assert response.status_code == 200
    assert response.json['translated_text'] == 'Hallo'

    # Verify in Real DB that spaces were removed
    with app.app_context():
        entry = db.session.query(Translation).first()
        assert entry.source_text == 'Hello' # Check that it was stripped