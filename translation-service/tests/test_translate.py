from unittest.mock import patch
from app import db 
from translation.models import Translation


@patch('translation.routes.requests.post')
def test_translate_success(mock_post, client, app):
    """Test the successful translation path writing to the real in-memory DB."""
    
    # 1. Mock the external API (Ollama)
    mock_response = mock_post.return_value
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {'response': 'Hallo'}

    # 2. Make the request
    response = client.post('/translate', json={
        'text': 'Hello',
        'target_language': 'nl'
    }, headers={'X-User-ID': 'test-user'})

    # 3. HTTP Assertions
    assert response.status_code == 200
    assert response.json['translated_text'] == 'Hallo'

    # 4. DATABASE Assertions
    with app.app_context():
        entry = db.session.query(Translation).first()
        
        assert entry is not None
        assert entry.source_text== 'Hello'
        assert entry.translated_text == 'Hallo'
        assert entry.user_id == 'test-user'
