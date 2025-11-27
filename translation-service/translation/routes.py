import os
import requests
from flask import Blueprint, request, jsonify, current_app
from translation.models import db, Translation

translation_bp = Blueprint('translation_bp', __name__)

@translation_bp.route('/translate', methods=['POST'])
def translate():
    # 1. Check Header
    user_id = request.headers.get('X-User-ID')
    if not user_id:
        current_app.logger.warning(
            "Translation request failed: Missing X-User-ID header",
            extra={'ip': request.remote_addr}
        )
        return jsonify({"message": "X-User-ID header is required"}), 400

    # 2. Check JSON existence
    data = request.get_json()

    # check for json
    if not data:
        current_app.logger.warning(
            "Translation request failed: Invalid JSON body",
            extra={'user_id': user_id}
        )
        return jsonify({"message": "Invalid JSON body"}), 400

    source_text = data.get('text')
    target_language = data.get('target_language')

    # 3. Check Target Language
    if target_language not in ["nl", "bg"]:
        current_app.logger.warning(
            "Translation request failed: Invalid target language",
            extra={
                'user_id': user_id, 
                'target_language_attempted': target_language
            }
        )
        return jsonify({"message": "Target language must be 'nl' or 'bg'"}), 400

    # 4. Check Text Existence
    if not source_text:
        current_app.logger.warning(
            "Translation request failed: Missing source text",
            extra={'user_id': user_id}
        )
        return jsonify({"message": "Text to translate is required"}), 400

    # 5. Check Text Type
    if not isinstance(source_text, str):
        current_app.logger.warning(
            "Translation request failed: Source text is not a string",
            extra={'user_id': user_id}
        )
        return jsonify({"message": "'text' must be a string"}), 400

    # 6. Check Text Length
    if len(source_text) > 2000:
        current_app.logger.warning(
            "Translation request failed: Text too long", 
            extra={
                'user_id': user_id, 
                'length': len(source_text)
            }
        )
        return jsonify({"message": "Text to translate is too long (max 2000 characters)"}), 400

    # normalise
    source_text = source_text.strip()

    # Call Ollama for translation
    try:
        ollama_url = os.environ.get('OLLAMA_API_URL')
        prompt = f"Translate the following text to {target_language}: '{source_text}' Return no other text."
        
        payload = {
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        }
        
        # Log start of external call
        current_app.logger.info(
            "Calling external translation service",
            extra={'service': 'ollama', 'target_language': target_language}
        )

        response = requests.post(ollama_url, json=payload)
        response.raise_for_status()
        
        translated_text = response.json().get('response', '').strip()

    except requests.exceptions.RequestException as e:
        current_app.logger.error(
            "Translation service failed",
            extra={
                'service': 'ollama',
                'error': str(e),
                'user_id': user_id
            }
        )
        return jsonify({"message": f"Could not connect to translation model: {e}"}), 500

    # Save the translation to the database
    try:
        new_translation = Translation(
            user_id=user_id,
            source_text=source_text,
            translated_text=translated_text
        )
        db.session.add(new_translation)
        db.session.commit()
        
        current_app.logger.info(
            "Text translated successfully",
            extra={
                'event': 'translation_success',
                'user_id': user_id,
                'source_length': len(source_text),
                'target_language': target_language
            }
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(
            "Database error during translation save",
            extra={
                'event': 'db_error',
                'error': str(e),
                'user_id': user_id
            }
        )
        return jsonify(message=f"Database error: {str(e)}"), 500

    return jsonify({
        "original_text": source_text,
        "translated_text": translated_text
    }), 200