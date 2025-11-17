import os
import requests
from flask import Blueprint, request, jsonify
from translation.models import db, Translation

translation_bp = Blueprint('translation_bp', __name__)

@translation_bp.route('/translate', methods=['POST'])
def translate():
    user_id = request.headers.get('X-User-ID')
    if not user_id:
        return jsonify({"message": "X-User-ID header is required"}), 400

    data = request.get_json()

    # check for json
    if not data:
        return jsonify({"message": "Invalid JSON body"}), 400

    source_text = data.get('text')
    target_language = data.get('target_language')

    if not target_language == "nl" and not target_language == "bg":
        return jsonify({"message": "Target language must be 'nl' or 'bg'"}), 400

    if not source_text:
        return jsonify({"message": "Text to translate is required"}), 400

    # Type-check
    if not isinstance(source_text, str):
        return jsonify({"message": "'text' must be a string"}), 400

    # length limit
    if len(source_text) > 2000:
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
        
        response = requests.post(ollama_url, json=payload)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        # Extract the translated text from the response
        translated_text = response.json().get('response', '').strip()

    except requests.exceptions.RequestException as e:
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
    except Exception as e:
        db.session.rollback()
        return jsonify(message=f"Database error: {str(e)}"), 500

    return jsonify({
        "original_text": source_text,
        "translated_text": translated_text
    }), 200