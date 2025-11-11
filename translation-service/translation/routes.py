from flask import Blueprint, request, jsonify
from translation.models import db, Translation

translation_bp = Blueprint('translation_bp', __name__)

@translation_bp.route('/translate', methods=['POST'])
def translate():
    # This service TRUSTS the user ID sent by the API Gateway.
    # It does not perform any authentication itself.
    user_id = request.headers.get('X-User-ID')
    if not user_id:
        return jsonify({"message": "X-User-ID header is required"}), 400

    data = request.get_json()
    source_text = data.get('text')
    if not source_text:
        return jsonify({"message": "Text to translate is required"}), 400

    # MOCKED TRANSLATION LOGIC
    # In a real system, you would call an external API here.
    translated_text = source_text # Just echoing for now

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