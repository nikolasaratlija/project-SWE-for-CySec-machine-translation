import os
import html  # voor simpele sanitization
import requests
from flask import Blueprint, request, jsonify

gateway_bp = Blueprint('gateway_bp', __name__)

# Get the internal URL of the auth service from environment variables
AUTH_SERVICE_URL = os.environ.get('AUTH_SERVICE_URL')
TRANSLATION_SERVICE_URL = os.environ.get('TRANSLATION_SERVICE_URL')


def sanitize_string(value: str) -> str:
    """
    Strip whitespace en escape gevaarlijke tekens.
    """
    if not isinstance(value, str):
        return value
    # verwijder spaties aan begin/einde en escape HTML
    return html.escape(value.strip())


def validate_login_payload(json_data):
    """
    Valideer input voor /login.
    """
    if not json_data:
        return False, ("Invalid JSON body", 400)

    username = json_data.get("username")
    password = json_data.get("password")

    # verplichte velden
    if username is None or password is None:
        return False, ("'username' and 'password' are required", 400)

    # type-checks
    if not isinstance(username, str) or not isinstance(password, str):
        return False, ("'username' and 'password' must be strings", 400)

    # simpele lengte-checks (optioneel, maar netjes)
    if len(username.strip()) == 0 or len(password.strip()) == 0:
        return False, ("'username' and 'password' cannot be empty", 400)

    # alles ok
    return True, {
        "username": sanitize_string(username),
        "password": password.strip(),  # wachtwoord niet HTML-escapen
    }


def validate_translate_payload(json_data):
    """
    Valideer input voor /translate.
    """
    if not json_data:
        return False, ("Invalid JSON body", 400)

    text = json_data.get("text")

    if text is None:
        return False, ("'text' field is required", 400)

    if not isinstance(text, str):
        return False, ("'text' must be a string", 400)

    text = sanitize_string(text)

    # leeg + max lengte check
    if len(text) == 0:
        return False, ("'text' cannot be empty", 400)

    if len(text) > 2000:
        return False, ("'text' is too long (max 2000 characters)", 400)

    return True, {"text": text}


@gateway_bp.route('/login', methods=['POST'])
def login():
    """Validates and forwards login request to the Authentication Service."""
    try:
        incoming_json = request.get_json()

        # 🔒 Input validation & sanitization
        ok, result = validate_login_payload(incoming_json)
        if not ok:
            message, status = result
            return jsonify({"message": message}), status

        sanitized_payload = result

        # Forward the request with sanitized data
        response = requests.post(
            f"{AUTH_SERVICE_URL}/login",
            json=sanitized_payload
        )

        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        # Handle network errors or if the auth service is down
        return jsonify(message=str(e)), 503  # Service Unavailable


@gateway_bp.route('/translate', methods=['POST'])
def translate():
    """
    Orchestrates the translation process:
    1. Validates token with Auth Service.
    2. Validates and sanitizes text input.
    3. If valid, forwards request to Translation Service with User ID.
    """
    # Step 1: Validate the token
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header is required"}), 401

    try:
        validation_response = requests.get(
            f"{AUTH_SERVICE_URL}/validate",
            headers={'Authorization': auth_header}
        )
        validation_response.raise_for_status()
        # Extract the user ID from the successful validation response
        user_id = validation_response.json().get('user_id')
    except requests.exceptions.RequestException:
        return jsonify({"message": "Invalid or expired token"}), 401

    # Step 2: Validate & sanitize request body
    incoming_json = request.get_json()
    ok, result = validate_translate_payload(incoming_json)
    if not ok:
        message, status = result
        return jsonify({"message": message}), status

    sanitized_payload = result

    # Step 3: Forward the request to the Translation Service
    try:
        # Create new headers, passing the validated user ID securely
        forward_headers = {
            'X-User-ID': user_id,
            'Content-Type': 'application/json'
        }

        translation_response = requests.post(
            f"{TRANSLATION_SERVICE_URL}/translate",
            json=sanitized_payload,
            headers=forward_headers
        )
        translation_response.raise_for_status()
        return jsonify(translation_response.json()), translation_response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify(message=f"Error with translation service: {str(e)}"), 503
