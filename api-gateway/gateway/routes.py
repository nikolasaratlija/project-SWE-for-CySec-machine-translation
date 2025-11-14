import os
import html
import requests
from flask import Blueprint, request, jsonify

gateway_bp = Blueprint('gateway_bp', __name__)

# Internal URLs for the microservices, set via environment variables
AUTH_SERVICE_URL = os.environ.get('AUTH_SERVICE_URL')
TRANSLATION_SERVICE_URL = os.environ.get('TRANSLATION_SERVICE_URL')


def sanitize_value(value):
    """
    Algemene sanitization:
    - Strings: strip whitespace + HTML escape
    - Lijsten/dicts: recursief sanitizen
    """
    if isinstance(value, str):
        # trim en escape gevaarlijke tekens zoals <, >, ", '
        return html.escape(value.strip())
    if isinstance(value, list):
        return [sanitize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    return value


@gateway_bp.route('/login', methods=['POST'])
def login():
    """
    Sanitize & forward login request to the Authentication Service.

    Let op:
    - De API-gateway doet alleen algemene JSON-check + sanitization.
    - Business logic / veldspecifieke validatie (username/password) gebeurt
      in de auth-service zelf, i.p.v. hier.
    """
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"message": "Invalid JSON body"}), 400

        sanitized_payload = sanitize_value(data)

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
    2. Sanitizes the JSON body.
    3. Forwards request to Translation Service with User ID.

    Veldspecifieke validatie van 'text' gebeurt in de translation-service.
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

    # Step 2: Sanitize JSON body (geen text-specific business rules hier)
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Invalid JSON body"}), 400

    sanitized_payload = sanitize_value(data)

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
