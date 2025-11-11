import os
import requests
from flask import Blueprint, request, jsonify

gateway_bp = Blueprint('gateway_bp', __name__)

# Get the internal URL of the auth service from environment variables
AUTH_SERVICE_URL = os.environ.get('AUTH_SERVICE_URL')
TRANSLATION_SERVICE_URL = os.environ.get('TRANSLATION_SERVICE_URL')

@gateway_bp.route('/login', methods=['POST'])
def login():
    """Forwards login request to the Authentication Service."""
    try:
        # Forward the request and get the response
        response = requests.post(
            f"{AUTH_SERVICE_URL}/login",
            json=request.get_json()
        )
        
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        # Handle network errors or if the auth service is down
        return jsonify(message=str(e)), 503 # Service Unavailable


@gateway_bp.route('/translate', methods=['POST'])
def translate():
    """
    Orchestrates the translation process:
    1. Validates token with Auth Service.
    2. If valid, forwards request to Translation Service with User ID.
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

    # Step 2: Forward the request to the Translation Service
    try:
        # Create new headers, passing the validated user ID securely
        forward_headers = {
            'X-User-ID': user_id,
            'Content-Type': 'application/json'
        }
        
        translation_response = requests.post(
            f"{TRANSLATION_SERVICE_URL}/translate",
            json=request.get_json(),
            headers=forward_headers
        )
        
        return jsonify(translation_response.json()), translation_response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify(message=f"Error with translation service: {str(e)}"), 503