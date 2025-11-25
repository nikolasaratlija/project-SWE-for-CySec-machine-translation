import html
import requests
from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest

gateway_bp = Blueprint('gateway_bp', __name__)


# catches malformed JSON for the whole blueprint.
@gateway_bp.app_errorhandler(BadRequest)
def handle_bad_request(e):
    """Catch 400 Bad Request and return a JSON response."""
    return jsonify({"message": "The request body contains invalid or malformed JSON."}), 400


def _forward_request(method, url, **kwargs):
    """
    A secure wrapper for making requests to internal services.
    It handles network errors and masks 5xx server errors.
    
    Returns:
        - On success: The 'requests.Response' object.
        - On failure: A Flask response tuple (dict, status_code).
    """
    try:
        response = requests.request(method, url, **kwargs)

        # service returns a server error, log and return a generic server error to client
        if 500 <= response.status_code < 600:
            current_app.logger.error(
                f"Internal service at {url} failed with status {response.status_code}. "
                f"Response: {response.text}"
            )
            generic_error = (jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred on the server."
            }), 500)
            return None, generic_error

        return response, None

    # if server is unreachable or down
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Could not connect to internal service at {url}. Error: {e}")
        service_unavailable_error = (jsonify({
            "error": "Service Unavailable",
            "message": "A required downstream service is currently unavailable."
        }), 503)
        return None, service_unavailable_error


def sanitize_value(value):
    """General sanitization for input values."""
    if isinstance(value, str):
        return html.escape(value.strip())
    if isinstance(value, list):
        return [sanitize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    return value


# --- API Endpoints ---
@gateway_bp.route('/login', methods=['POST'])
def login():
    """Sanitize & forward login request to the Authentication Service."""
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Invalid or missing JSON body"}), 400

    sanitized_payload = sanitize_value(data)

    # Get URL from the current app's configuration
    auth_service_url = current_app.config['AUTH_SERVICE_URL']

    response, error_response = _forward_request(
        'POST',
        f"{auth_service_url}/login",
        json=sanitized_payload
    )

    if error_response:
        return error_response

    return jsonify(response.json()), response.status_code

@gateway_bp.route('/login/totp', methods=['POST'])
def login_totp():
    """Sanitize & forward login request to the Authentication Service."""
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Invalid or missing JSON body"}), 400

    sanitized_payload = sanitize_value(data)

    # Get URL from the current app's configuration
    auth_service_url = current_app.config['AUTH_SERVICE_URL']

    response, error_response = _forward_request(
        'POST',
        f"{auth_service_url}/login/totp",
        json=sanitized_payload
    )

    if error_response:
        return error_response

    return jsonify(response.json()), response.status_code

@gateway_bp.route('/enable-2fa', methods=['POST'])
def enable_2fa():
    """
    Enable endpoint: validates token with Auth service, then forwards enable-2fa request.
    """
    # Check Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header is required"}), 401

    # Get Auth service URL from config
    auth_service_url = current_app.config.get('AUTH_SERVICE_URL')
    if not auth_service_url:
        return jsonify({"message": "Auth service URL not configured"}), 500

    # Validate token with Auth service
    try:
        validation_response = requests.get(
            f"{auth_service_url}/validate",
            headers={'Authorization': auth_header}
        )
        validation_response.raise_for_status()
        user_id = validation_response.json().get('user_id')

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return jsonify({"message": "Invalid or expired token"}), 401
        current_app.logger.error(f"Auth service error: {e}")
        return jsonify({"message": "Could not validate token"}), 500

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Auth service unreachable: {e}")
        return jsonify({"message": "Authentication service unavailable"}), 503

    #Parse JSON body
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Invalid or missing JSON body"}), 400

    # Sanitize payload
    sanitized_payload = sanitize_value(data)

    # Forward enable-2fa request to Auth service
    try:
        response = requests.post(
            f"{auth_service_url}/enable-2fa",
            json=sanitized_payload,
            headers={'Authorization': auth_header}
        )
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error forwarding enable-2fa: {e}")
        return jsonify({"message": "Enable-2fa service unavailable"}), 503

    # 6. Return Auth service response
    return jsonify(response.json()), response.status_code

@gateway_bp.route('/logout', methods=['POST'])
def logout():
    """
    Logout endpoint: validates token with Auth service, then forwards logout request.
    """
    # Check Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header is required"}), 401

    # Get Auth service URL from config
    auth_service_url = current_app.config.get('AUTH_SERVICE_URL')
    if not auth_service_url:
        return jsonify({"message": "Auth service URL not configured"}), 500

    # Validate token with Auth service
    try:
        validation_response = requests.get(
            f"{auth_service_url}/validate",
            headers={'Authorization': auth_header}
        )
        validation_response.raise_for_status()
        user_id = validation_response.json().get('user_id')

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return jsonify({"message": "Invalid or expired token"}), 401
        current_app.logger.error(f"Auth service error: {e}")
        return jsonify({"message": "Could not validate token"}), 500

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Auth service unreachable: {e}")
        return jsonify({"message": "Authentication service unavailable"}), 503

    # Parse JSON body
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Invalid or missing JSON body"}), 400

    # Sanitize payload
    sanitized_payload = sanitize_value(data)

    # Forward logout request to Auth service
    try:
        response = requests.post(
            f"{auth_service_url}/logout",
            json=sanitized_payload,
            headers={'Authorization': auth_header}
        )
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error forwarding logout: {e}")
        return jsonify({"message": "Logout service unavailable"}), 503

    # Return Auth service response
    return jsonify(response.json()), response.status_code



@gateway_bp.route('/translate', methods=['POST'])
def translate():
    """Orchestrates the translation process securely."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Authorization header is required"}), 401
    
    # Get URLs from the current app's configuration
    auth_service_url = current_app.config['AUTH_SERVICE_URL']
    translation_service_url = current_app.config['TRANSLATION_SERVICE_URL']

    try:
        validation_response = requests.get(
            f"{auth_service_url}/validate",
            headers={'Authorization': auth_header}
        )
        validation_response.raise_for_status() 
        user_id = validation_response.json().get('user_id')

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return jsonify({"message": "Invalid or expired token"}), 401
        current_app.logger.error(f"Auth service returned an error during validation: {e}")
        return jsonify({"message": "Could not validate token due to a server error."}), 500

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Could not connect to auth service for validation: {e}")
        return jsonify({"message": "Authentication service is unavailable."}), 503

    data = request.get_json()
    if data is None:
        return jsonify({"message": "Invalid or missing JSON body"}), 400
    
    sanitized_payload = sanitize_value(data)

    forward_headers = {
        'X-User-ID': user_id,
        'Content-Type': 'application/json'
    }

    response, error_response = _forward_request(
        'POST',
        f"{translation_service_url}/translate",
        json=sanitized_payload,
        headers=forward_headers
    )

    if error_response:
        return error_response

    return jsonify(response.json()), response.status_code