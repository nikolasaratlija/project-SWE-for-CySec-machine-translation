import html
import requests
from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest

gateway_bp = Blueprint('gateway_bp', __name__)

# Catches malformed JSON for the whole blueprint.
@gateway_bp.app_errorhandler(BadRequest)
def handle_bad_request(e):
    """Catch 400 Bad Request and return a JSON response."""
    # Log the malformed request attempt
    current_app.logger.warning(
        "Malformed JSON received",
        extra={
            'remote_addr': request.remote_addr,
            'method': request.method,
            'path': request.path
        }
    )
    return jsonify({"message": "The request body contains invalid or malformed JSON."}), 400


def _forward_request(method, url, **kwargs):
    """
    A secure wrapper for making requests to internal services.
    It handles network errors and masks 5xx server errors.
    """
    try:
        current_app.logger.info(f"Forwarding request: {method} {url}")
        response = requests.request(method, url, **kwargs)

        # Service returns a server error, log and return a generic server error to client
        if 500 <= response.status_code < 600:
            current_app.logger.error(
                f"Downstream service error",
                extra={
                    'service_url': url,
                    'status_code': response.status_code,
                    'response_body': response.text
                }
            )
            generic_error = (jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred on the server."
            }), 500)
            return None, generic_error

        return response, None

    # If server is unreachable or down
    except requests.exceptions.RequestException as e:
        current_app.logger.critical(
            f"Downstream service unavailable",
            extra={'service_url': url, 'error': str(e)}
        )
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

    # credentials are never logged
    current_app.logger.info("Login attempt received", extra={'remote_addr': request.remote_addr})
    
    data = request.get_json()
    if data is None:
        return jsonify({"message": "Invalid or missing JSON body"}), 400

    sanitized_payload = sanitize_value(data)

    auth_service_url = current_app.config['AUTH_SERVICE_URL']
    response, error_response = _forward_request(
        'POST',
        f"{auth_service_url}/login",
        json=sanitized_payload
    )

    if error_response:
        return error_response

    current_app.logger.info("Login request forwarded successfully", extra={'status_code': response.status_code})
    return jsonify(response.json()), response.status_code


@gateway_bp.route('/translate', methods=['POST'])
def translate():
    """Orchestrates the translation process securely."""
    current_app.logger.info("Translate request received", extra={'remote_addr': request.remote_addr})
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        current_app.logger.warning("Authorization header missing")
        return jsonify({"message": "Authorization header is required"}), 401
    
    auth_service_url = current_app.config['AUTH_SERVICE_URL']
    translation_service_url = current_app.config['TRANSLATION_SERVICE_URL']
    user_id = None

    try:
        # Step 1: Validate token with Auth Service
        validation_response = requests.get(
            f"{auth_service_url}/validate",
            headers={'Authorization': auth_header}
        )
        validation_response.raise_for_status() 
        user_id = validation_response.json().get('user_id')
        current_app.logger.info(f"Token validated successfully for user_id: {user_id}")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            current_app.logger.warning("Token validation failed: Invalid or expired token", extra={'remote_addr': request.remote_addr})
            return jsonify({"message": "Invalid or expired token"}), 401
        
        current_app.logger.error(f"Auth service returned an error during validation: {e}")
        return jsonify({"message": "Could not validate token due to a server error."}), 500

    except requests.exceptions.RequestException as e:
        current_app.logger.critical(f"Could not connect to auth service for validation: {e}")
        return jsonify({"message": "Authentication service is unavailable."}), 503

    data = request.get_json()
    if data is None:
        return jsonify({"message": "Invalid or missing JSON body"}), 400
    
    sanitized_payload = sanitize_value(data)

    forward_headers = {
        'X-User-ID': user_id,
        'Content-Type': 'application/json'
    }

    # Step 2: Forward request to Translation Service
    response, error_response = _forward_request(
        'POST',
        f"{translation_service_url}/translate",
        json=sanitized_payload,
        headers=forward_headers
    )

    if error_response:
        return error_response

    current_app.logger.info(f"Translation request for user_id: {user_id} completed successfully")
    return jsonify(response.json()), response.status_code