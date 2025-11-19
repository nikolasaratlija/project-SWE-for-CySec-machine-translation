from flask import Blueprint, request, jsonify
from auth.models import db, User
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
import logging
import pyotp
import html  # voor veilige logging / simpele sanitization

auth_bp = Blueprint('auth_bp', __name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def sanitize_for_log(value: str) -> str:
    """
    Maak een string veilig voor logging:
    - strip whitespace
    - escape gevaarlijke tekens zodat er geen log-injectie / rare terminals gebeuren.
    """
    if not isinstance(value, str):
        return str(value)
    return html.escape(value.strip())


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # 1. Check of er überhaupt JSON is
    if not data:
        return jsonify({"message": "Invalid JSON body"}), 400

    # 2. Haal velden eruit
    username = data.get('username')
    password = data.get('password')

    # 3. Verplichte velden
    if username is None or password is None:
        return jsonify({"message": "Missing 'username' or 'password' in request body"}), 400

    # 4. Type-checks
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"message": "'username' and 'password' must be strings"}), 400

    # 5. Leeg-check (username mag niet alleen whitespace zijn, password niet leeg)
    if len(username.strip()) == 0 or len(password) == 0:
        return jsonify({"message": "'username' and 'password' cannot be empty"}), 400

    # 6. Sanitization voor logging (niet voor DB-lookup)
    remote_ip = request.remote_addr or "unknown"
    safe_username_for_log = sanitize_for_log(username)

    # Voor de database lookup gebruiken we de 'ruwe' username, eventueel gestript:
    username_for_query = username.strip()

    user = User.query.filter_by(username=username_for_query).first()

    if user and user.check_password(password):
        if user.is_2fa_enabled:  
            return jsonify({"2fa_required": True, "user_id": user.id}), 200
        else:
            additional_claims = {"is_admin": user.is_admin}
            access_token = create_access_token(
                identity=str(user.id),
                additional_claims=additional_claims
            )

            logging.info(f"Successful login for user: '{safe_username_for_log}' from IP: {remote_ip}")
            return jsonify(access_token=access_token), 200
    
    logging.warning(f"Failed login attempt for user: '{username}' from IP: {remote_ip}")
    return jsonify({"message": "Invalid credentials"}), 401


@auth_bp.route('/login/totp', methods=['POST'])
def login_totp():
    data = request.get_json()
    user_id = data.get('user_id')
    totp_code = data.get('totp_code')

    user = User.query.get(user_id)
    if not user or not user.totp_secret:
        return jsonify({"message": "User not found or 2FA not enabled"}), 400

    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(totp_code, valid_window=1):
        additional_claims = {"is_admin": user.is_admin}
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims=additional_claims
            )
        return jsonify(access_token=access_token, message="Succesful login"), 200
    else:
        return jsonify({"message": "Invalid TOTP code"}), 401


@auth_bp.route('/validate', methods=['GET'])
@jwt_required()
def validate_token():
    """
    If the request reaches here, the token is valid. The API Gateway will call this.
    """
    current_user_id = get_jwt_identity()
    return jsonify(
        valid=True,
        user_id=current_user_id
    ), 200


@auth_bp.route('/enable-2fa', methods=['POST'])
@jwt_required()
def enable_2fa():
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=current_user_id).first()
    secret = pyotp.random_base32()
    user.totp_secret = secret
    user.is_2fa_enabled = True
    db.session.commit()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="TranslationApp")

    return jsonify({"qr_uri": uri})


@auth_bp.route('/logout', methods=["POST"])
@jwt_required()
def logout():
    # TODO: Blacklist token
    return jsonify(msg="Successfully logged out"), 200