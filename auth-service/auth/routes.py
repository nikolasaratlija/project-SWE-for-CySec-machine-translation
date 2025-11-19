from flask import Blueprint, request, jsonify
from auth.models import db, User
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
import logging
import pyotp

auth_bp = Blueprint('auth_bp', __name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Missing 'username' or 'password' in request body"}), 400

    username = data.get('username')
    password = data.get('password')

    remote_ip = request.remote_addr

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        if user.is_2fa_enabled:  
            return jsonify({"2fa_required": True, "user_id": user.id}), 200
        else:
            additional_claims = {"is_admin": user.is_admin}
            access_token = create_access_token(
            identity=str(user.id),
            additional_claims=additional_claims
            )
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