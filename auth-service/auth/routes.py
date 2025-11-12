from flask import Blueprint, request, jsonify
from auth.models import db, User
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import logging

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
        logging.info(f"Successful login for user: '{username}' from IP: {remote_ip}")

        additional_claims = {"is_admin": user.is_admin}
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims=additional_claims
        )
        return jsonify(access_token=access_token), 200
    
    logging.warning(f"Failed login attempt for user: '{username}' from IP: {remote_ip}")
    return jsonify({"message": "Invalid credentials"}), 401


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