import pyotp
from auth.models import User

# integration test
def test_totp_login_success(client, init_database):
    """Test completing login with a valid TOTP code."""
    # 1. Get user ID (simulating step 1 of login)
    user = User.query.filter_by(username='2fauser').first()
    
    # 2. Generate valid code
    totp = pyotp.TOTP(user.totp_secret)
    valid_code = totp.now()

    # 3. Submit code
    response = client.post('/login/totp', json={
        'user_id': user.id,
        'totp_code': valid_code
    })

    assert response.status_code == 200
    assert 'access_token' in response.json


# integration test
def test_totp_login_invalid_code(client, init_database):
    """Test login with invalid TOTP code."""
    user = User.query.filter_by(username='2fauser').first()
    
    response = client.post('/login/totp', json={
        'user_id': user.id,
        'totp_code': '000000' # Invalid code
    })

    assert response.status_code == 401
    assert response.json['message'] == "Invalid TOTP code"


# integration test
def test_enable_2fa(client, init_database):
    """Test enabling 2FA for a standard user."""
    # 1. Login as standard user to get token
    login_res = client.post('/login', json={
        'username': 'testuser', 
        'password': 'password123'
    })
    token = login_res.json['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # 2. Request to enable 2FA
    response = client.post('/enable-2fa', headers=headers)
    
    assert response.status_code == 200
    assert 'qr_uri' in response.json
    
    # 3. Verify DB updated
    user = User.query.filter_by(username='testuser').first()
    assert user.is_2fa_enabled is True
    assert user.totp_secret is not None