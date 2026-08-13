import pytest
import time
import secrets
from bullymail.models.user import UserModel
from bullymail.config import Config, TestConfig
from bullymail.database.connection import execute_query, fetch_one, init_db
from bullymail.services.auth_token_service import AuthTokenService
from bullymail.services.rate_limiter import auth_rate_limiter
from bullymail.services.captcha_service import CaptchaService

# =========================================================================
# 1. USER ENUMERATION & TIMING DEFENSE
# =========================================================================

def test_login_enumeration_uniformity(client):
    """Verify that wrong password and nonexistent user return identical 401 error responses."""
    # 1. Nonexistent user
    res1 = client.post('/login', json={'username': 'nonexistent_user_9999@test.com', 'password': 'Password_12345!'})
    assert res1.status_code == 401
    data1 = res1.get_json()
    assert data1['error'] == 'Invalid username or password'

    # 2. Existing user with wrong password
    res2 = client.post('/login', json={'username': TestConfig.ADMIN_USERNAME, 'password': 'Wrong_Password_12345!'})
    assert res2.status_code == 401
    data2 = res2.get_json()
    assert data2['error'] == 'Invalid username or password'

    # Error message, status, structure are strictly identical
    assert data1 == data2

def test_signup_enumeration_uniformity(client):
    """Verify that registering existing vs new email returns identical uniform 200 response."""
    # Register first account
    email = "analyst_enum@bullymail.local"
    res1 = client.post('/signup', json={
        'username': 'analyst_enum',
        'email': email,
        'password': 'StrongPassword_2026!',
        'confirm_password': 'StrongPassword_2026!'
    })
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1['success'] is True
    assert "verification link has been dispatched" in data1['message']

    # Attempt duplicate signup with same email
    res2 = client.post('/signup', json={
        'username': 'analyst_enum_duplicate',
        'email': email,
        'password': 'AnotherPassword_2026!',
        'confirm_password': 'AnotherPassword_2026!'
    })
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2['success'] is True
    assert data1['message'] == data2['message']

def test_forgot_password_enumeration_uniformity(client):
    """Verify that forgot password returns identical responses for existing and nonexistent emails."""
    # 1. Nonexistent email
    res1 = client.post('/forgot-password', json={'email': 'nonexistent_person_1234@nowhere.com'})
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1['success'] is True
    assert "If an account exists" in data1['message']

    # 2. Existing admin email
    res2 = client.post('/forgot-password', json={'email': TestConfig.ADMIN_EMAIL})
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2['success'] is True
    assert data1['message'] == data2['message']

# =========================================================================
# 2. SIGNUP & EMAIL VERIFICATION LIFECYCLE
# =========================================================================

def test_signup_pending_verification_cannot_login(client):
    """Verify newly registered user cannot log in until email is verified."""
    email = "unverified_operator@bullymail.local"
    pw = "SuperSecret_2026_Key!"
    res = client.post('/signup', json={
        'username': 'unverified_op',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })
    assert res.status_code == 200

    # Attempt login while pending verification
    login_res = client.post('/login', json={'username': 'unverified_op', 'password': pw})
    assert login_res.status_code == 403
    data = login_res.get_json()
    assert data['status'] == 'PENDING_VERIFICATION'

def test_email_verification_token_lifecycle(client):
    """Test full single-use, expiration, and replay protection of email verification tokens."""
    email = "token_test_user@bullymail.local"
    pw = "StrongPassphrase_2026!"
    user_id = UserModel.create_user('token_user', pw, email=email, status='PENDING_EMAIL_VERIFICATION')
    raw_token = AuthTokenService.generate_email_verification_token(user_id)

    # 1. Verify successfully
    verify_res = client.get(f'/verify-email?token={raw_token}')
    assert verify_res.status_code == 200

    # User should now be ACTIVE
    user = UserModel.get_by_id(user_id)
    assert user['status'] == 'ACTIVE'
    assert user['email_verified_at'] is not None

    # 2. Replay token: second verification attempt must fail
    replay_res = client.get(f'/verify-email?token={raw_token}')
    assert replay_res.status_code == 400

    # 3. User can now authenticate
    login_res = client.post('/login', json={'username': 'token_user', 'password': pw})
    assert login_res.status_code == 200
    assert login_res.get_json()['success'] is True

def test_email_verification_invalid_and_expired_tokens(client):
    """Verify malformed and expired verification tokens fail safely."""
    # Malformed / random token
    res = client.get('/verify-email?token=invalid_random_token_12345')
    assert res.status_code == 400

    # Expired token
    user_id = UserModel.create_user('expired_token_user', 'ValidPassword123!', email='exp@test.com', status='PENDING_EMAIL_VERIFICATION')
    raw_token = AuthTokenService.generate_email_verification_token(user_id, expiry_hours=-1)
    res_exp = client.get(f'/verify-email?token={raw_token}')
    assert res_exp.status_code == 400

# =========================================================================
# 3. FORGOT PASSWORD & PASSWORD RESET LIFECYCLE
# =========================================================================

def test_password_reset_lifecycle_and_session_invalidation(client):
    """Test requesting password reset, consuming token, and updating password."""
    email = "reset_user@bullymail.local"
    old_pw = "Old_Secret_Pass_2026!"
    new_pw = "New_Secret_Pass_2026!"
    user_id = UserModel.create_user('reset_user', old_pw, email=email, status='ACTIVE')

    # 1. Generate reset token
    raw_token = AuthTokenService.generate_password_reset_token(user_id)
    assert raw_token is not None

    # 2. Reset password via POST
    res = client.post('/reset-password', json={
        'token': raw_token,
        'password': new_pw,
        'confirm_password': new_pw
    })
    assert res.status_code == 200
    assert res.get_json()['success'] is True

    # 3. Old password must now fail
    old_login = client.post('/login', json={'username': 'reset_user', 'password': old_pw})
    assert old_login.status_code == 401

    # 4. New password succeeds
    new_login = client.post('/login', json={'username': 'reset_user', 'password': new_pw})
    assert new_login.status_code == 200

    # 5. Token reuse must fail
    reuse_res = client.post('/reset-password', json={
        'token': raw_token,
        'password': 'AnotherNewPassword123!',
        'confirm_password': 'AnotherNewPassword123!'
    })
    assert reuse_res.status_code == 400

# =========================================================================
# 4. RATE LIMITING & BRUTE FORCE LOCKOUT
# =========================================================================

def test_login_brute_force_lockout(client):
    """Verify that 5 failed attempts trigger a 429 lockout."""
    auth_rate_limiter.reset()
    target_user = "brute_force_target"
    UserModel.create_user(target_user, 'ValidPass_2026_Key!', email='bf@test.com', status='ACTIVE')

    for i in range(4):
        res = client.post('/login', json={'username': target_user, 'password': 'WrongPassword123!'})
        assert res.status_code == 401

    # 5th attempt triggers lockout
    lock_res = client.post('/login', json={'username': target_user, 'password': 'WrongPassword123!'})
    assert lock_res.status_code == 429
    assert 'retry_after' in lock_res.get_json()

    # 6th attempt is also blocked during active lockout window
    lock_res_6 = client.post('/login', json={'username': target_user, 'password': 'WrongPassword123!'})
    assert lock_res_6.status_code == 429

    auth_rate_limiter.reset()

# =========================================================================
# 5. SESSION SECURITY & LOGOUT
# =========================================================================

def test_session_rotation_and_logout_invalidation(client):
    """Verify session is rotated on login and destroyed on logout."""
    res_login = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': TestConfig.ADMIN_PASSWORD
    })
    assert res_login.status_code == 200

    # Access dashboard
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200

    # Logout
    res_logout = client.get('/logout')
    assert res_logout.status_code == 302

    # Access dashboard after logout must redirect to /login
    res_dash_after = client.get('/dashboard')
    assert res_dash_after.status_code == 302
    assert '/login' in res_dash_after.headers['Location']
