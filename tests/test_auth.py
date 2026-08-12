import pytest
import os
import secrets
from werkzeug.security import generate_password_hash
from bullymail.models.user import UserModel
from bullymail.config import Config, TestConfig
from bullymail.database.connection import execute_query, fetch_one, init_db

def test_admin_authentication_with_configured_credentials(app):
    """1. Test login with correct configured admin credentials."""
    user = UserModel.authenticate(TestConfig.ADMIN_USERNAME, TestConfig.ADMIN_PASSWORD)
    assert user is not None
    assert user['username'] == TestConfig.ADMIN_USERNAME

def test_login_invalid_password(app):
    """2. Test login with wrong password fails."""
    user = UserModel.authenticate(TestConfig.ADMIN_USERNAME, 'WrongPassword999!')
    assert user is None

def test_login_unknown_username(app):
    """3. Test login with nonexistent username fails."""
    user = UserModel.authenticate('nonexistent_operator', 'SomeValidPassword123!')
    assert user is None

def test_admin_initialization_idempotency(app):
    """4 & 13. Test that subsequent database inits do NOT overwrite the admin password."""
    admin_user_before = fetch_one("SELECT * FROM users WHERE username = %s", (TestConfig.ADMIN_USERNAME,))
    assert admin_user_before is not None
    old_hash = admin_user_before['password_hash']
    
    # Run setup_database / init_db again
    init_db()
    
    admin_user_after = fetch_one("SELECT * FROM users WHERE username = %s", (TestConfig.ADMIN_USERNAME,))
    assert admin_user_after is not None
    assert admin_user_after['password_hash'] == old_hash
    # Confirm password still authenticates
    assert UserModel.authenticate(TestConfig.ADMIN_USERNAME, TestConfig.ADMIN_PASSWORD) is not None

def test_no_hardcoded_admin123_in_codebase():
    """5. Verify that 'admin123' does NOT exist as an active hardcoded credential in core python files."""
    codebase_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    py_files = []
    for root, _, files in os.walk(os.path.join(codebase_dir, 'bullymail')):
        for f in files:
            if f.endswith('.py'):
                py_files.append(os.path.join(root, f))
                
    py_files.append(os.path.join(codebase_dir, 'app.py'))
    py_files.append(os.path.join(codebase_dir, 'run.py'))
    
    for filepath in py_files:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            assert 'admin123' not in content, f"Hardcoded 'admin123' found in {filepath}"

def test_password_stored_as_secure_hash_not_plaintext(app):
    """6. Ensure all stored passwords are secure Werkzeug hashes."""
    users = fetch_one("SELECT * FROM users WHERE username = %s", (TestConfig.ADMIN_USERNAME,))
    stored_hash = users['password_hash']
    assert stored_hash.startswith(('pbkdf2:sha256:', 'scrypt:', 'argon2:'))
    assert stored_hash != TestConfig.ADMIN_PASSWORD

def test_protected_routes_unauthenticated(client):
    """7. Verify that unauthenticated requests to protected endpoints return 302 or 401."""
    # Web UI redirect
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 302
    
    # API endpoints
    protected_apis = [
        ('/api/analyze-email', 'POST', {'email_text': 'test'}),
        ('/api/analysis-history', 'GET', None),
        ('/api/system-stats', 'GET', None),
        ('/api/model-status', 'GET', None),
        ('/api/train-model', 'POST', {}),
        ('/api/generate-dataset', 'POST', {}),
        ('/api/configure-email', 'POST', {}),
        ('/api/reports/download-csv', 'GET', None)
    ]
    
    for path, method, payload in protected_apis:
        if method == 'POST':
            res = client.post(path, json=payload)
        else:
            res = client.get(path)
        assert res.status_code == 401, f"Endpoint {path} failed auth restriction check (status: {res.status_code})"

def test_protected_routes_authenticated(auth_client):
    """8. Verify that authenticated user can access protected endpoints."""
    res_dash = auth_client.get('/dashboard')
    assert res_dash.status_code == 200
    
    res_stats = auth_client.get('/api/system-stats')
    assert res_stats.status_code == 200
    data = res_stats.get_json()
    assert data['success'] is True

def test_session_cookie_configuration(client):
    """9. Verify session cookie security configuration."""
    res = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': TestConfig.ADMIN_PASSWORD
    })
    assert res.status_code == 200
    cookies = res.headers.getlist('Set-Cookie')
    assert len(cookies) > 0
    cookie_str = cookies[0]
    assert 'HttpOnly' in cookie_str
    assert 'SameSite=Lax' in cookie_str

def test_password_policy_enforcement(app):
    """10. Test password policy rejects weak and short passwords upon creation."""
    # Under 12 characters
    is_valid, msg = UserModel.validate_password_policy('ShortPass1!')
    assert is_valid is False
    assert '12 characters' in msg
    
    # Obvious weak password
    is_valid, msg = UserModel.validate_password_policy('password123')
    assert is_valid is False
    
    # Weak disallowed list
    is_valid, msg = UserModel.validate_password_policy('admin123')
    assert is_valid is False
    
    # Valid strong password
    is_valid, msg = UserModel.validate_password_policy('Complex_Passphrase_2026!')
    assert is_valid is True
    assert msg == ""
    
    # UserModel.create_user should enforce policy
    with pytest.raises(ValueError):
        UserModel.create_user('bad_user', 'too_short')
        
    user_id = UserModel.create_user('good_user', 'StrongPass_2026_Key!', role='analyst')
    assert user_id > 0

def test_existing_users_backward_compatibility(app):
    """11. Verify that existing users with valid passwords are not invalidated."""
    user_id = UserModel.create_user('existing_operator', 'ValidLegacyPass123!', role='operator', enforce_policy=False)
    assert user_id > 0
    auth_user = UserModel.authenticate('existing_operator', 'ValidLegacyPass123!')
    assert auth_user is not None
    assert auth_user['username'] == 'existing_operator'

def test_login_route_success_and_failure(client):
    """12. Test HTTP login endpoints."""
    # Success
    res = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': TestConfig.ADMIN_PASSWORD
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    
    # Failure
    res_fail = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': 'InvalidPassword123!'
    })
    assert res_fail.status_code == 401
    data_fail = res_fail.get_json()
    assert data_fail['success'] is False
    assert data_fail['error'] == 'Invalid username or password'
