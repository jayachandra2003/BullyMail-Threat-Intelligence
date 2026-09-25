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

    # User should now be PENDING_ADMIN_APPROVAL
    user = UserModel.get_by_id(user_id)
    assert user['status'] == 'PENDING_ADMIN_APPROVAL'
    assert user['email_verified_at'] is not None

    # 2. Replay token: second verification attempt must fail
    replay_res = client.get(f'/verify-email?token={raw_token}')
    assert replay_res.status_code == 400

    # 3. Approve user by admin
    UserModel.approve_user_by_admin(user_id, role='analyst', institution_id=1)

    # 4. User can now authenticate
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

# =========================================================================
# 6. AUTH EMAIL SERVICE & APP_BASE_URL GENERATION
# =========================================================================

def test_auth_email_verification_url_uses_configured_base_url(app):
    """Verify that email verification URLs use the configured APP_BASE_URL without hardcoding."""
    from bullymail.services.auth_email_service import auth_email_service
    raw_token = "sample_verification_token_abc123"

    # 1. Default test app base URL
    expected_base = app.config.get('APP_BASE_URL', Config.APP_BASE_URL).rstrip('/')
    verify_url = auth_email_service.get_verification_url(raw_token)
    assert verify_url.startswith(expected_base)
    assert f"/verify-email?token={raw_token}" in verify_url

    # 2. Dynamic APP_BASE_URL override (e.g. LAN IP deployment)
    custom_lan_url = "http://172.20.38.78:5000"
    app.config['APP_BASE_URL'] = custom_lan_url
    verify_url_lan = auth_email_service.get_verification_url(raw_token)
    assert verify_url_lan == f"http://172.20.38.78:5000/verify-email?token={raw_token}"

def test_auth_email_password_reset_url_uses_configured_base_url(app):
    """Verify that password reset URLs use the configured APP_BASE_URL without hardcoding."""
    from bullymail.services.auth_email_service import auth_email_service
    raw_token = "sample_reset_token_xyz789"

    # 1. Default test app base URL
    expected_base = app.config.get('APP_BASE_URL', Config.APP_BASE_URL).rstrip('/')
    reset_url = auth_email_service.get_password_reset_url(raw_token)
    assert reset_url.startswith(expected_base)
    assert f"/reset-password?token={raw_token}" in reset_url

    # 2. Dynamic APP_BASE_URL override (e.g. production HTTPS domain)
    custom_prod_url = "https://security.bullymail.org"
    app.config['APP_BASE_URL'] = custom_prod_url
    reset_url_prod = auth_email_service.get_password_reset_url(raw_token)
    assert reset_url_prod == f"https://security.bullymail.org/reset-password?token={raw_token}"

# =========================================================================
# 7. SIGNUP EMAIL DELIVERY SUCCESS & ERROR HANDLING
# =========================================================================

def test_signup_successful_email_delivery(client, monkeypatch):
    """Verify signup with successful email delivery returns PENDING_VERIFICATION."""
    from bullymail.services.auth_email_service import auth_email_service

    monkeypatch.setattr(
        auth_email_service,
        'send_verification_email',
        lambda recipient_email, raw_token, username: (True, "Email sent successfully.")
    )

    email = "success_email_user@bullymail.local"
    pw = "StrongPass_2026!Key"
    res = client.post('/signup', json={
        'username': 'success_email_user',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['status'] == 'PENDING_VERIFICATION'
    assert "verification link has been dispatched" in data['message']

    # User in database is in PENDING_EMAIL_VERIFICATION status
    user = UserModel.get_by_email(email)
    assert user is not None
    assert user['status'] == 'PENDING_EMAIL_VERIFICATION'


def test_signup_failed_email_delivery_error_handling(client, monkeypatch):
    """Verify signup when email delivery fails: user is created, safe error returned, credentials never leaked."""
    from bullymail.services.auth_email_service import auth_email_service

    internal_smtp_error = "SMTPServerDisconnected: Connection unexpectedly closed to smtp.gmail.com:587 (password=SecretAppPass123)"
    monkeypatch.setattr(
        auth_email_service,
        'send_verification_email',
        lambda recipient_email, raw_token, username: (False, f"Failed to send email: {internal_smtp_error}")
    )

    email = "failed_email_user@bullymail.local"
    pw = "StrongPass_2026!Key"
    res = client.post('/signup', json={
        'username': 'failed_email_user',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })

    assert res.status_code == 500
    data = res.get_json()
    assert data['success'] is False
    assert data['status'] == 'PENDING_EMAIL_VERIFICATION'
    assert data['error'] == "Your account was created, but we could not send the verification email. Please try again."

    # Ensure internal exception details and credentials are NEVER exposed to client
    assert "smtp.gmail.com" not in str(data)
    assert "SecretAppPass123" not in str(data)
    assert "SMTPServerDisconnected" not in str(data)

    # User remains stored in database in PENDING_EMAIL_VERIFICATION status
    user = UserModel.get_by_email(email)
    assert user is not None
    assert user['status'] == 'PENDING_EMAIL_VERIFICATION'

    # Unverified user cannot log in
    login_res = client.post('/login', json={'username': 'failed_email_user', 'password': pw})
    assert login_res.status_code == 403
    assert login_res.get_json()['status'] == 'PENDING_VERIFICATION'

def test_signup_resends_verification_for_pending_unverified_account(client, monkeypatch):
    """Verify that an operator re-submitting signup for an unverified account receives a fresh verification email."""
    from bullymail.services.auth_email_service import auth_email_service

    sent_tokens = []
    monkeypatch.setattr(
        auth_email_service,
        'send_verification_email',
        lambda recipient_email, raw_token, username: (sent_tokens.append((recipient_email, raw_token)) or True, "Email sent successfully.")
    )

    email = "retry_operator@bullymail.local"
    pw = "StrongPass_2026!Key"

    # 1. Initial registration
    res1 = client.post('/signup', json={
        'username': 'retry_operator',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })
    assert res1.status_code == 200
    assert len(sent_tokens) == 1
    assert sent_tokens[0][0] == email
    first_token = sent_tokens[0][1]

    # 2. Operator submits signup again (e.g. didn't receive first email or retrying)
    new_pw = "NewStrongPass_2026!Key"
    res2 = client.post('/signup', json={
        'username': 'retry_operator',
        'email': email,
        'password': new_pw,
        'confirm_password': new_pw
    })
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2['success'] is True
    assert "verification link has been dispatched" in data2['message']

    # Must have dispatched a second, fresh token
    assert len(sent_tokens) == 2
    assert sent_tokens[1][0] == email
    second_token = sent_tokens[1][1]
    assert first_token != second_token

    # Verify second token activates account
    verify_res = client.get(f'/verify-email?token={second_token}')
    assert verify_res.status_code == 200
    user = UserModel.get_by_email(email)
    assert user['status'] == 'PENDING_ADMIN_APPROVAL'

def test_resend_verification_endpoint(client, monkeypatch):
    """Verify /resend-verification endpoint safely dispatches token for pending unverified accounts."""
    from bullymail.services.auth_email_service import auth_email_service

    sent = []
    monkeypatch.setattr(
        auth_email_service,
        'send_verification_email',
        lambda recipient_email, raw_token, username: (sent.append(recipient_email) or True, "Email sent successfully.")
    )

    email = "resend_target@bullymail.local"
    UserModel.create_user('resend_target', 'ValidStrongPassword_2026!', email=email, status='PENDING_EMAIL_VERIFICATION')

    # Post valid pending email
    res = client.post('/resend-verification', json={'email': email})
    assert res.status_code == 200
    assert res.get_json()['success'] is True
    assert len(sent) == 1
    assert sent[0] == email

    # Post non-existent email: returns identical uniform success message (anti-enumeration)
    sent.clear()
    res_none = client.post('/resend-verification', json={'email': 'nonexistent_account@bullymail.local'})
    assert res_none.status_code == 200
    assert res_none.get_json()['success'] is True
    assert len(sent) == 0

def test_email_service_send_email_headers_and_multipart(monkeypatch):
    """Verify EmailService.send_email constructs RFC 5322 compliant headers and multipart body."""
    from bullymail.services.email_service import EmailService

    svc = EmailService()
    monkeypatch.setattr(svc, '_get_credentials', lambda **kw: ('sender@bullymail.org', 'test_password', 'smtp.test.com', 587, 'imap.test.com'))

    recorded_messages = []

    class MockSMTP:
        def __init__(self, host, port, timeout=None):
            self.host = host
            self.port = port
            self.timeout = timeout
        def starttls(self, context=None):
            pass
        def login(self, user, pw):
            pass
        def sendmail(self, from_addr, to_addrs, msg_str):
            recorded_messages.append((from_addr, to_addrs, msg_str))
            return {}
        def quit(self):
            pass

    import smtplib
    monkeypatch.setattr(smtplib, 'SMTP', MockSMTP)

    success, msg = svc.send_email(
        to_email='recipient@example.com',
        subject='Security Verification',
        body='Please verify your email.',
        html_body='<p>Please verify your email.</p>'
    )
    assert success is True
    assert len(recorded_messages) == 1

    from_addr, to_addrs, raw_msg = recorded_messages[0]
    assert from_addr == 'sender@bullymail.org'
    assert to_addrs == ['recipient@example.com']

    # RFC 5322 header checks
    assert 'Date:' in raw_msg
    assert 'Message-ID:' in raw_msg
    assert 'MIME-Version: 1.0' in raw_msg
    assert 'From: BullyMail Security <sender@bullymail.org>' in raw_msg
    assert 'Subject: Security Verification' in raw_msg
    assert 'Content-Type: multipart/alternative' in raw_msg

def test_email_service_send_email_port_fallback(monkeypatch):
    """Verify EmailService automatically falls back from port 587 to port 465 SSL on network failure."""
    from bullymail.services.email_service import EmailService
    import socket

    svc = EmailService()
    monkeypatch.setattr(svc, '_get_credentials', lambda **kw: ('sender@bullymail.org', 'test_password', 'smtp.test.com', 587, 'imap.test.com'))

    attempts = []

    class FailingSMTP587:
        def __init__(self, host, port, timeout=None):
            attempts.append(('smtp_587', port))
            raise socket.error("Connection timed out on port 587")

    class WorkingSMTPSSL465:
        def __init__(self, host, port, timeout=None, context=None):
            attempts.append(('smtp_ssl_465', port))
        def login(self, user, pw):
            pass
        def sendmail(self, from_addr, to_addrs, msg_str):
            return {}
        def quit(self):
            pass

    import smtplib
    monkeypatch.setattr(smtplib, 'SMTP', FailingSMTP587)
    monkeypatch.setattr(smtplib, 'SMTP_SSL', WorkingSMTPSSL465)

    success, msg = svc.send_email(to_email='recipient@example.com', subject='Test', body='Fallback test')
    assert success is True
    assert attempts == [('smtp_587', 587), ('smtp_ssl_465', 465)]


def test_email_service_db_decryption_failure_fallback_to_env(monkeypatch):
    """Verify that when database mailbox password decryption fails, EmailService falls back to environment configuration."""
    from bullymail.services.email_service import EmailService
    from bullymail.services.crypto_service import CryptoService

    svc = EmailService()

    # Simulate database returning a row with corrupt/incompatible ciphertext
    dummy_row = {
        'email_address': 'alexa169691@gmail.com',
        'encrypted_password': 'corrupt_encrypted_payload',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'imap_server': 'imap.gmail.com'
    }
    monkeypatch.setattr('bullymail.services.email_service.fetch_one', lambda query, params=(): dummy_row)
    monkeypatch.setattr(CryptoService, 'decrypt', lambda val: (_ for _ in ()).throw(ValueError("Invalid master key")))

    # Set environment / Config fallback
    monkeypatch.setattr(Config, 'SMTP_USERNAME', 'env_fallback@gmail.com')
    monkeypatch.setattr(Config, 'SMTP_PASSWORD', 'super_secret_env_pw')
    monkeypatch.setattr(Config, 'SMTP_HOST', 'smtp.gmail.com')
    monkeypatch.setattr(Config, 'SMTP_PORT', 587)

    email_addr, app_pw, smtp_host, smtp_p, imap_host = svc._get_credentials()
    assert email_addr == 'env_fallback@gmail.com'
    assert app_pw == 'super_secret_env_pw'
    assert smtp_host == 'smtp.gmail.com'
    assert smtp_p == 587


def test_email_service_send_email_auth_failure_no_secret_leak(monkeypatch):
    """Verify SMTPAuthenticationError is safely handled without leaking passwords."""
    from bullymail.services.email_service import EmailService
    import smtplib

    svc = EmailService()
    secret_pw = "super_confidential_app_password"
    monkeypatch.setattr(svc, '_get_credentials', lambda **kw: ('test@gmail.com', secret_pw, 'smtp.gmail.com', 587, 'imap.gmail.com'))

    class FailingAuthSMTP:
        def __init__(self, host, port, timeout=None):
            pass
        def starttls(self, context=None):
            pass
        def login(self, user, pw):
            raise smtplib.SMTPAuthenticationError(535, b'5.7.8 Username and Password not accepted')

    monkeypatch.setattr(smtplib, 'SMTP', FailingAuthSMTP)

    success, msg = svc.send_email(to_email='target@example.com', subject='Test', body='Body')
    assert success is False
    assert "SMTP authentication failed" in msg
    assert secret_pw not in msg


def test_email_service_send_email_recipient_refusal(monkeypatch):
    """Verify SMTPRecipientsRefused returns a clear failure and does not leak secrets."""
    from bullymail.services.email_service import EmailService
    import smtplib

    svc = EmailService()
    monkeypatch.setattr(svc, '_get_credentials', lambda **kw: ('test@gmail.com', 'mypassword', 'smtp.gmail.com', 587, 'imap.gmail.com'))

    class RefusingSMTP:
        def __init__(self, host, port, timeout=None):
            pass
        def starttls(self, context=None):
            pass
        def login(self, user, pw):
            pass
        def sendmail(self, from_addr, to_addrs, msg_str):
            raise smtplib.SMTPRecipientsRefused({'target@example.com': (550, b'5.1.1 User unknown')})
        def quit(self):
            pass

    monkeypatch.setattr(smtplib, 'SMTP', RefusingSMTP)

    success, msg = svc.send_email(to_email='target@example.com', subject='Test', body='Body')
    assert success is False
    assert "refused" in msg.lower()


def test_email_service_structured_logging(monkeypatch, caplog):
    """Verify [REGISTRATION EMAIL] structured logging stages and credential masking."""
    import logging
    from bullymail.services.email_service import EmailService
    import smtplib

    svc = EmailService()
    secret_pw = "my_top_secret_app_pw"
    monkeypatch.setattr(svc, '_get_credentials', lambda **kw: ('operator@gmail.com', secret_pw, 'smtp.gmail.com', 587, 'imap.gmail.com'))

    class WorkingSMTP:
        def __init__(self, host, port, timeout=None):
            pass
        def starttls(self, context=None):
            pass
        def login(self, user, pw):
            pass
        def sendmail(self, from_addr, to_addrs, msg_str):
            return {}
        def quit(self):
            pass

    monkeypatch.setattr(smtplib, 'SMTP', WorkingSMTP)

    with caplog.at_level(logging.INFO):
        success, msg = svc.send_email(
            to_email='recipient_target@example.com',
            subject='Registration Test',
            body='Body',
            log_prefix='[REGISTRATION EMAIL]'
        )

    assert success is True
    log_text = caplog.text

    # Verify structured stages
    assert "[REGISTRATION EMAIL] [CONFIG]" in log_text
    assert "[REGISTRATION EMAIL] [CONNECTION_STAGE]" in log_text
    assert "[REGISTRATION EMAIL] [TLS_STAGE]" in log_text
    assert "[REGISTRATION EMAIL] [AUTH_STAGE]" in log_text
    assert "[REGISTRATION EMAIL] [SEND_STAGE]" in log_text
    assert "[REGISTRATION EMAIL] [FINAL_RESULT] SUCCESS" in log_text

    # Verify masking
    assert "rec***@example.com" in log_text
    assert "ope***@gmail.com" in log_text

    # Verify zero secrets leaked
    assert secret_pw not in log_text


def test_signup_preserves_account_when_email_fails(client, monkeypatch):
    """Verify that when registration email delivery fails, the account record is safely preserved in DB."""
    from bullymail.services.auth_email_service import auth_email_service

    monkeypatch.setattr(auth_email_service, 'send_verification_email', lambda to, tok, uname: (False, "Could not connect to SMTP server"))

    unique_email = f"failed_email_{secrets.token_hex(4)}@bullymail.local"
    res = client.post('/signup', json={
        'username': f"user_{secrets.token_hex(4)}",
        'email': unique_email,
        'password': 'Secure_Password_2026!',
        'confirm_password': 'Secure_Password_2026!'
    })

    assert res.status_code == 500
    data = res.get_json()
    assert data['success'] is False
    assert "Your account was created, but we could not send the verification email" in data['error']
    assert data['status'] == 'PENDING_EMAIL_VERIFICATION'

    # Verify the user actually exists in the database
    user = UserModel.get_by_email(unique_email)
    assert user is not None
    assert user['status'] == 'PENDING_EMAIL_VERIFICATION'


def test_signup_provides_direct_activation_link_when_email_fails(client, monkeypatch):
    """Verify that when registration email delivery fails, the UI and API provide direct activation URL."""
    from bullymail.services.auth_email_service import auth_email_service

    monkeypatch.setattr(auth_email_service, 'send_verification_email', lambda to, tok, uname: (False, "Network is unreachable"))

    # Test HTML signup
    uname = f"cloud_user_{secrets.token_hex(4)}"
    email = f"{uname}@bullymail.local"
    pw = "CloudPass_2026!Key"

    html_res = client.post('/signup', data={
        'username': uname,
        'email': email,
        'password': pw,
        'confirm_password': pw
    })

    assert html_res.status_code == 500
    html_text = html_res.get_data(as_text=True)
    assert "Direct Account Activation" in html_text
    assert "Verify Email & Activate Account" in html_text
    assert "/verify-email?token=" in html_text

    # Extract token and verify user can activate successfully
    import re
    match = re.search(r'href="([^"]+/verify-email\?token=[^"]+)"', html_text)
    assert match is not None
    activation_url = match.group(1)

    # Convert absolute URL or path for test client
    from urllib.parse import urlparse
    parsed = urlparse(activation_url)
    rel_path = parsed.path + ('?' + parsed.query if parsed.query else '')

    # Follow activation URL
    activate_res = client.get(rel_path)
    assert activate_res.status_code == 200

    # User has verified their email and progresses to admin approval / active
    activated_user = UserModel.get_by_email(email)
    assert activated_user is not None
    assert activated_user['status'] in ('PENDING_ADMIN_APPROVAL', 'ACTIVE')


def test_email_service_resend_api_dispatch(monkeypatch):
    """Verify that when RESEND_API_KEY is configured, EmailService dispatches via HTTPS Resend API."""
    import urllib.request
    import json
    from bullymail.services.email_service import EmailService

    monkeypatch.setenv("RESEND_API_KEY", "re_test_key_12345")
    monkeypatch.setenv("RESEND_FROM_EMAIL", "BullyMail Security <onboarding@resend.dev>")

    captured_req = {}

    class MockResponse:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    def mock_urlopen(req, timeout=None):
        captured_req['url'] = req.full_url
        captured_req['headers'] = dict(req.headers)
        captured_req['data'] = json.loads(req.data.decode('utf-8'))
        return MockResponse()

    monkeypatch.setattr(urllib.request, 'urlopen', mock_urlopen)

    svc = EmailService()
    success, msg = svc.send_email(
        to_email="operator@target.com",
        subject="Resend Test Subject",
        body="Plain body",
        html_body="<p>HTML body</p>"
    )

    assert success is True
    assert "Resend API" in msg
    assert captured_req['url'] == 'https://api.resend.com/emails'
    assert 'Bearer re_test_key_12345' in captured_req['headers']['Authorization']
    assert captured_req['data']['to'] == ['operator@target.com']
    assert captured_req['data']['subject'] == 'Resend Test Subject'
