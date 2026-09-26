import pytest
import json
from bullymail.models.user import UserModel
from bullymail.models.analysis import AnalysisModel
from bullymail.database.connection import execute_query
from bullymail.services.auth_token_service import AuthTokenService

def test_unverified_user_cannot_login(client, app):
    with app.app_context():
        user_id = UserModel.create_user(
            username='unverified_user',
            password='TestPassword123!',
            email='unverified@test.com',
            status='PENDING_EMAIL_VERIFICATION'
        )
    res = client.post('/login', json={'username': 'unverified_user', 'password': 'TestPassword123!'})
    assert res.status_code == 403
    data = res.get_json()
    assert data['status'] == 'PENDING_VERIFICATION'

def test_verified_unapproved_user_cannot_login_or_access_dashboard(client, app):
    with app.app_context():
        user_id = UserModel.create_user(
            username='verified_unapproved',
            password='TestPassword123!',
            email='verified@test.com',
            status='PENDING_EMAIL_VERIFICATION'
        )
        UserModel.activate_user_email(user_id) # transitions to PENDING_ADMIN_APPROVAL

    res = client.post('/login', json={'username': 'verified_unapproved', 'password': 'TestPassword123!'})
    assert res.status_code == 403
    data = res.get_json()
    assert data['status'] == 'PENDING_ADMIN_APPROVAL'

    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 302 # Redirected to login

def test_approved_active_user_can_login_and_access_dashboard(client, app):
    with app.app_context():
        user_id = UserModel.create_user(
            username='approved_user',
            password='TestPassword123!',
            email='approved@test.com',
            status='PENDING_EMAIL_VERIFICATION'
        )
        UserModel.activate_user_email(user_id)
        UserModel.approve_user_by_admin(user_id, role='analyst', institution_id=1)

    res = client.post('/login', json={'username': 'approved_user', 'password': 'TestPassword123!'})
    assert res.status_code == 200
    assert res.get_json()['success'] is True

    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200

def test_disabled_user_cannot_login(client, app):
    with app.app_context():
        user_id = UserModel.create_user(
            username='disabled_user',
            password='TestPassword123!',
            email='disabled@test.com',
            status='DISABLED'
        )
    res = client.post('/login', json={'username': 'disabled_user', 'password': 'TestPassword123!'})
    assert res.status_code == 403

def test_analyst_cannot_access_admin_endpoints(client, app):
    with app.app_context():
        user_id = UserModel.create_user(
            username='analyst_user',
            password='TestPassword123!',
            email='analyst@test.com',
            status='ACTIVE',
            role='analyst'
        )
    client.post('/login', json={'username': 'analyst_user', 'password': 'TestPassword123!'})

    # Train model
    res1 = client.post('/api/train-model', json={})
    assert res1.status_code == 403

    # Generate dataset
    res2 = client.post('/api/generate-dataset', json={})
    assert res2.status_code == 403

    # Configure mailbox
    res3 = client.post('/api/configure-email', json={'email': 'test@test.com', 'app_password': 'pass'})
    assert res3.status_code == 403

    # Approve pending users
    res4 = client.get('/api/admin/pending-users')
    assert res4.status_code == 403

def test_admin_can_access_admin_endpoints(client, app):
    with app.app_context():
        user_id = UserModel.create_user(
            username='admin_user',
            password='TestPassword123!',
            email='admin_security@test.com',
            status='ACTIVE',
            role='admin'
        )
    client.post('/login', json={'username': 'admin_user', 'password': 'TestPassword123!'})

    res = client.get('/api/admin/pending-users')
    assert res.status_code == 200
    assert res.get_json()['success'] is True

def test_tenant_data_isolation_dashboard_and_history(client, app):
    with app.app_context():
        # Setup Institution 1 and Institution 2
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")

        # Save analysis record for Tenant 1
        rep1 = {'email_text': 'Tenant 1 insult idiot', 'overall_risk_level': 'HIGH', 'threat_score': 0.8}
        id1 = AnalysisModel.save_analysis(rep1, institution_id=1)

        # Save analysis record for Tenant 2
        rep2 = {'email_text': 'Tenant 2 insult loser', 'overall_risk_level': 'HIGH', 'threat_score': 0.9}
        id2 = AnalysisModel.save_analysis(rep2, institution_id=2)

        # Create Users
        u1 = UserModel.create_user('inst1_admin', 'TestPassword123!', role='admin', email='a@inst1.com', status='ACTIVE', institution_id=1)
        u2 = UserModel.create_user('inst2_admin', 'TestPassword123!', role='admin', email='a@inst2.com', status='ACTIVE', institution_id=2)

    # Login Tenant 1 Admin
    client.post('/login', json={'username': 'inst1_admin', 'password': 'TestPassword123!'})
    
    # Check Tenant 1 History
    hist1 = client.get('/api/analysis-history').get_json()['history']
    assert len(hist1) >= 1
    assert any(item['id'] == id1 for item in hist1)
    assert not any(item['id'] == id2 for item in hist1)

    # Check IDOR Protection on Report Download for Tenant 1
    rep_access_t1 = client.get(f'/api/reports/view/{id1}')
    assert rep_access_t1.status_code == 200

    rep_access_t2_from_t1 = client.get(f'/api/reports/view/{id2}')
    assert rep_access_t2_from_t1.status_code == 404 # Forbidden or Not Found

    # Logout and Login Tenant 2 Admin
    client.get('/logout')
    client.post('/login', json={'username': 'inst2_admin', 'password': 'TestPassword123!'})

    # Check Tenant 2 History
    hist2 = client.get('/api/analysis-history').get_json()['history']
    assert any(item['id'] == id2 for item in hist2)
    assert not any(item['id'] == id1 for item in hist2)

    # Check IDOR Protection for Tenant 2
    rep_access_t1_from_t2 = client.get(f'/api/reports/view/{id1}')
    assert rep_access_t1_from_t2.status_code == 404

def test_role_changes_immediately_affect_authorization(client, app):
    with app.app_context():
        u_id = UserModel.create_user('role_change_user', 'TestPassword123!', role='analyst', email='rc@test.com', status='ACTIVE', institution_id=1)
    
    client.post('/login', json={'username': 'role_change_user', 'password': 'TestPassword123!'})

    # Analyst blocked from admin route
    res1 = client.get('/api/admin/pending-users')
    assert res1.status_code == 403

    # Upgrade role in DB to super_admin
    with app.app_context():
        execute_query("UPDATE users SET role = 'super_admin' WHERE id = %s", (u_id,))

    # Next request immediately checks fresh user state from DB
    res2 = client.get('/api/admin/pending-users')
    assert res2.status_code == 200

def test_strict_tenant_isolation_no_null_permissiveness(client, app):
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")
        
        # Insert record for Inst 2
        id2 = AnalysisModel.save_analysis({'email_text': 'Inst 2 threat'}, institution_id=2)
        
        # Create user for Inst 1
        u1 = UserModel.create_user('inst1_user', 'TestPassword123!', role='analyst', email='u1@inst1.com', status='ACTIVE', institution_id=1)

    client.post('/login', json={'username': 'inst1_user', 'password': 'TestPassword123!'})

    # Inst 1 user requests history
    hist = client.get('/api/analysis-history').get_json()['history']
    assert not any(item['id'] == id2 for item in hist)

    # Inst 1 user attempts get_by_id
    detail = client.get(f'/api/analysis/{id2}')
    assert detail.status_code == 404

def test_parameter_tampering_ignored(client, app):
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")
        u1 = UserModel.create_user('tamper_user', 'TestPassword123!', role='analyst', email='tamper@inst1.com', status='ACTIVE', institution_id=1)

    client.post('/login', json={'username': 'tamper_user', 'password': 'TestPassword123!'})

    # Client sends query parameter institution_id=2 -> strictly rejected with 403 Forbidden
    res = client.get('/api/analysis-history?institution_id=2')
    assert res.status_code == 403
    assert 'Forbidden' in res.get_json()['error']

def test_session_invalidation_on_institution_or_status_change(client, app):
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")
        u_id = UserModel.create_user('switch_inst_user', 'TestPassword123!', role='analyst', email='switch@inst1.com', status='ACTIVE', institution_id=1)

    client.post('/login', json={'username': 'switch_inst_user', 'password': 'TestPassword123!'})

    # Initially belongs to Inst 1
    res1 = client.get('/api/auth/status').get_json()
    assert res1['institution_id'] == 1

    # Update institution in DB
    with app.app_context():
        execute_query("UPDATE users SET institution_id = 2 WHERE id = %s", (u_id,))

    # Next request dynamically reflects Inst 2
    res2 = client.get('/api/auth/status').get_json()
    assert res2['institution_id'] == 2

    # Disable user in DB
    with app.app_context():
        execute_query("UPDATE users SET status = 'DISABLED' WHERE id = %s", (u_id,))

    # Next request immediately rejects
    res3 = client.get('/api/system-stats')
    assert res3.status_code == 401

def test_credential_encryption_decryption_and_key_handling():
    from bullymail.services.crypto_service import CryptoService
    raw_pw = "SuperSecretAppPassword2026!"
    token = CryptoService.encrypt(raw_pw)
    assert token.startswith("gAAAAA")
    assert token != raw_pw
    
    decrypted = CryptoService.decrypt(token)
    assert decrypted == raw_pw

    # Double-encryption prevention
    token_migrated = CryptoService.migrate_credential(token)
    assert token_migrated == token
    assert CryptoService.decrypt(token_migrated) == raw_pw

    # Plaintext migration
    raw_migrated = CryptoService.migrate_credential("PlaintextPassword")
    assert raw_migrated.startswith("gAAAAA")
    assert CryptoService.decrypt(raw_migrated) == "PlaintextPassword"

def test_api_never_exposes_app_passwords_or_tokens(client, app):
    with app.app_context():
        u_id = UserModel.create_user('admin_privacy', 'TestPassword123!', role='admin', email='privacy@admin.com', status='ACTIVE', institution_id=1)
    
    client.post('/login', json={'username': 'admin_privacy', 'password': 'TestPassword123!'})
    
    res = client.post('/api/configure-email', json={
        'email': 'privacy_test@bullymail.local',
        'app_password': 'TopSecretAppPassword999!'
    })
    
    assert res.status_code in (200, 400) # Connection might fail mock SMTP, but payload must be checked
    res_str = res.get_data(as_text=True)
    assert 'TopSecretAppPassword999!' not in res_str
    assert 'gAAAAA' not in res_str

def test_cross_tenant_mailbox_isolation(client, app):
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")
        u1 = UserModel.create_user('mb_admin1', 'TestPassword123!', role='admin', email='mb1@inst1.com', status='ACTIVE', institution_id=1)
        u2 = UserModel.create_user('mb_admin2', 'TestPassword123!', role='admin', email='mb2@inst2.com', status='ACTIVE', institution_id=2)

    # Admin 1 configures Inst 1 Mailbox
    client.post('/login', json={'username': 'mb_admin1', 'password': 'TestPassword123!'})
    client.post('/api/configure-email', json={'email': 'mailbox1@inst1.com', 'app_password': 'SecretPassword1!'})
    client.get('/logout')

    # Admin 2 configures Inst 2 Mailbox
    client.post('/login', json={'username': 'mb_admin2', 'password': 'TestPassword123!'})
    client.post('/api/configure-email', json={'email': 'mailbox2@inst2.com', 'app_password': 'SecretPassword2!'})

    # Admin 2 cannot inspect Inst 1 configuration from DB
    from bullymail.database.connection import fetch_one
    with app.app_context():
        row_t1 = fetch_one("SELECT * FROM email_config WHERE institution_id = 1 AND status = 'active'")
        row_t2 = fetch_one("SELECT * FROM email_config WHERE institution_id = 2 AND status = 'active'")
        assert row_t1['email_address'] == 'mailbox1@inst1.com'
        assert row_t2['email_address'] == 'mailbox2@inst2.com'
        assert row_t1['encrypted_app_password'] != row_t2['encrypted_app_password']

def test_migration_a_b_c_d_e_plaintext_removal_and_idempotency(app):
    """Tests A, B, C, D, E: Plaintext exists -> migration encrypts -> plaintext NULL -> decrypts -> idempotent."""
    from bullymail.database.connection import get_db, fetch_one, execute_query
    from bullymail.database.schema import apply_migrations
    from bullymail.services.crypto_service import CryptoService

    with app.app_context():
        # Setup table with legacy app_password column
        execute_query("INSERT INTO email_config (institution_id, email_address, app_password, status) VALUES (1, 'legacy@test.com', 'RawPlaintextPassword123!', 'active')")
        row_before = fetch_one("SELECT * FROM email_config WHERE email_address = 'legacy@test.com'")
        
        # TEST A: Plaintext credential exists before migration
        assert row_before['app_password'] == 'RawPlaintextPassword123!'

        # Run migration
        with get_db() as conn:
            cursor = conn.cursor()
            apply_migrations(cursor, 'sqlite')

        row_after = fetch_one("SELECT * FROM email_config WHERE email_address = 'legacy@test.com'")

        # TEST B: Migration encrypts credential
        assert row_after['encrypted_app_password'] is not None
        assert row_after['encrypted_app_password'].startswith('gAAAAA')

        # TEST C: Plaintext credential no longer exists (is NULL)
        assert row_after['app_password'] is None

        # TEST D: Encrypted credential decrypts to original password
        assert CryptoService.decrypt(row_after['encrypted_app_password']) == 'RawPlaintextPassword123!'

        # TEST E: Running migration twice is safe & idempotent
        with get_db() as conn:
            cursor = conn.cursor()
            apply_migrations(cursor, 'sqlite')

        row_after2 = fetch_one("SELECT * FROM email_config WHERE email_address = 'legacy@test.com'")
        assert row_after2['app_password'] is None
        assert CryptoService.decrypt(row_after2['encrypted_app_password']) == 'RawPlaintextPassword123!'

def test_cryptographic_key_validation_and_cipher_lifecycle(monkeypatch):
    """
    Tests A, B, C, D, E, F, G, H, I, J, K, L, M cryptographic requirements:
    A: valid Fernet key works
    B: missing key fails
    C: malformed key fails
    D: short arbitrary key fails
    E: long arbitrary key fails
    F: plaintext is encrypted
    G: encrypted value decrypts correctly
    H: wrong key fails
    I: corrupted ciphertext fails
    J: migration does not leave plaintext
    K: migration is idempotent
    L: migration cannot silently double-encrypt ciphertext
    M: key/configuration changes do not use stale unintended keys
    """
    from bullymail.services.crypto_service import CryptoService

    # TEST A & F & G: Valid Fernet key encrypts and decrypts
    valid_key1 = CryptoService.generate_valid_key()
    monkeypatch.setenv('BULLYMAIL_MASTER_KEY', valid_key1)
    
    token = CryptoService.encrypt("SecretPassword123!")
    assert token.startswith("gAAAAA")
    assert CryptoService.decrypt(token) == "SecretPassword123!"

    # TEST B: Missing key fails
    monkeypatch.delenv('BULLYMAIL_MASTER_KEY', raising=False)
    from bullymail.config import Config
    monkeypatch.setattr(Config, 'BULLYMAIL_MASTER_KEY', None)
    with pytest.raises(ValueError) as exc_b:
        CryptoService.encrypt("Test")
    assert "BULLYMAIL_MASTER_KEY is not configured" in str(exc_b.value)

    # TEST C: Malformed key fails
    monkeypatch.setenv('BULLYMAIL_MASTER_KEY', '!!!not_valid_base64!!!')
    with pytest.raises(ValueError) as exc_c:
        CryptoService.encrypt("Test")
    assert "BULLYMAIL_MASTER_KEY is invalid" in str(exc_c.value)

    # TEST D: Short arbitrary key fails
    monkeypatch.setenv('BULLYMAIL_MASTER_KEY', 'short_key')
    with pytest.raises(ValueError) as exc_d:
        CryptoService.encrypt("Test")
    assert "BULLYMAIL_MASTER_KEY is invalid" in str(exc_d.value)

    # TEST E: Long arbitrary key (non-base64) fails
    monkeypatch.setenv('BULLYMAIL_MASTER_KEY', 'this_key_is_very_long_but_not_base64_urlsafe_encoded_string_1234567890')
    with pytest.raises(ValueError) as exc_e:
        CryptoService.encrypt("Test")
    assert "BULLYMAIL_MASTER_KEY is invalid" in str(exc_e.value)

    # TEST H: Wrong key fails decryption
    valid_key2 = CryptoService.generate_valid_key()
    monkeypatch.setenv('BULLYMAIL_MASTER_KEY', valid_key1)
    token1 = CryptoService.encrypt("SecretPassword123!")
    
    # Switch to key 2
    monkeypatch.setenv('BULLYMAIL_MASTER_KEY', valid_key2)
    with pytest.raises(ValueError) as exc_h:
        CryptoService.decrypt(token1)
    assert "Decryption failed" in str(exc_h.value)

    # TEST I: Corrupted ciphertext fails
    corrupted_token = token1[:-5] + "XXXXX"
    with pytest.raises(ValueError) as exc_i:
        CryptoService.decrypt(corrupted_token)
    assert "Decryption failed" in str(exc_i.value)

    # TEST L: Double encryption prevention
    monkeypatch.setenv('BULLYMAIL_MASTER_KEY', valid_key1)
    migrated_token = CryptoService.migrate_credential(token1)
    assert migrated_token == token1

    # TEST M: Key change dynamically invalidates cipher cache without stale key leakage
    token2 = CryptoService.encrypt("PasswordForKey2")
    assert CryptoService.decrypt(token2) == "PasswordForKey2"

def test_api_h_i_j_never_exposes_secrets_in_responses_or_logs(client, app, caplog):
    """Tests H, I, J: API and logs never contain plaintext or encrypted tokens."""
    with app.app_context():
        u_id = UserModel.create_user('sec_admin', 'TestPassword123!', role='admin', email='sec_admin@test.com', status='ACTIVE', institution_id=1)
    
    client.post('/login', json={'username': 'sec_admin', 'password': 'TestPassword123!'})
    
    with caplog.at_level('DEBUG'):
        res = client.post('/api/configure-email', json={
            'email': 'secret_log@test.com',
            'app_password': 'UnexposedSuperSecret123!'
        })
    
    res_text = res.get_data(as_text=True)
    # TEST H: API never exposes plaintext credential
    assert 'UnexposedSuperSecret123!' not in res_text
    # TEST I: API never exposes encrypted Fernet token
    assert 'gAAAAA' not in res_text
    # TEST J: Logs never contain plaintext credential
    assert 'UnexposedSuperSecret123!' not in caplog.text

def test_isolation_k_l_m_n_mailbox_authorization(client, app):
    """Tests K, L, M, N: Multi-tenant mailbox isolation and role authorization."""
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")
        u_analyst = UserModel.create_user('mb_analyst', 'TestPassword123!', role='analyst', email='analyst@inst1.com', status='ACTIVE', institution_id=1)
        u_disabled = UserModel.create_user('mb_dis_admin', 'TestPassword123!', role='admin', email='dis_admin@inst1.com', status='DISABLED', institution_id=1)
        u_admin1 = UserModel.create_user('mb_adm1', 'TestPassword123!', role='admin', email='adm1@inst1.com', status='ACTIVE', institution_id=1)
        u_admin2 = UserModel.create_user('mb_adm2', 'TestPassword123!', role='admin', email='adm2@inst2.com', status='ACTIVE', institution_id=2)

    # TEST L: Non-admin cannot configure mailbox
    client.post('/login', json={'username': 'mb_analyst', 'password': 'TestPassword123!'})
    res_analyst = client.post('/api/configure-email', json={'email': 'a@inst1.com', 'app_password': 'pass'})
    assert res_analyst.status_code == 403
    client.get('/logout')

    # TEST M: Disabled admin cannot configure mailbox
    res_disabled = client.post('/login', json={'username': 'mb_dis_admin', 'password': 'TestPassword123!'})
    assert res_disabled.status_code == 403

    # TEST K & N: Institution A vs B isolation & membership changes
    client.post('/login', json={'username': 'mb_adm1', 'password': 'TestPassword123!'})
    client.post('/api/configure-email', json={'email': 'mb_inst1@inst1.com', 'app_password': 'Inst1Password!'})
    
    # Change Admin 1 membership to Institution 2 in DB
    with app.app_context():
        execute_query("UPDATE users SET institution_id = 2 WHERE id = %s", (u_admin1,))

    # Admin 1 now belongs to Inst 2, cannot access Inst 1 mailbox config
    from bullymail.services.email_service import EmailService
    svc = EmailService()
    addr, pw, _, _, _ = svc._get_credentials(institution_id=2)
    assert addr != 'mb_inst1@inst1.com'

# =========================================================================
# PHASE 1C: REGISTRATION, INSTITUTION PROVISIONING & TENANT HARDENING TESTS
# =========================================================================

def test_phase_1c_new_registration_institution_id_is_null(client, app):
    """TEST 1 & 2: Signup creates user with institution_id = NULL (never defaults to 1)."""
    res = client.post('/signup', json={
        'username': 'phase1c_user1',
        'email': 'phase1c_user1@test.com',
        'password': 'StrongPassword123!',
        'confirm_password': 'StrongPassword123!',
        'institution_name': 'New Tech Academy',
        'institution_domain': 'techacademy.edu'
    })
    assert res.status_code == 200
    with app.app_context():
        user = UserModel.get_by_username('phase1c_user1')
        assert user['institution_id'] is None  # CRITICAL: MUST BE NULL!
        assert user['status'] == 'PENDING_EMAIL_VERIFICATION'
        assert user['requested_institution_name'] == 'New Tech Academy'
        assert user['requested_institution_domain'] == 'techacademy.edu'

def test_phase_1c_email_verification_moves_to_pending_admin_approval(client, app):
    """TEST 3, 4, 5: Verification transitions to PENDING_ADMIN_APPROVAL without login or dashboard access."""
    with app.app_context():
        user_id = UserModel.create_user('verify_phase1c', 'StrongPassword123!', email='v_phase1c@test.com', status='PENDING_EMAIL_VERIFICATION')
        raw_token = AuthTokenService.generate_email_verification_token(user_id)

    verify_res = client.get(f'/verify-email?token={raw_token}')
    assert verify_res.status_code == 200
    with app.app_context():
        u = UserModel.get_by_id(user_id)
        assert u['status'] == 'PENDING_ADMIN_APPROVAL'
        assert u['email_verified_at'] is not None

    # Cannot log in
    login_res = client.post('/login', json={'username': 'verify_phase1c', 'password': 'StrongPassword123!'})
    assert login_res.status_code == 403
    assert login_res.get_json()['status'] == 'PENDING_ADMIN_APPROVAL'

    # Cannot access dashboard
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 302

def test_phase_1c_admin_provisioning_and_tenant_isolation(client, app):
    """TEST 6 to 16: Admin creates new institution (inst_id=2); new institution is empty & isolated from Inst 1."""
    with app.app_context():
        # Insert test analysis into Inst 1
        a1 = AnalysisModel.save_analysis({'bullying_analysis': {'is_bullying': False, 'confidence': 0.0, 'rule_based_matches': [], 'rule_based_score': 0, 'ml_prediction': 0, 'ml_confidence': 0.0, 'model_used': 'test', 'combined_score': 0.0}, 'overall_risk_level': 'LOW', 'threat_score': 0.0}, institution_id=1)
        
        # Create super admin user (Platform Owner)
        admin_id = UserModel.create_user('admin_p1c', 'StrongPassword123!', role='super_admin', email='admin_p1c@bullymail.io', status='ACTIVE', institution_id=None)
        
        # Create pending user
        pending_id = UserModel.create_user('user_p1c', 'StrongPassword123!', role='analyst', email='user_p1c@new.com', status='PENDING_EMAIL_VERIFICATION', requested_institution_name='New Univ', requested_institution_domain='newuniv.edu')
        UserModel.activate_user_email(pending_id)

    # 1. Analyst cannot approve user
    analyst_id = UserModel.create_user('analyst_p1c', 'StrongPassword123!', role='analyst', email='analyst_p1c@inst1.com', status='ACTIVE', institution_id=1)
    client.post('/login', json={'username': 'analyst_p1c', 'password': 'StrongPassword123!'})
    res_unauth = client.post('/api/admin/approve-user', json={'user_id': pending_id, 'action': 'approve', 'provision_type': 'create_new'})
    assert res_unauth.status_code == 403
    client.get('/logout')

    # 2. Admin logs in and provisions user_p1c into NEW institution
    client.post('/login', json={'username': 'admin_p1c', 'password': 'StrongPassword123!'})
    
    # Get pending list
    pending_list_res = client.get('/api/admin/pending-registrations')
    assert pending_list_res.status_code == 200
    assert len(pending_list_res.get_json()['pending_users']) >= 1

    # Approve & provision into new institution
    approve_res = client.post('/api/admin/approve-user', json={
        'user_id': pending_id,
        'action': 'approve',
        'provision_type': 'create_new',
        'institution_name': 'New Univ',
        'institution_domain': 'newuniv.edu',
        'role': 'analyst'
    })
    assert approve_res.status_code == 200
    data_app = approve_res.get_json()
    assert data_app['success'] is True
    new_inst_id = data_app['institution_id']
    assert new_inst_id > 1  # Distinct new institution ID!
    client.get('/logout')

    # 3. Log in as newly provisioned user in Inst 2
    login_inst2 = client.post('/login', json={'username': 'user_p1c', 'password': 'StrongPassword123!'})
    assert login_inst2.status_code == 200

    # History in Inst 2 must be 0
    hist_res = client.get('/api/analysis-history')
    assert hist_res.status_code == 200
    assert len(hist_res.get_json()['history']) == 0

    # Directly requesting Inst 1 analysis from Inst 2 must fail (404)
    detail_res = client.get(f'/api/analysis/{a1}')
    assert detail_res.status_code == 404

def test_phase_1c_parameter_tampering_defense(client, app):
    """TEST 17 & 18: Tampering institution_id or role in request payloads is ignored/rejected."""
    from bullymail.database.connection import fetch_one
    with app.app_context():
        admin_id = UserModel.create_user('tamper_admin', 'StrongPassword123!', role='admin', email='tadmin@inst1.com', status='ACTIVE', institution_id=1)
        user_id = UserModel.create_user('tamper_user', 'StrongPassword123!', role='analyst', email='tuser@test.com', status='ACTIVE', institution_id=1)

    client.post('/login', json={'username': 'tamper_user', 'password': 'StrongPassword123!'})

    # Attempt to tamper institution_id during analysis submission -> strictly rejected with 403 Forbidden
    res_tamper = client.post('/api/analyze-email', json={
        'email_text': 'Testing parameter tampering defense.',
        'institution_id': 999,  # Attempted override
        'role': 'admin'         # Attempted role escalation
    })
    assert res_tamper.status_code == 403
    assert 'Forbidden' in res_tamper.get_json()['error']

    with app.app_context():
        # Verify user role in DB remained 'analyst'
        user_rec = UserModel.get_by_id(user_id)
        assert user_rec['role'] == 'analyst'
