import json
import pytest
from bullymail.models.analysis import AnalysisModel
from bullymail.models.user import UserModel
from bullymail.models.institution import InstitutionModel
from bullymail.services.admin_warning_service import admin_warning_service

@pytest.fixture
def test_setup_incidents(app):
    """Sets up test institutions, users (admin and analyst), and threat analysis records."""
    with app.app_context():
        # Create Institution 2 if not exists
        inst2_id = InstitutionModel.create_institution("Institution 2", "other-uni.edu")
        if not inst2_id:
            inst2 = InstitutionModel.get_by_domain("other-uni.edu")
            inst2_id = inst2['id'] if inst2 else 2

        # Create users
        # Admin user (inst 1)
        admin_id = UserModel.create_user(
            username="test_admin_warning",
            password="AdminPass123!",
            email="admin_warning@inst1.com",
            role="admin",
            status="ACTIVE",
            institution_id=1
        )

        # Analyst user (inst 1)
        analyst_id = UserModel.create_user(
            username="test_analyst_warning",
            password="AnalystPass123!",
            email="analyst_warning@inst1.com",
            role="analyst",
            status="ACTIVE",
            institution_id=1
        )

        # Admin user (inst 2)
        admin2_id = UserModel.create_user(
            username="test_admin2_warning",
            password="Admin2Pass123!",
            email="admin_warning@inst2.com",
            role="admin",
            status="ACTIVE",
            institution_id=inst2_id
        )

        # Create a bullying analysis report for inst 1
        rep1 = {
            'email_subject': 'You are a failure',
            'email_from': 'Sender Person <sender_user@university.edu>',
            'email_to': 'recipient_user@university.edu',
            'email_text': 'You are completely useless and nobody respects you.',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.92,
            'threat_score': 0.92,
            'incident_status': 'PENDING_REVIEW',
            'bullying_analysis': {
                'is_bullying': True,
                'confidence': 0.92,
                'rule_based_matches': ['insulting language', 'threatening expression'],
                'rule_based_score': 0.85,
                'ml_prediction': 1,
                'ml_confidence': 0.90,
                'model_used': 'Hybrid'
            }
        }
        analysis_id_1 = AnalysisModel.save_analysis(rep1, institution_id=1, user_id=admin_id)

        # Create a clean analysis report for inst 1
        rep_clean = {
            'email_subject': 'Office hours schedule',
            'email_from': 'Clean User <clean_user@university.edu>',
            'email_to': 'faculty@university.edu',
            'email_text': 'Here are my questions for the project.',
            'overall_risk_level': 'LOW',
            'overall_confidence': 0.10,
            'threat_score': 0.10,
            'incident_status': 'PENDING_REVIEW',
            'bullying_analysis': {
                'is_bullying': False,
                'confidence': 0.10,
                'rule_based_matches': [],
                'rule_based_score': 0.0,
                'ml_prediction': 0,
                'ml_confidence': 0.05,
                'model_used': 'Hybrid'
            }
        }
        analysis_id_clean = AnalysisModel.save_analysis(rep_clean, institution_id=1, user_id=admin_id)

        # Create a bullying analysis report for inst 2
        rep2 = {
            'email_subject': 'Institution 2 Threat',
            'email_from': 'inst2_sender@other-uni.edu',
            'email_to': 'inst2_recipient@other-uni.edu',
            'email_text': 'I will destroy your career.',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.95,
            'threat_score': 0.95,
            'incident_status': 'PENDING_REVIEW',
            'bullying_analysis': {
                'is_bullying': True,
                'confidence': 0.95,
                'rule_based_matches': ['threat'],
                'rule_based_score': 0.95,
                'ml_prediction': 1,
                'ml_confidence': 0.92,
                'model_used': 'Hybrid'
            }
        }
        analysis_id_2 = AnalysisModel.save_analysis(rep2, institution_id=inst2_id, user_id=admin2_id)

        return {
            'admin_id': admin_id,
            'analyst_id': analyst_id,
            'admin2_id': admin2_id,
            'inst2_id': inst2_id,
            'analysis_id_1': analysis_id_1,
            'analysis_id_clean': analysis_id_clean,
            'analysis_id_2': analysis_id_2
        }

def test_01_analyst_cannot_access_warning_endpoints(client, test_setup_incidents):
    """TEST 1: Normal analyst user cannot send warning or access admin intervention endpoints (403)."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['analyst_id']
        sess['username'] = 'test_analyst_warning'
        sess['role'] = 'analyst'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_1']

    # Preview endpoint
    res = client.get(f'/api/admin/analysis/{aid}/warning-preview')
    assert res.status_code == 403

    # Send warning endpoint
    res = client.post(f'/api/admin/analysis/{aid}/warning', json={})
    assert res.status_code == 403

    # Review endpoint
    res = client.post(f'/api/admin/analysis/{aid}/review', json={})
    assert res.status_code == 403

    # False positive endpoint
    res = client.post(f'/api/admin/analysis/{aid}/false-positive', json={})
    assert res.status_code == 403

def test_02_warning_preview_generated_correctly_with_hello_greeting(client, test_setup_incidents):
    """TEST 2: Warning preview has 'Hello,' greeting, correct sender & recipient, and non-accusatory tone."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_1']
    res = client.get(f'/api/admin/analysis/{aid}/warning-preview')
    assert res.status_code == 200
    data = res.get_json()

    assert data['success'] is True
    assert data['target_recipient'] == 'sender_user@university.edu'
    assert data['email_from'] == 'Sender Person <sender_user@university.edu>'
    assert data['email_to'] == 'recipient_user@university.edu'
    assert data['incident_status'] == 'PENDING_REVIEW'
    assert data['is_already_sent'] is False

    # Verify neutral greeting
    assert data['warning_body'].startswith("Hello,\n\n")
    assert "Dear Student" not in data['warning_body']
    assert "Dear Faculty" not in data['warning_body']

    # Ensure advisory, non-accusatory language
    assert "guilty" not in data['warning_body'].lower()
    assert "violated the law" not in data['warning_body'].lower()

def test_03_admin_sends_warning_to_original_sender(client, test_setup_incidents, monkeypatch):
    """TEST 3: Admin sends warning email; recipient is original sender, status -> WARNING_SENT, audit created."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_1']
    sent_emails = []

    def mock_send(recipient_email, subject=None, body=None, **kwargs):
        sent_emails.append({
            'recipient': recipient_email,
            'subject': subject,
            'body': body
        })
        return True, "Warning email sent successfully."

    monkeypatch.setattr(admin_warning_service, 'send_warning_email', mock_send)

    res = client.post(f'/api/admin/analysis/{aid}/warning', json={})
    assert res.status_code == 200
    data = res.get_json()

    assert data['success'] is True
    assert data['status'] == 'WARNING_SENT'
    assert data['warning_recipient'] == 'sender_user@university.edu'

    # Verify mock received original sender
    assert len(sent_emails) == 1
    assert sent_emails[0]['recipient'] == 'sender_user@university.edu'
    assert "Notice Regarding University Communication Guidelines" in sent_emails[0]['subject']

    # Verify database status updated
    updated_rec = AnalysisModel.get_by_id(aid, institution_id=1, role='admin')
    assert updated_rec['incident_status'] == 'WARNING_SENT'

    # Verify audit log created
    assert len(updated_rec['audit_logs']) >= 1
    last_audit = updated_rec['audit_logs'][0]
    assert last_audit['action'] == 'WARNING_SENT'
    assert last_audit['admin_username'] == 'test_admin_warning'
    assert last_audit['warning_recipient'] == 'sender_user@university.edu'
    assert last_audit['delivery_status'] == 'SUCCESS'

def test_04_duplicate_warning_is_blocked(client, test_setup_incidents, monkeypatch):
    """TEST 4: Duplicate warning is blocked if incident_status is already WARNING_SENT."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_1']
    # Set status to WARNING_SENT
    AnalysisModel.update_incident_status(aid, 'WARNING_SENT', institution_id=1)

    monkeypatch.setattr(admin_warning_service, 'send_warning_email', lambda *args, **kwargs: (True, "OK"))

    res = client.post(f'/api/admin/analysis/{aid}/warning', json={})
    assert res.status_code == 400
    data = res.get_json()
    assert data['success'] is False
    assert data.get('warning_already_sent') is True
    assert 'already been dispatched' in data['error']

def test_05_cross_tenant_admin_cannot_access_other_tenant_incident(client, test_setup_incidents):
    """TEST 5: Admin of Institution 1 cannot send warning or access incident of Institution 2 (404)."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    # Analysis ID 2 belongs to Institution 2
    aid_2 = test_setup_incidents['analysis_id_2']

    res = client.get(f'/api/admin/analysis/{aid_2}/warning-preview')
    assert res.status_code == 404

    res = client.post(f'/api/admin/analysis/{aid_2}/warning', json={})
    assert res.status_code == 404

    res = client.post(f'/api/admin/analysis/{aid_2}/review', json={})
    assert res.status_code == 404

def test_06_failed_smtp_does_not_mark_warning_as_sent(client, test_setup_incidents, monkeypatch):
    """TEST 6: If SMTP sending fails, status remains PENDING_REVIEW and error is reported."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_clean']
    # Reset status
    AnalysisModel.update_incident_status(aid, 'PENDING_REVIEW', institution_id=1)

    # Mock SMTP failure
    monkeypatch.setattr(admin_warning_service, 'send_warning_email', lambda *a, **k: (False, "SMTP connection timed out."))

    res = client.post(f'/api/admin/analysis/{aid}/warning', json={})
    assert res.status_code == 500
    data = res.get_json()
    assert data['success'] is False
    assert "SMTP connection timed out" in data['error']

    # Confirm status was NOT changed to WARNING_SENT
    rec = AnalysisModel.get_by_id(aid, institution_id=1, role='admin')
    assert rec['incident_status'] == 'PENDING_REVIEW'

def test_07_mark_reviewed_action(client, test_setup_incidents):
    """TEST 7: Admin can mark incident as REVIEWED and audit trail is recorded."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_1']
    res = client.post(f'/api/admin/analysis/{aid}/review', json={'note': 'Acknowledged benign inquiry'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['status'] == 'REVIEWED'

    rec = AnalysisModel.get_by_id(aid, institution_id=1, role='admin')
    assert rec['incident_status'] == 'REVIEWED'
    assert any(log['action'] == 'REVIEWED' for log in rec['audit_logs'])

def test_08_mark_false_positive_action(client, test_setup_incidents):
    """TEST 8: Admin can mark incident as FALSE_POSITIVE with reason and audit trail."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_1']
    res = client.post(f'/api/admin/analysis/{aid}/false-positive', json={
        'reason': 'Academic criticism',
        'notes': 'Peer review critique on thesis draft'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['status'] == 'FALSE_POSITIVE'

    rec = AnalysisModel.get_by_id(aid, institution_id=1, role='admin')
    assert rec['incident_status'] == 'FALSE_POSITIVE'
    fp_audit = next((l for l in rec['audit_logs'] if l['action'] == 'FALSE_POSITIVE'), None)
    assert fp_audit is not None
    assert 'Academic criticism' in fp_audit['reason']

def test_09_credentials_never_exposed_in_any_warning_endpoint(client, test_setup_incidents):
    """TEST 9: API endpoints never expose SMTP passwords, tokens, or encryption keys in JSON responses."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_setup_incidents['admin_id']
        sess['username'] = 'test_admin_warning'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    aid = test_setup_incidents['analysis_id_1']
    res = client.get(f'/api/admin/analysis/{aid}/warning-preview')
    resp_str = res.get_data(as_text=True)

    assert 'SMTP_PASSWORD' not in resp_str
    assert 'EMAIL_APP_PASSWORD' not in resp_str
    assert 'password_hash' not in resp_str
    assert 'encrypted_app_password' not in resp_str

def test_10_smtp_config_prioritizes_active_db_mailbox_over_env_vars(app, monkeypatch):
    """TEST 10: get_smtp_config prioritizes active DB mailbox decrypted credentials over environment variables."""
    from bullymail.services.crypto_service import CryptoService
    from bullymail.services.email_service import EmailService

    with app.app_context():
        # Set stale environment variables
        monkeypatch.setattr('bullymail.config.Config.SMTP_USERNAME', 'stale_env_user@domain.com')
        monkeypatch.setattr('bullymail.config.Config.SMTP_PASSWORD', 'stale_env_pass_123')

        # Configure an active mailbox in DB for institution 1
        email_svc = EmailService()
        email_svc.configure_mailbox(
            institution_id=1,
            email_address="active_db_mailbox@gmail.com",
            app_password="decrypted_db_app_pass_456"
        )

        cfg = admin_warning_service.get_smtp_config(institution_id=1)
        assert cfg['username'] == "active_db_mailbox@gmail.com"
        assert cfg['password'] == "decrypted_db_app_pass_456"
        assert cfg['credential_source'] == "connected_mailbox"
        assert cfg['from_email'] == "active_db_mailbox@gmail.com"

def test_11_crypto_service_decrypt_strips_quotes_and_whitespace():
    """TEST 11: CryptoService.decrypt strips leading/trailing whitespace and surrounding quotes."""
    from bullymail.services.crypto_service import CryptoService

    token_quoted = CryptoService.encrypt('"  my_secret_app_pass  "')
    decrypted = CryptoService.decrypt(token_quoted)
    assert decrypted == "my_secret_app_pass"

    token_single_quoted = CryptoService.encrypt("'  another_secret_pass  '")
    decrypted_single = CryptoService.decrypt(token_single_quoted)
    assert decrypted_single == "another_secret_pass"

def test_12_smtp_authentication_error_handling_and_message(monkeypatch):
    """TEST 12: send_warning_email catches SMTPAuthenticationError and returns truthful error message."""
    import smtplib

    def mock_login(*args, **kwargs):
        raise smtplib.SMTPAuthenticationError(535, b'5.7.8 Username and Password not accepted')

    monkeypatch.setattr('smtplib.SMTP.login', mock_login)
    monkeypatch.setattr('smtplib.SMTP.starttls', lambda *args, **kwargs: None)
    monkeypatch.setattr('smtplib.SMTP.connect', lambda *args, **kwargs: (220, b'Ready'))

    from bullymail.services.admin_warning_service import AdminWarningService
    monkeypatch.setattr(AdminWarningService, 'get_smtp_config', lambda institution_id=None: {
        'host': 'smtp.gmail.com',
        'port': 587,
        'username': 'admin_test@gmail.com',
        'password': 'test_app_password',
        'use_tls': True,
        'from_email': 'admin_test@gmail.com',
        'from_name': 'BullyMail Admin',
        'credential_source': 'connected_mailbox'
    })

    ok, msg = admin_warning_service.send_warning_email(
        recipient_email="target_user@domain.com",
        subject="Test Warning",
        body="Test Body",
        institution_id=1
    )

    assert ok is False
    assert "Gmail SMTP authentication failed. Verify the connected mailbox App Password/credentials." in msg

def test_13_gmail_sender_matches_authenticated_username(monkeypatch):
    """TEST 13: For Gmail host, From header / envelope sender matches authenticated username strictly."""
    import smtplib

    sent_data = {}

    class MockSMTP:
        def __init__(self, host, port, timeout=15):
            pass
        def starttls(self, context=None):
            pass
        def login(self, user, password):
            sent_data['logged_in_user'] = user
        def sendmail(self, from_addr, to_addrs, msg_str):
            sent_data['from_addr'] = from_addr
            sent_data['to_addrs'] = to_addrs
            sent_data['msg_str'] = msg_str
            return {}
        def quit(self):
            pass

    monkeypatch.setattr('smtplib.SMTP', MockSMTP)
    from bullymail.services.admin_warning_service import AdminWarningService
    monkeypatch.setattr(AdminWarningService, 'get_smtp_config', lambda institution_id=None: {
        'host': 'smtp.gmail.com',
        'port': 587,
        'username': 'authenticated_gmail_user@gmail.com',
        'password': 'valid_app_password',
        'use_tls': True,
        'from_email': 'unmatched_sender@bullymail.local',
        'from_name': 'BullyMail Admin',
        'credential_source': 'connected_mailbox'
    })

    ok, msg = admin_warning_service.send_warning_email(
        recipient_email="target_user@domain.com",
        subject="Test Warning",
        body="Test Body",
        institution_id=1
    )

    assert ok is True
    assert sent_data['logged_in_user'] == 'authenticated_gmail_user@gmail.com'
    assert sent_data['from_addr'] == 'authenticated_gmail_user@gmail.com'
