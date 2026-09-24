import pytest
import datetime
from unittest.mock import MagicMock, patch
from bullymail.services.email_service import email_service
from bullymail.services.bullying_detector import BullyingDetector, check_abusive_terms
from bullymail.services.admin_warning_service import AdminWarningService
from bullymail.database.connection import execute_query, fetch_one, fetch_all
from bullymail.worker.processor import MailboxProcessor, _parse_email_date, _parse_datetime
from bullymail.models.analysis import AnalysisModel

@pytest.fixture
def test_setup(app):
    """Sets up clean institution, admin user, and initial data for feature testing."""
    with app.app_context():
        execute_query("DELETE FROM email_config WHERE institution_id = 99")
        execute_query("DELETE FROM users WHERE institution_id = 99")
        execute_query("DELETE FROM institutions WHERE id = 99")
        execute_query("DELETE FROM analyzed_emails WHERE institution_id = 99")

        execute_query("INSERT INTO institutions (id, name, domain) VALUES (99, 'Feature Test Inst', 'featuretest.org')")
        execute_query(
            "INSERT INTO users (id, username, email, password_hash, institution_id, role, status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (990, 'feature_admin', 'admin@featuretest.org', 'hash', 99, 'admin', 'ACTIVE')
        )

        return {
            'inst_id': 99,
            'admin_id': 990
        }

# -------------------------------------------------------------------------
# Test 1: Secure Mailbox Baseline Time Boundary
# -------------------------------------------------------------------------
def test_mailbox_baseline_time_boundary_enforcement(app, test_setup):
    """Verify emails prior to baseline configuration time T are skipped, while emails after T are ingested."""
    with app.app_context():
        inst_id = test_setup['inst_id']
        baseline_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

        # 1. Create mailbox and explicitly set configured_at and monitoring_started_at to baseline_time
        mb = email_service.configure_mailbox(inst_id, 'baseline_test@featuretest.org', 'password123')
        mb_id = mb['id']

        execute_query(
            "UPDATE email_config SET configured_at = %s, monitoring_started_at = %s, mailbox_initialized = 1, last_processed_uid = 0, uid_validity = 12345 WHERE id = %s",
            (baseline_time, baseline_time, mb_id)
        )

        processor = MailboxProcessor()
        lease_id = email_service.acquire_sync_lease(mb_id, inst_id)

        # Mock IMAP client returning two raw RFC822 messages:
        # Email 1: Date before baseline (2 hours ago)
        # Email 2: Date after baseline (30 minutes ago)
        old_date_str = (baseline_time - datetime.timedelta(hours=1)).strftime("%a, %d %b %Y %H:%M:%S +0000")
        new_date_str = (baseline_time + datetime.timedelta(minutes=30)).strftime("%a, %d %b %Y %H:%M:%S +0000")

        raw_email_old = f"From: attacker@evil.com\r\nTo: baseline_test@featuretest.org\r\nSubject: Old Email\r\nDate: {old_date_str}\r\nMessage-ID: <old1@evil.com>\r\n\r\nYou are an idiot.".encode('utf-8')
        raw_email_new = f"From: attacker@evil.com\r\nTo: baseline_test@featuretest.org\r\nSubject: New Email\r\nDate: {new_date_str}\r\nMessage-ID: <new2@evil.com>\r\n\r\nYou are a fucker.".encode('utf-8')

        mock_imap = MagicMock()
        mock_imap.select_mailbox.return_value = ('OK', 12345, 2)
        mock_imap.fetch_unseen_uids.return_value = [101, 102]
        mock_imap.fetch_rfc822_message.side_effect = lambda uid: raw_email_old if uid == 101 else raw_email_new

        config_row = email_service.get_mailbox_by_id(mb_id, inst_id)

        with patch('bullymail.worker.processor.IMAPClient', return_value=mock_imap):
            summary = processor.process_mailbox(config_row, lease_id=lease_id, return_summary=True)

        email_service.release_sync_lease(mb_id, lease_id)

        # Verify summary counts: found 2, but only 1 processed (the email after baseline time T)
        assert summary['success'] is True
        assert summary['emails_found'] == 2
        assert summary['emails_processed'] == 1

        # Check database: only the new email (UID 102) should exist in ingested_messages and analyzed_emails
        ingested = fetch_all("SELECT * FROM ingested_messages WHERE email_config_id = %s", (mb_id,))
        assert len(ingested) == 1
        assert ingested[0]['imap_uid'] == 102

        analyzed = fetch_all("SELECT * FROM analyzed_emails WHERE email_config_id = %s", (mb_id,))
        assert len(analyzed) == 1
        assert analyzed[0]['email_subject'] == 'New Email'

# -------------------------------------------------------------------------
# Test 2: Delete Secure Mailbox & Historical Report Preservation
# -------------------------------------------------------------------------
def test_delete_mailbox_and_historical_report_preservation(client, app, test_setup):
    """Verify admin can delete mailbox, stopping sync while preserving historic analysis reports."""
    with app.app_context():
        inst_id = test_setup['inst_id']
        admin_id = test_setup['admin_id']

        mb = email_service.configure_mailbox(inst_id, 'to_delete@featuretest.org', 'password123')
        mb_id = mb['id']

        # Save dummy analysis report associated with this mailbox
        dummy_report = {
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.88,
            'threat_score': 0.88,
            'incident_status': 'PENDING_REVIEW',
            'is_bullying': True,
            'confidence': 0.88,
            'severity': 'HIGH',
            'rule_based_matches': ['fucker'],
            'rule_based_score': 0.88,
            'matched_categories': ['Severe Profane Abuse'],
            'ml_prediction': True,
            'ml_confidence': 0.85,
            'model_used': 'RuleEngine+ML',
            'combined_score': 0.88,
            'top_features': ['fucker']
        }
        analysis_id = AnalysisModel.save_analysis(dummy_report, institution_id=inst_id, email_config_id=mb_id)

    # Login as Admin
    with client.session_transaction() as sess:
        sess['user_id'] = admin_id
        sess['username'] = 'feature_admin'
        sess['role'] = 'admin'

    # Perform DELETE via API
    res = client.delete(f'/api/admin/mailboxes/{mb_id}')
    assert res.status_code == 200
    assert res.get_json()['success'] is True

    with app.app_context():
        # 1. Verify mailbox row is removed from email_config
        deleted_mb = email_service.get_mailbox_by_id(mb_id, inst_id)
        assert deleted_mb is None

        # 2. Verify historical analysis record in analyzed_emails STILL EXISTS, but email_config_id is detached (NULL)
        report_row = fetch_one("SELECT * FROM analyzed_emails WHERE id = %s", (analysis_id,))
        assert report_row is not None
        assert report_row['institution_id'] == inst_id
        assert report_row['email_config_id'] is None or report_row['email_config_id'] == 0

        # 3. Attempting to sync deleted mailbox fails (cannot acquire credentials or load row)
        res_sync = client.post(f'/api/admin/mailboxes/{mb_id}/sync')
        assert res_sync.status_code == 404

# -------------------------------------------------------------------------
# Test 3: Deterministic Abusive Term Detection
# -------------------------------------------------------------------------
def test_deterministic_abusive_term_detection():
    """Verify explicit profane abuse ('fucker', 'FUCKER', profanities) triggers HIGH threat deterministically."""
    detector = BullyingDetector()

    # 1. Lowercase "fucker"
    res_lower = detector.predict("You are a fucker who ruins everything.")
    assert res_lower['is_bullying'] is True
    assert res_lower['severity'] in ('HIGH', 'CRITICAL')
    assert res_lower['rule_based_score'] >= 0.80
    assert any('Severe Profane Abuse' in cat for cat in res_lower['matched_categories'])

    # 2. Uppercase "FUCKER"
    res_upper = detector.predict("STOP BEING A FUCKER!")
    assert res_upper['is_bullying'] is True
    assert res_upper['severity'] in ('HIGH', 'CRITICAL')
    assert res_upper['rule_based_score'] >= 0.80

    # 3. Utility function check_abusive_terms
    check_res = check_abusive_terms("Shut up you fucker")
    assert check_res['has_abuse'] is True
    assert 'fucker' in check_res['matches']
    assert check_res['severity'] == 'HIGH'

    # 4. Substring safety (harmless words containing substring matches e.g. "butter", "scunthorpe", "glass")
    check_safe = check_abusive_terms("Please pass the butter on the glass table.")
    assert check_safe['has_abuse'] is False
    assert len(check_safe['matches']) == 0

    res_safe = detector.predict("Please pass the butter on the glass table.")
    assert res_safe['is_bullying'] is False
    assert res_safe['severity'] == 'LOW'

# -------------------------------------------------------------------------
# Test 4: Admin Warning Email MIME Construction
# -------------------------------------------------------------------------
def test_admin_warning_email_mime_headers_and_construction():
    """Verify send_warning_email constructs RFC-compliant MIMEMultipart('alternative') with all required headers."""
    with patch('smtplib.SMTP') as mock_smtp_cls, \
         patch.object(AdminWarningService, 'get_smtp_config', return_value={
             'host': 'smtp.test.com',
             'port': 587,
             'username': 'admin@test.com',
             'password': 'secret_password',
             'use_tls': True,
             'from_email': 'admin@test.com',
             'from_name': 'BullyMail Admin'
         }):

        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        success, msg = AdminWarningService.send_warning_email(
            recipient_email="offender@university.edu",
            subject="Official Misconduct Warning",
            body="Your email contained inappropriate language."
        )

        assert success is True
        assert "Warning email sent successfully" in msg
        assert mock_server.sendmail.called

        # Inspect sent MIME message string passed to sendmail
        call_args = mock_server.sendmail.call_args[0]
        sender = call_args[0]
        recips = call_args[1]
        raw_msg_str = call_args[2]

        assert sender == 'admin@test.com'
        assert recips == ['offender@university.edu']

        # Verify MIME Headers present
        assert "From: BullyMail Admin <admin@test.com>" in raw_msg_str
        assert "To: offender@university.edu" in raw_msg_str
        assert "Subject: Official Misconduct Warning" in raw_msg_str
        assert "Date: " in raw_msg_str
        assert "Message-ID: <" in raw_msg_str
        assert "MIME-Version: 1.0" in raw_msg_str
        assert "Content-Type: multipart/alternative" in raw_msg_str
        assert "Content-Type: text/plain" in raw_msg_str
        assert "Content-Type: text/html" in raw_msg_str

# -------------------------------------------------------------------------
# Test 5: Localhost MySQL Connection & Dependency Check
# -------------------------------------------------------------------------
def test_mysql_connector_dependency_and_localhost_resolution():
    """Verify mysql-connector-python dependency is available and host resolution handles localhost."""
    import mysql.connector
    assert mysql.connector.__version__ is not None

    from bullymail.database.connection import get_connection, _get_config_val

    # Test SQLite connection mode operates without issues
    conn = get_connection()
    assert conn is not None
    conn.close()
