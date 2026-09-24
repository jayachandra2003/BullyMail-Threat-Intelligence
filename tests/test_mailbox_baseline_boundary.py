import pytest
import datetime
from unittest.mock import MagicMock, patch
from bullymail.database.connection import execute_query, fetch_one
from bullymail.services.email_service import EmailService
from bullymail.worker.processor import MailboxProcessor


def test_configure_mailbox_sets_boundary_fields(app):
    """Verifies that configure_mailbox initializes boundary tracking columns."""
    inst_id = 101
    execute_query("INSERT INTO institutions (id, name, domain, created_at) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)", (inst_id, "Boundary Test Inst", "boundary.com"))

    svc = EmailService()
    mb = svc.configure_mailbox(
        institution_id=inst_id,
        email_address="boundary_test@example.com",
        app_password="testpassword123",
        imap_server="imap.example.com",
        smtp_server="smtp.example.com",
        smtp_port=587
    )

    assert mb is not None
    assert mb['email_address'] == "boundary_test@example.com"
    assert mb['monitoring_started_at'] is not None


@patch("bullymail.worker.processor.IMAPClient")
def test_worker_baseline_initialization_suppresses_history(mock_imap_class, app):
    """Verifies that an uninitialized mailbox sets boundary initial_uid and skips historical email ingestion."""
    inst_id = 102
    execute_query("INSERT INTO institutions (id, name, domain, created_at) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)", (inst_id, "Boundary Test Inst", "boundary.com"))

    svc = EmailService()
    # Configure mailbox directly in DB with mailbox_initialized = 0
    execute_query(
        '''INSERT INTO email_config (institution_id, email_address, encrypted_app_password, status, sync_status, mailbox_initialized, sync_lease_id)
           VALUES (%s, %s, 'encpass', 'active', 'IDLE', 0, 'test_lease_123')''',
        (inst_id, "new_inbox@example.com")
    )
    mb = fetch_one("SELECT * FROM email_config WHERE email_address = %s", ("new_inbox@example.com",))
    cfg_id = mb['id']

    # Mock IMAP client
    mock_imap = MagicMock()
    mock_imap.connect.return_value = True
    mock_imap.select_mailbox.return_value = ('OK', '12345', 50)
    mock_imap.get_max_uid.return_value = 500  # Inbox currently has 500 emails
    mock_imap_class.return_value = mock_imap

    processor = MailboxProcessor()
    summary = processor.process_mailbox(
        config_row=mb,
        lease_id="test_lease_123",
        return_summary=True
    )

    assert summary['success'] is True
    assert summary['emails_processed'] == 0  # Historical 500 emails suppressed!

    # Check updated database record
    updated_mb = fetch_one("SELECT * FROM email_config WHERE id = %s", (cfg_id,))
    assert updated_mb['mailbox_initialized'] == 1
    assert updated_mb['initial_uid'] == 500
    assert updated_mb['last_processed_uid'] == 500
    assert str(updated_mb['uid_validity']) == '12345'


@patch("bullymail.worker.processor.IMAPClient")
def test_worker_incremental_sync_processes_only_new_uids(mock_imap_class, app):
    """Verifies that subsequent sync loops only fetch and ingest emails with UID > last_processed_uid."""
    inst_id = 103
    execute_query("INSERT INTO institutions (id, name, domain, created_at) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)", (inst_id, "Boundary Test Inst 3", "boundary3.com"))

    # Configure initialized mailbox with last_processed_uid = 500
    execute_query(
        '''INSERT INTO email_config (
               institution_id, email_address, encrypted_app_password, status, sync_status,
               mailbox_initialized, initial_uid, last_processed_uid, uid_validity, sync_lease_id
           ) VALUES (%s, %s, 'encpass', 'active', 'IDLE', 1, 500, 500, '12345', 'test_lease_456')''',
        (inst_id, "active_inbox@example.com")
    )
    mb = fetch_one("SELECT * FROM email_config WHERE email_address = %s", ("active_inbox@example.com",))
    cfg_id = mb['id']

    # Mock IMAP client returning UIDs 501, 502
    mock_imap = MagicMock()
    mock_imap.connect.return_value = True
    mock_imap.select_mailbox.return_value = ('OK', '12345', 52)
    mock_imap.fetch_unseen_uids.return_value = [501, 502]
    mock_imap.fetch_rfc822_message.side_effect = lambda uid: f"Message-ID: <msg_{uid}@example.com>\r\nFrom: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test {uid}\r\n\r\nHello threat test {uid}".encode('utf-8')
    mock_imap_class.return_value = mock_imap

    processor = MailboxProcessor()

    with patch.object(processor.risk_engine, "analyze_email") as mock_analyze:
        mock_analyze.return_value = {
            'overall_risk_level': 'LOW',
            'overall_risk_score': 0.1,
            'bullying_analysis': {'is_bullying': False, 'confidence': 0.1}
        }

        summary = processor.process_mailbox(
            config_row=mb,
            lease_id="test_lease_456",
            return_summary=True
        )

        assert summary['success'] is True
        assert summary['emails_processed'] == 2

    updated_mb = fetch_one("SELECT * FROM email_config WHERE id = %s", (cfg_id,))
    assert updated_mb['last_processed_uid'] == 502
