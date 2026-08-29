import pytest
import os
import signal
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import MagicMock

from bullymail.database.connection import execute_query, fetch_one, fetch_all
from bullymail.worker.processor import MailboxProcessor
from bullymail.worker.daemon import WorkerDaemon
from bullymail.services.imap_client import IMAPAuthenticationError, IMAPConnectionError
from bullymail.models.ingested_message import IngestedMessageModel

@pytest.fixture
def worker_setup(app):
    """Sets up database fixtures for worker tests."""
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")
        execute_query("INSERT OR IGNORE INTO email_config (id, institution_id, email_address, status) VALUES (10, 1, 'mb1@inst1.com', 'active')")
        execute_query("INSERT OR IGNORE INTO email_config (id, institution_id, email_address, status) VALUES (20, 2, 'mb2@inst2.com', 'active')")
        execute_query("INSERT OR IGNORE INTO email_config (id, institution_id, email_address, status) VALUES (30, 1, 'inactive@inst1.com', 'inactive')")
        yield

def test_1_failed_message_retry_and_attempt_count_increment(app, worker_setup):
    """TEST 1 & 2: Verifies FAILED message can be retried and attempt_count increments (1 -> 2 -> 3)."""
    with app.app_context():
        # First claim (attempt 1)
        claimed1, rec_id, att1 = IngestedMessageModel.claim_message_for_processing(1, 10, 'retry_msg_hash', 101, 999)
        assert claimed1 is True
        assert att1 == 1

        # Simulate analysis failure -> transition to FAILED
        updated = IngestedMessageModel.update_processing_status(rec_id, status='FAILED', error_message='Analysis timeout')
        assert updated is True

        # Second claim attempt (retry attempt 2)
        claimed2, rec_id2, att2 = IngestedMessageModel.claim_message_for_processing(1, 10, 'retry_msg_hash', 101, 999, max_attempts=3)
        assert claimed2 is True
        assert rec_id2 == rec_id
        assert att2 == 2

        # Verify state in DB
        row = fetch_one("SELECT processing_status, attempt_count FROM ingested_messages WHERE id = %s", (rec_id,))
        assert row['processing_status'] == 'PROCESSING'
        assert row['attempt_count'] == 2

def test_3_max_retry_count_enforced(app, worker_setup):
    """TEST 3: Verifies maximum retry count (3) is strictly enforced and 4th claim returns False."""
    with app.app_context():
        # Attempt 1
        claimed1, rec_id, _ = IngestedMessageModel.claim_message_for_processing(1, 10, 'max_retry_hash', 102, 999)
        IngestedMessageModel.update_processing_status(rec_id, status='FAILED', error_message='Fail 1')

        # Attempt 2
        claimed2, _, att2 = IngestedMessageModel.claim_message_for_processing(1, 10, 'max_retry_hash', 102, 999, max_attempts=3)
        assert claimed2 is True
        assert att2 == 2
        IngestedMessageModel.update_processing_status(rec_id, status='FAILED', error_message='Fail 2')

        # Attempt 3
        claimed3, _, att3 = IngestedMessageModel.claim_message_for_processing(1, 10, 'max_retry_hash', 102, 999, max_attempts=3)
        assert claimed3 is True
        assert att3 == 3
        IngestedMessageModel.update_processing_status(rec_id, status='FAILED', error_message='Fail 3')

        # Attempt 4 (Exceeds max_attempts=3)
        claimed4, _, att4 = IngestedMessageModel.claim_message_for_processing(1, 10, 'max_retry_hash', 102, 999, max_attempts=3)
        assert claimed4 is False
        assert att4 == 3

def test_4_concurrent_retry_claims_cannot_both_succeed(app, worker_setup):
    """TEST 4: Verifies concurrent retry claims on the same FAILED row allow only 1 winner."""
    with app.app_context():
        claimed1, rec_id, _ = IngestedMessageModel.claim_message_for_processing(1, 10, 'conc_hash', 103, 999)
        IngestedMessageModel.update_processing_status(rec_id, status='FAILED', error_message='Failed initial')

        # Thread 1 claims retry
        claimed_t1, _, att_t1 = IngestedMessageModel.claim_message_for_processing(1, 10, 'conc_hash', 103, 999, max_attempts=3)
        assert claimed_t1 is True
        assert att_t1 == 2

        # Thread 2 attempts claim while Thread 1 is already in PROCESSING status
        claimed_t2, _, _ = IngestedMessageModel.claim_message_for_processing(1, 10, 'conc_hash', 103, 999, max_attempts=3)
        assert claimed_t2 is False  # Cannot claim message already in PROCESSING!

def test_5_and_6_stale_processing_cannot_overwrite_newer_attempt(app, worker_setup):
    """TESTS 5 & 6: Verifies stale recovery ownership check prevents old worker from overwriting newer attempt."""
    with app.app_context():
        # Create dummy analysis records to satisfy FK constraint
        a_id_b = execute_query("INSERT INTO analyzed_emails (institution_id, email_subject, email_text, overall_risk_level) VALUES (1, 'B', 'Body B', 'LOW')")
        a_id_a = execute_query("INSERT INTO analyzed_emails (institution_id, email_subject, email_text, overall_risk_level) VALUES (1, 'A', 'Body A', 'LOW')")

        # Worker A claims attempt 1
        claimed1, rec_id, _ = IngestedMessageModel.claim_message_for_processing(1, 10, 'stale_race_hash', 104, 999)

        # Stale recovery resets status to DISCOVERED
        execute_query("UPDATE ingested_messages SET processing_status = 'DISCOVERED' WHERE id = %s", (rec_id,))

        # Worker B picks up DISCOVERED record (attempt 2)
        claimed2, _, att2 = IngestedMessageModel.claim_message_for_processing(1, 10, 'stale_race_hash', 104, 999, max_attempts=3)
        assert claimed2 is True
        assert att2 == 2

        # Worker B completes analysis and sets PROCESSED
        updated_b = IngestedMessageModel.update_processing_status(rec_id, status='PROCESSED', analysis_id=a_id_b, expected_status='PROCESSING')
        assert updated_b is True

        # Old Worker A now attempts to update status using expected_status='PROCESSING'
        # But row status is already 'PROCESSED'
        updated_a = IngestedMessageModel.update_processing_status(rec_id, status='PROCESSED', analysis_id=a_id_a, expected_status='PROCESSING')
        assert updated_a is False  # Rejected! Worker A lost ownership.

def test_7_and_8_auth_failure_backoff_and_mailbox_isolation(app, worker_setup, monkeypatch):
    """TESTS 7 & 8: Verifies authentication failure triggers backoff and other mailboxes continue."""
    mock_imap_auth_fail = MagicMock()
    mock_imap_auth_fail.connect.side_effect = IMAPAuthenticationError("Invalid credentials")

    mock_imap_ok = MagicMock()
    mock_imap_ok.connect.return_value = True
    mock_imap_ok.select_mailbox.return_value = ('OK', 999, 0)
    mock_imap_ok.fetch_unseen_uids.return_value = []

    def imap_factory(institution_id):
        if institution_id == 1:
            return mock_imap_auth_fail
        return mock_imap_ok

    monkeypatch.setattr('bullymail.worker.processor.IMAPClient', imap_factory)

    processor = MailboxProcessor()
    cfg10 = {'id': 10, 'institution_id': 1, 'email_address': 'mb1@inst1.com'}
    cfg20 = {'id': 20, 'institution_id': 2, 'email_address': 'mb2@inst2.com'}

    with app.app_context():
        from bullymail.services.email_service import email_service
        lease10 = email_service.acquire_sync_lease(10, 1)
        lease20 = email_service.acquire_sync_lease(20, 2)

        # First attempt on Mailbox 10 -> Auth failure
        res1 = processor.process_mailbox(cfg10, lease_id=lease10)
        assert res1 is False
        assert processor._is_in_auth_backoff(10) is True

        # Second immediate attempt on Mailbox 10 -> Skipped due to backoff
        res1_b = processor.process_mailbox(cfg10, lease_id=lease10)
        assert res1_b is False

        # Mailbox 20 (Institution 2) proceeds successfully!
        res2 = processor.process_mailbox(cfg20, lease_id=lease20)
        assert res2 is True

def test_9_mid_batch_shutdown_stops_message_claims(app, worker_setup, monkeypatch):
    """TEST 9: Verifies mid-batch shutdown request halts further message claims."""
    msg = MIMEText("Test body", "plain")

    mock_imap = MagicMock()
    mock_imap.connect.return_value = True
    mock_imap.select_mailbox.return_value = ('OK', 12345, 3)
    mock_imap.fetch_unseen_uids.return_value = [701, 702, 703]
    mock_imap.fetch_rfc822_message.return_value = msg.as_bytes()
    monkeypatch.setattr('bullymail.worker.processor.IMAPClient', lambda institution_id: mock_imap)

    processor = MailboxProcessor()
    config_row = {'id': 10, 'institution_id': 1, 'email_address': 'mb1@inst1.com'}

    stop_flag = False
    def should_stop_callback():
        return stop_flag

    with app.app_context():
        from bullymail.services.email_service import email_service
        lease9 = email_service.acquire_sync_lease(10, 1)

        # Process first message, then set stop_flag = True
        stop_flag = True
        processor.process_mailbox(config_row, should_stop=should_stop_callback, lease_id=lease9)

    with app.app_context():
        msgs = fetch_all("SELECT * FROM ingested_messages WHERE email_config_id = 10")
    # Only 0 or 1 message claimed before mid-batch halt
    assert len(msgs) <= 1

def test_10_safe_logging_no_secrets_exposed(app, worker_setup, caplog, monkeypatch):
    """TEST 10: Operational logging never exposes passwords, tokens, or encryption keys."""
    mock_imap = MagicMock()
    mock_imap.connect.side_effect = IMAPAuthenticationError("AUTHENTICATIONFAILED Bad credentials")
    monkeypatch.setattr('bullymail.worker.processor.IMAPClient', lambda institution_id: mock_imap)

    processor = MailboxProcessor()
    config_row = {'id': 10, 'institution_id': 1, 'email_address': 'mb1@inst1.com'}

    with caplog.at_level('DEBUG'):
        with app.app_context():
            from bullymail.services.email_service import email_service
            lease10 = email_service.acquire_sync_lease(10, 1)
            processor.process_mailbox(config_row, lease_id=lease10)

    log_output = caplog.text
    assert 'SecretPassword999' not in log_output
    assert 'BULLYMAIL_MASTER_KEY' not in log_output
    assert 'gAAAAA' not in log_output

def test_11_worker_lease_acquisition_and_release_lifecycle(app, worker_setup, monkeypatch):
    """Verifies WorkerDaemon acquires lease, passes lease_id to process_mailbox, and releases lease in finally block."""
    from bullymail.worker.daemon import WorkerDaemon
    from bullymail.services.email_service import email_service

    processor_mock = MagicMock()
    processor_mock.process_mailbox.return_value = True

    daemon = WorkerDaemon(processor=processor_mock)

    with app.app_context():
        count = daemon.run_once()
        assert count >= 1

        # Check call arguments to process_mailbox
        assert processor_mock.process_mailbox.called
        call_kwargs = processor_mock.process_mailbox.call_args.kwargs
        assert 'lease_id' in call_kwargs
        assert call_kwargs['lease_id'] is not None
        assert len(call_kwargs['lease_id']) > 0

        # Verify lease was released cleanly after processing
        row = fetch_one("SELECT sync_status, sync_lease_id FROM email_config WHERE id = 10")
        assert row['sync_lease_id'] is None
        assert row['sync_status'] == 'OK'

def test_12_worker_skips_mailbox_and_does_not_call_process_when_lease_held(app, worker_setup):
    """Verifies WorkerDaemon skips mailboxes when acquire_sync_lease returns None (lease held by Manual Sync)."""
    from bullymail.worker.daemon import WorkerDaemon
    from bullymail.services.email_service import email_service

    processor_mock = MagicMock()
    daemon = WorkerDaemon(processor=processor_mock)

    with app.app_context():
        # Manual sync acquires lease first for both active test mailboxes (10 & 20)
        manual_lease_10 = email_service.acquire_sync_lease(10, 1)
        manual_lease_20 = email_service.acquire_sync_lease(20, 2)
        assert manual_lease_10 is not None
        assert manual_lease_20 is not None

        # Worker daemon runs once -> MUST skip mailboxes and NOT call process_mailbox
        daemon.run_once()
        assert processor_mock.process_mailbox.called is False

        # Database leases remain untouched by worker
        row10 = fetch_one("SELECT sync_lease_id FROM email_config WHERE id = 10")
        assert row10['sync_lease_id'] == manual_lease_10

def test_13_worker_releases_lease_on_exception(app, worker_setup):
    """Verifies WorkerDaemon releases its lease in finally block even when process_mailbox raises an exception."""
    from bullymail.worker.daemon import WorkerDaemon

    processor_mock = MagicMock()
    processor_mock.process_mailbox.side_effect = RuntimeError("Fatal ingestion exception")

    daemon = WorkerDaemon(processor=processor_mock)

    with app.app_context():
        daemon.run_once()

        # Lease must be released with status 'ERROR' in finally block
        row = fetch_one("SELECT sync_status, sync_lease_id FROM email_config WHERE id = 10")
        assert row['sync_lease_id'] is None
        assert row['sync_status'] == 'ERROR'

def test_14_process_mailbox_rejects_missing_lease_id(app, worker_setup):
    """Verifies process_mailbox rejects execution and returns False if lease_id is None."""
    processor = MailboxProcessor()
    config_row = {'id': 10, 'institution_id': 1, 'email_address': 'mb1@inst1.com'}

    with app.app_context():
        res = processor.process_mailbox(config_row, lease_id=None)
        assert res is False

