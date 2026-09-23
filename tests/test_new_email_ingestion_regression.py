import pytest
import datetime
from unittest.mock import MagicMock, patch
from bullymail.database.connection import execute_query, fetch_one, fetch_all
from bullymail.worker.processor import MailboxProcessor, _parse_datetime, _parse_email_date
from bullymail.services.email_service import email_service

def create_raw_email(subject, sender, date_str, body):
    return (
        f"From: {sender}\r\n"
        f"To: target998@school.edu\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {date_str}\r\n"
        f"Message-ID: <{abs(hash(subject + date_str))}@school.edu>\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        f"{body}"
    ).encode('utf-8')

@pytest.fixture
def regression_setup(app):
    """Sets up isolated institution ID=998 for regression testing."""
    with app.app_context():
        execute_query("DELETE FROM ingested_messages WHERE institution_id = 998")
        execute_query("DELETE FROM analyzed_emails WHERE institution_id = 998")
        execute_query("DELETE FROM email_config WHERE institution_id = 998")
        execute_query("DELETE FROM users WHERE institution_id = 998")
        execute_query("DELETE FROM institutions WHERE id = 998")

        execute_query("INSERT INTO institutions (id, name, domain) VALUES (998, 'Regression Test Inst', 'regtest998.org')")
        yield {'inst_id': 998}

        execute_query("DELETE FROM ingested_messages WHERE institution_id = 998")
        execute_query("DELETE FROM analyzed_emails WHERE institution_id = 998")
        execute_query("DELETE FROM email_config WHERE institution_id = 998")
        execute_query("DELETE FROM users WHERE institution_id = 998")
        execute_query("DELETE FROM institutions WHERE id = 998")

def test_timezone_aware_date_parsing():
    """Verifies that naive DB datetimes and RFC822 timezone dates compare accurately in UTC."""
    # 04:00 AM IST on Sept 24 = 22:30 UTC on Sept 23
    baseline = _parse_datetime('2026-09-23 22:30:00')
    assert baseline.tzinfo == datetime.timezone.utc

    # 03:50 AM IST on Sept 24 = 22:20 UTC on Sept 23 (HISTORICAL -> BEFORE baseline)
    old_email = _parse_email_date('Thu, 24 Sep 2026 03:50:00 +0530')
    assert old_email.tzinfo == datetime.timezone.utc
    assert old_email < baseline

    # 04:10 AM IST on Sept 24 = 22:40 UTC on Sept 23 (NEW -> AFTER baseline)
    new_email = _parse_email_date('Thu, 24 Sep 2026 04:10:00 +0530')
    assert new_email.tzinfo == datetime.timezone.utc
    assert new_email > baseline

@patch('bullymail.worker.processor.IMAPClient')
def test_new_email_ingestion_end_to_end(mock_imap_cls, app, regression_setup):
    """
    Simulates end-to-end ingestion where a mailbox configured at 04:00:00 IST:
    - Ignores emails received at 2026-09-23 10:00 IST and 2026-09-24 03:00 IST.
    - Ingests emails received at 2026-09-24 04:10 IST and 2026-09-24 04:20 IST.
    - Prevents duplicate ingestion on subsequent sync calls.
    """
    with app.app_context():
        inst_id = regression_setup['inst_id']
        baseline_time_str = '2026-09-23 22:30:00'

        # 1. Configure Mailbox at T = 2026-09-23 22:30:00 UTC (04:00 IST)
        mb = email_service.configure_mailbox(inst_id, 'target998@school.edu', 'password123')
        mb_id = mb['id']

        execute_query('''
            UPDATE email_config
            SET configured_at = %s, monitoring_started_at = %s, initial_uid = 0, last_processed_uid = 0, uid_validity = '100', mailbox_initialized = 1
            WHERE id = %s
        ''', (baseline_time_str, baseline_time_str, mb_id))

        # 2. Mock IMAP Client with 4 emails (2 before baseline, 2 after baseline)
        mock_imap = MagicMock()
        mock_imap_cls.return_value = mock_imap
        mock_imap.connect.return_value = True
        mock_imap.select_mailbox.return_value = ('OK', 100, 4)
        mock_imap.fetch_unseen_uids.return_value = [1, 2, 3, 4]

        email_1 = create_raw_email("Old Email 1", "old1@external.com", "Wed, 23 Sep 2026 10:00:00 +0530", "Hello world")
        email_2 = create_raw_email("Old Email 2", "old2@external.com", "Thu, 24 Sep 2026 03:00:00 +0530", "Early morning")
        email_3 = create_raw_email("New Threat 1", "attacker1@external.com", "Thu, 24 Sep 2026 04:10:00 +0530", "You fucker die")
        email_4 = create_raw_email("New Email 2", "friend@external.com", "Thu, 24 Sep 2026 04:20:00 +0530", "Good morning friend")

        msg_map = {
            1: (email_1, "23-Sep-2026 10:00:00 +0530"),
            2: (email_2, "24-Sep-2026 03:00:00 +0530"),
            3: (email_3, "24-Sep-2026 04:10:00 +0530"),
            4: (email_4, "24-Sep-2026 04:20:00 +0530"),
        }
        mock_imap.fetch_message_with_metadata.side_effect = lambda uid: msg_map[uid]
        mock_imap.fetch_rfc822_message.side_effect = lambda uid: msg_map[uid][0]

        processor = MailboxProcessor()
        cfg_row = fetch_one("SELECT * FROM email_config WHERE id = %s", (mb_id,))

        lease_id = email_service.acquire_sync_lease(mb_id, inst_id)

        # 3. Perform Sync 1 (Manual "Sync Now")
        summary1 = processor.process_mailbox(cfg_row, lease_id=lease_id, return_summary=True)
        assert summary1['success'] is True
        assert summary1['emails_found'] == 4
        assert summary1['emails_processed'] == 2  # Only email_3 and email_4 ingested!

        # Verify DB records
        analyzed = fetch_all("SELECT email_subject, overall_risk_level FROM analyzed_emails WHERE email_config_id = %s ORDER BY id ASC", (mb_id,))
        assert len(analyzed) == 2
        subjects = [a['email_subject'] for a in analyzed]
        assert "New Threat 1" in subjects
        assert "New Email 2" in subjects
        assert "Old Email 1" not in subjects
        assert "Old Email 2" not in subjects

        # Verify last_processed_uid was updated to high watermark 4
        cfg_after = fetch_one("SELECT last_processed_uid FROM email_config WHERE id = %s", (mb_id,))
        assert int(cfg_after['last_processed_uid']) == 4

        # 4. Perform Sync 2 (Deduplication Check)
        mock_imap.fetch_unseen_uids.return_value = []  # No new UIDs > 4
        lease_id_2 = email_service.acquire_sync_lease(mb_id, inst_id)
        summary2 = processor.process_mailbox(cfg_row, lease_id=lease_id_2, return_summary=True)
        assert summary2['success'] is True
        assert summary2['emails_found'] == 0
        assert summary2['emails_processed'] == 0

        # Verify total count in DB remains 2
        analyzed_after_sync2 = fetch_all("SELECT id FROM analyzed_emails WHERE email_config_id = %s", (mb_id,))
        assert len(analyzed_after_sync2) == 2
