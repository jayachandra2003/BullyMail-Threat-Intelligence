import pytest
import datetime
from unittest.mock import MagicMock
from bullymail.services.email_service import email_service
from bullymail.database.connection import execute_query, fetch_one, fetch_all

@pytest.fixture
def setup_tenants(app):
    """Sets up Tenant 1 and Tenant 2 with active admin users and sample mailboxes."""
    with app.app_context():
        # Clean existing test data
        execute_query("DELETE FROM email_config")
        execute_query("DELETE FROM users WHERE id IN (100, 101, 102)")
        execute_query("DELETE FROM institutions WHERE id IN (10, 20)")

        # Create Institutions
        execute_query("INSERT INTO institutions (id, name, domain) VALUES (10, 'Inst Alpha', 'alpha.com')")
        execute_query("INSERT INTO institutions (id, name, domain) VALUES (20, 'Inst Beta', 'beta.com')")

        # Create Users
        # Admin Alpha (Inst 10)
        execute_query(
            "INSERT INTO users (id, username, email, password_hash, institution_id, role, status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (100, 'admin_alpha', 'admin@alpha.com', 'hash', 10, 'admin', 'ACTIVE')
        )
        # Admin Beta (Inst 20)
        execute_query(
            "INSERT INTO users (id, username, email, password_hash, institution_id, role, status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (101, 'admin_beta', 'admin@beta.com', 'hash', 20, 'admin', 'ACTIVE')
        )
        # Analyst Alpha (Inst 10)
        execute_query(
            "INSERT INTO users (id, username, email, password_hash, institution_id, role, status) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (102, 'analyst_alpha', 'analyst@alpha.com', 'hash', 10, 'analyst', 'ACTIVE')
        )

        # Configure Mailboxes
        mb1 = email_service.configure_mailbox(10, 'mailbox_alpha@alpha.com', 'app_pass_1000')
        mb2 = email_service.configure_mailbox(20, 'mailbox_beta@beta.com', 'app_pass_2000')

        return {
            'inst_alpha_id': 10,
            'inst_beta_id': 20,
            'admin_alpha_id': 100,
            'admin_beta_id': 101,
            'analyst_alpha_id': 102,
            'mb_alpha_id': mb1['id'],
            'mb_beta_id': mb2['id']
        }

def test_admin_mailbox_listing_and_tenant_isolation(client, setup_tenants):
    """Verify admin listing returns mailboxes for caller's institution only."""
    # Auth as Admin Alpha (Inst 10)
    with client.session_transaction() as sess:
        sess['user_id'] = 100
        sess['username'] = 'admin_alpha'
        sess['role'] = 'admin'

    res = client.get('/api/admin/mailboxes')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['mailboxes']) == 1
    assert data['mailboxes'][0]['email_address'] == 'mailbox_alpha@alpha.com'

    # Auth as Admin Beta (Inst 20)
    with client.session_transaction() as sess:
        sess['user_id'] = 101
        sess['username'] = 'admin_beta'
        sess['role'] = 'admin'

    res = client.get('/api/admin/mailboxes')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['mailboxes']) == 1
    assert data['mailboxes'][0]['email_address'] == 'mailbox_beta@beta.com'

def test_cross_tenant_mailbox_status_access_returns_404(client, setup_tenants):
    """Verify Admin Alpha attempting to modify Admin Beta's mailbox returns HTTP 404."""
    with client.session_transaction() as sess:
        sess['user_id'] = 100
        sess['username'] = 'admin_alpha'
        sess['role'] = 'admin'

    beta_mb_id = setup_tenants['mb_beta_id']

    # Cross-tenant status update attempt
    res = client.post(f'/api/admin/mailboxes/{beta_mb_id}/status', json={'status': 'disabled'})
    assert res.status_code == 404
    assert res.get_json()['error'] == 'Mailbox not found.'

    # Cross-tenant sync attempt
    res = client.post(f'/api/admin/mailboxes/{beta_mb_id}/sync')
    assert res.status_code == 404
    assert res.get_json()['error'] == 'Mailbox not found.'

def test_role_authorization_for_mailbox_management(client, setup_tenants):
    """Verify non-admin users (analysts) receive HTTP 403 Forbidden on admin endpoints."""
    with client.session_transaction() as sess:
        sess['user_id'] = 102
        sess['username'] = 'analyst_alpha'
        sess['role'] = 'analyst'

    res = client.get('/api/admin/mailboxes')
    assert res.status_code == 403

def test_password_secret_protection_in_api_responses(client, setup_tenants):
    """Verify plaintext or encrypted app_passwords are never leaked in API JSON responses."""
    with client.session_transaction() as sess:
        sess['user_id'] = 100
        sess['username'] = 'admin_alpha'
        sess['role'] = 'admin'

    res = client.get('/api/admin/mailboxes')
    assert res.status_code == 200
    mb = res.get_json()['mailboxes'][0]

    assert 'app_password' not in mb
    assert 'encrypted_app_password' not in mb

def test_preflight_connection_test_endpoint(client, setup_tenants, monkeypatch):
    """Verify pre-flight connection test endpoint safely validates credentials with mocked IMAPClient."""
    with client.session_transaction() as sess:
        sess['user_id'] = 100
        sess['username'] = 'admin_alpha'
        sess['role'] = 'admin'

    # Mock IMAP4_SSL
    class MockIMAP4_SSL:
        def __init__(self, *args, **kwargs):
            pass
        def login(self, user, password):
            return 'OK', [b'Logged in']
        def logout(self):
            pass

    monkeypatch.setattr('imaplib.IMAP4_SSL', MockIMAP4_SSL)

    res = client.post('/api/admin/mailboxes/test-connection', json={
        'email_address': 'test@alpha.com',
        'app_password': 'secret_pass_123'
    })
    assert res.status_code == 200
    assert res.get_json()['success'] is True

def test_atomic_sync_lease_acquisition_and_conflict_409(app, setup_tenants, client):
    """Verify atomic lease acquisition succeeds for first process and returns 409 Conflict for concurrent attempt."""
    alpha_mb_id = setup_tenants['mb_alpha_id']

    with app.app_context():
        # First lease acquisition
        lease1 = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert lease1 is not None
        assert len(lease1) > 0

        # Concurrent lease acquisition attempt MUST fail
        lease2 = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert lease2 is None

    # Test HTTP 409 Conflict via API endpoint
    with client.session_transaction() as sess:
        sess['user_id'] = 100
        sess['username'] = 'admin_alpha'
        sess['role'] = 'admin'

    res = client.post(f'/api/admin/mailboxes/{alpha_mb_id}/sync')
    assert res.status_code == 409
    assert res.get_json()['error'] == 'Synchronization already in progress for this mailbox.'

def test_stale_lease_recovery_and_ownership_safe_release(app, setup_tenants):
    """Verify expired lease can be reclaimed and stale lease owner cannot overwrite newer lease."""
    alpha_mb_id = setup_tenants['mb_alpha_id']

    with app.app_context():
        # Acquire initial lease
        lease1 = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert lease1 is not None

        # Simulate lease expiration by updating sync_lease_expires_at to past timestamp
        execute_query(
            "UPDATE email_config SET sync_lease_expires_at = '2000-01-01 00:00:00' WHERE id = %s",
            (alpha_mb_id,)
        )

        # Reclaim expired lease
        lease2 = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert lease2 is not None
        assert lease2 != lease1

        # Stale owner (lease1) attempts release -> MUST fail
        released_stale = email_service.release_sync_lease(alpha_mb_id, lease1, final_status='OK')
        assert released_stale is False

        # Current owner (lease2) releases lease -> MUST succeed
        released_current = email_service.release_sync_lease(alpha_mb_id, lease2, final_status='OK')
        assert released_current is True

def test_disabled_mailbox_exclusion(client, setup_tenants):
    """Verify disabled mailbox cannot be manually synchronized."""
    alpha_mb_id = setup_tenants['mb_alpha_id']

    with client.session_transaction() as sess:
        sess['user_id'] = 100
        sess['username'] = 'admin_alpha'
        sess['role'] = 'admin'

    # Disable mailbox
    res = client.post(f'/api/admin/mailboxes/{alpha_mb_id}/status', json={'status': 'disabled'})
    assert res.status_code == 200

    # Sync attempt should fail with error
    res_sync = client.post(f'/api/admin/mailboxes/{alpha_mb_id}/sync')
    assert res_sync.status_code == 400
    assert res_sync.get_json()['error'] == 'Cannot synchronize a disabled mailbox.'

def test_legacy_configure_email_compatibility(client, setup_tenants, monkeypatch):
    """Verify legacy /api/configure-email endpoint maintains backward compatibility with tenant isolation."""
    with client.session_transaction() as sess:
        sess['user_id'] = 100
        sess['username'] = 'admin_alpha'
        sess['role'] = 'admin'

    monkeypatch.setattr('bullymail.routes.email_integration.email_service.test_connection', lambda *a, **k: (True, "Connection OK"))

    res = client.post('/api/configure-email', json={
        'email': 'legacy_mailbox@alpha.com',
        'app_password': 'legacy_pass_999'
    })
    assert res.status_code == 200
    assert res.get_json()['success'] is True

def test_stale_owner_cannot_update_telemetry_or_overwrite_newer_lease(app, setup_tenants):
    """
    MANDATORY REGRESSION TEST:
    Process A acquires lease_A, lease_A expires, Process B acquires lease_B.
    Process A calls update_telemetry with lease_A -> MUST be rejected (0 rows updated).
    """
    alpha_mb_id = setup_tenants['mb_alpha_id']
    from bullymail.worker.processor import MailboxProcessor

    with app.app_context():
        # Process A acquires lease_A
        lease_A = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert lease_A is not None

        # Simulate expiration of lease_A
        execute_query(
            "UPDATE email_config SET sync_lease_expires_at = '2000-01-01 00:00:00' WHERE id = %s",
            (alpha_mb_id,)
        )

        # Process B acquires lease_B
        lease_B = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert lease_B is not None
        assert lease_B != lease_A

        # Set initial Process B state marker
        execute_query(
            "UPDATE email_config SET last_error = 'Process B active' WHERE id = %s",
            (alpha_mb_id,)
        )

        # Stale Process A attempts to update telemetry with lease_A -> MUST return False and update 0 rows
        success_A = MailboxProcessor.update_telemetry(
            alpha_mb_id,
            sync_status='OK',
            last_error='Process A stale overwrite attempt',
            increment_count=True,
            lease_id=lease_A
        )
        assert success_A is False

        # Verify database state was NOT corrupted by stale Process A
        row = fetch_one("SELECT sync_status, sync_lease_id, last_error FROM email_config WHERE id = %s", (alpha_mb_id,))
        assert row['sync_status'] == 'SYNCING'  # Still owned by Process B
        assert row['sync_lease_id'] == lease_B   # Still owned by Process B
        assert row['last_error'] == 'Process B active'  # Process A could not modify last_error

        # Process B updates telemetry with active lease_B -> MUST succeed
        success_B = MailboxProcessor.update_telemetry(
            alpha_mb_id,
            sync_status='OK',
            last_error=None,
            increment_count=False,
            lease_id=lease_B
        )
        assert success_B is True

def test_telemetry_lease_id_options_and_fallback(app, setup_tenants):
    """Verifies valid lease owner, wrong lease owner, and missing lease_id (legacy Phase 1B worker) behaviors."""
    alpha_mb_id = setup_tenants['mb_alpha_id']
    from bullymail.worker.processor import MailboxProcessor

    with app.app_context():
        # 1. Missing lease_id (Legacy Phase 1B worker fallback)
        res_fallback = MailboxProcessor.update_telemetry(alpha_mb_id, sync_status='OK', lease_id=None)
        assert res_fallback is True

        # 2. Acquire active lease
        active_lease = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert active_lease is not None

        # 3. Wrong lease_id -> MUST fail
        res_wrong = MailboxProcessor.update_telemetry(alpha_mb_id, sync_status='ERROR', lease_id='invalid-uuid-1234')
        assert res_wrong is False

        # 4. Correct lease_id -> MUST succeed
        res_correct = MailboxProcessor.update_telemetry(alpha_mb_id, sync_status='SYNCING', lease_id=active_lease)
        assert res_correct is True

def test_telemetry_refreshes_lease_expiration_heartbeat(app, setup_tenants):
    """Verifies that successful telemetry updates extend sync_lease_expires_at (lease heartbeat)."""
    alpha_mb_id = setup_tenants['mb_alpha_id']
    from bullymail.worker.processor import MailboxProcessor

    with app.app_context():
        # Acquire initial lease
        active_lease = email_service.acquire_sync_lease(alpha_mb_id, 10)
        assert active_lease is not None

        # Manually set lease expiration to near-expired timestamp (10 seconds from now)
        execute_query(
            "UPDATE email_config SET sync_lease_expires_at = '2026-01-01 00:00:10' WHERE id = %s",
            (alpha_mb_id,)
        )

        # Trigger heartbeat update_telemetry
        ok = MailboxProcessor.update_telemetry(alpha_mb_id, sync_status='SYNCING', lease_id=active_lease)
        assert ok is True

        # Verify sync_lease_expires_at was refreshed to > year 2026
        row = fetch_one("SELECT sync_lease_expires_at FROM email_config WHERE id = %s", (alpha_mb_id,))
        assert str(row['sync_lease_expires_at']) != '2026-01-01 00:00:10'

def test_process_mailbox_halts_immediately_on_lease_loss(app, setup_tenants, monkeypatch):
    """Verifies that process_mailbox halts immediately and stops loop when telemetry update fails due to lease loss."""
    alpha_mb_id = setup_tenants['mb_alpha_id']
    from bullymail.worker.processor import MailboxProcessor
    from email.mime.text import MIMEText

    msg = MIMEText("Test body", "plain")

    mock_imap = MagicMock()
    mock_imap.connect.return_value = True
    mock_imap.select_mailbox.return_value = ('OK', 12345, 3)
    mock_imap.fetch_unseen_uids.return_value = [801, 802, 803]
    mock_imap.fetch_rfc822_message.return_value = msg.as_bytes()
    monkeypatch.setattr('bullymail.worker.processor.IMAPClient', lambda institution_id: mock_imap)

    processor = MailboxProcessor()
    config_row = {'id': alpha_mb_id, 'institution_id': 10, 'email_address': 'alpha@alpha.com'}

    with app.app_context():
        # Acquire initial lease
        lease_id = email_service.acquire_sync_lease(alpha_mb_id, 10)

        # Force update_telemetry to fail (simulating lease loss mid-loop) after start
        original_update = processor.update_telemetry
        call_count = [0]
        def failing_update(config_id, sync_status, last_error=None, increment_count=False, lease_id=None):
            call_count[0] += 1
            if call_count[0] >= 2:  # Fail on second telemetry call (during message loop)
                return False
            return original_update(config_id, sync_status, last_error, increment_count, lease_id)

        monkeypatch.setattr(processor, 'update_telemetry', failing_update)

        res = processor.process_mailbox(config_row, lease_id=lease_id)

        # Loop must break after 1st message when failing_update returns False
        msgs = fetch_all("SELECT * FROM ingested_messages WHERE email_config_id = %s", (alpha_mb_id,))
        assert len(msgs) == 1  # Only 1 message processed, 802 and 803 skipped!


