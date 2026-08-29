import pytest
import datetime
from bullymail.database.connection import get_db, fetch_one, fetch_all, execute_query
from bullymail.models.ingested_message import IngestedMessageModel

def test_ingested_messages_table_schema_and_columns(app):
    """Verifies ingested_messages table is created with required columns."""
    with app.app_context():
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(ingested_messages)")
            cols = {row[1]: row[2] for row in cursor.fetchall()}

        assert 'id' in cols
        assert 'institution_id' in cols
        assert 'email_config_id' in cols
        assert 'message_id_hash' in cols
        assert 'imap_uid' in cols
        assert 'uidvalidity' in cols
        assert 'processing_status' in cols
        assert 'attempt_count' in cols
        assert 'last_attempt_at' in cols
        assert 'error_message' in cols
        assert 'analysis_id' in cols

def test_email_config_telemetry_columns(app):
    """Verifies email_config telemetry migration columns exist."""
    with app.app_context():
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(email_config)")
            cols = {row[1]: row[2] for row in cursor.fetchall()}

        assert 'last_synced_at' in cols
        assert 'sync_status' in cols
        assert 'last_error' in cols
        assert 'total_ingested_count' in cols

def test_message_id_deterministic_sha256_identity():
    """CORRECTION TEST 1: Message-ID produces deterministic SHA-256 identity."""
    raw_msg_id = "<CAG8q_12345_unique@mail.gmail.com>"
    hash1 = IngestedMessageModel.compute_message_id_hash(raw_msg_id)
    hash2 = IngestedMessageModel.compute_message_id_hash("<CAG8q_12345_unique@mail.gmail.com>")
    hash3 = IngestedMessageModel.compute_message_id_hash("CAG8q_12345_unique@mail.gmail.com")

    assert len(hash1) == 64
    assert hash1 == hash2
    assert hash1 == hash3  # Angle brackets normalized

def test_same_message_id_cannot_create_duplicate_records(app):
    """CORRECTION TEST 2: Same Message-ID for the same mailbox cannot create duplicate ingestion records."""
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Test Inst', 'test.com')")
        execute_query("INSERT OR IGNORE INTO email_config (id, institution_id, email_address, status) VALUES (10, 1, 'mb@test.com', 'active')")

        msg_hash = IngestedMessageModel.compute_message_id_hash("<msg_id_100@test.com>")

        # First claim succeeds
        res1 = IngestedMessageModel.claim_message_for_processing(1, 10, msg_hash, imap_uid=50)
        success1, rec1 = res1[0], res1[1]
        assert success1 is True
        assert rec1 is not None

        # Second claim for same mailbox fails cleanly due to database uniqueness
        res2 = IngestedMessageModel.claim_message_for_processing(1, 10, msg_hash, imap_uid=50)
        success2, rec2 = res2[0], res2[1]
        assert success2 is False
        assert rec2 == rec1

def test_missing_message_id_uses_deterministic_fallback():
    """CORRECTION TEST 3 & 4: Missing Message-ID uses normalized content fallback deterministically."""
    # Test missing Message-ID (None or empty)
    fallback_hash1 = IngestedMessageModel.compute_message_id_hash(
        raw_msg_id=None,
        from_addr="Alice Smith <ALICE@EXAMPLE.COM>",
        to_addr="Bob Jones <bob@example.com>",
        date_str="Fri, 28 Aug 2026 10:00:00 +0000",
        subject="  URGENT Security Notice  ",
        body_snippet="Please review your login details immediately..."
    )
    assert len(fallback_hash1) == 64

    # Equivalent input with different whitespace/casing must produce identical fallback hash
    fallback_hash2 = IngestedMessageModel.compute_message_id_hash(
        raw_msg_id="",
        from_addr="alice@example.com",
        to_addr="bob@example.com",
        date_str="Fri, 28 Aug 2026 10:00:00 +0000",
        subject="URGENT Security Notice",
        body_snippet="Please review your login details immediately..."
    )

    assert fallback_hash1 == fallback_hash2

def test_sqlite_stale_processing_recovery(app):
    """CORRECTION TEST 5: SQLite stale-processing recovery works and is tenant-safe."""
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Inst 1', 'inst1.com')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Inst 2', 'inst2.com')")
        execute_query("INSERT OR IGNORE INTO email_config (id, institution_id, email_address, status) VALUES (10, 1, 'mb1@inst1.com', 'active')")
        execute_query("INSERT OR IGNORE INTO email_config (id, institution_id, email_address, status) VALUES (20, 2, 'mb2@inst2.com', 'active')")

        stale_time = (datetime.datetime.utcnow() - datetime.timedelta(minutes=25)).strftime('%Y-%m-%d %H:%M:%S')

        # Insert stale record for Tenant 1
        id1 = execute_query(
            '''INSERT INTO ingested_messages 
               (institution_id, email_config_id, message_id_hash, processing_status, attempt_count, updated_at) 
               VALUES (%s, %s, %s, 'PROCESSING', 1, %s)''',
            (1, 10, 'stale_t1_hash', stale_time)
        )

        # Insert stale record for Tenant 2
        id2 = execute_query(
            '''INSERT INTO ingested_messages 
               (institution_id, email_config_id, message_id_hash, processing_status, attempt_count, updated_at) 
               VALUES (%s, %s, %s, 'PROCESSING', 1, %s)''',
            (2, 20, 'stale_t2_hash', stale_time)
        )

        # Tenant-scoped recovery for Tenant 1 ONLY
        IngestedMessageModel.recover_stale_processing(institution_id=1, timeout_minutes=15)

        row1 = fetch_one("SELECT * FROM ingested_messages WHERE id = %s", (id1,))
        row2 = fetch_one("SELECT * FROM ingested_messages WHERE id = %s", (id2,))

        # Tenant 1 is recovered
        assert row1['processing_status'] == 'DISCOVERED'
        assert 'stale processing timeout' in row1['error_message']

        # Tenant 2 is NOT affected by Tenant 1 recovery call
        assert row2['processing_status'] == 'PROCESSING'

def test_mysql_stale_processing_query_generation():
    """CORRECTION TEST 6: MySQL stale-processing SQL query generation is verified without faking MySQL server."""
    query_gen, params_gen = IngestedMessageModel.get_stale_recovery_query('mysql', institution_id=1, timeout_minutes=15)

    assert "DATE_SUB(NOW(), INTERVAL %s MINUTE)" in query_gen
    assert "institution_id = %s" in query_gen
    assert params_gen == ("Reset after stale processing timeout", 15, 1)

    query_global, params_global = IngestedMessageModel.get_stale_recovery_query('mysql', institution_id=None, timeout_minutes=20)
    assert "DATE_SUB(NOW(), INTERVAL %s MINUTE)" in query_global
    assert "institution_id" not in query_global
    assert params_global == ("Reset after stale processing timeout", 20)

def test_email_config_sync_lease_columns_exist_and_default_to_null(app):
    """Verify sync_lease_id and sync_lease_expires_at columns exist on email_config and default to NULL."""
    with app.app_context():
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(email_config)")
            cols = {row[1]: row for row in cursor.fetchall()}

        assert 'sync_lease_id' in cols
        assert 'sync_lease_expires_at' in cols

        # Insert a sample mailbox
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Lease Test Inst', 'leasetest.com')")
        execute_query(
            "INSERT INTO email_config (institution_id, email_address, status) VALUES (%s, %s, %s)",
            (1, 'lease_test@leasetest.com', 'active')
        )

        row = fetch_one("SELECT sync_lease_id, sync_lease_expires_at FROM email_config WHERE email_address = %s", ('lease_test@leasetest.com',))
        assert row is not None
        assert row['sync_lease_id'] is None
        assert row['sync_lease_expires_at'] is None

def test_email_config_migration_is_idempotent(app):
    """Verify that apply_migrations() can be safely called multiple times without error or data loss."""
    from bullymail.database.schema import apply_migrations
    from bullymail.database.connection import get_engine_type
    with app.app_context():
        engine = get_engine_type()
        with get_db() as conn:
            cursor = conn.cursor()
            apply_migrations(cursor, engine)
            apply_migrations(cursor, engine)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(email_config)")
            cols = {row[1] for row in cursor.fetchall()}

        assert 'sync_lease_id' in cols
        assert 'sync_lease_expires_at' in cols

def test_email_config_requires_explicit_institution_id(app):
    """Verify that inserting email_config with NULL institution_id raises an IntegrityError."""
    with app.app_context():
        with pytest.raises(Exception):
            execute_query(
                "INSERT INTO email_config (institution_id, email_address, status) VALUES (NULL, %s, %s)",
                ('no_inst@test.com', 'active')
            )

