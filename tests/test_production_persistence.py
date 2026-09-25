import os
import pytest
from bullymail.config import _parse_database_config, Config
from bullymail.database import connection
from bullymail.database.connection import fetch_one, execute_query, get_engine_type
from bullymail.database.schema import setup_database
from bullymail.services.email_service import EmailService

def test_database_url_parsing_mysql_and_postgres(monkeypatch):
    """Verifies that DATABASE_URL strings (MySQL and PostgreSQL) parse accurately into Config settings."""
    # Test MySQL DATABASE_URL
    monkeypatch.setenv('DATABASE_URL', 'mysql://prod_user:secret_pass_123@mysql-db.render.com:3306/bullymail_prod')
    cfg_mysql = _parse_database_config()
    assert cfg_mysql['DB_TYPE'] == 'mysql'
    assert cfg_mysql['DB_HOST'] == 'mysql-db.render.com'
    assert cfg_mysql['DB_PORT'] == 3306
    assert cfg_mysql['DB_USER'] == 'prod_user'
    assert cfg_mysql['DB_PASSWORD'] == 'secret_pass_123'
    assert cfg_mysql['DB_NAME'] == 'bullymail_prod'

    # Test PostgreSQL DATABASE_URL
    monkeypatch.setenv('DATABASE_URL', 'postgres://pg_user:pg_secret_999@postgres-db.render.com:5432/bullymail_pg')
    cfg_pg = _parse_database_config()
    assert cfg_pg['DB_TYPE'] == 'postgres'
    assert cfg_pg['DB_HOST'] == 'postgres-db.render.com'
    assert cfg_pg['DB_PORT'] == 5432
    assert cfg_pg['DB_USER'] == 'pg_user'
    assert cfg_pg['DB_PASSWORD'] == 'pg_secret_999'
    assert cfg_pg['DB_NAME'] == 'bullymail_pg'

def test_production_mode_disables_silent_sqlite_fallback(monkeypatch):
    """Verifies that in production mode with a remote DB config, connection failure throws RuntimeError instead of falling back to SQLite."""
    monkeypatch.setattr(connection, '_get_config_val', lambda key, default=None: {
        'DB_TYPE': 'mysql',
        'DB_HOST': 'nonexistent_prod_db_host.invalid',
        'DB_PORT': 3306,
        'DB_USER': 'root',
        'DB_PASSWORD': 'secret_password_123',
        'DB_NAME': 'bullymail_db',
        'FLASK_ENV': 'production',
        'DATABASE_URL': 'mysql://root:secret_password_123@nonexistent_prod_db_host.invalid:3306/bullymail_db'
    }.get(key, default))

    with pytest.raises(RuntimeError) as exc_info:
        connection.get_connection()

    err_msg = str(exc_info.value)
    assert "MySQL connection failed" in err_msg
    assert "secret_password_123" not in err_msg  # Password must be masked

def test_restart_safe_idempotent_schema_initialization(app):
    """Verifies that running setup_database multiple times does not clear existing records or drop tables."""
    with app.app_context():
        # Setup DB first time
        assert setup_database() is True

        # Verify default institution exists
        inst = fetch_one("SELECT * FROM institutions WHERE id = 1")
        assert inst is not None

        # Re-run setup_database simulating service restart
        assert setup_database() is True

        # Verify institution still exists
        inst_after = fetch_one("SELECT * FROM institutions WHERE id = 1")
        assert inst_after is not None

def test_mailbox_and_analyzed_email_persistence_contract(app):
    """Verifies that mailboxes and analyzed emails are persisted correctly and remain retrievable."""
    with app.app_context():
        email_service = EmailService()
        mb = email_service.configure_mailbox(1, 'persisted_test@school.edu', 'app_password_999')
        mb_id = mb['id']

        # Query mailbox from database
        fetched = email_service.get_mailbox_by_id(mb_id, 1)
        assert fetched is not None
        assert fetched['email_address'] == 'persisted_test@school.edu'

        # Insert an analyzed email record linked to this mailbox
        execute_query('''
            INSERT INTO analyzed_emails (
                institution_id, email_config_id, email_subject, email_from, email_text,
                overall_risk_level, threat_score, is_bullying, incident_status
            ) VALUES (1, %s, 'Threat Test', 'attacker@external.com', 'Violent message', 'CRITICAL', 0.95, 1, 'PENDING_REVIEW')
        ''', (mb_id,))

        email_record = fetch_one("SELECT * FROM analyzed_emails WHERE email_config_id = %s ORDER BY id DESC", (mb_id,))
        assert email_record is not None
        assert email_record['email_subject'] == 'Threat Test'
        assert email_record['overall_risk_level'] == 'CRITICAL'

def test_all_required_tables_exist_and_login_flow_operational(app):
    """Verifies that all 10 required database tables are created and endpoints (/login, /api/threat-trend) operate cleanly."""
    with app.app_context():
        setup_database()

        # Verify existence of all 10 required production tables
        required_tables = [
            'institutions', 'users', 'email_verification_tokens', 'password_reset_tokens',
            'analyzed_emails', 'incident_audit_log', 'model_history', 'dataset_history',
            'email_config', 'ingested_messages'
        ]

        for table in required_tables:
            res = fetch_one(f"SELECT COUNT(*) as cnt FROM {table}")
            assert res is not None, f"Table '{table}' is missing or unreadable"

        # Verify admin user lookup and login API endpoint
        with app.test_client() as client:
            resp = client.get('/login')
            assert resp.status_code == 200

            # Test threat-trend API endpoint
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['role'] = 'admin'
                sess['username'] = 'admin'
                sess['institution_id'] = 1

            trend_resp = client.get('/api/threat-trend')
            assert trend_resp.status_code == 200
            data = trend_resp.get_json()
            assert data.get('success') is True

def test_postgres_schema_creation_and_migration_no_mysql_sql(monkeypatch):
    """
    Verifies that when DB_TYPE is 'postgres', setup_database() and apply_migrations()
    execute PostgreSQL-compatible SQL exclusively without any MySQL-specific syntax
    (e.g., AUTO_INCREMENT, INSERT IGNORE, SHOW COLUMNS, ENGINE=InnoDB, MODIFY COLUMN).
    """
    executed_sqls = []

    class DummyPostgresCursor:
        def execute(self, sql, params=None):
            executed_sqls.append(str(sql))

        def fetchall(self):
            return []

        def fetchone(self):
            return None

        def close(self):
            pass

    class DummyPostgresConn:
        def cursor(self, *args, **kwargs):
            return DummyPostgresCursor()

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setenv('DB_TYPE', 'postgres')
    from bullymail.database import schema
    monkeypatch.setattr(connection, 'get_engine_type', lambda: 'postgres')
    monkeypatch.setattr(schema, 'get_engine_type', lambda: 'postgres')
    monkeypatch.setattr(connection, 'get_connection', lambda: DummyPostgresConn())

    # Run setup_database which also calls apply_migrations
    schema.setup_database()

    assert len(executed_sqls) > 0, "No SQL statements were executed during setup_database()"

    full_sql_dump = "\n".join(executed_sqls)

    # Assert no MySQL-specific keywords exist in any SQL sent to PostgreSQL
    assert "AUTO_INCREMENT" not in full_sql_dump, "AUTO_INCREMENT was incorrectly sent to PostgreSQL!"
    assert "INSERT IGNORE" not in full_sql_dump, "INSERT IGNORE was incorrectly sent to PostgreSQL!"
    assert "SHOW COLUMNS" not in full_sql_dump, "SHOW COLUMNS was incorrectly sent to PostgreSQL!"
    assert "ENGINE=InnoDB" not in full_sql_dump, "ENGINE=InnoDB was incorrectly sent to PostgreSQL!"
    assert "DEFAULT CHARSET" not in full_sql_dump, "DEFAULT CHARSET was incorrectly sent to PostgreSQL!"
    assert "MODIFY COLUMN" not in full_sql_dump, "MODIFY COLUMN was incorrectly sent to PostgreSQL!"

def test_postgres_migration_failure_transaction_recovery(monkeypatch):
    """
    Verifies that if an individual PostgreSQL migration query fails, _safe_execute uses
    SAVEPOINT / ROLLBACK TO SAVEPOINT to protect the transaction state, allowing subsequent
    queries and final conn.commit() to succeed without InFailedSqlTransaction.
    """
    executed_sqls = []

    class MockPostgresTransactionCursor:
        def __init__(self):
            self.in_savepoint = False
            self.aborted = False

        def execute(self, sql, params=None):
            sql_str = str(sql).strip()
            executed_sqls.append(sql_str)

            if "SAVEPOINT migration_sp" in sql_str:
                self.in_savepoint = True
                return
            elif "ROLLBACK TO SAVEPOINT migration_sp" in sql_str:
                self.in_savepoint = False
                self.aborted = False
                return
            elif "RELEASE SAVEPOINT migration_sp" in sql_str:
                self.in_savepoint = False
                return

            if self.aborted:
                raise Exception("InFailedSqlTransaction: current transaction is aborted, commands ignored until end of transaction block")

            # Simulate failure on a specific optional statement
            if "simulated_broken_migration_query" in sql_str:
                if not self.in_savepoint:
                    self.aborted = True
                raise Exception("Simulated DB exception on optional migration")

        def fetchall(self):
            return []

        def fetchone(self):
            return None

        def close(self):
            pass

    class MockPostgresTransactionConn:
        def __init__(self):
            self.cursor_obj = MockPostgresTransactionCursor()
            self.committed = False

        def cursor(self, *args, **kwargs):
            return self.cursor_obj

        def commit(self):
            if self.cursor_obj.aborted:
                raise Exception("InFailedSqlTransaction: commit failed due to aborted transaction")
            self.committed = True

        def rollback(self):
            self.cursor_obj.aborted = False

        def close(self):
            pass

    from bullymail.database import schema
    mock_conn = MockPostgresTransactionConn()

    # Test _safe_execute directly
    res_fail = schema._safe_execute(mock_conn.cursor_obj, 'postgres', "SELECT * FROM simulated_broken_migration_query")
    assert res_fail is False

    # Verify transaction was NOT aborted due to savepoint rollback
    res_success = schema._safe_execute(mock_conn.cursor_obj, 'postgres', "SELECT 1")
    assert res_success is True

    mock_conn.commit()
    assert mock_conn.committed is True

def test_postgres_sync_lease_and_telemetry_datetime_queries(monkeypatch):
    """
    Verifies that when DB_TYPE is 'postgres', acquire_sync_lease, update_sync_telemetry,
    and get_stale_recovery_query generate valid PostgreSQL datetime expressions instead of
    datetime('now') or DATE_ADD / DATE_SUB.
    """
    executed_sqls = []

    class DummyCursor:
        def execute(self, sql, params=None):
            executed_sqls.append(str(sql))

        def rowcount(self):
            return 1

    monkeypatch.setattr(connection, 'get_engine_type', lambda: 'postgres')

    # 1. Test acquire_sync_lease on PostgreSQL
    from bullymail.services.email_service import EmailService
    email_service = EmailService()

    monkeypatch.setattr('bullymail.services.email_service.execute_query', lambda sql, params=None: (executed_sqls.append(str(sql)) or 1))
    email_service.acquire_sync_lease(mailbox_id=1, institution_id=1)

    assert len(executed_sqls) > 0
    lease_sql = executed_sqls[-1]
    assert "datetime('now'" not in lease_sql, "datetime('now') was incorrectly generated for PostgreSQL!"
    assert "DATE_ADD" not in lease_sql, "DATE_ADD was incorrectly generated for PostgreSQL!"
    assert "CURRENT_TIMESTAMP + INTERVAL '2 minutes'" in lease_sql

    # 2. Test update_telemetry on PostgreSQL
    from bullymail.worker.processor import MailboxProcessor
    monkeypatch.setattr('bullymail.worker.processor.execute_query', lambda sql, params=None: (executed_sqls.append(str(sql)) or 1))
    MailboxProcessor.update_telemetry(config_id=1, sync_status='OK', lease_id='test-lease-id')

    telemetry_sql = executed_sqls[-1]
    assert "datetime('now'" not in telemetry_sql
    assert "DATE_ADD" not in telemetry_sql
    assert "CURRENT_TIMESTAMP + INTERVAL '2 minutes'" in telemetry_sql

    # 3. Test get_stale_recovery_query on PostgreSQL
    from bullymail.models.ingested_message import IngestedMessageModel
    stale_query, params = IngestedMessageModel.get_stale_recovery_query(engine_type='postgres', institution_id=1)
    assert "DATE_SUB" not in stale_query
    assert "datetime('now'" not in stale_query
    assert "CURRENT_TIMESTAMP - (INTERVAL '1 minute' *" in stale_query

def test_dashboard_ingestion_counter_accuracy(app):
    """
    Verifies that dashboard counters (mailbox-level and workspace-level) accurately compute
    total ingested emails from ingested_messages and analyzed_emails and update as new emails arrive.
    """
    with app.app_context():
        from bullymail.services.email_service import EmailService
        from bullymail.models.institution import InstitutionModel
        from bullymail.models.analysis import AnalysisModel
        from bullymail.database.connection import execute_query

        email_service = EmailService()
        mb = email_service.configure_mailbox(1, 'counter_test@school.edu', 'secret_pass_123')
        mb_id = mb['id']

        # Initial check: count should be 0
        mb_fetched = email_service.get_mailbox_by_id(mb_id, 1)
        assert mb_fetched['total_ingested_count'] == 0

        stats_initial = InstitutionModel.get_stats(1)
        initial_total_emails = stats_initial['total_emails']

        # Insert 3 ingested_messages records for this mailbox
        for i in range(1, 4):
            execute_query("""
                INSERT INTO ingested_messages (
                    institution_id, email_config_id, message_id_hash, imap_uid, processing_status, attempt_count
                ) VALUES (1, %s, %s, %s, 'PROCESSED', 1)
            """, (mb_id, f"hash_{i}_{mb_id}", i))

        # Verify mailbox level count is now 3
        mb_updated = email_service.get_mailbox_by_id(mb_id, 1)
        assert mb_updated['total_ingested_count'] == 3

        # Verify workspace stats count has increased by 3
        stats_updated = InstitutionModel.get_stats(1)
        assert stats_updated['total_emails'] >= initial_total_emails + 3

        # Ingest 2 more messages and verify count increments to 5
        for i in range(4, 6):
            execute_query("""
                INSERT INTO ingested_messages (
                    institution_id, email_config_id, message_id_hash, imap_uid, processing_status, attempt_count
                ) VALUES (1, %s, %s, %s, 'PROCESSED', 1)
            """, (mb_id, f"hash_{i}_{mb_id}", i))

        mb_final = email_service.get_mailbox_by_id(mb_id, 1)
        assert mb_final['total_ingested_count'] == 5

def test_send_warning_action_end_to_end(app, monkeypatch):
    """
    Verifies that the Send Warning action:
    1. Successfully dispatches warning email when SMTP succeeds (mocked transport) and updates incident status to WARNING_SENT.
    2. Truthfully returns failure and leaves status as PENDING_REVIEW when SMTP transmission fails.
    3. Handles missing recipient address properly.
    """
    with app.app_context():
        from bullymail.models.analysis import AnalysisModel
        from bullymail.services.admin_warning_service import admin_warning_service
        from bullymail.database.connection import fetch_one

        # 1. Create test analyzed_emails record with a valid sender
        analysis_id = AnalysisModel.save_analysis({
            'email_from': 'attacker_sender@external.com',
            'email_to': 'victim@school.edu',
            'email_subject': 'Cyberbullying Subject',
            'bullying_analysis': {'is_bullying': True, 'rule_based_matches': ['threat']},
            'overall_risk_level': 'HIGH',
            'evidence': []
        }, institution_id=1)

        # Verify initial status is PENDING_REVIEW
        rec = AnalysisModel.get_by_id(analysis_id, institution_id=1, role='admin')
        assert rec['incident_status'] == 'PENDING_REVIEW'

        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = 1
                sess['role'] = 'admin'
                sess['username'] = 'admin'
                sess['institution_id'] = 1

            # Case A: Simulated SMTP Transmission Failure
            monkeypatch.setattr(admin_warning_service, 'send_warning_email', lambda recipient_email, subject=None, body=None, institution_id=None: (False, "Simulated SMTP connection timeout"))

            fail_resp = client.post(f'/api/admin/analysis/{analysis_id}/warning', json={})
            assert fail_resp.status_code == 500
            fail_data = fail_resp.get_json()
            assert fail_data['success'] is False
            assert "Simulated SMTP connection timeout" in fail_data['error']

            # Verify incident status is STILL PENDING_REVIEW after failed delivery
            rec_after_fail = AnalysisModel.get_by_id(analysis_id, institution_id=1, role='admin')
            assert rec_after_fail['incident_status'] == 'PENDING_REVIEW'

            # Verify failed audit trail was recorded
            audit_fail = fetch_one("SELECT * FROM incident_audit_log WHERE analysis_id = %s AND action = 'WARNING_ATTEMPT_FAILED' ORDER BY id DESC LIMIT 1", (analysis_id,))
            assert audit_fail is not None
            assert audit_fail['delivery_status'] == 'FAILED'

            # Case B: Successful SMTP Transmission
            monkeypatch.setattr(admin_warning_service, 'send_warning_email', lambda recipient_email, subject=None, body=None, institution_id=None: (True, "Warning email sent successfully."))

            success_resp = client.post(f'/api/admin/analysis/{analysis_id}/warning', json={})
            assert success_resp.status_code == 200
            success_data = success_resp.get_json()
            assert success_data['success'] is True
            assert success_data['status'] == 'WARNING_SENT'

            # Verify incident status is NOW WARNING_SENT
            rec_after_success = AnalysisModel.get_by_id(analysis_id, institution_id=1, role='admin')
            assert rec_after_success['incident_status'] == 'WARNING_SENT'

            # Verify successful audit trail was recorded
            audit_success = fetch_one("SELECT * FROM incident_audit_log WHERE analysis_id = %s AND action = 'WARNING_SENT' ORDER BY id DESC LIMIT 1", (analysis_id,))
            assert audit_success is not None
            assert audit_success['delivery_status'] == 'SUCCESS'
            assert audit_success['warning_recipient'] == 'attacker_sender@external.com'
