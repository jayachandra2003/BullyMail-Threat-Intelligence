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

        email_record = fetch_one("SELECT * FROM analyzed_emails WHERE email_config_id = %s", (mb_id,))
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
