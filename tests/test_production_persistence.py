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
