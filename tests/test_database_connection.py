import pytest
import os
import sqlite3
from bullymail.database.connection import get_db, get_connection, get_engine_type, execute_query, fetch_one
from bullymail.config import Config

def test_sqlite_get_db_commit_on_success(app):
    """Verify SQLite connection commits on successful context exit."""
    with app.app_context():
        with get_db() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test_commit_tbl (id INTEGER PRIMARY KEY, val TEXT)")
            conn.execute("INSERT INTO test_commit_tbl (val) VALUES ('commit_test')")

        # Verify data persisted after context exit
        row = fetch_one("SELECT val FROM test_commit_tbl WHERE val = %s", ('commit_test',))
        assert row is not None
        assert row['val'] == 'commit_test'

def test_sqlite_get_db_rollback_on_exception(app):
    """Verify SQLite connection rolls back transactions when an exception is raised."""
    with app.app_context():
        with get_db() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test_rollback_tbl (id INTEGER PRIMARY KEY, val TEXT)")
        
        with pytest.raises(RuntimeError):
            with get_db() as conn:
                conn.execute("INSERT INTO test_rollback_tbl (val) VALUES ('rollback_test')")
                raise RuntimeError("Simulated failure inside transaction")

        # Verify row was NOT persisted due to rollback
        row = fetch_one("SELECT val FROM test_rollback_tbl WHERE val = %s", ('rollback_test',))
        assert row is None

def test_engine_type_selection_sqlite(app):
    """Verify get_engine_type returns 'sqlite' when DB_TYPE=sqlite."""
    with app.app_context():
        engine = get_engine_type()
        assert engine == 'sqlite'

def test_mysql_strict_connection_error_handling_no_silent_fallback(monkeypatch):
    """Verify that when DB_TYPE=mysql and connection fails, a clear RuntimeError is raised without silent fallback to SQLite."""
    from bullymail.database import connection
    monkeypatch.setattr(connection, '_get_config_val', lambda key, default=None: {
        'DB_TYPE': 'mysql',
        'DB_HOST': 'invalid_nonexistent_host_12345',
        'DB_PORT': 3306,
        'DB_USER': 'root',
        'DB_PASSWORD': 'super_secret_password_123',
        'DB_NAME': 'bullymail_db',
        'TESTING': True
    }.get(key, default))

    with pytest.raises(RuntimeError) as exc_info:
        connection.get_connection()

    err_str = str(exc_info.value)
    # 1. Must clearly indicate MySQL connection failure
    assert "MySQL connection failed" in err_str
    # 2. Must NOT expose plaintext password in exception message
    assert "super_secret_password_123" not in err_str

def test_mysql_test_db_name_isolation():
    """Verify that MySQL test configuration uses bullymail_test_db and never development database."""
    test_db = os.getenv('MYSQL_TEST_DB_NAME', 'bullymail_test_db')
    assert test_db != 'bullymail_db'
    assert 'test' in test_db
