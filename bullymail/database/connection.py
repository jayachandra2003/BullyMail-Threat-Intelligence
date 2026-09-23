import sqlite3
import re
import os
import json
from contextlib import contextmanager
from ..config import Config

_active_engine = None

def _get_config_val(key, default=None):
    """Retrieves configuration parameter from active Flask application context or Config class."""
    try:
        from flask import current_app
        if current_app and key in current_app.config:
            return current_app.config[key]
    except Exception:
        pass
    return getattr(Config, key, default)

def get_connection():
    """Returns a database connection based on configuration with fallback to SQLite in development."""
    global _active_engine
    
    db_type = str(_get_config_val('DB_TYPE', 'sqlite')).strip().lower()
    is_testing = bool(_get_config_val('TESTING', False))

    if db_type == 'mysql':
        try:
            import mysql.connector
            from mysql.connector import ClientFlag
            db_host = _get_config_val('DB_HOST', 'localhost')
            if str(db_host).strip().lower() == 'localhost':
                db_host = '127.0.0.1'
            db_pass = _get_config_val('DB_PASSWORD', '')
            conn = mysql.connector.connect(
                host=db_host,
                port=int(_get_config_val('DB_PORT', 3306)),
                user=_get_config_val('DB_USER', 'root'),
                password=db_pass,
                database=_get_config_val('DB_NAME', 'bullymail_db'),
                charset='utf8mb4',
                collation='utf8mb4_unicode_ci',
                autocommit=False,
                client_flags=[ClientFlag.FOUND_ROWS]
            )
            _active_engine = 'mysql'
            return conn
        except Exception as e:
            if is_testing or db_type == 'mysql':
                # In testing or explicit MySQL mode, do not silently fallback to SQLite
                # Mask password from exception string if present
                safe_err = str(e)
                db_pass = _get_config_val('DB_PASSWORD', '')
                if db_pass and db_pass in safe_err:
                    safe_err = safe_err.replace(db_pass, '********')
                _active_engine = None
                raise RuntimeError(f"MySQL connection failed: {safe_err}") from None
            _active_engine = 'sqlite'

    # SQLite connection
    _active_engine = 'sqlite'
    db_path = _get_config_val('SQLITE_DB_PATH', 'bullymail.db')
    if db_path != ':memory:' and not os.path.isabs(db_path):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def get_engine_type():
    """Returns 'mysql' or 'sqlite' depending on current active configuration."""
    db_type = str(_get_config_val('DB_TYPE', 'sqlite')).strip().lower()
    return 'mysql' if db_type == 'mysql' else 'sqlite'

@contextmanager
def get_db():
    """Context manager for obtaining a database connection and managing transactions."""
    conn = get_connection()
    try:
        yield conn
        if hasattr(conn, 'commit'):
            conn.commit()
    except Exception:
        if hasattr(conn, 'rollback'):
            conn.rollback()
        raise
    finally:
        if hasattr(conn, 'close'):
            conn.close()

def _adapt_query_for_sqlite(query):
    """Converts MySQL-style query placeholders (%s, AUTO_INCREMENT, etc.) to SQLite equivalents."""
    # Replace parameter markers %s with ?
    query = re.sub(r'(?<!%)(%s)', '?', query)
    # Replace DATE_SUB(NOW(), INTERVAL 7 DAY) with datetime('now', '-7 days')
    query = re.sub(
        r'DATE_SUB\s*\(\s*NOW\s*\(\s*\)\s*,\s*INTERVAL\s+(\d+)\s+DAY\s*\)', 
        r"datetime('now', '-\1 days')", 
        query, 
        flags=re.IGNORECASE
    )
    # Replace NOW() with datetime('now')
    query = re.sub(r'\bNOW\s*\(\s*\)', "datetime('now')", query, flags=re.IGNORECASE)
    # Replace INSERT IGNORE with INSERT OR IGNORE
    query = re.sub(r'\bINSERT\s+IGNORE\b', 'INSERT OR IGNORE', query, flags=re.IGNORECASE)
    return query

def execute_query(query, params=None):
    """Executes a query (INSERT, UPDATE, DELETE) and returns lastrowid for INSERT, or rowcount for UPDATE/DELETE."""
    with get_db() as conn:
        engine = get_engine_type()
        if engine == 'sqlite':
            query = _adapt_query_for_sqlite(query)
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            if query.strip().upper().startswith(('UPDATE', 'DELETE')):
                return cursor.rowcount
            return cursor.lastrowid
        else:
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            if query.strip().upper().startswith(('UPDATE', 'DELETE')):
                count = cursor.rowcount
                cursor.close()
                return count
            last_id = cursor.lastrowid
            cursor.close()
            return last_id

def fetch_all(query, params=None):
    """Executes a SELECT query and returns all matching rows as a list of dicts."""
    with get_db() as conn:
        engine = get_engine_type()
        if engine == 'sqlite':
            query = _adapt_query_for_sqlite(query)
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        else:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params or ())
            rows = cursor.fetchall()
            cursor.close()
            return rows

def fetch_one(query, params=None):
    """Executes a SELECT query and returns a single matching row as a dict, or None."""
    with get_db() as conn:
        engine = get_engine_type()
        if engine == 'sqlite':
            query = _adapt_query_for_sqlite(query)
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            row = cursor.fetchone()
            return dict(row) if row else None
        else:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params or ())
            row = cursor.fetchone()
            cursor.close()
            return row

def close_db(e=None):
    """Hook for Flask teardown appcontext if needed."""
    pass

def init_db():
    """Initializes the database schema."""
    from .schema import setup_database
    return setup_database()
