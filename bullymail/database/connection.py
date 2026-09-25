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
    """Returns a database connection based on configuration with fallback to SQLite ONLY in local development mode."""
    global _active_engine
    
    db_type = str(_get_config_val('DB_TYPE', 'sqlite')).strip().lower()
    is_prod = str(_get_config_val('FLASK_ENV', '')).strip().lower() == 'production'
    is_testing = bool(_get_config_val('TESTING', False))
    has_remote_config = bool(_get_config_val('DATABASE_URL')) or bool(_get_config_val('DB_HOST') and str(_get_config_val('DB_HOST')).strip().lower() not in ('localhost', '127.0.0.1'))

    def _sanitize_err(err_str, db_pass):
        if not err_str:
            return ""
        clean = str(err_str)
        if db_pass and str(db_pass) in clean:
            clean = clean.replace(str(db_pass), '********')
        return clean

    if db_type == 'mysql':
        db_host = _get_config_val('DB_HOST', 'localhost')
        if str(db_host).strip().lower() == 'localhost':
            db_host = '127.0.0.1'
        db_pass = _get_config_val('DB_PASSWORD', '')
        db_port = int(_get_config_val('DB_PORT', 3306))
        db_user = _get_config_val('DB_USER', 'root')
        db_name = _get_config_val('DB_NAME', 'bullymail_db')

        last_err = None
        try:
            import mysql.connector
            from mysql.connector import ClientFlag
            conn = mysql.connector.connect(
                host=db_host,
                port=db_port,
                user=db_user,
                password=db_pass,
                database=db_name,
                charset='utf8mb4',
                collation='utf8mb4_unicode_ci',
                autocommit=False,
                client_flags=[ClientFlag.FOUND_ROWS]
            )
            _active_engine = 'mysql'
            return conn
        except Exception as e1:
            last_err = e1
            try:
                import pymysql
                conn = pymysql.connect(
                    host=db_host,
                    port=db_port,
                    user=db_user,
                    password=db_pass,
                    database=db_name,
                    charset='utf8mb4',
                    autocommit=False,
                    cursorclass=pymysql.cursors.DictCursor
                )
                _active_engine = 'mysql'
                return conn
            except Exception as e2:
                last_err = e2

        safe_err = _sanitize_err(last_err, db_pass)
        _active_engine = None
        raise RuntimeError(f"MySQL connection failed: Production database connection to {db_host}:{db_port}/{db_name} failed: {safe_err}") from None

    elif db_type in ('postgres', 'postgresql'):
        db_host = _get_config_val('DB_HOST', 'localhost')
        db_pass = _get_config_val('DB_PASSWORD', '')
        db_port = int(_get_config_val('DB_PORT', 5432))
        db_user = _get_config_val('DB_USER', 'postgres')
        db_name = _get_config_val('DB_NAME', 'bullymail_db')

        try:
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(
                host=db_host,
                port=db_port,
                user=db_user,
                password=db_pass,
                dbname=db_name
            )
            conn.autocommit = False
            _active_engine = 'postgres'
            return conn
        except Exception as e:
            safe_err = _sanitize_err(e, db_pass)
            _active_engine = None
            raise RuntimeError(f"Production PostgreSQL database connection to {db_host}:{db_port}/{db_name} failed: {safe_err}") from None

    # SQLite
    if is_prod and has_remote_config:
        raise RuntimeError("Production environment is configured for remote database but failed to connect. Silent SQLite fallback is disabled in production to prevent data loss.")

    _active_engine = 'sqlite'
    db_path = _get_config_val('SQLITE_DB_PATH', 'bullymail.db')
    if db_path != ':memory:' and not os.path.isabs(db_path):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def get_engine_type():
    """Returns 'mysql', 'postgres', or 'sqlite' depending on current active configuration."""
    db_type = str(_get_config_val('DB_TYPE', 'sqlite')).strip().lower()
    if db_type in ('postgres', 'postgresql'):
        return 'postgres'
    elif db_type == 'mysql':
        return 'mysql'
    return 'sqlite'

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
    query = re.sub(r'(?<!%)(%s)', '?', query)
    query = re.sub(
        r'DATE_SUB\s*\(\s*NOW\s*\(\s*\)\s*,\s*INTERVAL\s+(\d+)\s+DAY\s*\)', 
        r"datetime('now', '-\1 days')", 
        query, 
        flags=re.IGNORECASE
    )
    query = re.sub(r'\bNOW\s*\(\s*\)', "datetime('now')", query, flags=re.IGNORECASE)
    query = re.sub(r'\bINSERT\s+IGNORE\b', 'INSERT OR IGNORE', query, flags=re.IGNORECASE)
    return query

def _get_cursor(conn, engine):
    """Returns a dictionary-aware cursor for the target database engine."""
    if engine == 'sqlite':
        return conn.cursor()
    elif engine == 'postgres':
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        try:
            return conn.cursor(dictionary=True)
        except AttributeError:
            import pymysql
            return conn.cursor(pymysql.cursors.DictCursor)

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
        elif engine == 'postgres':
            cursor = _get_cursor(conn, engine)
            stripped = query.strip()
            if stripped.upper().startswith(('UPDATE', 'DELETE')):
                cursor.execute(query, params or ())
                count = cursor.rowcount
                cursor.close()
                return count
            elif stripped.upper().startswith('INSERT'):
                if 'RETURNING' not in stripped.upper():
                    try:
                        cursor.execute(f"{stripped} RETURNING id", params or ())
                        row = cursor.fetchone()
                        cursor.close()
                        if row:
                            return row.get('id') if isinstance(row, dict) else row[0]
                        return None
                    except Exception:
                        conn.rollback()
                        cursor = _get_cursor(conn, engine)
                        cursor.execute(query, params or ())
                        cursor.close()
                        return None
                else:
                    cursor.execute(query, params or ())
                    row = cursor.fetchone()
                    cursor.close()
                    if row:
                        return row.get('id') if isinstance(row, dict) else row[0]
                    return None
            else:
                cursor.execute(query, params or ())
                cursor.close()
                return None
        else:
            cursor = _get_cursor(conn, engine)
            cursor.execute(query, params or ())
            if query.strip().upper().startswith(('UPDATE', 'DELETE')):
                count = cursor.rowcount
                cursor.close()
                return count
            last_id = getattr(cursor, 'lastrowid', None)
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
            cursor = _get_cursor(conn, engine)
            cursor.execute(query, params or ())
            rows = cursor.fetchall()
            cursor.close()
            return [dict(row) for row in rows] if rows else []

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
            cursor = _get_cursor(conn, engine)
            cursor.execute(query, params or ())
            row = cursor.fetchone()
            cursor.close()
            return dict(row) if row else None

def close_db(e=None):
    """Hook for Flask teardown appcontext if needed."""
    pass

def init_db():
    """Initializes the database schema."""
    from .schema import setup_database
    return setup_database()
