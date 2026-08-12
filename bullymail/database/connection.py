import sqlite3
import re
import os
import json
from contextlib import contextmanager
from ..config import Config

_active_engine = None

def get_connection():
    """Returns a database connection based on configuration with fallback to SQLite."""
    global _active_engine
    
    if Config.DB_TYPE == 'mysql':
        try:
            import mysql.connector
            conn = mysql.connector.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                database=Config.DB_NAME,
                charset='utf8mb4',
                collation='utf8mb4_unicode_ci',
                autocommit=True
            )
            _active_engine = 'mysql'
            return conn
        except Exception as e:
            # Graceful fallback to SQLite
            _active_engine = 'sqlite'
    
    # SQLite connection
    _active_engine = 'sqlite'
    db_path = Config.SQLITE_DB_PATH
    if db_path != ':memory:' and not os.path.isabs(db_path):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def get_engine_type():
    """Returns 'mysql' or 'sqlite' depending on current active connection."""
    global _active_engine
    if _active_engine is None:
        conn = get_connection()
        conn.close()
    return _active_engine

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
    """Executes a query (INSERT, UPDATE, DELETE) and returns the last row ID."""
    with get_db() as conn:
        engine = get_engine_type()
        if engine == 'sqlite':
            query = _adapt_query_for_sqlite(query)
            cursor = conn.cursor()
            cursor.execute(query, params or ())
            return cursor.lastrowid
        else:
            cursor = conn.cursor()
            cursor.execute(query, params or ())
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
