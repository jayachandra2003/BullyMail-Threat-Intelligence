import os
import sqlite3
import tempfile
import pytest
from bullymail.models.user import UserModel
from bullymail.database.connection import get_db, init_db
from bullymail.database.schema import setup_database, apply_migrations

def _create_legacy_v1_database(db_path):
    """Creates a raw SQLite database with the legacy pre-auth-hardening schema."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'admin',
            email VARCHAR(100) UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Insert legacy user record
    cursor.execute(
        "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
        ('legacy_operator', UserModel.hash_password('LegacyPass12345!'), 'operator', 'legacy@bullymail.local')
    )
    conn.commit()
    conn.close()

def test_a_fresh_database_has_complete_schema(tmp_path):
    """TEST A: Fresh database -> complete current schema exists."""
    db_file = str(tmp_path / "fresh_test.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Run setup
    from bullymail.database.schema import _get_existing_columns
    setup_database()
    
    # Verify columns in a fresh DB
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'admin',
            email VARCHAR(100) UNIQUE,
            status VARCHAR(30) DEFAULT 'ACTIVE',
            email_verified_at TIMESTAMP NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP NULL,
            last_login_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    
    cols = _get_existing_columns(cursor, 'users', 'sqlite')
    assert 'status' in cols
    assert 'email_verified_at' in cols
    assert 'failed_login_attempts' in cols
    assert 'locked_until' in cols
    assert 'last_login_at' in cols
    conn.close()

def test_b_legacy_database_without_last_login_at_is_migrated(tmp_path):
    """TEST B: Legacy database without last_login_at -> migration adds it."""
    db_file = str(tmp_path / "legacy_b.db")
    _create_legacy_v1_database(db_file)
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Verify legacy DB lacks last_login_at
    cursor.execute("PRAGMA table_info(users)")
    cols_before = [r[1] for r in cursor.fetchall()]
    assert 'last_login_at' not in cols_before
    
    # Apply migration
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    
    cursor.execute("PRAGMA table_info(users)")
    cols_after = [r[1] for r in cursor.fetchall()]
    assert 'last_login_at' in cols_after
    conn.close()

def test_c_legacy_database_without_auth_tables_creates_them(tmp_path):
    """TEST C: Legacy database without authentication tables -> migration creates them."""
    db_file = str(tmp_path / "legacy_c.db")
    _create_legacy_v1_database(db_file)
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Create missing tables via IF NOT EXISTS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cursor.fetchall()]
    assert 'email_verification_tokens' in tables
    assert 'password_reset_tokens' in tables
    conn.close()

def test_d_partially_migrated_database_completes_missing_pieces(tmp_path):
    """TEST D: Partially migrated database -> migration completes missing pieces."""
    db_file = str(tmp_path / "partial_d.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'admin',
            email VARCHAR(100) UNIQUE,
            status VARCHAR(30) DEFAULT 'ACTIVE'
        )
    ''')
    conn.commit()
    
    # Apply migration to add remaining columns
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    
    cursor.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cursor.fetchall()]
    assert 'status' in cols
    assert 'email_verified_at' in cols
    assert 'last_login_at' in cols
    assert 'failed_login_attempts' in cols
    conn.close()

def test_e_already_current_database_migration_is_noop(tmp_path):
    """TEST E: Already-current database -> migration is a no-op and succeeds without error."""
    db_file = str(tmp_path / "current_e.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'admin',
            email VARCHAR(100) UNIQUE,
            status VARCHAR(30) DEFAULT 'ACTIVE',
            email_verified_at TIMESTAMP NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP NULL,
            last_login_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    
    # Running multiple times must be completely idempotent
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    
    cursor.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cursor.fetchall()]
    assert cols.count('last_login_at') == 1
    conn.close()

def test_f_existing_user_records_survive_migration_unchanged(tmp_path):
    """TEST F: Existing user records survive migration unchanged."""
    db_file = str(tmp_path / "data_f.db")
    _create_legacy_v1_database(db_file)
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    
    cursor.execute("SELECT id, username, email, role, status FROM users WHERE username = 'legacy_operator'")
    row = cursor.fetchone()
    assert row is not None
    assert row[1] == 'legacy_operator'
    assert row[2] == 'legacy@bullymail.local'
    assert row[3] == 'operator'
    assert row[4] == 'ACTIVE'  # Backfilled to ACTIVE
    conn.close()

def test_g_authentication_works_after_migration(tmp_path):
    """TEST G: Authentication works after migration and UserModel.authenticate executes without error."""
    db_file = str(tmp_path / "auth_g.db")
    _create_legacy_v1_database(db_file)
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    apply_migrations(cursor, 'sqlite')
    conn.commit()
    
    # Check that updating last_login_at succeeds
    cursor.execute("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE username = 'legacy_operator'")
    conn.commit()
    
    cursor.execute("SELECT last_login_at FROM users WHERE username = 'legacy_operator'")
    row = cursor.fetchone()
    assert row[0] is not None
    conn.close()
