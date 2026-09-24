import os
import secrets
from werkzeug.security import generate_password_hash
from ..config import Config
from .connection import get_db, get_engine_type, execute_query, fetch_one

def _get_existing_columns(cursor, table_name, engine):
    """
    Returns a set of lowercase column names present in the specified table.
    Works seamlessly across SQLite, MySQL, and PostgreSQL.
    """
    columns = set()
    try:
        if engine == 'sqlite':
            cursor.execute(f"PRAGMA table_info({table_name})")
            for row in cursor.fetchall():
                name = row[1] if isinstance(row, (tuple, list)) else row['name']
                columns.add(name.lower())
        elif engine == 'postgres':
            cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table_name.lower()}'")
            for row in cursor.fetchall():
                name = row[0] if isinstance(row, (tuple, list)) else (row.get('column_name') or row.get('COLUMN_NAME'))
                columns.add(name.lower())
        else:
            cursor.execute(f"SHOW COLUMNS FROM `{table_name}`")
            for row in cursor.fetchall():
                name = row[0] if isinstance(row, (tuple, list)) else (row.get('Field') or row.get('field'))
                columns.add(name.lower())
    except Exception:
        pass
    return columns

def apply_migrations(cursor, engine):
    """
    Idempotently inspects database tables and applies non-destructive schema migrations
    to upgrade legacy installations without data loss.
    """
    # -------------------------------------------------------------------------
    # 0. Institutions Table Migrations
    # -------------------------------------------------------------------------
    inst_cols = _get_existing_columns(cursor, 'institutions', engine)
    if inst_cols:
        if 'code' not in inst_cols:
            cursor.execute("ALTER TABLE institutions ADD COLUMN code VARCHAR(30) NULL")
        if 'status' not in inst_cols:
            cursor.execute("ALTER TABLE institutions ADD COLUMN status VARCHAR(20) DEFAULT 'ACTIVE'")
        if 'updated_at' not in inst_cols:
            cursor.execute("ALTER TABLE institutions ADD COLUMN updated_at TIMESTAMP NULL")
        try:
            cursor.execute("UPDATE institutions SET code = 'BM-DEMO' WHERE (code IS NULL OR code = '') AND id = 1")
            cursor.execute("UPDATE institutions SET status = 'ACTIVE' WHERE status IS NULL OR status = ''")
        except Exception:
            pass

    # Ensure default institution exists
    try:
        if engine == 'sqlite':
            cursor.execute("INSERT OR IGNORE INTO institutions (id, name, domain, code, status) VALUES (1, 'BullyMail Demo Institution', 'bullymail.local', 'BM-DEMO', 'ACTIVE')")
        elif engine == 'postgres':
            cursor.execute("INSERT INTO institutions (id, name, domain, code, status) VALUES (1, 'BullyMail Demo Institution', 'bullymail.local', 'BM-DEMO', 'ACTIVE') ON CONFLICT DO NOTHING")
        else:
            cursor.execute("INSERT IGNORE INTO institutions (id, name, domain, code, status) VALUES (1, 'BullyMail Demo Institution', 'bullymail.local', 'BM-DEMO', 'ACTIVE')")
    except Exception:
        pass

    # -------------------------------------------------------------------------
    # 1. Users Table Migrations
    # -------------------------------------------------------------------------
    user_cols = _get_existing_columns(cursor, 'users', engine)
    if user_cols:
        if engine == 'mysql' and 'password' in user_cols:
            try:
                cursor.execute("ALTER TABLE users MODIFY COLUMN password VARCHAR(255) NULL")
            except Exception:
                pass
        elif engine == 'postgres' and 'password' in user_cols:
            try:
                cursor.execute("ALTER TABLE users ALTER COLUMN password TYPE VARCHAR(255), ALTER COLUMN password DROP NOT NULL")
            except Exception:
                pass

        if 'email' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN email VARCHAR(100) NULL UNIQUE")

        if 'password_hash' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NULL")

        try:
            cursor.execute("UPDATE users SET password_hash = password WHERE (password_hash IS NULL OR password_hash = '') AND password IS NOT NULL")
        except Exception:
            pass

        if 'status' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN status VARCHAR(30) DEFAULT 'ACTIVE'")

        if 'email_verified_at' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP NULL")

        if 'failed_login_attempts' not in user_cols:
            col_type = "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0"
            cursor.execute(f"ALTER TABLE users ADD COLUMN failed_login_attempts {col_type}")

        if 'locked_until' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL")

        if 'last_login_at' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP NULL")

        if 'institution_id' not in user_cols:
            col_type = "INTEGER NULL" if engine == 'sqlite' else "INT NULL"
            cursor.execute(f"ALTER TABLE users ADD COLUMN institution_id {col_type}")

        if 'requested_institution_name' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN requested_institution_name VARCHAR(100) NULL")

        if 'requested_institution_domain' not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN requested_institution_domain VARCHAR(100) NULL")

        # Backfill active status for legacy accounts without altering pending registrations
        try:
            cursor.execute("UPDATE users SET status = 'ACTIVE' WHERE status IS NULL OR status = ''")
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 2. Multi-Vector Analyzed Emails Migrations
    # -------------------------------------------------------------------------
    email_cols = _get_existing_columns(cursor, 'analyzed_emails', engine)
    if email_cols:
        if 'institution_id' not in email_cols:
            col_type = "INTEGER DEFAULT 1" if engine == 'sqlite' else "INT DEFAULT 1"
            cursor.execute(f"ALTER TABLE analyzed_emails ADD COLUMN institution_id {col_type}")

        if 'user_id' not in email_cols:
            col_type = "INTEGER NULL" if engine == 'sqlite' else "INT NULL"
            cursor.execute(f"ALTER TABLE analyzed_emails ADD COLUMN user_id {col_type}")

        if 'email_config_id' not in email_cols:
            col_type = "INTEGER NULL" if engine == 'sqlite' else "INT NULL"
            cursor.execute(f"ALTER TABLE analyzed_emails ADD COLUMN email_config_id {col_type}")

        try:
            cursor.execute("UPDATE analyzed_emails SET institution_id = 1 WHERE institution_id IS NULL OR institution_id = 0")
            cursor.execute("UPDATE analyzed_emails SET email_config_id = (SELECT email_config_id FROM ingested_messages WHERE analyzed_email_id = analyzed_emails.id) WHERE email_config_id IS NULL")
        except Exception:
            pass

        missing_defs = {
            'overall_risk_level': "VARCHAR(20) DEFAULT 'LOW'",
            'overall_confidence': "FLOAT DEFAULT 0.0",
            'threat_score': "FLOAT DEFAULT 0.0",
            'incident_status': "VARCHAR(30) DEFAULT 'PENDING_REVIEW'",
            'phishing_risk_level': "VARCHAR(20) DEFAULT 'LOW'",
            'phishing_confidence': "FLOAT DEFAULT 0.0",
            'phishing_indicators': 'TEXT NULL',
            'urls_detected': "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0",
            'suspicious_urls_count': "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0",
            'url_analysis_summary': 'TEXT NULL',
            'evidence_summary': 'TEXT NULL',
            'domain_analysis_summary': 'TEXT DEFAULT "{}"',
            'social_eng_risk_level': "VARCHAR(20) DEFAULT 'LOW'",
            'social_eng_confidence': "FLOAT DEFAULT 0.0",
            'social_eng_techniques': 'TEXT DEFAULT "[]"',
            'attachments_count': "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0",
            'malware_detected': "INTEGER DEFAULT 0" if engine == 'sqlite' else ("INT DEFAULT 0" if engine == 'postgres' else "TINYINT(1) DEFAULT 0"),
            'malicious_attachments_count': "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0",
            'attachment_risk_level': "VARCHAR(20) DEFAULT 'LOW'",
            'attachment_findings': 'TEXT DEFAULT "[]"',
            'images_count': "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0",
            'suspicious_images_count': "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0",
            'image_forensics_summary': 'TEXT DEFAULT "[]"'
        }
        for col_name, col_def in missing_defs.items():
            if col_name not in email_cols:
                try:
                    cursor.execute(f"ALTER TABLE analyzed_emails ADD COLUMN {col_name} {col_def}")
                except Exception:
                    pass

        try:
            cursor.execute("UPDATE analyzed_emails SET incident_status = 'PENDING_REVIEW' WHERE incident_status IS NULL OR incident_status = ''")
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 3. Email Config Migrations
    # -------------------------------------------------------------------------
    config_cols = _get_existing_columns(cursor, 'email_config', engine)
    if config_cols:
        if 'institution_id' not in config_cols:
            col_type = "INTEGER" if engine == 'sqlite' else "INT"
            cursor.execute(f"ALTER TABLE email_config ADD COLUMN institution_id {col_type}")

        if 'encrypted_app_password' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN encrypted_app_password TEXT")

        if 'imap_server' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN imap_server VARCHAR(255) DEFAULT 'imap.gmail.com'")

        if 'smtp_server' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN smtp_server VARCHAR(255) DEFAULT 'smtp.gmail.com'")

        if 'smtp_port' not in config_cols:
            col_type = "INTEGER DEFAULT 587" if engine == 'sqlite' else "INT DEFAULT 587"
            cursor.execute(f"ALTER TABLE email_config ADD COLUMN smtp_port {col_type}")

        if 'last_synced_at' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN last_synced_at TIMESTAMP NULL")

        if 'sync_status' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN sync_status VARCHAR(30) DEFAULT 'IDLE'")

        if 'sync_lease_id' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN sync_lease_id VARCHAR(64) NULL")

        if 'sync_lease_expires_at' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN sync_lease_expires_at TIMESTAMP NULL")

        if 'last_error' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN last_error TEXT NULL")

        if 'total_ingested_count' not in config_cols:
            col_type = "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0"
            cursor.execute(f"ALTER TABLE email_config ADD COLUMN total_ingested_count {col_type}")

        if 'configured_at' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN configured_at TIMESTAMP NULL")

        if 'monitoring_started_at' not in config_cols:
            cursor.execute("ALTER TABLE email_config ADD COLUMN monitoring_started_at TIMESTAMP NULL")

        if 'initial_uid' not in config_cols:
            col_type = "INTEGER NULL" if engine == 'sqlite' else "INT NULL"
            cursor.execute(f"ALTER TABLE email_config ADD COLUMN initial_uid {col_type}")

        if 'last_processed_uid' not in config_cols:
            col_type = "INTEGER NULL" if engine == 'sqlite' else "INT NULL"
            cursor.execute(f"ALTER TABLE email_config ADD COLUMN last_processed_uid {col_type}")

        if 'uid_validity' not in config_cols:
            col_type = "INTEGER NULL" if engine == 'sqlite' else "INT NULL"
            cursor.execute(f"ALTER TABLE email_config ADD COLUMN uid_validity {col_type}")

        if 'mailbox_initialized' not in config_cols:
            col_type = "INTEGER DEFAULT 0" if engine == 'sqlite' else ("INT DEFAULT 0" if engine == 'postgres' else "TINYINT(1) DEFAULT 0")
            cursor.execute(f"ALTER TABLE email_config ADD COLUMN mailbox_initialized {col_type}")

        # Idempotently migrate existing mailboxes that already ingested messages
        try:
            cursor.execute("""
                UPDATE email_config
                SET mailbox_initialized = 1,
                    last_processed_uid = (
                        SELECT MAX(imap_uid) FROM ingested_messages WHERE email_config_id = email_config.id
                    ),
                    initial_uid = COALESCE((
                        SELECT MIN(imap_uid) FROM ingested_messages WHERE email_config_id = email_config.id
                    ), 0),
                    monitoring_started_at = COALESCE(configured_at, CURRENT_TIMESTAMP)
                WHERE (mailbox_initialized IS NULL OR mailbox_initialized = 0)
                  AND id IN (SELECT DISTINCT email_config_id FROM ingested_messages WHERE imap_uid IS NOT NULL)
            """)
        except Exception:
            pass

        # Check for legacy unencrypted app_password column and migrate idempotently
        if 'app_password' in config_cols:
            from ..services.crypto_service import CryptoService
            cursor.execute("SELECT id, app_password FROM email_config WHERE app_password IS NOT NULL AND app_password != ''")
            rows = cursor.fetchall()
            for row in rows:
                cfg_id = row[0] if isinstance(row, (tuple, list)) else row['id']
                raw_pw = row[1] if isinstance(row, (tuple, list)) else row['app_password']
                if raw_pw:
                    enc_pw = CryptoService.encrypt(raw_pw)
                    # Verify encryption before nullifying plaintext
                    dec_pw = CryptoService.decrypt(enc_pw)
                    if dec_pw == raw_pw:
                        ph = '?' if engine == 'sqlite' else '%s'
                        cursor.execute(
                            f"UPDATE email_config SET encrypted_app_password = {ph}, app_password = NULL WHERE id = {ph}",
                            (enc_pw, cfg_id)
                        )

        try:
            cursor.execute("UPDATE email_config SET institution_id = 1 WHERE institution_id IS NULL OR institution_id = 0")
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 4. Incident Audit Log Table Migration
    # -------------------------------------------------------------------------
    if engine == 'sqlite':
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                institution_id INTEGER NOT NULL,
                admin_id INTEGER NOT NULL,
                admin_username VARCHAR(50) NOT NULL,
                action VARCHAR(30) NOT NULL,
                original_sender VARCHAR(255) NULL,
                original_recipient VARCHAR(255) NULL,
                warning_recipient VARCHAR(255) NULL,
                warning_subject VARCHAR(255) NULL,
                delivery_status VARCHAR(30) DEFAULT 'SUCCESS',
                reason TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE CASCADE,
                FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
    elif engine == 'postgres':
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_audit_log (
                id SERIAL PRIMARY KEY,
                analysis_id INT NOT NULL,
                institution_id INT NOT NULL,
                admin_id INT NOT NULL,
                admin_username VARCHAR(50) NOT NULL,
                action VARCHAR(30) NOT NULL,
                original_sender VARCHAR(255) NULL,
                original_recipient VARCHAR(255) NULL,
                warning_recipient VARCHAR(255) NULL,
                warning_subject VARCHAR(255) NULL,
                delivery_status VARCHAR(30) DEFAULT 'SUCCESS',
                reason TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE CASCADE,
                FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                analysis_id INT NOT NULL,
                institution_id INT NOT NULL,
                admin_id INT NOT NULL,
                admin_username VARCHAR(50) NOT NULL,
                action VARCHAR(30) NOT NULL,
                original_sender VARCHAR(255) NULL,
                original_recipient VARCHAR(255) NULL,
                warning_recipient VARCHAR(255) NULL,
                warning_subject VARCHAR(255) NULL,
                delivery_status VARCHAR(30) DEFAULT 'SUCCESS',
                reason MEDIUMTEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_audit_analysis (analysis_id),
                INDEX idx_audit_institution (institution_id),
                INDEX idx_audit_admin (admin_id),
                FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE CASCADE,
                FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ''')

    # -------------------------------------------------------------------------
    # 5. Model History Table Migrations
    # -------------------------------------------------------------------------
    model_cols = _get_existing_columns(cursor, 'model_history', engine)
    if model_cols:
        if 'confusion_matrix' not in model_cols:
            cursor.execute("ALTER TABLE model_history ADD COLUMN confusion_matrix TEXT NULL")
        if 'evaluation_type' not in model_cols:
            cursor.execute("ALTER TABLE model_history ADD COLUMN evaluation_type VARCHAR(50) DEFAULT 'Synthetic Evaluation'")
        if 'dataset_used' not in model_cols:
            cursor.execute("ALTER TABLE model_history ADD COLUMN dataset_used VARCHAR(255) DEFAULT 'default_academic_dataset'")

    # -------------------------------------------------------------------------
    # 6. Dataset History Table Migrations
    # -------------------------------------------------------------------------
    dataset_cols = _get_existing_columns(cursor, 'dataset_history', engine)
    if dataset_cols:
        if 'neutral_samples' not in dataset_cols:
            col_type = "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0"
            cursor.execute(f"ALTER TABLE dataset_history ADD COLUMN neutral_samples {col_type}")

def setup_database():
    """Sets up all required database tables with UTF-8 support and idempotent secure administrator initialization."""
    engine = get_engine_type()

    with get_db() as conn:
        cursor = conn.cursor()

        if engine == 'sqlite':
            # Institutions / Tenants Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS institutions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(100) NOT NULL,
                    domain VARCHAR(100) UNIQUE NOT NULL,
                    code VARCHAR(30) NULL,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Users Table with Account Lifecycle Status & Tenant Association
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    institution_id INTEGER NULL,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'analyst',
                    email VARCHAR(100) UNIQUE,
                    status VARCHAR(30) DEFAULT 'PENDING_EMAIL_VERIFICATION',
                    requested_institution_name VARCHAR(100) NULL,
                    requested_institution_domain VARCHAR(100) NULL,
                    email_verified_at TIMESTAMP NULL,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL,
                    last_login_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE RESTRICT
                )
            ''')

            # Email Verification Tokens Table (Stores SHA-256 Hashes Only)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            # Password Reset Tokens Table (Stores SHA-256 Hashes Only)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            # Multi-Vector Threat Analysis Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyzed_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    institution_id INTEGER DEFAULT 1,
                    user_id INTEGER NULL,
                    email_config_id INTEGER NULL,
                    email_subject TEXT,
                    email_from TEXT,
                    email_to TEXT,
                    email_text TEXT NOT NULL,

                    -- Overall Unified Risk
                    overall_risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
                    overall_confidence FLOAT NOT NULL DEFAULT 0.0,
                    threat_score FLOAT NOT NULL DEFAULT 0.0,
                    incident_status VARCHAR(30) NOT NULL DEFAULT 'PENDING_REVIEW',

                    -- Cyberbullying Detection Vector
                    is_bullying INTEGER NOT NULL DEFAULT 0,
                    confidence FLOAT NOT NULL DEFAULT 0.0,
                    rule_based_matches TEXT DEFAULT '',
                    rule_based_score FLOAT DEFAULT 0.0,
                    ml_prediction INTEGER DEFAULT 0,
                    ml_confidence FLOAT DEFAULT 0.0,
                    model_used VARCHAR(50) DEFAULT 'Hybrid',

                    -- Phishing Detection Vector
                    phishing_risk_level VARCHAR(20) DEFAULT 'LOW',
                    phishing_confidence FLOAT DEFAULT 0.0,
                    phishing_indicators TEXT DEFAULT '[]',

                    -- URL & Link Analysis Vector
                    urls_detected INTEGER DEFAULT 0,
                    suspicious_urls_count INTEGER DEFAULT 0,
                    url_analysis_summary TEXT DEFAULT '[]',

                    -- Look-Alike / Domain Vector
                    domain_analysis_summary TEXT DEFAULT '{}',

                    -- Social Engineering Vector
                    social_eng_risk_level VARCHAR(20) DEFAULT 'LOW',
                    social_eng_confidence FLOAT DEFAULT 0.0,
                    social_eng_techniques TEXT DEFAULT '[]',

                    -- Attachment / Malware Vector
                    attachments_count INTEGER DEFAULT 0,
                    malware_detected INTEGER DEFAULT 0,
                    malicious_attachments_count INTEGER DEFAULT 0,
                    attachment_risk_level VARCHAR(20) DEFAULT 'LOW',
                    attachment_findings TEXT DEFAULT '[]',

                    -- Image Forensics Vector
                    images_count INTEGER DEFAULT 0,
                    suspicious_images_count INTEGER DEFAULT 0,
                    image_forensics_summary TEXT DEFAULT '[]',

                    -- Explanation / XAI
                    explanation TEXT DEFAULT '{}',
                    top_risk_factors TEXT DEFAULT '[]',

                    -- Metadata
                    analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    email_date TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incident_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    institution_id INTEGER NOT NULL,
                    admin_id INTEGER NOT NULL,
                    admin_username VARCHAR(50) NOT NULL,
                    action VARCHAR(30) NOT NULL,
                    original_sender VARCHAR(255) NULL,
                    original_recipient VARCHAR(255) NULL,
                    warning_recipient VARCHAR(255) NULL,
                    warning_subject VARCHAR(255) NULL,
                    delivery_status VARCHAR(30) DEFAULT 'SUCCESS',
                    reason TEXT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE CASCADE,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                    FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS model_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_type VARCHAR(50) NOT NULL,
                    precision_score FLOAT DEFAULT 0.0,
                    recall_score FLOAT DEFAULT 0.0,
                    f1_score FLOAT DEFAULT 0.0,
                    accuracy FLOAT DEFAULT 0.0,
                    confusion_matrix TEXT,
                    training_samples INTEGER DEFAULT 0,
                    test_samples INTEGER DEFAULT 0,
                    evaluation_type VARCHAR(50) DEFAULT 'Synthetic Evaluation',
                    dataset_used VARCHAR(255) DEFAULT 'default_academic_dataset',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dataset_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename VARCHAR(255) NOT NULL,
                    total_samples INTEGER DEFAULT 0,
                    bullying_samples INTEGER DEFAULT 0,
                    non_bullying_samples INTEGER DEFAULT 0,
                    neutral_samples INTEGER DEFAULT 0,
                    file_size VARCHAR(50) DEFAULT '0 MB',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    institution_id INTEGER NOT NULL,
                    email_address VARCHAR(255),
                    app_password TEXT NULL,
                    encrypted_app_password TEXT,
                    imap_server VARCHAR(255) DEFAULT 'imap.gmail.com',
                    smtp_server VARCHAR(255) DEFAULT 'smtp.gmail.com',
                    smtp_port INTEGER DEFAULT 587,
                    status VARCHAR(50) DEFAULT 'inactive',
                    last_synced_at TIMESTAMP NULL,
                    sync_status VARCHAR(30) DEFAULT 'IDLE',
                    sync_lease_id VARCHAR(64) NULL,
                    sync_lease_expires_at TIMESTAMP NULL,
                    last_error TEXT NULL,
                    total_ingested_count INTEGER DEFAULT 0,
                    configured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    monitoring_started_at TIMESTAMP NULL,
                    initial_uid INTEGER NULL,
                    last_processed_uid INTEGER NULL,
                    uid_validity INTEGER NULL,
                    mailbox_initialized INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ingested_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    institution_id INTEGER NOT NULL,
                    email_config_id INTEGER NOT NULL,
                    message_id_hash VARCHAR(64) NOT NULL,
                    imap_uid INTEGER NULL,
                    uidvalidity INTEGER NULL,
                    processing_status VARCHAR(30) DEFAULT 'DISCOVERED',
                    attempt_count INTEGER DEFAULT 0,
                    last_attempt_at TIMESTAMP NULL,
                    error_message TEXT NULL,
                    analysis_id INTEGER NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                    FOREIGN KEY (email_config_id) REFERENCES email_config (id) ON DELETE CASCADE,
                    FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE SET NULL,
                    UNIQUE (institution_id, email_config_id, message_id_hash)
                )
            ''')

            # Apply schema migrations for existing SQLite databases
            apply_migrations(cursor, engine)

        elif engine == 'postgres':
            # PostgreSQL Database Engine Setup
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS institutions (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    domain VARCHAR(100) UNIQUE NOT NULL,
                    code VARCHAR(30) NULL,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    institution_id INT NULL,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'analyst',
                    email VARCHAR(100) UNIQUE,
                    status VARCHAR(30) DEFAULT 'PENDING_EMAIL_VERIFICATION',
                    requested_institution_name VARCHAR(100) NULL,
                    requested_institution_domain VARCHAR(100) NULL,
                    email_verified_at TIMESTAMP NULL,
                    failed_login_attempts INT DEFAULT 0,
                    locked_until TIMESTAMP NULL,
                    last_login_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE RESTRICT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INT NOT NULL,
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INT NOT NULL,
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyzed_emails (
                    id SERIAL PRIMARY KEY,
                    institution_id INT DEFAULT 1,
                    user_id INT NULL,
                    email_config_id INT NULL,
                    email_subject VARCHAR(255),
                    email_from VARCHAR(255),
                    email_to VARCHAR(255),
                    email_text TEXT NOT NULL,

                    overall_risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
                    overall_confidence FLOAT NOT NULL DEFAULT 0.0,
                    threat_score FLOAT NOT NULL DEFAULT 0.0,
                    incident_status VARCHAR(30) NOT NULL DEFAULT 'PENDING_REVIEW',

                    is_bullying INT NOT NULL DEFAULT 0,
                    confidence FLOAT NOT NULL DEFAULT 0.0,
                    rule_based_matches TEXT DEFAULT '',
                    rule_based_score FLOAT DEFAULT 0.0,
                    ml_prediction INT DEFAULT 0,
                    ml_confidence FLOAT DEFAULT 0.0,
                    model_used VARCHAR(50) DEFAULT 'Hybrid',

                    phishing_risk_level VARCHAR(20) DEFAULT 'LOW',
                    phishing_confidence FLOAT DEFAULT 0.0,
                    phishing_indicators TEXT DEFAULT '[]',

                    urls_detected INT DEFAULT 0,
                    suspicious_urls_count INT DEFAULT 0,
                    url_analysis_summary TEXT DEFAULT '[]',

                    domain_analysis_summary TEXT DEFAULT '{}',

                    social_eng_risk_level VARCHAR(20) DEFAULT 'LOW',
                    social_eng_confidence FLOAT DEFAULT 0.0,
                    social_eng_techniques TEXT DEFAULT '[]',

                    attachments_count INT DEFAULT 0,
                    malware_detected INT DEFAULT 0,
                    malicious_attachments_count INT DEFAULT 0,
                    attachment_risk_level VARCHAR(20) DEFAULT 'LOW',
                    attachment_findings TEXT DEFAULT '[]',

                    images_count INT DEFAULT 0,
                    suspicious_images_count INT DEFAULT 0,
                    image_forensics_summary TEXT DEFAULT '[]',

                    explanation TEXT DEFAULT '{}',
                    top_risk_factors TEXT DEFAULT '[]',

                    analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    email_date TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incident_audit_log (
                    id SERIAL PRIMARY KEY,
                    analysis_id INT NOT NULL,
                    institution_id INT NOT NULL,
                    admin_id INT NOT NULL,
                    admin_username VARCHAR(50) NOT NULL,
                    action VARCHAR(30) NOT NULL,
                    original_sender VARCHAR(255) NULL,
                    original_recipient VARCHAR(255) NULL,
                    warning_recipient VARCHAR(255) NULL,
                    warning_subject VARCHAR(255) NULL,
                    delivery_status VARCHAR(30) DEFAULT 'SUCCESS',
                    reason TEXT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE CASCADE,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                    FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS model_history (
                    id SERIAL PRIMARY KEY,
                    model_type VARCHAR(50) NOT NULL,
                    precision_score FLOAT DEFAULT 0.0,
                    recall_score FLOAT DEFAULT 0.0,
                    f1_score FLOAT DEFAULT 0.0,
                    accuracy FLOAT DEFAULT 0.0,
                    confusion_matrix TEXT,
                    training_samples INT DEFAULT 0,
                    test_samples INT DEFAULT 0,
                    evaluation_type VARCHAR(50) DEFAULT 'Synthetic Evaluation',
                    dataset_used VARCHAR(255) DEFAULT 'default_academic_dataset',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dataset_history (
                    id SERIAL PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    total_samples INT DEFAULT 0,
                    bullying_samples INT DEFAULT 0,
                    non_bullying_samples INT DEFAULT 0,
                    neutral_samples INT DEFAULT 0,
                    file_size VARCHAR(50) DEFAULT '0 MB',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_config (
                    id SERIAL PRIMARY KEY,
                    institution_id INT NOT NULL,
                    email_address VARCHAR(255),
                    app_password TEXT NULL,
                    encrypted_app_password TEXT,
                    imap_server VARCHAR(255) DEFAULT 'imap.gmail.com',
                    smtp_server VARCHAR(255) DEFAULT 'smtp.gmail.com',
                    smtp_port INT DEFAULT 587,
                    status VARCHAR(50) DEFAULT 'inactive',
                    last_synced_at TIMESTAMP NULL,
                    sync_status VARCHAR(30) DEFAULT 'IDLE',
                    sync_lease_id VARCHAR(64) NULL,
                    sync_lease_expires_at TIMESTAMP NULL,
                    last_error TEXT NULL,
                    total_ingested_count INT DEFAULT 0,
                    configured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    monitoring_started_at TIMESTAMP NULL,
                    initial_uid INT NULL,
                    last_processed_uid INT NULL,
                    uid_validity INT NULL,
                    mailbox_initialized INT DEFAULT 0,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ingested_messages (
                    id SERIAL PRIMARY KEY,
                    institution_id INT NOT NULL,
                    email_config_id INT NOT NULL,
                    message_id_hash VARCHAR(64) NOT NULL,
                    imap_uid INT NULL,
                    uidvalidity INT NULL,
                    processing_status VARCHAR(30) DEFAULT 'DISCOVERED',
                    attempt_count INT DEFAULT 0,
                    last_attempt_at TIMESTAMP NULL,
                    error_message TEXT NULL,
                    analysis_id INT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                    FOREIGN KEY (email_config_id) REFERENCES email_config (id) ON DELETE CASCADE,
                    FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE SET NULL,
                    CONSTRAINT uq_inst_cfg_msg UNIQUE (institution_id, email_config_id, message_id_hash)
                )
            ''')

            apply_migrations(cursor, engine)

        else:
            # MySQL Database Engine Setup
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS institutions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    domain VARCHAR(100) UNIQUE NOT NULL,
                    code VARCHAR(30) NULL,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    institution_id INT NULL,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'analyst',
                    email VARCHAR(100) UNIQUE,
                    status VARCHAR(30) DEFAULT 'PENDING_EMAIL_VERIFICATION',
                    requested_institution_name VARCHAR(100) NULL,
                    requested_institution_domain VARCHAR(100) NULL,
                    email_verified_at TIMESTAMP NULL,
                    failed_login_attempts INT DEFAULT 0,
                    locked_until TIMESTAMP NULL,
                    last_login_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE RESTRICT
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyzed_emails (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    institution_id INT DEFAULT 1,
                    user_id INT NULL,
                    email_config_id INT NULL,
                    email_subject VARCHAR(255),
                    email_from VARCHAR(255),
                    email_to VARCHAR(255),
                    email_text MEDIUMTEXT,

                    overall_risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
                    overall_confidence FLOAT NOT NULL DEFAULT 0.0,
                    threat_score FLOAT NOT NULL DEFAULT 0.0,
                    incident_status VARCHAR(30) NOT NULL DEFAULT 'PENDING_REVIEW',

                    is_bullying TINYINT(1) NOT NULL DEFAULT 0,
                    confidence FLOAT NOT NULL DEFAULT 0.0,
                    rule_based_matches TEXT,
                    rule_based_score FLOAT DEFAULT 0.0,
                    ml_prediction TINYINT(1) DEFAULT 0,
                    ml_confidence FLOAT DEFAULT 0.0,
                    model_used VARCHAR(50) DEFAULT 'Hybrid',

                    phishing_risk_level VARCHAR(20) DEFAULT 'LOW',
                    phishing_confidence FLOAT DEFAULT 0.0,
                    phishing_indicators MEDIUMTEXT,

                    urls_detected INT DEFAULT 0,
                    suspicious_urls_count INT DEFAULT 0,
                    url_analysis_summary MEDIUMTEXT,

                    domain_analysis_summary MEDIUMTEXT,

                    social_eng_risk_level VARCHAR(20) DEFAULT 'LOW',
                    social_eng_confidence FLOAT DEFAULT 0.0,
                    social_eng_techniques MEDIUMTEXT,

                    attachments_count INT DEFAULT 0,
                    malware_detected TINYINT(1) DEFAULT 0,
                    malicious_attachments_count INT DEFAULT 0,
                    attachment_risk_level VARCHAR(20) DEFAULT 'LOW',
                    attachment_findings MEDIUMTEXT,

                    images_count INT DEFAULT 0,
                    suspicious_images_count INT DEFAULT 0,
                    image_forensics_summary MEDIUMTEXT,

                    explanation MEDIUMTEXT,
                    top_risk_factors MEDIUMTEXT,

                    analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    email_date TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_risk (overall_risk_level),
                    INDEX idx_bullying (is_bullying),
                    INDEX idx_incident_status (incident_status),
                    INDEX idx_created (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incident_audit_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    analysis_id INT NOT NULL,
                    institution_id INT NOT NULL,
                    admin_id INT NOT NULL,
                    admin_username VARCHAR(50) NOT NULL,
                    action VARCHAR(30) NOT NULL,
                    original_sender VARCHAR(255) NULL,
                    original_recipient VARCHAR(255) NULL,
                    warning_recipient VARCHAR(255) NULL,
                    warning_subject VARCHAR(255) NULL,
                    delivery_status VARCHAR(30) DEFAULT 'SUCCESS',
                    reason MEDIUMTEXT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_audit_analysis (analysis_id),
                    INDEX idx_audit_institution (institution_id),
                    INDEX idx_audit_admin (admin_id),
                    FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE CASCADE,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                    FOREIGN KEY (admin_id) REFERENCES users (id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS model_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_type VARCHAR(50) NOT NULL,
                    precision_score FLOAT DEFAULT 0.0,
                    recall_score FLOAT DEFAULT 0.0,
                    f1_score FLOAT DEFAULT 0.0,
                    accuracy FLOAT DEFAULT 0.0,
                    confusion_matrix TEXT,
                    training_samples INT DEFAULT 0,
                    test_samples INT DEFAULT 0,
                    evaluation_type VARCHAR(50) DEFAULT 'Synthetic Evaluation',
                    dataset_used VARCHAR(255) DEFAULT 'default_academic_dataset',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dataset_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    total_samples INT DEFAULT 0,
                    bullying_samples INT DEFAULT 0,
                    non_bullying_samples INT DEFAULT 0,
                    neutral_samples INTEGER DEFAULT 0,
                    file_size VARCHAR(50) DEFAULT '0 MB',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_config (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    institution_id INT NOT NULL,
                    email_address VARCHAR(255),
                    app_password TEXT NULL,
                    encrypted_app_password TEXT,
                    imap_server VARCHAR(255) DEFAULT 'imap.gmail.com',
                    smtp_server VARCHAR(255) DEFAULT 'smtp.gmail.com',
                    smtp_port INT DEFAULT 587,
                    status VARCHAR(50) DEFAULT 'inactive',
                    last_synced_at TIMESTAMP NULL,
                    sync_status VARCHAR(30) DEFAULT 'IDLE',
                    sync_lease_id VARCHAR(64) NULL,
                    sync_lease_expires_at TIMESTAMP NULL,
                    last_error TEXT NULL,
                    total_ingested_count INT DEFAULT 0,
                    configured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    monitoring_started_at TIMESTAMP NULL,
                    initial_uid INT NULL,
                    last_processed_uid INT NULL,
                    uid_validity INT NULL,
                    mailbox_initialized TINYINT(1) DEFAULT 0,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ingested_messages (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    institution_id INT NOT NULL,
                    email_config_id INT NOT NULL,
                    message_id_hash VARCHAR(64) NOT NULL,
                    imap_uid INT NULL,
                    uidvalidity INT NULL,
                    processing_status VARCHAR(30) DEFAULT 'DISCOVERED',
                    attempt_count INT DEFAULT 0,
                    last_attempt_at TIMESTAMP NULL,
                    error_message TEXT NULL,
                    analysis_id INT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (institution_id) REFERENCES institutions (id) ON DELETE CASCADE,
                    FOREIGN KEY (email_config_id) REFERENCES email_config (id) ON DELETE CASCADE,
                    FOREIGN KEY (analysis_id) REFERENCES analyzed_emails (id) ON DELETE SET NULL,
                    UNIQUE KEY uq_inst_cfg_msg (institution_id, email_config_id, message_id_hash)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')

            # Apply schema migrations for existing MySQL databases
            apply_migrations(cursor, engine)
            cursor.close()

    # -------------------------------------------------------------------------
    # Idempotent & Secure Administrator Initialization & Environment Sync
    # -------------------------------------------------------------------------
    try:
        from flask import current_app
        if current_app:
            admin_username = current_app.config.get('ADMIN_USERNAME') or Config.ADMIN_USERNAME or 'admin'
            admin_email = current_app.config.get('ADMIN_EMAIL') or Config.ADMIN_EMAIL or 'admin@bullymail.local'
            admin_password = current_app.config.get('ADMIN_PASSWORD') or Config.ADMIN_PASSWORD
            is_testing = current_app.config.get('TESTING', False)
            is_production = current_app.config.get('FLASK_ENV') == 'production'
        else:
            admin_username = Config.ADMIN_USERNAME or 'admin'
            admin_email = Config.ADMIN_EMAIL or 'admin@bullymail.local'
            admin_password = Config.ADMIN_PASSWORD
            is_testing = getattr(Config, 'TESTING', False)
            is_production = Config.FLASK_ENV == 'production'
    except Exception:
        admin_username = Config.ADMIN_USERNAME or 'admin'
        admin_email = Config.ADMIN_EMAIL or 'admin@bullymail.local'
        admin_password = Config.ADMIN_PASSWORD
        is_testing = getattr(Config, 'TESTING', False)
        is_production = Config.FLASK_ENV == 'production'


    if not admin_password:
        if is_production:
            raise RuntimeError(
                "[BullyMail Security Fatal] Production environment detected without ADMIN_PASSWORD configured. "
                "You must explicitly set ADMIN_PASSWORD in your environment / .env file before starting in production."
            )
        elif is_testing:
            admin_password = getattr(Config, 'ADMIN_PASSWORD', None) or "TEST_ONLY_PASSWORD_DO_NOT_USE_IN_PRODUCTION_123!"
        else:
            # In development/test mode without explicit password: generate a secure cryptographically random token
            generated_token = secrets.token_urlsafe(16)
            admin_password = f"DevAdmin_{generated_token}"
            print("==================================================================")
            print(" [BullyMail First-Time Dev Init] Temporary Admin Password Generated:")
            print(f" Username: {admin_username}")
            print(f" Password: {admin_password}")
            print(" Set ADMIN_PASSWORD in .env to specify a permanent custom password.")
            print("==================================================================")

    from ..models.user import UserModel
    admin_user = fetch_one("SELECT * FROM users WHERE role = 'admin' LIMIT 1")
    if not admin_user:
        hashed_pw = UserModel.hash_password(admin_password)
        execute_query(
            "INSERT INTO users (username, password_hash, role, email, status) VALUES (%s, %s, %s, %s, %s)",
            (admin_username, hashed_pw, 'admin', admin_email, 'ACTIVE')
        )
    else:
        # Admin user exists: synchronize credentials if environment parameters differ
        sql_parts = []
        update_params = []

        if admin_username and admin_user.get('username') != admin_username:
            sql_parts.append("username = %s")
            update_params.append(admin_username)

        if admin_email and admin_user.get('email') != admin_email:
            sql_parts.append("email = %s")
            update_params.append(admin_email)

        if admin_user.get('status') != 'ACTIVE':
            sql_parts.append("status = %s")
            update_params.append('ACTIVE')

        if admin_password:
            stored_hash = admin_user.get('password_hash') or ''
            if not UserModel.verify_password(stored_hash, admin_password):
                new_hash = UserModel.hash_password(admin_password)
                sql_parts.append("password_hash = %s")
                update_params.append(new_hash)

        if sql_parts:
            update_params.append(admin_user['id'])
            sql = f"UPDATE users SET {', '.join(sql_parts)} WHERE id = %s"
            execute_query(sql, tuple(update_params))

    return True
