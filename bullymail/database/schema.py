import os
import secrets
from werkzeug.security import generate_password_hash
from ..config import Config
from .connection import get_db, get_engine_type, execute_query, fetch_one

def _get_existing_columns(cursor, table_name, engine):
    """
    Returns a set of lowercase column names present in the specified table.
    Works seamlessly across SQLite and MySQL.
    """
    columns = set()
    try:
        if engine == 'sqlite':
            cursor.execute(f"PRAGMA table_info({table_name})")
            for row in cursor.fetchall():
                name = row[1] if isinstance(row, (tuple, list)) else row['name']
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
    # 1. Users Table Migrations
    # -------------------------------------------------------------------------
    user_cols = _get_existing_columns(cursor, 'users', engine)
    if user_cols:
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

        # Backfill active status for any legacy accounts
        try:
            cursor.execute("UPDATE users SET status = 'ACTIVE' WHERE status IS NULL OR status = ''")
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 2. Multi-Vector Analyzed Emails Migrations
    # -------------------------------------------------------------------------
    email_cols = _get_existing_columns(cursor, 'analyzed_emails', engine)
    if email_cols:
        missing_defs = {
            'domain_analysis_summary': 'TEXT DEFAULT "{}"',
            'social_eng_risk_level': "VARCHAR(20) DEFAULT 'LOW'",
            'social_eng_confidence': "FLOAT DEFAULT 0.0",
            'social_eng_techniques': 'TEXT DEFAULT "[]"',
            'attachments_count': "INTEGER DEFAULT 0" if engine == 'sqlite' else "INT DEFAULT 0",
            'malware_detected': "INTEGER DEFAULT 0" if engine == 'sqlite' else "TINYINT(1) DEFAULT 0",
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

def setup_database():
    """Sets up all required database tables with UTF-8 support and idempotent secure administrator initialization."""
    engine = get_engine_type()
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        if engine == 'sqlite':
            # Users Table with Account Lifecycle Status
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
                    email_subject TEXT,
                    email_from TEXT,
                    email_to TEXT,
                    email_text TEXT NOT NULL,
                    
                    -- Overall Unified Risk
                    overall_risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
                    overall_confidence FLOAT NOT NULL DEFAULT 0.0,
                    threat_score FLOAT NOT NULL DEFAULT 0.0,
                    
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
                    email_address VARCHAR(255),
                    configured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'inactive'
                )
            ''')
            
            # Apply schema migrations for existing SQLite databases
            apply_migrations(cursor, engine)
            
        else:
            # MySQL Database Engine Setup
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'admin',
                    email VARCHAR(100) UNIQUE,
                    status VARCHAR(30) DEFAULT 'ACTIVE',
                    email_verified_at TIMESTAMP NULL,
                    failed_login_attempts INT DEFAULT 0,
                    locked_until TIMESTAMP NULL,
                    last_login_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    email_subject TEXT,
                    email_from VARCHAR(255),
                    email_to VARCHAR(255),
                    email_text MEDIUMTEXT NOT NULL,
                    
                    overall_risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
                    overall_confidence FLOAT NOT NULL DEFAULT 0.0,
                    threat_score FLOAT NOT NULL DEFAULT 0.0,
                    
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
                    INDEX idx_created (created_at)
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
                    neutral_samples INT DEFAULT 0,
                    file_size VARCHAR(50) DEFAULT '0 MB',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_config (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email_address VARCHAR(255),
                    configured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'inactive'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ''')
            
            # Apply schema migrations for existing MySQL databases
            apply_migrations(cursor, engine)
            cursor.close()

    # -------------------------------------------------------------------------
    # Idempotent & Secure Administrator Initialization
    # -------------------------------------------------------------------------
    admin_user = fetch_one("SELECT * FROM users WHERE role = 'admin' LIMIT 1")
    if not admin_user:
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
                is_testing = Config.TESTING
                is_production = Config.FLASK_ENV == 'production'
        except Exception:
            admin_username = Config.ADMIN_USERNAME or 'admin'
            admin_email = Config.ADMIN_EMAIL or 'admin@bullymail.local'
            admin_password = Config.ADMIN_PASSWORD
            is_testing = Config.TESTING
            is_production = Config.FLASK_ENV == 'production'
        
        if not admin_password:
            if is_production:
                raise RuntimeError(
                    "[BullyMail Security Fatal] Production environment detected without ADMIN_PASSWORD configured. "
                    "You must explicitly set ADMIN_PASSWORD in your environment / .env file before starting in production."
                )
            elif is_testing:
                admin_password = "TestSecretPass_2026!Key"
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
        hashed_pw = UserModel.hash_password(admin_password)
        execute_query(
            "INSERT INTO users (username, password_hash, role, email, status) VALUES (%s, %s, %s, %s, %s)",
            (admin_username, hashed_pw, 'admin', admin_email, 'ACTIVE')
        )
        
    return True
