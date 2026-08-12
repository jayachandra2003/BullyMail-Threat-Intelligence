import os
import secrets
from werkzeug.security import generate_password_hash
from ..config import Config
from .connection import get_db, get_engine_type, execute_query, fetch_one

def setup_database():
    """Sets up all required database tables with UTF-8 support and idempotent secure administrator initialization."""
    engine = get_engine_type()
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        if engine == 'sqlite':
            # Users Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'admin',
                    email VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    malware_risk_level VARCHAR(20) DEFAULT 'LOW',
                    attachment_analysis_summary TEXT DEFAULT '[]',
                    
                    -- Image Forensics Vector
                    images_count INTEGER DEFAULT 0,
                    image_risk_level VARCHAR(20) DEFAULT 'LOW',
                    image_analysis_summary TEXT DEFAULT '[]',
                    
                    -- Explainable Evidence
                    evidence_summary TEXT DEFAULT '[]',
                    
                    email_date TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Model Performance History Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS model_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_type VARCHAR(50) NOT NULL,
                    precision_score FLOAT DEFAULT 0.0,
                    recall_score FLOAT DEFAULT 0.0,
                    f1_score FLOAT DEFAULT 0.0,
                    accuracy FLOAT DEFAULT 0.0,
                    confusion_matrix TEXT DEFAULT '[]',
                    training_samples INTEGER DEFAULT 0,
                    test_samples INTEGER DEFAULT 0,
                    evaluation_type VARCHAR(50) DEFAULT 'Synthetic Evaluation',
                    dataset_used VARCHAR(255) DEFAULT 'default_academic_dataset',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Dataset Generation History Table
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
            
            # Email Configuration Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_address VARCHAR(255),
                    configured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'inactive'
                )
            ''')
            
        else:
            # MySQL Tables (UTF8mb4)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'admin',
                    email VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    malware_risk_level VARCHAR(20) DEFAULT 'LOW',
                    attachment_analysis_summary MEDIUMTEXT,
                    
                    images_count INT DEFAULT 0,
                    image_risk_level VARCHAR(20) DEFAULT 'LOW',
                    image_analysis_summary MEDIUMTEXT,
                    
                    evidence_summary MEDIUMTEXT,
                    
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
            cursor.close()

    # -------------------------------------------------------------------------
    # Idempotent & Secure Administrator Initialization
    # -------------------------------------------------------------------------
    admin_user = fetch_one("SELECT * FROM users WHERE role = 'admin' LIMIT 1")
    if not admin_user:
        admin_username = Config.ADMIN_USERNAME or 'admin'
        admin_email = Config.ADMIN_EMAIL or 'admin@bullymail.local'
        admin_password = Config.ADMIN_PASSWORD
        
        is_production = Config.FLASK_ENV == 'production'
        
        if not admin_password:
            if is_production:
                raise RuntimeError(
                    "[BullyMail Security Fatal] Production environment detected without ADMIN_PASSWORD configured. "
                    "You must explicitly set ADMIN_PASSWORD in your environment / .env file before starting in production."
                )
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

        hashed_pw = generate_password_hash(admin_password)
        execute_query(
            "INSERT INTO users (username, password_hash, role, email) VALUES (%s, %s, %s, %s)",
            (admin_username, hashed_pw, 'admin', admin_email)
        )
        
    return True
