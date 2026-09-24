import os
import secrets
from pathlib import Path

# Load .env if present
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent.parent / '.env'
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent.parent

def _resolve_secret_key():
    """Resolves SECRET_KEY: requires explicit env in production, generates ephemeral key for zero-config dev."""
    env_key = os.environ.get('SECRET_KEY')
    if env_key and env_key.strip():
        return env_key.strip()
    is_prod = os.environ.get('FLASK_ENV') == 'production'
    if is_prod:
        return None  # Enforced in production startup validation
    return secrets.token_hex(32)

def _parse_database_config():
    """
    Parses database configuration from DATABASE_URL, DB_URL, MYSQL_URL, or individual environment variables.
    Supports MySQL, PostgreSQL, and local SQLite with strict validation.
    """
    db_url = os.environ.get('DATABASE_URL') or os.environ.get('DB_URL') or os.environ.get('MYSQL_URL')
    explicit_type = os.environ.get('DB_TYPE', '').strip().lower()
    raw_host = os.environ.get('DB_HOST') or os.environ.get('MYSQL_HOST') or os.environ.get('MYSQLHOST')
    raw_port = os.environ.get('DB_PORT') or os.environ.get('MYSQL_PORT') or os.environ.get('MYSQLPORT')
    raw_user = os.environ.get('DB_USER') or os.environ.get('MYSQL_USER') or os.environ.get('MYSQLUSER')
    raw_pass = os.environ.get('DB_PASSWORD') or os.environ.get('MYSQL_PASSWORD') or os.environ.get('MYSQLPASSWORD')
    raw_name = os.environ.get('DB_NAME') or os.environ.get('MYSQL_DATABASE') or os.environ.get('MYSQLDATABASE')

    if db_url and db_url.strip():
        from urllib.parse import urlparse, unquote
        parsed = urlparse(db_url.strip())
        scheme = (parsed.scheme or '').lower()

        if 'mysql' in scheme:
            db_type = 'mysql'
            default_port = 3306
        elif 'postgres' in scheme or 'psycopg' in scheme:
            db_type = 'postgres'
            default_port = 5432
        elif 'sqlite' in scheme:
            db_type = 'sqlite'
            default_port = None
        else:
            db_type = scheme or 'mysql'
            default_port = 3306

        db_host = parsed.hostname or raw_host or 'localhost'
        db_port = parsed.port or (int(raw_port) if raw_port else default_port)
        db_user = unquote(parsed.username) if parsed.username else (raw_user or 'root')
        db_pass = unquote(parsed.password) if parsed.password else (raw_pass or '')
        db_name = parsed.path.lstrip('/') if parsed.path else (raw_name or 'bullymail_db')
    else:
        db_type = explicit_type
        if not db_type:
            if os.environ.get('MYSQL_HOST') or os.environ.get('MYSQLHOST') or os.environ.get('MYSQL_DATABASE'):
                db_type = 'mysql'
            elif raw_host and raw_host.strip().lower() not in ('localhost', '127.0.0.1', ''):
                db_type = 'mysql'
            else:
                db_type = 'sqlite'

        db_host = raw_host or 'localhost'
        db_port = int(raw_port) if raw_port else 3306
        db_user = raw_user or 'root'
        db_pass = raw_pass or ''
        db_name = raw_name or 'bullymail_db'

    return {
        'DB_TYPE': db_type,
        'DB_HOST': db_host,
        'DB_PORT': db_port if db_port else 3306,
        'DB_USER': db_user,
        'DB_PASSWORD': db_pass,
        'DB_NAME': db_name,
        'DATABASE_URL': db_url
    }

_db_cfg = _parse_database_config()

class Config:
    """Base Configuration for BullyMail V2"""
    SECRET_KEY = _resolve_secret_key()
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 't')
    
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '0.0.0.0')
    
    # Administrator Initialization Settings (Configured via Environment)
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', None)
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@bullymail.local')
    
    # Database Settings
    DATABASE_URL = _db_cfg['DATABASE_URL']
    DB_TYPE = _db_cfg['DB_TYPE']
    DB_HOST = _db_cfg['DB_HOST']
    DB_PORT = _db_cfg['DB_PORT']
    DB_USER = _db_cfg['DB_USER']
    DB_PASSWORD = _db_cfg['DB_PASSWORD']
    DB_NAME = _db_cfg['DB_NAME']
    
    # SQLite Path (Fallback or Primary)
    SQLITE_DB_PATH = os.environ.get('SQLITE_DB_PATH', str(BASE_DIR / 'bullymail.db'))
    
    # Storage Paths
    MODEL_PATH = str(BASE_DIR / os.environ.get('MODEL_PATH', 'saved_models'))
    DATASET_PATH = str(BASE_DIR / os.environ.get('DATASET_PATH', 'datasets'))
    UPLOAD_PATH = str(BASE_DIR / os.environ.get('UPLOAD_PATH', 'uploads'))
    
    # File Upload Limits
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16 MB
    ALLOWED_EXTENSIONS = set(os.environ.get(
        'ALLOWED_EXTENSIONS', 
        'pdf,doc,docx,xls,xlsx,txt,zip,rar,7z,png,jpg,jpeg,gif,eml,msg'
    ).split(','))
    
    # Email Integration Defaults & SMTP Configuration
    EMAIL_IMAP_SERVER = os.environ.get('EMAIL_IMAP_SERVER', 'imap.gmail.com')
    EMAIL_SMTP_SERVER = os.environ.get('EMAIL_SMTP_SERVER', os.environ.get('SMTP_HOST', 'smtp.gmail.com'))
    EMAIL_SMTP_PORT = int(os.environ.get('EMAIL_SMTP_PORT', os.environ.get('SMTP_PORT', 587)))
    EMAIL_ADDRESS = os.environ.get('EMAIL_ADDRESS', os.environ.get('SMTP_USERNAME', ''))
    EMAIL_APP_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD', os.environ.get('SMTP_PASSWORD', ''))
    WORKER_POLL_INTERVAL = int(os.environ.get('WORKER_POLL_INTERVAL', 15))

    # Dedicated SMTP Warning Configuration (Environment-Driven)
    SMTP_HOST = os.environ.get('SMTP_HOST', EMAIL_SMTP_SERVER)
    SMTP_PORT = int(os.environ.get('SMTP_PORT', EMAIL_SMTP_PORT))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', EMAIL_ADDRESS)
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', EMAIL_APP_PASSWORD)
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True').lower() in ('true', '1', 't')
    SMTP_FROM_EMAIL = os.environ.get('SMTP_FROM_EMAIL', SMTP_USERNAME or EMAIL_ADDRESS or 'admin@bullymail.local')
    SMTP_FROM_NAME = os.environ.get('SMTP_FROM_NAME', 'BullyMail Administration')

    # Master Key for Fernet Credential Encryption (AES-128-CBC + HMAC-SHA256)
    BULLYMAIL_MASTER_KEY = os.environ.get('BULLYMAIL_MASTER_KEY', None)

    # Trusted Public Base URL (Prevents Host Header Poisoning in Auth Emails)
    APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:5000').rstrip('/')
    
    # Password Hashing Method (OWASP Recommended PBKDF2-HMAC-SHA256)
    PASSWORD_HASH_METHOD = os.environ.get('PASSWORD_HASH_METHOD', 'pbkdf2:sha256:600000')
    
    # Auth Token Expirations
    AUTH_EMAIL_TOKEN_EXPIRY_HOURS = int(os.environ.get('AUTH_EMAIL_TOKEN_EXPIRY_HOURS', 24))
    AUTH_RESET_TOKEN_EXPIRY_MINUTES = int(os.environ.get('AUTH_RESET_TOKEN_EXPIRY_MINUTES', 60))
    
    # CAPTCHA / Bot Defense Configuration
    CAPTCHA_ENABLED = os.environ.get('CAPTCHA_ENABLED', 'False').lower() in ('true', '1', 't')
    CAPTCHA_PROVIDER = os.environ.get('CAPTCHA_PROVIDER', 'turnstile').lower() # 'turnstile' or 'hcaptcha'
    CAPTCHA_SECRET_KEY = os.environ.get('CAPTCHA_SECRET_KEY', '')
    CAPTCHA_SITE_KEY = os.environ.get('CAPTCHA_SITE_KEY', '')
    
    # Environment-Aware Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_SECURE = (
        os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() in ('true', '1', 't')
        if os.environ.get('FLASK_ENV') == 'production'
        else os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1', 't')
    )
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('PERMANENT_SESSION_LIFETIME', 86400))  # 24 hours

class TestConfig(Config):
    """Testing Configuration with SQLite test database"""
    TESTING = True
    DB_TYPE = 'sqlite'
    SQLITE_DB_PATH = ':memory:'
    DEBUG = False
    WTF_CSRF_ENABLED = False
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'TEST_ONLY_PASSWORD_DO_NOT_USE_IN_PRODUCTION_123!'
    ADMIN_EMAIL = 'admin@bullymail.local'
    BULLYMAIL_MASTER_KEY = 'ghNXQBv5dpR4x5h5UCkhrnfBLXR3nKrZY2mHHTPGRGE='
    SESSION_COOKIE_SECURE = False
    CAPTCHA_ENABLED = False
