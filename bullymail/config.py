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
    DB_TYPE = os.environ.get('DB_TYPE', 'sqlite').lower()
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 3306))
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'bullymail_db')
    
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
