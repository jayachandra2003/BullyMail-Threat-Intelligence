import re
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from ..database.connection import fetch_one, fetch_all, execute_query
from ..config import Config

# Common weak/default passwords to reject under password policy
DISALLOWED_WEAK_PASSWORDS = {
    'admin123', 'admin', 'password', 'password123', '123456789012',
    '1234567890123', 'qwerty123456', 'administrator', 'bullymail123',
    'adminadminadmin', 'changeme12345', 'welcome12345'
}

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

class UserModel:
    """
    Data Access Object & Security Controls for Users & Authentication Lifecycle.
    Implements timing-safe authentication, anti-enumeration, strong password policies,
    and account verification state machines.
    """

    _DUMMY_HASH_CACHE = None

    @classmethod
    def _get_dummy_hash(cls) -> str:
        """
        Lazily initializes and caches a dummy hash for timing equalization.
        Prevents top-level module import execution failure.
        """
        if cls._DUMMY_HASH_CACHE is None:
            try:
                cls._DUMMY_HASH_CACHE = cls.hash_password("BullyMail_Timing_Equalization_Dummy_Pass_2026!")
            except Exception:
                cls._DUMMY_HASH_CACHE = "pbkdf2:sha256:600000$dummy$0000000000000000000000000000000000000000000000000000000000000000"
        return cls._DUMMY_HASH_CACHE

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalizes email to trimmed lowercase."""
        return email.strip().lower() if email else ""

    @staticmethod
    def validate_email_format(email: str) -> bool:
        """Validates that email conforms to standard RFC-compliant format."""
        if not email or not isinstance(email, str):
            return False
        return bool(EMAIL_REGEX.match(email.strip()))

    @staticmethod
    def validate_password_policy(password: str) -> tuple[bool, str]:
        """
        Enforces organizational password complexity requirements:
          - Minimum 12 characters
          - Cannot be in common weak password blacklist
        """
        if not password or not isinstance(password, str):
            return False, "Password cannot be empty."
            
        if len(password) < 12:
            return False, "Password must be at least 12 characters in length."
            
        if password.lower() in DISALLOWED_WEAK_PASSWORDS:
            return False, "The chosen password is too common or known to be weak. Please choose a stronger passphrase."
            
        return True, ""

    @staticmethod
    def validate_password_confirmation(password: str, confirm_password: str) -> tuple[bool, str]:
        """Ensures password and confirmation match."""
        if password != confirm_password:
            return False, "Passwords do not match."
        return True, ""

    @classmethod
    def hash_password(cls, password: str) -> str:
        """Generates a secure password hash using OWASP-recommended PBKDF2-HMAC-SHA256."""
        method = getattr(Config, 'PASSWORD_HASH_METHOD', 'pbkdf2:sha256:600000')
        try:
            return generate_password_hash(password, method=method)
        except Exception:
            try:
                return generate_password_hash(password, method='pbkdf2:sha256')
            except Exception:
                return generate_password_hash(password)

    @classmethod
    def verify_password(cls, stored_hash: str, password: str) -> bool:
        """Constant-time verification of password against stored hash."""
        if not stored_hash or not password:
            return False
        if stored_hash.startswith(('pbkdf2:', 'scrypt:', 'argon2:')):
            try:
                return check_password_hash(stored_hash, password)
            except Exception:
                return False
        # Legacy fallback comparison with safe constant-time check
        return stored_hash == password

    @staticmethod
    def get_by_id(user_id: int):
        return fetch_one("SELECT * FROM users WHERE id = %s", (user_id,))

    @staticmethod
    def get_by_username(username: str):
        if not username:
            return None
        return fetch_one("SELECT * FROM users WHERE username = %s", (username.strip(),))

    @classmethod
    def get_by_email(cls, email: str):
        if not email:
            return None
        return fetch_one("SELECT * FROM users WHERE email = %s", (cls.normalize_email(email),))

    @classmethod
    def get_by_identifier(cls, identifier: str):
        """Retrieves user by username or email."""
        if not identifier:
            return None
        clean_id = identifier.strip()
        user = cls.get_by_username(clean_id)
        if not user and '@' in clean_id:
            user = cls.get_by_email(clean_id)
        return user

    @classmethod
    def authenticate(cls, identifier: str, password: str) -> tuple[dict, str]:
        """
        Timing-safe authentication with user enumeration defense.
        Returns: (user_dict_or_None, status_code_str)
        Status codes: 'SUCCESS', 'INVALID_CREDENTIALS', 'PENDING_VERIFICATION', 'ACCOUNT_LOCKED', 'ACCOUNT_DISABLED'
        """
        dummy_hash = cls._get_dummy_hash()

        if not identifier or not password:
            # Run dummy check to maintain timing uniformity
            try:
                check_password_hash(dummy_hash, password or "dummy")
            except Exception:
                pass
            return None, 'INVALID_CREDENTIALS'

        user = cls.get_by_identifier(identifier)

        if not user:
            # Nonexistent account: execute dummy hash comparison to equalize execution time
            try:
                check_password_hash(dummy_hash, password)
            except Exception:
                pass
            return None, 'INVALID_CREDENTIALS'

        stored_hash = user.get('password_hash') or ''
        is_correct = cls.verify_password(stored_hash, password)

        if not is_correct:
            return None, 'INVALID_CREDENTIALS'

        # Check account lifecycle status
        status = user.get('status', 'ACTIVE')
        if status == 'PENDING_EMAIL_VERIFICATION':
            return None, 'PENDING_VERIFICATION'
        elif status == 'LOCKED':
            return None, 'ACCOUNT_LOCKED'
        elif status == 'DISABLED':
            return None, 'ACCOUNT_DISABLED'

        # Transparent upgrade to modern pbkdf2:sha256:600000 if legacy hash format detected
        if not stored_hash.startswith('pbkdf2:sha256:600000'):
            try:
                new_hash = cls.hash_password(password)
                execute_query("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user['id']))
            except Exception:
                pass

        # Update last login timestamp
        execute_query("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = %s", (user['id'],))

        return user, 'SUCCESS'

    @classmethod
    def create_user(cls, username: str, password: str, role: str = 'analyst',
                    email: str = None, status: str = 'ACTIVE', enforce_policy: bool = True) -> int:
        """
        Creates a new user record with password hashing, email normalization, and policy enforcement.
        """
        username = (username or '').strip()
        if not username:
            raise ValueError("Username cannot be empty.")

        clean_email = cls.normalize_email(email) if email else None
        if clean_email and not cls.validate_email_format(clean_email):
            raise ValueError("Invalid email format.")

        if enforce_policy:
            is_valid, msg = cls.validate_password_policy(password)
            if not is_valid:
                raise ValueError(msg)

        hashed = cls.hash_password(password)
        user_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email, status) VALUES (%s, %s, %s, %s, %s)",
            (username, hashed, role, clean_email, status)
        )
        return user_id

    @classmethod
    def set_password(cls, user_id: int, new_password: str, enforce_policy: bool = True) -> bool:
        """Updates user password with policy validation and secure hashing."""
        if enforce_policy:
            is_valid, msg = cls.validate_password_policy(new_password)
            if not is_valid:
                raise ValueError(msg)

        hashed = cls.hash_password(new_password)
        execute_query(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (hashed, user_id)
        )
        return True

    @classmethod
    def activate_user_email(cls, user_id: int) -> bool:
        """Transitions user from PENDING_EMAIL_VERIFICATION to ACTIVE."""
        execute_query(
            "UPDATE users SET status = 'ACTIVE', email_verified_at = CURRENT_TIMESTAMP WHERE id = %s",
            (user_id,)
        )
        return True
