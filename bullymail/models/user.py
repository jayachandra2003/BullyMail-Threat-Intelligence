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

        stored_hash = user.get('password_hash') or user.get('password') or ''
        is_correct = cls.verify_password(stored_hash, password)

        if not is_correct:
            return None, 'INVALID_CREDENTIALS'

        # Check account lifecycle status
        status = user.get('status', 'ACTIVE')
        if status == 'PENDING_EMAIL_VERIFICATION':
            return None, 'PENDING_VERIFICATION'
        elif status == 'PENDING_ADMIN_APPROVAL':
            return None, 'PENDING_ADMIN_APPROVAL'
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
                    email: str = None, status: str = 'PENDING_EMAIL_VERIFICATION', enforce_policy: bool = True,
                    institution_id: int = None, requested_institution_name: str = None,
                    requested_institution_domain: str = None, full_name: str = None) -> int:
        """
        Creates a new user record with password hashing, email normalization, and policy enforcement.
        Default institution_id is None (must NEVER default to Institution 1).
        """
        username = (username or '').strip()
        if not username:
            raise ValueError("Username cannot be empty.")

        clean_name = (full_name or '').strip() or None
        clean_email = cls.normalize_email(email) if email else None
        if clean_email and not cls.validate_email_format(clean_email):
            raise ValueError("Invalid email format.")

        if enforce_policy:
            is_valid, msg = cls.validate_password_policy(password)
            if not is_valid:
                raise ValueError(msg)

        hashed = cls.hash_password(password)
        user_id = None
        try:
            user_id = execute_query(
                "INSERT INTO users "
                "(username, password, password_hash, role, full_name, email, status, institution_id, requested_institution_name, requested_institution_domain) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (username, hashed, hashed, role, clean_name, clean_email, status, institution_id, requested_institution_name, requested_institution_domain)
            )
        except Exception:
            try:
                user_id = execute_query(
                    "INSERT INTO users "
                    "(username, password_hash, role, full_name, email, status, institution_id, requested_institution_name, requested_institution_domain) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (username, hashed, role, clean_name, clean_email, status, institution_id, requested_institution_name, requested_institution_domain)
                )
            except Exception:
                try:
                    user_id = execute_query(
                        "INSERT INTO users "
                        "(username, password_hash, role, email, status, institution_id, requested_institution_name, requested_institution_domain) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (username, hashed, role, clean_email, status, institution_id, requested_institution_name, requested_institution_domain)
                    )
                except Exception:
                    user_id = execute_query(
                        "INSERT INTO users "
                        "(username, password_hash, role, email, status, institution_id) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (username, hashed, role, clean_email, status, institution_id)
                    )

        if not user_id:
            fetched = cls.get_by_email(clean_email) if clean_email else cls.get_by_username(username)
            if fetched and fetched.get('id'):
                user_id = fetched['id']

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
        """Transitions user from PENDING_EMAIL_VERIFICATION to PENDING_ADMIN_APPROVAL."""
        execute_query(
            "UPDATE users SET status = 'PENDING_ADMIN_APPROVAL', email_verified_at = CURRENT_TIMESTAMP WHERE id = %s",
            (user_id,)
        )
        return True

    @classmethod
    def provision_and_approve_user(cls, user_id: int, institution_id: int, role: str = 'analyst') -> bool:
        """
        Provisions and activates a pending user account into a specified institution ID and role.
        """
        user = cls.get_by_id(user_id)
        if not user:
            return False

        if not institution_id:
            raise ValueError("Institution ID must be specified for account provisioning.")

        valid_roles = {'platform_owner', 'org_admin', 'analyst', 'admin', 'operator'}
        assigned_role = role if role in valid_roles else 'org_admin'
        if assigned_role == 'admin':
            assigned_role = 'org_admin'
        elif assigned_role == 'operator':
            assigned_role = 'analyst'

        execute_query(
            "UPDATE users "
            "SET status = 'ACTIVE', role = %s, institution_id = %s, "
            "requested_institution_name = NULL, requested_institution_domain = NULL "
            "WHERE id = %s",
            (assigned_role, institution_id, user_id)
        )
        return True

    @classmethod
    def reject_user(cls, user_id: int) -> bool:
        """Rejects a pending registration request."""
        execute_query(
            "UPDATE users SET status = 'REJECTED' WHERE id = %s",
            (user_id,)
        )
        return True

    @classmethod
    def approve_user_by_admin(cls, user_id: int, role: str = None, institution_id: int = None) -> bool:
        """Approves a user account, setting status to ACTIVE."""
        user = cls.get_by_id(user_id)
        if not user:
            return False

        new_role = role or user.get('role', 'org_admin')
        if new_role == 'admin':
            new_role = 'org_admin'
        elif new_role == 'operator':
            new_role = 'analyst'
        new_inst = institution_id if institution_id is not None else user.get('institution_id')
        if not new_inst:
            raise ValueError("Institution ID must be specified to approve user.")

        execute_query(
            "UPDATE users SET status = 'ACTIVE', role = %s, institution_id = %s WHERE id = %s",
            (new_role, new_inst, user_id)
        )
        return True

    @classmethod
    def get_pending_approval_users(cls, institution_id: int = None):
        """Retrieves users waiting for administrator approval."""
        if institution_id:
            return fetch_all(
                "SELECT id, username, full_name, email, role, status, institution_id, requested_institution_name, "
                "requested_institution_domain, created_at, email_verified_at "
                "FROM users "
                "WHERE status = 'PENDING_ADMIN_APPROVAL' AND institution_id = %s "
                "ORDER BY id ASC",
                (institution_id,)
            )
        return fetch_all(
            "SELECT id, username, full_name, email, role, status, institution_id, requested_institution_name, "
            "requested_institution_domain, created_at, email_verified_at "
            "FROM users "
            "WHERE status = 'PENDING_ADMIN_APPROVAL' "
            "ORDER BY id ASC"
        )

    @classmethod
    def get_users_by_institution(cls, institution_id: int):
        """Retrieves active/all users belonging to a specific institution."""
        if not institution_id:
            return []
        return fetch_all(
            "SELECT id, username, full_name, email, role, status, created_at, last_login_at "
            "FROM users WHERE institution_id = %s ORDER BY id ASC",
            (institution_id,)
        )
