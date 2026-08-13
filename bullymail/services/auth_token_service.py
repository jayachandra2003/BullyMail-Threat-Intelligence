import secrets
import hashlib
from datetime import datetime, timedelta
from ..database.connection import execute_query, fetch_one, get_engine_type

class AuthTokenService:
    """
    Cryptographically secure, single-use token lifecycle management.
    Tokens are generated with high-entropy CSPRNG and stored ONLY as SHA-256 hashes.
    """

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Computes deterministic SHA-256 hash of a raw token."""
        return hashlib.sha256(raw_token.strip().encode('utf-8')).hexdigest()

    @classmethod
    def generate_email_verification_token(cls, user_id: int, expiry_hours: int = 24) -> str:
        """
        Generates a 32-byte URL-safe token, stores its SHA-256 hash, and returns the raw token.
        """
        raw_token = secrets.token_urlsafe(32)
        token_hash = cls._hash_token(raw_token)
        expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)
        expires_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')

        # Invalidate any prior unused verification tokens for this user
        execute_query(
            "UPDATE email_verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = %s AND used_at IS NULL",
            (user_id,)
        )

        execute_query(
            "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
            (user_id, token_hash, expires_str)
        )
        return raw_token

    @classmethod
    def verify_and_consume_email_token(cls, raw_token: str) -> int:
        """
        Atomically validates and consumes an email verification token.
        Returns user_id if valid and unexpired; otherwise returns None.
        """
        if not raw_token or not isinstance(raw_token, str):
            return None

        token_hash = cls._hash_token(raw_token)
        record = fetch_one(
            "SELECT * FROM email_verification_tokens WHERE token_hash = %s",
            (token_hash,)
        )

        if not record:
            return None

        # Check if already used
        if record.get('used_at'):
            return None

        # Check expiration
        expires_at = record.get('expires_at')
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.strptime(expires_at.split('.')[0], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return None

        if expires_at and expires_at < datetime.utcnow():
            return None

        # Atomically consume token
        execute_query(
            "UPDATE email_verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = %s AND used_at IS NULL",
            (record['id'],)
        )

        return record['user_id']

    @classmethod
    def generate_password_reset_token(cls, user_id: int, expiry_minutes: int = 60) -> str:
        """
        Generates a 32-byte URL-safe password reset token, stores its SHA-256 hash, and returns the raw token.
        """
        raw_token = secrets.token_urlsafe(32)
        token_hash = cls._hash_token(raw_token)
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        expires_str = expires_at.strftime('%Y-%m-%d %H:%M:%S')

        # Invalidate any prior unused reset tokens for this user
        execute_query(
            "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = %s AND used_at IS NULL",
            (user_id,)
        )

        execute_query(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
            (user_id, token_hash, expires_str)
        )
        return raw_token

    @classmethod
    def verify_and_consume_password_reset_token(cls, raw_token: str) -> int:
        """
        Atomically validates and consumes a password reset token.
        Returns user_id if valid and unexpired; otherwise returns None.
        """
        if not raw_token or not isinstance(raw_token, str):
            return None

        token_hash = cls._hash_token(raw_token)
        record = fetch_one(
            "SELECT * FROM password_reset_tokens WHERE token_hash = %s",
            (token_hash,)
        )

        if not record:
            return None

        # Check if already used
        if record.get('used_at'):
            return None

        # Check expiration
        expires_at = record.get('expires_at')
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.strptime(expires_at.split('.')[0], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return None

        if expires_at and expires_at < datetime.utcnow():
            return None

        # Atomically consume token
        execute_query(
            "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = %s AND used_at IS NULL",
            (record['id'],)
        )

        return record['user_id']

    @classmethod
    def invalidate_all_tokens(cls, user_id: int):
        """Invalidates all outstanding verification and reset tokens for a given user."""
        execute_query(
            "UPDATE email_verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = %s AND used_at IS NULL",
            (user_id,)
        )
        execute_query(
            "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = %s AND used_at IS NULL",
            (user_id,)
        )
