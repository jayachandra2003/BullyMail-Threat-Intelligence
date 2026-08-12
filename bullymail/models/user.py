from werkzeug.security import generate_password_hash, check_password_hash
from ..database.connection import fetch_one, fetch_all, execute_query

# Common weak/default passwords to reject under password policy
DISALLOWED_WEAK_PASSWORDS = {
    'admin123', 'admin', 'password', 'password123', '123456789012',
    '1234567890123', 'qwerty123456', 'administrator', 'bullymail123',
    'adminadminadmin', 'changeme12345', 'welcome12345'
}

class UserModel:
    """Data Access Object for Users & Authentication with Security Policy Enforcement"""
    
    @staticmethod
    def validate_password_policy(password):
        """
        Enforces password strength requirements for new accounts and updates.
        Requirements:
          - Minimum 12 characters
          - Cannot be in common weak/default password list
        """
        if not password or not isinstance(password, str):
            return False, "Password cannot be empty."
            
        if len(password) < 12:
            return False, "Password must be at least 12 characters in length."
            
        if password.lower() in DISALLOWED_WEAK_PASSWORDS:
            return False, "The chosen password is too common or known to be weak. Please choose a stronger passphrase."
            
        return True, ""
    
    @staticmethod
    def get_by_id(user_id):
        return fetch_one("SELECT * FROM users WHERE id = %s", (user_id,))
    
    @staticmethod
    def get_by_username(username):
        return fetch_one("SELECT * FROM users WHERE username = %s", (username,))
    
    @staticmethod
    def verify_password(stored_hash_or_plaintext, password):
        """Verifies password hash with backward compatibility for legacy users."""
        if not stored_hash_or_plaintext or not password:
            return False
        # If it's a werkzeug hash format (pbkdf2 / scrypt / argon2)
        if stored_hash_or_plaintext.startswith(('pbkdf2:', 'scrypt:', 'argon2:')):
            return check_password_hash(stored_hash_or_plaintext, password)
        # Legacy fallback comparison (upgraded upon successful login in authenticate)
        return stored_hash_or_plaintext == password

    @staticmethod
    def authenticate(username, password):
        """Authenticates user with generic failure handling and hash upgrading."""
        if not username or not password:
            return None
            
        user = UserModel.get_by_username(username)
        if not user:
            return None
            
        stored_hash = user.get('password_hash') or user.get('password')
        if UserModel.verify_password(stored_hash, password):
            # If user was using legacy plaintext, upgrade to secure hash immediately
            if not (stored_hash or '').startswith(('pbkdf2:', 'scrypt:', 'argon2:')):
                new_hash = generate_password_hash(password)
                execute_query("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user['id']))
            return user
        return None

    @staticmethod
    def create_user(username, password, role='moderator', email=None, enforce_policy=True):
        """Creates a new user record with password policy enforcement and secure hashing."""
        username = (username or '').strip()
        if not username:
            raise ValueError("Username cannot be empty.")
            
        if enforce_policy:
            is_valid, msg = UserModel.validate_password_policy(password)
            if not is_valid:
                raise ValueError(msg)
                
        hashed = generate_password_hash(password)
        user_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email) VALUES (%s, %s, %s, %s)",
            (username, hashed, role, email)
        )
        return user_id
