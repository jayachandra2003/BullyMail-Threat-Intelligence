import os
import base64
from cryptography.fernet import Fernet, InvalidToken

class CryptoService:
    """
    Fernet Authenticated Encryption Service (AES-128-CBC + HMAC-SHA256).
    Enforces strict Fernet key validation (32 bytes, url-safe base64).
    Never silently pads, truncates, hashes, or transforms invalid keys.
    """
    _FERNET_INSTANCE = None
    _CACHED_KEY_BYTES = None

    @classmethod
    def generate_valid_key(cls) -> str:
        """Generates a valid 32-byte url-safe base64-encoded Fernet key for production configuration."""
        return Fernet.generate_key().decode('utf-8')

    @classmethod
    def _get_fernet(cls):
        """Resolves active Fernet cipher instance from environment key or Config, validating strict key format."""
        raw_key = os.environ.get('BULLYMAIL_MASTER_KEY')
        if not raw_key:
            try:
                from flask import current_app
                if current_app and current_app.config:
                    raw_key = current_app.config.get('BULLYMAIL_MASTER_KEY')
            except Exception:
                pass
        
        if not raw_key:
            from ..config import Config
            raw_key = getattr(Config, 'BULLYMAIL_MASTER_KEY', None)

        if not raw_key or not str(raw_key).strip():
            raise ValueError(
                "BULLYMAIL_MASTER_KEY is not configured in environment or Flask config. "
                "Generate a valid key using `from cryptography.fernet import Fernet; Fernet.generate_key().decode()`."
            )

        if isinstance(raw_key, str):
            raw_key_bytes = raw_key.strip().encode('utf-8')
        else:
            raw_key_bytes = raw_key

        # Dynamic Key Invalidation Cache Check (Prevents Stale Keys)
        if cls._FERNET_INSTANCE is not None and cls._CACHED_KEY_BYTES == raw_key_bytes:
            return cls._FERNET_INSTANCE

        # Strict Key Validation: MUST be a valid Fernet key. NEVER pad, truncate, or transform.
        try:
            instance = Fernet(raw_key_bytes)
            cls._FERNET_INSTANCE = instance
            cls._CACHED_KEY_BYTES = raw_key_bytes
            return cls._FERNET_INSTANCE
        except Exception as err:
            cls._FERNET_INSTANCE = None
            cls._CACHED_KEY_BYTES = None
            raise ValueError(
                f"BULLYMAIL_MASTER_KEY is invalid: {str(err)}. "
                "Must be a 32-byte url-safe base64-encoded key generated via Fernet.generate_key()."
            )

    @classmethod
    def reset_instance(cls):
        """Resets cached Fernet instance and key tracking."""
        cls._FERNET_INSTANCE = None
        cls._CACHED_KEY_BYTES = None

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        """Encrypts a plaintext string into a Base64 Fernet token."""
        if not plaintext or not isinstance(plaintext, str):
            return ""
        fernet = cls._get_fernet()
        token = fernet.encrypt(plaintext.encode('utf-8'))
        return token.decode('utf-8')

    @classmethod
    def decrypt(cls, ciphertext: str) -> str:
        """Decrypts a Fernet token back into plaintext. Raises ValueError if invalid key or corrupted token."""
        if not ciphertext or not isinstance(ciphertext, str):
            return ""
        fernet = cls._get_fernet()
        try:
            decrypted_bytes = fernet.decrypt(ciphertext.encode('utf-8'))
            decrypted_str = decrypted_bytes.decode('utf-8').strip()
            if (decrypted_str.startswith('"') and decrypted_str.endswith('"')) or (decrypted_str.startswith("'") and decrypted_str.endswith("'")):
                decrypted_str = decrypted_str[1:-1].strip()
            return decrypted_str
        except (InvalidToken, Exception) as err:
            raise ValueError(f"Decryption failed: Invalid master key or corrupted ciphertext. ({type(err).__name__})")

    @classmethod
    def is_encrypted(cls, text: str) -> bool:
        """
        Determines whether a credential string is formatted as a Fernet ciphertext token.
        Fernet tokens structurally begin with 'gAAAAA' (version byte 0x80 + timestamp 0x00...).
        Identifies ciphertexts structurally regardless of key state to prevent accidental re-encryption.
        """
        if not text or not isinstance(text, str):
            return False
        return text.startswith('gAAAAA')

    @classmethod
    def migrate_credential(cls, text: str) -> str:
        """Idempotently encrypts plaintext credentials while preserving already-encrypted tokens."""
        if not text or not isinstance(text, str):
            return ""
        if cls.is_encrypted(text):
            return text  # Already encrypted (prevents double encryption!)
        return cls.encrypt(text)
