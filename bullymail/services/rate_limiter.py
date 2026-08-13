import time
from threading import Lock

class AuthRateLimiter:
    """
    Thread-safe in-memory sliding-window rate limiter & brute-force defense
    covering all authentication lifecycle endpoints (Signup, Login, Verification, Reset).
    
    Default Endpoint Policies:
      - 'login': 5 failed attempts per 300s window -> 900s temporary lockout.
      - 'signup': 5 registration attempts per 600s window per IP.
      - 'forgot_password': 5 requests per 900s window per IP/email.
      - 'reset_password': 5 attempts per 900s window per IP/email.
      - 'verify_email': 10 verification attempts per 900s window per IP.
      - 'resend_verification': 3 requests per 900s window per IP/email.
    """

    def __init__(self, max_attempts=5, window_seconds=300, lockout_seconds=900, captcha_threshold=3):
        self._failures = {}   # key -> list of float timestamps
        self._lockouts = {}   # key -> float timestamp when lockout expires
        self._lock = Lock()
        self.DEFAULT_POLICIES = {
            'login': {'max_attempts': max_attempts, 'window_seconds': window_seconds, 'lockout_seconds': lockout_seconds, 'captcha_threshold': captcha_threshold},
            'signup': {'max_attempts': 5, 'window_seconds': 600, 'lockout_seconds': 600, 'captcha_threshold': 3},
            'forgot_password': {'max_attempts': 5, 'window_seconds': 900, 'lockout_seconds': 900, 'captcha_threshold': 3},
            'reset_password': {'max_attempts': 5, 'window_seconds': 900, 'lockout_seconds': 900, 'captcha_threshold': 3},
            'verify_email': {'max_attempts': 10, 'window_seconds': 900, 'lockout_seconds': 900, 'captcha_threshold': 5},
            'resend_verification': {'max_attempts': 3, 'window_seconds': 900, 'lockout_seconds': 900, 'captcha_threshold': 2}
        }

    def _get_keys(self, action, ip, identifier=None):
        keys = []
        if ip:
            clean_ip = ip.strip()
            keys.append(f"{action}:ip:{clean_ip}")
        if identifier:
            clean_id = identifier.lower().strip()
            keys.append(f"{action}:id:{clean_id}")
        return keys

    def _clean_expired(self, now, action='login'):
        policy = self.DEFAULT_POLICIES.get(action, self.DEFAULT_POLICIES['login'])
        window = policy['window_seconds']
        
        for key in list(self._failures.keys()):
            if key.startswith(f"{action}:"):
                self._failures[key] = [t for t in self._failures[key] if now - t < window]
                if not self._failures[key]:
                    del self._failures[key]
                    
        for key in list(self._lockouts.keys()):
            if key.startswith(f"{action}:") and now >= self._lockouts[key]:
                del self._lockouts[key]

    def is_locked(self, ip, identifier=None, action='login'):
        """
        Checks if either the IP address or identifier is currently in a temporary lockout for action.
        Returns: (is_locked: bool, retry_after_seconds: int)
        """
        now = time.time()
        with self._lock:
            self._clean_expired(now, action)
            keys = self._get_keys(action, ip, identifier)
            
            for key in keys:
                if key in self._lockouts:
                    expiry = self._lockouts[key]
                    if now < expiry:
                        remaining = int(expiry - now) + 1
                        return True, remaining
                    else:
                        del self._lockouts[key]
                        
        return False, 0

    def requires_captcha(self, ip, identifier=None, action='login'):
        """
        Returns True if the failure count has crossed the CAPTCHA challenge threshold.
        """
        policy = self.DEFAULT_POLICIES.get(action, self.DEFAULT_POLICIES['login'])
        threshold = policy.get('captcha_threshold', 3)
        now = time.time()
        with self._lock:
            self._clean_expired(now, action)
            keys = self._get_keys(action, ip, identifier)
            for key in keys:
                if len(self._failures.get(key, [])) >= threshold:
                    return True
        return False

    def record_failure(self, ip, identifier=None, action='login'):
        """
        Records a failed attempt for an action. Locks out keys if max_attempts is reached.
        """
        policy = self.DEFAULT_POLICIES.get(action, self.DEFAULT_POLICIES['login'])
        max_attempts = policy['max_attempts']
        lockout_sec = policy['lockout_seconds']
        
        now = time.time()
        with self._lock:
            self._clean_expired(now, action)
            keys = self._get_keys(action, ip, identifier)
            
            for key in keys:
                if key not in self._failures:
                    self._failures[key] = []
                self._failures[key].append(now)
                
                if len(self._failures[key]) >= max_attempts:
                    self._lockouts[key] = now + lockout_sec
                    del self._failures[key]

    def record_success(self, ip, identifier=None, action='login'):
        """Resets the failure counters upon successful action."""
        with self._lock:
            keys = self._get_keys(action, ip, identifier)
            for key in keys:
                self._failures.pop(key, None)
                self._lockouts.pop(key, None)

    def reset(self):
        """Clears all tracking state (used in automated test fixtures)."""
        with self._lock:
            self._failures.clear()
            self._lockouts.clear()

# Backward compatibility alias for legacy imports
LoginRateLimiter = AuthRateLimiter

# Global rate limiter instance for the application
auth_rate_limiter = AuthRateLimiter()
login_rate_limiter = auth_rate_limiter  # Backward compatibility singleton alias
