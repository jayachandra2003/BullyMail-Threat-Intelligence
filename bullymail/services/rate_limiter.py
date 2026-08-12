import time
from threading import Lock

class LoginRateLimiter:
    """
    Thread-safe in-memory rate limiter and brute-force defense for authentication.
    
    Policy:
      - 5 failed login attempts within a 5-minute (300s) sliding window.
      - Triggers a 15-minute (900s) temporary lockout for the offending IP and Target Username.
      - Successful authentication resets the failure count for that IP & Username.
      - Sliding window ensures failures naturally expire after 5 minutes of inactivity.
    """
    
    def __init__(self, max_attempts=5, window_seconds=300, lockout_seconds=900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures = {}  # key -> list of float timestamps
        self._lockouts = {}  # key -> float timestamp when lockout expires
        self._lock = Lock()

    def _get_keys(self, ip, username):
        keys = []
        if ip:
            keys.append(f"ip:{ip.strip()}")
        if username:
            keys.append(f"user:{username.lower().strip()}")
        return keys

    def _clean_expired(self, now):
        """Purges old timestamps and expired lockouts to prevent memory leaks."""
        for key in list(self._failures.keys()):
            self._failures[key] = [t for t in self._failures[key] if now - t < self.window_seconds]
            if not self._failures[key]:
                del self._failures[key]
                
        for key in list(self._lockouts.keys()):
            if now >= self._lockouts[key]:
                del self._lockouts[key]

    def is_locked(self, ip, username=None):
        """
        Checks if either the IP address or username is currently in a temporary lockout.
        Returns: (is_locked: bool, retry_after_seconds: int)
        """
        now = time.time()
        with self._lock:
            self._clean_expired(now)
            keys = self._get_keys(ip, username)
            
            for key in keys:
                if key in self._lockouts:
                    expiry = self._lockouts[key]
                    if now < expiry:
                        remaining = int(expiry - now) + 1
                        return True, remaining
                    else:
                        del self._lockouts[key]
                        
        return False, 0

    def record_failure(self, ip, username=None):
        """
        Records a failed authentication attempt.
        Locks out the IP and username if max_attempts is exceeded within window_seconds.
        """
        now = time.time()
        with self._lock:
            self._clean_expired(now)
            keys = self._get_keys(ip, username)
            
            for key in keys:
                if key not in self._failures:
                    self._failures[key] = []
                self._failures[key].append(now)
                
                if len(self._failures[key]) >= self.max_attempts:
                    self._lockouts[key] = now + self.lockout_seconds
                    del self._failures[key]

    def record_success(self, ip, username=None):
        """Resets the failure counters upon successful authentication."""
        with self._lock:
            keys = self._get_keys(ip, username)
            for key in keys:
                self._failures.pop(key, None)
                self._lockouts.pop(key, None)

    def reset(self):
        """Clears all tracking state (used in automated test fixtures)."""
        with self._lock:
            self._failures.clear()
            self._lockouts.clear()

# Global rate limiter instance for the application
login_rate_limiter = LoginRateLimiter()
