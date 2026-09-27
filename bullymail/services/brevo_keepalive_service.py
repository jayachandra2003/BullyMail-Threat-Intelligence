"""
Brevo (Sendinblue) API Key Keep-Alive Service
Automatically executes periodic lightweight authenticated requests (GET /v3/account)
to prevent the API key from expiring due to Brevo's 90-day inactivity policy.
Consumes zero email credits and sends no emails.
"""
import os
import time
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from ..config import Config

logger = logging.getLogger('bullymail.services.brevo_keepalive')

class BrevoKeepAliveService:
    """
    Automated background heartbeat bot for Brevo API Key activity maintenance.
    """
    DEFAULT_INTERVAL_DAYS = 14  # Ping every 14 days (well within the 90-day expiry window)
    ACCOUNT_ENDPOINT = 'https://api.brevo.com/v3/account'

    def __init__(self):
        self._lock = threading.Lock()
        self._is_pinging = False
        self._state_file = Path(getattr(Config, 'UPLOAD_PATH', Path(__file__).resolve().parent.parent.parent / 'uploads')) / '.brevo_keepalive.json'

    def _get_api_key(self) -> str:
        """Retrieves configured Brevo API key from environment or Config."""
        return (
            os.environ.get('BREVO_API_KEY')
            or os.environ.get('SENDINBLUE_API_KEY')
            or getattr(Config, 'BREVO_API_KEY', None)
            or ''
        ).strip()

    def _load_state(self) -> dict:
        """Loads last ping metadata from disk cache."""
        try:
            if self._state_file.exists():
                with open(self._state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.debug(f"[BREVO_KEEPALIVE] Could not read state cache: {e}")
        return {'last_ping_timestamp': 0.0, 'last_status': 'NEVER_RUN'}

    def _save_state(self, timestamp: float, status: str, detail: str = ""):
        """Persists ping metadata to disk cache."""
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'last_ping_timestamp': timestamp,
                'last_ping_iso': datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                'last_status': status,
                'detail': detail
            }
            with open(self._state_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"[BREVO_KEEPALIVE] Could not save state cache: {e}")

    def ping(self, force: bool = False, interval_days: int = DEFAULT_INTERVAL_DAYS) -> tuple[bool, str]:
        """
        Executes a lightweight read-only authenticated GET request to Brevo.
        Resets the 90-day inactivity countdown on Brevo's servers.
        
        Args:
            force: If True, bypasses the interval throttling.
            interval_days: Minimum days to wait before sending another ping.
        Returns:
            tuple[bool, str]: (success, status_message)
        """
        api_key = self._get_api_key()
        if not api_key:
            return False, "Brevo API key is not configured."

        state = self._load_state()
        last_ts = state.get('last_ping_timestamp', 0.0)
        now = time.time()
        elapsed_seconds = now - last_ts
        min_seconds = interval_days * 86400

        if not force and elapsed_seconds < min_seconds and last_ts > 0:
            days_ago = round(elapsed_seconds / 86400, 1)
            return True, f"Keep-alive skipped: recent ping was {days_ago} days ago (interval is {interval_days} days)."

        with self._lock:
            if self._is_pinging:
                return True, "Keep-alive ping is already in progress."
            self._is_pinging = True

        try:
            import urllib.request
            import urllib.error

            logger.info("[BREVO_KEEPALIVE] Executing automated Brevo keep-alive activity ping...")
            req = urllib.request.Request(
                self.ACCOUNT_ENDPOINT,
                headers={
                    'api-key': api_key,
                    'Accept': 'application/json',
                    'User-Agent': 'BullyMail-Security-KeepAlive/2.0'
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode('utf-8'))
                    email = resp_data.get('email', 'unknown')
                    self._save_state(now, 'SUCCESS', f"Account email: {email}")
                    logger.info(f"[BREVO_KEEPALIVE] SUCCESS: Brevo API key keep-alive renewed. 90-day timer reset. Account: {email}")
                    return True, f"Brevo keep-alive ping successful (Account: {email}). 90-day activity window renewed."
                else:
                    msg = f"Unexpected response status from Brevo: {resp.status}"
                    logger.warning(f"[BREVO_KEEPALIVE] {msg}")
                    return False, msg
        except urllib.error.HTTPError as he:
            err_msg = f"HTTP Error {he.code}: {he.reason}"
            logger.error(f"[BREVO_KEEPALIVE] FAILED: {err_msg}")
            self._save_state(last_ts, 'FAILED', err_msg)
            return False, err_msg
        except Exception as ex:
            err_msg = str(ex)
            logger.error(f"[BREVO_KEEPALIVE] FAILED: {err_msg}")
            self._save_state(last_ts, 'FAILED', err_msg)
            return False, err_msg
        finally:
            with self._lock:
                self._is_pinging = False

    def check_and_ping_async(self, interval_days: int = DEFAULT_INTERVAL_DAYS, force: bool = False):
        """
        Asynchronously checks if a keep-alive ping is due and dispatches it in a background daemon thread.
        Never blocks the caller (e.g. web requests or health check probes).
        """
        api_key = self._get_api_key()
        if not api_key:
            return

        state = self._load_state()
        last_ts = state.get('last_ping_timestamp', 0.0)
        elapsed = time.time() - last_ts
        min_seconds = interval_days * 86400

        if force or elapsed >= min_seconds or last_ts == 0.0:
            thread = threading.Thread(
                target=self.ping,
                args=(force, interval_days),
                name="BrevoKeepAliveThread",
                daemon=True
            )
            thread.start()

    def get_status(self) -> dict:
        """Returns structured diagnostic status for admin monitoring."""
        api_key = self._get_api_key()
        state = self._load_state()
        last_ts = state.get('last_ping_timestamp', 0.0)
        now = time.time()
        days_since = round((now - last_ts) / 86400, 1) if last_ts > 0 else None

        return {
            'configured': bool(api_key),
            'last_ping_iso': state.get('last_ping_iso'),
            'days_since_last_ping': days_since,
            'last_status': state.get('last_status', 'NEVER_RUN'),
            'detail': state.get('detail', ''),
            'expiry_days_remaining': max(0, round(90 - (days_since or 0), 1)) if days_since is not None else 90
        }

brevo_keepalive_service = BrevoKeepAliveService()
