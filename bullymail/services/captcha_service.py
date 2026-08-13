import json
import urllib.request
import urllib.parse
from ..config import Config

class CaptchaService:
    """
    Bot and abuse mitigation service supporting Cloudflare Turnstile and hCaptcha.
    Configurable via environment variables (CAPTCHA_ENABLED, CAPTCHA_SECRET_KEY, CAPTCHA_PROVIDER).
    """

    VERIFY_URLS = {
        'turnstile': 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        'hcaptcha': 'https://hcaptcha.com/siteverify'
    }

    @classmethod
    def is_enabled(cls):
        """Returns True if CAPTCHA verification is globally enabled and a secret key is present."""
        return Config.CAPTCHA_ENABLED and bool(Config.CAPTCHA_SECRET_KEY)

    @classmethod
    def verify_token(cls, token, client_ip=None):
        """
        Validates the client response token against the configured CAPTCHA provider.
        Returns: (is_valid: bool, error_message: str)
        """
        # If CAPTCHA is not enabled in config, pass automatically
        if not cls.is_enabled():
            return True, ""

        if not token or not isinstance(token, str) or not token.strip():
            return False, "CAPTCHA verification required. Please complete the security challenge."

        token = token.strip()
        provider = Config.CAPTCHA_PROVIDER.lower()
        secret_key = Config.CAPTCHA_SECRET_KEY
        verify_url = cls.VERIFY_URLS.get(provider, cls.VERIFY_URLS['turnstile'])

        # Allow test mock tokens in testing/development
        if Config.TESTING or Config.DEBUG:
            if token in ('mock_pass_token', 'test_captcha_token_valid'):
                return True, ""
            if token == 'mock_fail_token':
                return False, "Security challenge verification failed."

        try:
            payload = {
                'secret': secret_key,
                'response': token
            }
            if client_ip:
                payload['remoteip'] = client_ip

            data = urllib.parse.urlencode(payload).encode('utf-8')
            req = urllib.request.Request(
                verify_url,
                data=data,
                headers={'User-Agent': 'BullyMail-Security-Engine/2.0', 'Content-Type': 'application/x-www-form-urlencoded'}
            )

            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode('utf-8'))
                if result.get('success'):
                    return True, ""
                else:
                    err_codes = result.get('error-codes', [])
                    return False, f"CAPTCHA validation failed ({', '.join(err_codes) if err_codes else 'invalid response'})."
        except Exception:
            # Fallback fail-closed in production if validation service unreachable, or log securely
            return False, "Unable to verify security challenge at this time. Please retry."
