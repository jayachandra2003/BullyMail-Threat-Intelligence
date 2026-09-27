"""
Unit tests for BrevoKeepAliveService
Verifies automated keep-alive requests, throttling, and state management.
"""
import io
import time
import json
import urllib.request
import urllib.error
import pytest
from bullymail.services.brevo_keepalive_service import BrevoKeepAliveService

def test_keepalive_not_configured(monkeypatch, tmp_path):
    """When BREVO_API_KEY is not configured, ping returns False with clean message."""
    monkeypatch.delenv("BREVO_API_KEY", raising=False)
    monkeypatch.delenv("SENDINBLUE_API_KEY", raising=False)

    svc = BrevoKeepAliveService()
    svc._state_file = tmp_path / '.brevo_state.json'

    ok, msg = svc.ping(force=True)
    assert ok is False
    assert "not configured" in msg

    status = svc.get_status()
    assert status['configured'] is False


def test_keepalive_successful_ping_updates_state(monkeypatch, tmp_path):
    """When BREVO_API_KEY is valid, ping executes GET /account and updates state."""
    monkeypatch.setenv("BREVO_API_KEY", "xkeysib-mock-valid-key")

    captured = {}

    class MockResponse:
        status = 200
        def read(self):
            return b'{"email": "admin@example.com", "plan": [{"type": "free"}]}'
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    def mock_urlopen(req, timeout=None):
        captured['url'] = req.full_url
        captured['headers'] = dict(req.headers)
        return MockResponse()

    monkeypatch.setattr(urllib.request, 'urlopen', mock_urlopen)

    svc = BrevoKeepAliveService()
    svc._state_file = tmp_path / '.brevo_state.json'

    ok, msg = svc.ping(force=True)
    assert ok is True
    assert "admin@example.com" in msg
    assert captured['url'] == 'https://api.brevo.com/v3/account'
    assert captured['headers']['Api-key'] == 'xkeysib-mock-valid-key'

    status = svc.get_status()
    assert status['configured'] is True
    assert status['last_status'] == 'SUCCESS'
    assert status['days_since_last_ping'] == 0.0
    assert status['expiry_days_remaining'] == 90.0


def test_keepalive_throttling_within_interval(monkeypatch, tmp_path):
    """Subsequent pings within interval_days are skipped unless force=True."""
    monkeypatch.setenv("BREVO_API_KEY", "xkeysib-mock-valid-key")

    svc = BrevoKeepAliveService()
    svc._state_file = tmp_path / '.brevo_state.json'

    # Save initial state with timestamp = 2 days ago
    two_days_ago = time.time() - (2 * 86400)
    svc._save_state(two_days_ago, 'SUCCESS', 'Account email: admin@example.com')

    call_count = 0
    def mock_urlopen(req, timeout=None):
        nonlocal call_count
        call_count += 1
        return None

    monkeypatch.setattr(urllib.request, 'urlopen', mock_urlopen)

    # Calling with 14-day interval should skip (only 2 days passed)
    ok, msg = svc.ping(force=False, interval_days=14)
    assert ok is True
    assert "skipped" in msg
    assert call_count == 0


def test_keepalive_http_error_graceful(monkeypatch, tmp_path):
    """HTTP errors from Brevo are caught, logged, and state is preserved without crashing."""
    monkeypatch.setenv("BREVO_API_KEY", "xkeysib-bad-key")

    def mock_urlopen(req, timeout=None):
        err_fp = io.BytesIO(b'{"code": "unauthorized"}')
        raise urllib.error.HTTPError(req.full_url, 401, 'Unauthorized', {}, err_fp)

    monkeypatch.setattr(urllib.request, 'urlopen', mock_urlopen)

    svc = BrevoKeepAliveService()
    svc._state_file = tmp_path / '.brevo_state.json'

    ok, msg = svc.ping(force=True)
    assert ok is False
    assert "401" in msg


def test_health_route_triggers_keepalive(client, monkeypatch):
    """Calling /health runs without error and invokes check_and_ping_async."""
    called = []

    from bullymail.services.brevo_keepalive_service import BrevoKeepAliveService
    monkeypatch.setattr(
        BrevoKeepAliveService,
        'check_and_ping_async',
        lambda self, *a, **k: called.append(True)
    )

    res = client.get('/health')
    assert res.status_code == 200
    assert res.get_json()['status'] == 'ok'
    assert len(called) == 1
