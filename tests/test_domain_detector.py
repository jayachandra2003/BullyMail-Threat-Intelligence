import pytest
from bullymail.services.domain_detector import DomainDetector

def test_legitimate_domain():
    detector = DomainDetector()
    res = detector.check_domain("https://www.paypal.com/signin")
    assert res['is_suspicious'] is False

def test_homoglyph_substitution_domain():
    detector = DomainDetector()
    res = detector.check_domain("https://paypa1.com/login")
    assert res['is_suspicious'] is True
    assert res['impersonated_brand'] == 'PayPal'

def test_brand_embedding_subdomain():
    detector = DomainDetector()
    res = detector.check_domain("https://paypal-security-verification.net/auth")
    assert res['is_suspicious'] is True
    assert 'PayPal' in res.get('impersonated_brand', '')
