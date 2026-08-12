import pytest
from bullymail.services.url_analyzer import URLAnalyzer

def test_extract_urls():
    analyzer = URLAnalyzer()
    text = "Visit our portal at https://university.edu/login or check http://192.168.1.100/admin for updates."
    urls = analyzer.extract_urls(text)
    assert len(urls) == 2

def test_ip_address_url():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_url("http://192.168.1.1/login/verify")
    assert result['is_ip'] is True
    assert result['risk_level'] in ('SUSPICIOUS', 'HIGH_RISK')

def test_shortened_url_classification():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_url("https://bit.ly/3xX9Yz")
    assert result['is_shortened'] is True
    assert result['risk_level'] == 'SUSPICIOUS'  # NOT automatically malicious

def test_safe_academic_url():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_url("https://cs.stanford.edu/research/papers")
    assert result['risk_level'] == 'SAFE'
