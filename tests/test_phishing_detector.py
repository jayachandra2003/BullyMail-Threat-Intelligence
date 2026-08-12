import pytest
from bullymail.services.phishing_detector import PhishingDetector

def test_phishing_detection_credential_theft():
    detector = PhishingDetector()
    text = "Your account has been locked due to suspicious activity. Verify your password immediately within 24 hours or your account will be deleted."
    result = detector.analyze(text, email_subject="Urgent Security Alert")
    
    assert result['risk_level'] in ('HIGH', 'CRITICAL')
    assert result['confidence'] >= 0.70
    assert len(result['indicators']) >= 2

def test_phishing_detection_benign():
    detector = PhishingDetector()
    text = "Hi team, please find attached the meeting notes from yesterday's sync. Have a great weekend!"
    result = detector.analyze(text, email_subject="Weekly Notes")
    
    assert result['risk_level'] == 'LOW'
    assert result['confidence'] < 0.40

def test_phishing_sender_mismatch():
    detector = PhishingDetector()
    text = "Dear Customer, please review your invoice."
    result = detector.analyze(text, email_from="PayPal Security Team <secure-support129@gmail.com>")
    
    assert any(i['category'] == 'Sender Mismatch' for i in result['indicators'])
