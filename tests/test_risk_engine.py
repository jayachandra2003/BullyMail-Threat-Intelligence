import pytest
from bullymail.services.risk_engine import UnifiedRiskEngine

def test_unified_risk_engine_clean_email():
    engine = UnifiedRiskEngine()
    report = engine.analyze_email(
        email_text="Hi Professor, could you please confirm the office hours for tomorrow?",
        email_subject="Office Hours Question",
        email_from="student@university.edu"
    )
    
    assert report['overall_risk_level'] == 'LOW'
    assert report['overall_confidence'] >= 0.90
    assert report['bullying_analysis']['is_bullying'] is False
    assert report['phishing_analysis']['risk_level'] == 'LOW'
    assert report['url_analysis']['total_urls'] == 0
    assert len(report['evidence']) == 0

def test_unified_risk_engine_single_insult_medium_risk():
    engine = UnifiedRiskEngine()
    report = engine.analyze_email(
        email_text="You are an idiot.",
        email_subject="Quick Message",
        email_from="peer@university.edu"
    )
    
    assert report['bullying_analysis']['is_bullying'] is True
    assert report['bullying_analysis']['severity'] == 'MEDIUM'
    assert report['overall_risk_level'] == 'MEDIUM'
    assert len(report['evidence']) >= 1

def test_unified_risk_engine_multiple_insults_high_risk():
    engine = UnifiedRiskEngine()
    report = engine.analyze_email(
        email_text="You are an idiot and everyone hates you. You should leave the course.",
        email_subject="Regarding your participation",
        email_from="group@university.edu"
    )
    
    assert report['bullying_analysis']['is_bullying'] is True
    assert report['bullying_analysis']['severity'] == 'HIGH'
    assert report['overall_risk_level'] == 'HIGH'
    assert len(report['evidence']) >= 1

def test_unified_risk_engine_threat_and_insult_critical_risk():
    engine = UnifiedRiskEngine()
    report = engine.analyze_email(
        email_text="You are completely useless. If you don't stop, I will hurt you.",
        email_subject="Warning",
        email_from="threat@anonymous.com"
    )
    
    assert report['bullying_analysis']['is_bullying'] is True
    assert report['bullying_analysis']['severity'] == 'CRITICAL'
    assert report['overall_risk_level'] == 'CRITICAL'
    assert len(report['evidence']) >= 1

def test_unified_risk_engine_severe_abusive_email():
    engine = UnifiedRiskEngine()
    report = engine.analyze_email(
        email_text="motherfucker",
        email_subject="Angry Notice",
        email_from="anonymous@mailer.com"
    )
    
    assert report['overall_risk_level'] in ('HIGH', 'CRITICAL')
    assert report['bullying_analysis']['is_bullying'] is True
    assert report['bullying_analysis']['confidence'] >= 0.70
    assert len(report['evidence']) >= 1

def test_unified_risk_engine_critical_multi_vector():
    engine = UnifiedRiskEngine()
    report = engine.analyze_email(
        email_text="URGENT: Your account has been locked. Verify your password at http://192.168.1.50/login or you will be expelled immediately.",
        email_subject="Urgent Security Alert",
        email_from="IT Security <admin@paypa1-security.com>",
        attachments=[{'filename': 'update_patch.exe', 'content': b'MZ\x90\x00'}]
    )
    
    assert report['overall_risk_level'] in ('HIGH', 'CRITICAL')
    assert len(report['evidence']) >= 2
    assert report['url_analysis']['suspicious_count'] >= 1
