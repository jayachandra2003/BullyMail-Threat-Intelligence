import pytest
from bullymail.services.social_engineering import SocialEngineeringDetector

def test_social_engineering_coercion_and_authority():
    detector = SocialEngineeringDetector()
    text = "This is an official notice from the Office of the Dean. Immediate action needed: you will be expelled unless you respond within 2 hours."
    result = detector.analyze(text, subject="Urgent Notice")
    
    assert result['risk_level'] in ('HIGH', 'CRITICAL')
    tech_names = [t['name'] for t in result['techniques']]
    assert 'Authority Impersonation' in tech_names
    assert 'Fear, Intimidation & Coercion' in tech_names or 'Urgency & Time Pressure' in tech_names

def test_social_engineering_reward_lure():
    detector = SocialEngineeringDetector()
    text = "Congratulations! You have been awarded a grant of $5000 from the student foundation. Claim your prize immediately."
    result = detector.analyze(text)
    
    assert result['risk_level'] in ('MEDIUM', 'HIGH')
    assert any('Reward' in t['name'] for t in result['techniques'])
