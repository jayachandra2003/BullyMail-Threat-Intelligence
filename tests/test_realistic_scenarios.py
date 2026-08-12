import pytest
import io
from bullymail.services.risk_engine import UnifiedRiskEngine

@pytest.fixture
def engine():
    return UnifiedRiskEngine()

# 1. Normal academic email
def test_scenario_1_normal_academic_email(engine):
    report = engine.analyze_email(
        email_subject="CS301 Assignment 2 Guidelines",
        email_from="professor.smith@harvard.edu",
        email_text="Dear Students, the guidelines for Assignment 2 on Graph Algorithms have been posted on the portal. Office hours are on Thursday at 2 PM."
    )
    assert report['overall_risk_level'] == 'LOW'
    assert report['overall_confidence'] >= 0.90
    assert report['bullying_analysis']['is_bullying'] is False
    assert len(report['bullying_analysis']['rule_based_matches']) == 0
    assert report['phishing_analysis']['risk_level'] == 'LOW'
    assert len(report['evidence']) == 0

# 2. Bullying email
def test_scenario_2_bullying_email(engine):
    report = engine.analyze_email(
        email_subject="Your Disappointing Performance",
        email_from="advisor@university.edu",
        email_text="Your recent submission is a complete failure and proves you cannot do anything right. You are a useless student and you should quit this program."
    )
    assert report['bullying_analysis']['is_bullying'] is True
    assert report['overall_risk_level'] in ('HIGH', 'CRITICAL')
    assert len(report['bullying_analysis']['rule_based_matches']) >= 2

# 3. Phishing email
def test_scenario_3_phishing_email(engine):
    report = engine.analyze_email(
        email_subject="Urgent: Account Suspension Alert",
        email_from="IT Helpdesk <support-desk@gmail.com>",
        email_text="Unusual sign-in activity detected on your student portal. You must verify your password within 24 hours to prevent permanent account deactivation."
    )
    assert report['phishing_analysis']['risk_level'] in ('HIGH', 'CRITICAL')
    assert report['overall_risk_level'] in ('HIGH', 'CRITICAL')

# 4. Fake login link
def test_scenario_4_fake_login_link(engine):
    report = engine.analyze_email(
        email_subject="Important Security Update",
        email_from="Security Office",
        email_text="Please sign in to update your credentials at http://paypa1.com/login/auth to secure your account."
    )
    assert report['url_analysis']['suspicious_count'] >= 1
    assert report['domain_analysis']['is_suspicious'] is True

# 5. Shortened URL
def test_scenario_5_shortened_url(engine):
    report = engine.analyze_email(
        email_subject="Project Documentation",
        email_from="colleague@university.edu",
        email_text="Here is the link to the study resources: https://bit.ly/3xX9Yz for your review."
    )
    # Shortened URL should be flagged as SUSPICIOUS, not immediately MALICIOUS
    assert report['url_analysis']['urls'][0]['is_shortened'] is True
    assert report['url_analysis']['urls'][0]['risk_level'] == 'SUSPICIOUS'

# 6. Suspicious attachment
def test_scenario_6_suspicious_attachment(engine):
    report = engine.analyze_email(
        email_subject="Invoice Attached",
        email_from="billing@vendor.com",
        email_text="Please find your overdue invoice attached.",
        attachments=[{'filename': 'invoice_receipt.pdf.exe', 'content': b'MZ\x90\x00BinaryPayload'}]
    )
    assert report['malware_analysis']['risk_level'] in ('HIGH_RISK', 'MALICIOUS')
    assert report['overall_risk_level'] in ('HIGH', 'CRITICAL')

# 7. Social engineering email
def test_scenario_7_social_engineering_email(engine):
    report = engine.analyze_email(
        email_subject="Notice from the Dean's Office",
        email_from="Dean Office",
        email_text="Immediate action needed: You will be expelled and reported to campus police unless you submit your response without delay."
    )
    assert report['social_eng_analysis']['risk_level'] in ('HIGH', 'CRITICAL')
    assert len(report['social_eng_analysis']['techniques']) >= 1

# 8. Email with suspicious image
def test_scenario_8_email_with_suspicious_image(engine):
    try:
        from PIL import Image
        img = Image.new('RGB', (50, 50), color='red')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='JPEG')
        
        report = engine.analyze_email(
            email_subject="Screenshot",
            email_from="user@site.com",
            email_text="Please check this image.",
            images=[{'filename': 'screenshot.jpg', 'content': img_bytes.getvalue()}]
        )
        assert 'image_analysis' in report
        assert report['image_analysis']['total_images'] == 1
    except ImportError:
        pass

# 9. Completely safe email
def test_scenario_9_completely_safe_email(engine):
    report = engine.analyze_email(
        email_subject="Happy Holidays",
        email_from="dean.faculty@university.edu",
        email_text="Wishing all students and faculty a restful and happy winter break. Campus offices will reopen on January 5th."
    )
    assert report['overall_risk_level'] == 'LOW'
    assert report['overall_confidence'] >= 0.90
    assert report['threat_score'] < 0.20
    assert report['bullying_analysis']['is_bullying'] is False
    assert len(report['bullying_analysis']['rule_based_matches']) == 0
    assert report['phishing_analysis']['risk_level'] == 'LOW'
    assert len(report['evidence']) == 0
