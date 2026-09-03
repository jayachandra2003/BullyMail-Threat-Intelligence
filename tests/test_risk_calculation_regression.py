import pytest
from bullymail.services.risk_engine import UnifiedRiskEngine
from bullymail.services.bullying_detector import BullyingDetector
from bullymail.models.analysis import AnalysisModel
from bullymail.models.user import UserModel

@pytest.fixture
def risk_engine():
    return UnifiedRiskEngine()

@pytest.fixture
def bullying_detector():
    return BullyingDetector()

def test_regression_threatening_email_is_not_low_risk(risk_engine):
    """REGRESSION TEST: 'You will be killed' must be detected as CRITICAL threat, NOT LOW RISK."""
    res = risk_engine.analyze_email(
        email_text="You will be killed",
        email_subject="You will be killed"
    )

    assert res['overall_risk_level'] in ('CRITICAL', 'HIGH')
    assert res['overall_risk_level'] != 'LOW'
    assert res['threat_score'] >= 0.88
    assert res['bullying_analysis']['is_bullying'] is True
    assert res['bullying_analysis']['severity'] in ('CRITICAL', 'HIGH')

def test_regression_passive_and_modal_violence_threats(bullying_detector):
    """Verifies that passive and modal violent death threats are caught by Tier 1 physical threat detector."""
    threat_cases = [
        "You will be killed",
        "You are going to be killed",
        "You will be murdered",
        "You will die for what you did",
        "I will destroy you",
        "Someone will kill you"
    ]

    for text in threat_cases:
        pred = bullying_detector.predict(text, email_subject="Urgent Notice")
        assert pred['is_bullying'] is True, f"Failed to detect physical threat in: {text}"
        assert pred['severity'] == 'CRITICAL', f"Expected CRITICAL severity for: {text}"
        assert pred['confidence'] >= 0.90

def test_regression_benign_email_remains_low_risk_with_zero_threat_score(risk_engine):
    """Verifies that legitimate benign business/academic email remains LOW risk with 0.0 threat score."""
    benign_text = "Hello, please find the meeting notes attached. Thank you."
    res = risk_engine.analyze_email(
        email_text=benign_text,
        email_subject="Meeting Agenda & Notes"
    )

    assert res['overall_risk_level'] == 'LOW'
    assert res['threat_score'] == 0.0
    assert res['bullying_analysis']['is_bullying'] is False
    assert res['bullying_analysis']['severity'] == 'LOW'
    assert res['overall_confidence'] >= 0.90

def test_regression_saved_analysis_retrieval_does_not_corrupt_threat_score(app, client):
    """Verifies that DB persistence and /api/analysis/<id> endpoint do not overwrite 0.0 threat score with 0.95 confidence."""
    with app.app_context():
        admin_id = UserModel.create_user(
            username="regr_admin",
            password="AdminPass123!",
            email="regr_admin@inst1.com",
            role="admin",
            status="ACTIVE",
            institution_id=1
        )

        engine = UnifiedRiskEngine()

        # 1. Threat email analysis
        threat_report = engine.analyze_email("You will be killed", email_subject="You will be killed")
        threat_id = AnalysisModel.save_analysis(threat_report, institution_id=1, user_id=admin_id)

        # 2. Benign email analysis
        benign_report = engine.analyze_email("Meeting notes attached.", email_subject="Meeting Notes")
        benign_id = AnalysisModel.save_analysis(benign_report, institution_id=1, user_id=admin_id)

    with client.session_transaction() as sess:
        sess['user_id'] = admin_id
        sess['username'] = 'regr_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    # Check threat record via API
    res_threat = client.get(f'/api/analysis/{threat_id}')
    assert res_threat.status_code == 200
    threat_data = res_threat.get_json()['analysis']
    assert threat_data['overall_risk_level'] in ('CRITICAL', 'HIGH')
    assert threat_data['threat_score'] >= 0.88
    assert threat_data['bullying_analysis']['is_bullying'] is True

    # Check benign record via API
    res_benign = client.get(f'/api/analysis/{benign_id}')
    assert res_benign.status_code == 200
    benign_data = res_benign.get_json()['analysis']
    assert benign_data['overall_risk_level'] == 'LOW'
    assert benign_data['threat_score'] == 0.0, "Benign threat score must be 0.0, not overwritten with overall_confidence!"
    assert benign_data['bullying_analysis']['is_bullying'] is False