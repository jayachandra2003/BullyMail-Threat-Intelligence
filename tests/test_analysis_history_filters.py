import json
import pytest
from bullymail.models.analysis import AnalysisModel
from bullymail.models.user import UserModel
from bullymail.models.institution import InstitutionModel

@pytest.fixture
def test_filter_dataset(app):
    """Sets up records with diverse risk levels and incident statuses."""
    with app.app_context():
        # Create test admin user
        admin_id = UserModel.create_user(
            username="filter_test_admin",
            password="AdminPass123!",
            email="filter_admin@inst1.com",
            role="admin",
            status="ACTIVE",
            institution_id=1
        )

        records_data = [
            # 1. Critical + Pending
            {
                'email_subject': 'Critical Threat Pending',
                'email_from': 'user1@univ.edu',
                'email_to': 'target1@univ.edu',
                'email_text': 'I will severely harm you today.',
                'overall_risk_level': 'CRITICAL',
                'overall_confidence': 0.98,
                'threat_score': 0.98,
                'incident_status': 'PENDING_REVIEW',
                'bullying_analysis': {'is_bullying': True, 'confidence': 0.98}
            },
            # 2. High + Pending
            {
                'email_subject': 'High Risk Pending',
                'email_from': 'user2@univ.edu',
                'email_to': 'target2@univ.edu',
                'email_text': 'You are pathetic and useless.',
                'overall_risk_level': 'HIGH',
                'overall_confidence': 0.91,
                'threat_score': 0.91,
                'incident_status': 'PENDING_REVIEW',
                'bullying_analysis': {'is_bullying': True, 'confidence': 0.91}
            },
            # 3. High + Warning Sent
            {
                'email_subject': 'High Risk Warning Sent',
                'email_from': 'user3@univ.edu',
                'email_to': 'target3@univ.edu',
                'email_text': 'Do not show your face here again.',
                'overall_risk_level': 'HIGH',
                'overall_confidence': 0.89,
                'threat_score': 0.89,
                'incident_status': 'WARNING_SENT',
                'bullying_analysis': {'is_bullying': True, 'confidence': 0.89}
            },
            # 4. Medium + Warning Sent
            {
                'email_subject': 'Medium Risk Warning Sent',
                'email_from': 'user4@univ.edu',
                'email_to': 'target4@univ.edu',
                'email_text': 'You are terrible at your work.',
                'overall_risk_level': 'MEDIUM',
                'overall_confidence': 0.65,
                'threat_score': 0.65,
                'incident_status': 'WARNING_SENT',
                'bullying_analysis': {'is_bullying': True, 'confidence': 0.65}
            },
            # 5. Medium + Reviewed
            {
                'email_subject': 'Medium Risk Reviewed',
                'email_from': 'user5@univ.edu',
                'email_to': 'target5@univ.edu',
                'email_text': 'Nobody wants you on this team.',
                'overall_risk_level': 'MEDIUM',
                'overall_confidence': 0.60,
                'threat_score': 0.60,
                'incident_status': 'REVIEWED',
                'bullying_analysis': {'is_bullying': True, 'confidence': 0.60}
            },
            # 6. Medium + False Positive
            {
                'email_subject': 'Medium Risk False Positive',
                'email_from': 'user6@univ.edu',
                'email_to': 'target6@univ.edu',
                'email_text': 'Your research paper feedback was too harsh.',
                'overall_risk_level': 'MEDIUM',
                'overall_confidence': 0.55,
                'threat_score': 0.55,
                'incident_status': 'FALSE_POSITIVE',
                'bullying_analysis': {'is_bullying': False, 'confidence': 0.55}
            },
            # 7. Low / Clean + Pending
            {
                'email_subject': 'Low Clean Pending',
                'email_from': 'user7@univ.edu',
                'email_to': 'target7@univ.edu',
                'email_text': 'Meeting agenda attached for review.',
                'overall_risk_level': 'LOW',
                'overall_confidence': 0.12,
                'threat_score': 0.12,
                'incident_status': 'PENDING_REVIEW',
                'bullying_analysis': {'is_bullying': False, 'confidence': 0.12}
            },
            # 8. Low / Clean + False Positive
            {
                'email_subject': 'Low Clean False Positive',
                'email_from': 'user8@univ.edu',
                'email_to': 'target8@univ.edu',
                'email_text': 'Great job on the final exam.',
                'overall_risk_level': 'LOW',
                'overall_confidence': 0.05,
                'threat_score': 0.05,
                'incident_status': 'FALSE_POSITIVE',
                'bullying_analysis': {'is_bullying': False, 'confidence': 0.05}
            }
        ]

        ids = []
        for rec in records_data:
            aid = AnalysisModel.save_analysis(rec, institution_id=1, user_id=admin_id)
            ids.append(aid)

        return {'admin_id': admin_id, 'ids': ids}

def test_all_risk_levels_and_all_statuses(client, test_filter_dataset):
    """GET /api/analysis-history returns all records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    # At least our 8 inserted records
    assert len(data['history']) >= 8

def test_status_filter_pending(client, test_filter_dataset):
    """GET /api/analysis-history?status=pending returns only pending records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history?status=pending')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    for item in data['history']:
        assert item.get('incident_status') in ('PENDING_REVIEW', 'PENDING', None)

def test_status_filter_warning_sent(client, test_filter_dataset):
    """GET /api/analysis-history?status=warning_sent returns only warning sent records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history?status=warning_sent')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    for item in data['history']:
        assert item.get('incident_status') == 'WARNING_SENT'
    subjects = [item['email_subject'] for item in data['history']]
    assert 'High Risk Warning Sent' in subjects
    assert 'Medium Risk Warning Sent' in subjects

def test_status_filter_reviewed(client, test_filter_dataset):
    """GET /api/analysis-history?status=reviewed returns only reviewed records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history?status=reviewed')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    for item in data['history']:
        assert item.get('incident_status') == 'REVIEWED'
    subjects = [item['email_subject'] for item in data['history']]
    assert 'Medium Risk Reviewed' in subjects

def test_status_filter_false_positive(client, test_filter_dataset):
    """GET /api/analysis-history?status=false_positive returns only false positive records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history?status=false_positive')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    for item in data['history']:
        assert item.get('incident_status') == 'FALSE_POSITIVE'
    subjects = [item['email_subject'] for item in data['history']]
    assert 'Medium Risk False Positive' in subjects
    assert 'Low Clean False Positive' in subjects

def test_combined_high_risk_and_pending(client, test_filter_dataset):
    """GET /api/analysis-history?risk=HIGH&status=pending returns only HIGH risk pending records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history?risk=HIGH&status=pending')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    for item in data['history']:
        assert item.get('overall_risk_level') == 'HIGH'
        assert item.get('incident_status') in ('PENDING_REVIEW', 'PENDING', None)
    subjects = [item['email_subject'] for item in data['history']]
    assert 'High Risk Pending' in subjects
    assert 'High Risk Warning Sent' not in subjects
    assert 'Critical Threat Pending' not in subjects

def test_combined_medium_risk_and_warning_sent(client, test_filter_dataset):
    """GET /api/analysis-history?risk=MEDIUM&status=warning_sent returns only MEDIUM risk warning sent records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history?risk=MEDIUM&status=warning_sent')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    for item in data['history']:
        assert item.get('overall_risk_level') == 'MEDIUM'
        assert item.get('incident_status') == 'WARNING_SENT'
    subjects = [item['email_subject'] for item in data['history']]
    assert 'Medium Risk Warning Sent' in subjects
    assert 'High Risk Warning Sent' not in subjects

def test_combined_low_risk_and_false_positive(client, test_filter_dataset):
    """GET /api/analysis-history?risk=LOW&status=false_positive returns only LOW risk false positive records."""
    with client.session_transaction() as sess:
        sess['user_id'] = test_filter_dataset['admin_id']
        sess['username'] = 'filter_test_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/analysis-history?risk=LOW&status=false_positive')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    for item in data['history']:
        assert item.get('overall_risk_level') == 'LOW'
        assert item.get('incident_status') == 'FALSE_POSITIVE'
    subjects = [item['email_subject'] for item in data['history']]
    assert 'Low Clean False Positive' in subjects
    assert 'Medium Risk False Positive' not in subjects