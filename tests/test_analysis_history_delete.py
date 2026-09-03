import json
import pytest
from bullymail.models.analysis import AnalysisModel
from bullymail.models.user import UserModel
from bullymail.models.institution import InstitutionModel
from bullymail.database.connection import fetch_one, execute_query

@pytest.fixture
def delete_test_env(app):
    """Sets up test users and sample analysis record with linked audit log and ingested message."""
    with app.app_context():
        # 1. Create admin and analyst users
        admin_id = UserModel.create_user(
            username="del_test_admin",
            password="AdminPass123!",
            email="del_admin@inst1.com",
            role="admin",
            status="ACTIVE",
            institution_id=1
        )
        analyst_id = UserModel.create_user(
            username="del_test_analyst",
            password="AnalystPass123!",
            email="del_analyst@inst1.com",
            role="analyst",
            status="ACTIVE",
            institution_id=1
        )

        # 2. Create email_config
        config_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, imap_server, smtp_server, status) VALUES (%s, %s, %s, %s, %s)",
            (1, "soc-test@inst1.com", "imap.test.com", "smtp.test.com", "active")
        )

        # 3. Create sample analysis record
        report_data = {
            'email_subject': 'Harassment Incident Case 901',
            'email_from': 'offender@test.edu',
            'email_to': 'victim@test.edu',
            'email_text': 'You will regret coming to class tomorrow.',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.95,
            'threat_score': 0.95,
            'incident_status': 'PENDING_REVIEW',
            'bullying_analysis': {'is_bullying': True, 'confidence': 0.95}
        }
        analysis_id = AnalysisModel.save_analysis(report_data, institution_id=1, user_id=admin_id, email_config_id=config_id)

        # 4. Create linked audit log
        execute_query(
            "INSERT INTO incident_audit_log (analysis_id, institution_id, admin_id, admin_username, action, reason) VALUES (%s, %s, %s, %s, %s, %s)",
            (analysis_id, 1, admin_id, "del_test_admin", "REVIEW_INCIDENT", "Verified hostile harassment")
        )

        # 5. Create linked ingested message to verify safe nullification
        execute_query(
            "INSERT INTO ingested_messages (institution_id, email_config_id, message_id_hash, processing_status, analysis_id) VALUES (%s, %s, %s, %s, %s)",
            (1, config_id, f"hash-del-{analysis_id}", "PROCESSED", analysis_id)
        )

        yield {
            'admin_id': admin_id,
            'analyst_id': analyst_id,
            'analysis_id': analysis_id,
            'config_id': config_id
        }

def test_delete_analysis_unauthenticated(client, delete_test_env):
    """Unauthenticated users cannot delete analysis records."""
    res = client.delete(f"/api/analysis/{delete_test_env['analysis_id']}")
    assert res.status_code == 401
    data = res.get_json()
    assert data['success'] is False

def test_delete_analysis_forbidden_for_analysts(client, delete_test_env):
    """Non-admin / regular analyst role cannot delete analysis records."""
    # Login as analyst
    client.post('/login', data={'username': 'del_test_analyst', 'password': 'AnalystPass123!'})

    res = client.delete(f"/api/analysis/{delete_test_env['analysis_id']}")
    assert res.status_code == 403
    data = res.get_json()
    assert data['success'] is False
    assert "Administrative privileges required" in data['error']

def test_delete_analysis_not_found(client, delete_test_env):
    """Deleting a non-existent analysis record returns 404."""
    client.post('/login', data={'username': 'del_test_admin', 'password': 'AdminPass123!'})

    res = client.delete("/api/analysis/99999999")
    assert res.status_code == 404
    data = res.get_json()
    assert data['success'] is False

def test_delete_analysis_success_and_safety(client, delete_test_env):
    """Admin can delete analysis, nullifies ingested message reference, and leaves other tables safe."""
    client.post('/login', data={'username': 'del_test_admin', 'password': 'AdminPass123!'})
    analysis_id = delete_test_env['analysis_id']

    # Execute DELETE
    res = client.delete(f"/api/analysis/{analysis_id}")
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True

    # 1. Verify analyzed_emails record is gone
    record = fetch_one("SELECT * FROM analyzed_emails WHERE id = %s", (analysis_id,))
    assert record is None

    # 2. Verify dependent audit log is cleaned up
    audit = fetch_one("SELECT * FROM incident_audit_log WHERE analysis_id = %s", (analysis_id,))
    assert audit is None

    # 3. Verify ingested message STILL EXISTS but analysis_id was nullified
    msg = fetch_one("SELECT * FROM ingested_messages WHERE message_id_hash = %s", (f"hash-del-{analysis_id}",))
    assert msg is not None
    assert msg.get('analysis_id') is None

    # 4. Verify users & institution are untouched
    user = fetch_one("SELECT * FROM users WHERE id = %s", (delete_test_env['admin_id'],))
    assert user is not None
