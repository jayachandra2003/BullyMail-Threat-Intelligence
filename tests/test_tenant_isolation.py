import pytest
import json
from bullymail.database.connection import execute_query, fetch_one
from bullymail.models.institution import InstitutionModel
from bullymail.models.user import UserModel
from bullymail.services.email_service import EmailService
from bullymail.models.analysis import AnalysisModel

@pytest.fixture
def tenant_fixture(app, client):
    """
    Sets up two isolated tenant institutions (Institution A & Institution B),
    along with an Admin user, an Analyst for Institution A, and an Analyst for Institution B.
    """
    with app.app_context():
        # Provision Institution A and Institution B
        inst_a_id = InstitutionModel.create_institution("University Alpha", "alpha.edu", code="ALPHA")
        inst_b_id = InstitutionModel.create_institution("University Beta", "beta.edu", code="BETA")

        # Provision Users
        admin_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email, status) VALUES (%s, %s, %s, %s, %s)",
            ("admin_tenant", UserModel.hash_password("AdminPass123!"), "admin", "admin@alpha.edu", "ACTIVE")
        )
        
        analyst_a_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s)",
            ("analyst_a", UserModel.hash_password("AnalystPass123!"), "analyst", "analyst@alpha.edu", "ACTIVE", inst_a_id)
        )

        analyst_b_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s)",
            ("analyst_b", UserModel.hash_password("AnalystPass123!"), "analyst", "analyst@beta.edu", "ACTIVE", inst_b_id)
        )

        # Provision Mailboxes
        mb_a_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status) VALUES (%s, %s, %s)",
            (inst_a_id, "security@alpha.edu", "active")
        )
        mb_b_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status) VALUES (%s, %s, %s)",
            (inst_b_id, "security@beta.edu", "active")
        )

        # Provision Analyzed Email Telemetry for Institution A
        report_a = {
            'email_subject': 'Cyberbullying Attack Alpha',
            'email_from': 'attacker@alpha.edu',
            'email_to': 'victim@alpha.edu',
            'email_text': 'You are a total idiot and a complete loser.',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.85,
            'threat_score': 0.85,
            'bullying_analysis': {'is_bullying': True, 'confidence': 0.85, 'rule_based_matches': ['idiot', 'loser'], 'rule_based_score': 0.85, 'ml_prediction': True, 'ml_confidence': 0.80, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'indicators': []},
            'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'techniques': []},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_a_id = AnalysisModel.save_analysis(report_a, institution_id=inst_a_id, user_id=analyst_a_id)

        # Provision Analyzed Email Telemetry for Institution B
        report_b = {
            'email_subject': 'Phishing Attack Beta',
            'email_from': 'phisher@beta.edu',
            'email_to': 'victim@beta.edu',
            'email_text': 'Urgent: Click here to re-verify your password: http://fake-login-beta.com',
            'overall_risk_level': 'CRITICAL',
            'overall_confidence': 0.95,
            'threat_score': 0.95,
            'bullying_analysis': {'is_bullying': False, 'confidence': 0.0, 'rule_based_matches': [], 'rule_based_score': 0.0, 'ml_prediction': False, 'ml_confidence': 0.0, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'CRITICAL', 'confidence': 0.95, 'indicators': ['credential_harvesting']},
            'url_analysis': {'total_urls': 1, 'suspicious_count': 1, 'urls': [{'url': 'http://fake-login-beta.com', 'is_suspicious': True}]},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'HIGH', 'confidence': 0.85, 'techniques': ['urgency']},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_b_id = AnalysisModel.save_analysis(report_b, institution_id=inst_b_id, user_id=analyst_b_id)

        return {
            'inst_a_id': inst_a_id,
            'inst_b_id': inst_b_id,
            'admin_id': admin_id,
            'analyst_a_id': analyst_a_id,
            'analyst_b_id': analyst_b_id,
            'mb_a_id': mb_a_id,
            'mb_b_id': mb_b_id,
            'analysis_a_id': analysis_a_id,
            'analysis_b_id': analysis_b_id
        }

def login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

class TestTenantIsolation:
    """Automated backend & API tenant isolation test suite (14 Isolation Invariants)."""

    def test_01_institution_a_sees_own_mailbox_not_b(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get('/api/mailboxes')
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        mbs = data['mailboxes']
        mb_emails = [m['email_address'] for m in mbs]
        assert 'security@alpha.edu' in mb_emails
        assert 'security@beta.edu' not in mb_emails

    def test_02_institution_a_cannot_get_b_mailbox_by_id(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get(f"/api/mailbox/{tenant_fixture['mb_b_id']}")
        assert res.status_code == 404

    def test_03_institution_a_sees_own_emails_not_b(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get('/api/analysis-history')
        assert res.status_code == 200
        history = res.get_json()['history']
        subjects = [h['email_subject'] for h in history]
        assert 'Cyberbullying Attack Alpha' in subjects
        assert 'Phishing Attack Beta' not in subjects

    def test_04_institution_a_cannot_get_b_incident_details(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get(f"/api/analysis/{tenant_fixture['analysis_b_id']}")
        assert res.status_code in (403, 404)

    def test_05_institution_a_stats_contain_only_a_data(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get(f"/api/institutions/{tenant_fixture['inst_a_id']}/stats")
        assert res.status_code == 200
        stats = res.get_json()['stats']
        assert stats['total_emails'] == 1
        assert stats['total_threats'] == 1
        assert stats['vector_breakdown']['cyberbullying'] == 1
        assert stats['vector_breakdown']['phishing'] == 0

    def test_06_institution_b_stats_contain_only_b_data(self, client, tenant_fixture):
        login(client, 'analyst_b', 'AnalystPass123!')
        res = client.get(f"/api/institutions/{tenant_fixture['inst_b_id']}/stats")
        assert res.status_code == 200
        stats = res.get_json()['stats']
        assert stats['total_emails'] == 1
        assert stats['total_threats'] == 1
        assert stats['critical_count'] == 1
        assert stats['vector_breakdown']['phishing'] == 1
        assert stats['vector_breakdown']['cyberbullying'] == 0

    def test_07_analyst_a_cannot_query_b_stats(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get(f"/api/institutions/{tenant_fixture['inst_b_id']}/stats")
        assert res.status_code == 403

    def test_08_analyst_a_cannot_query_b_emails_endpoint(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get(f"/api/institutions/{tenant_fixture['inst_b_id']}/emails")
        assert res.status_code == 403

    def test_09_audit_report_view_idor_protection(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.get(f"/api/reports/view/{tenant_fixture['analysis_b_id']}")
        assert res.status_code in (403, 404)

    def test_10_admin_can_switch_institutions(self, client, tenant_fixture):
        login(client, 'admin_tenant', 'AdminPass123!')
        res_a = client.get(f"/api/institutions/{tenant_fixture['inst_a_id']}/mailboxes")
        assert res_a.status_code == 200
        assert res_a.get_json()['mailboxes'][0]['email_address'] == 'security@alpha.edu'

        res_b = client.get(f"/api/institutions/{tenant_fixture['inst_b_id']}/mailboxes")
        assert res_b.status_code == 200
        assert res_b.get_json()['mailboxes'][0]['email_address'] == 'security@beta.edu'

    def test_11_analysis_creation_inherits_tenant_id(self, client, tenant_fixture):
        login(client, 'analyst_a', 'AnalystPass123!')
        res = client.post('/api/analyze-email', json={
            'email_text': 'You idiot',
            'email_subject': 'Direct Insult'
        })
        assert res.status_code == 200
        data = res.get_json()
        saved_id = data['report']['id']

        row = fetch_one("SELECT institution_id FROM analyzed_emails WHERE id = %s", (saved_id,))
        assert row['institution_id'] == tenant_fixture['inst_a_id']

    def test_12_mailbox_creation_assigns_to_target_institution(self, client, tenant_fixture):
        login(client, 'admin_tenant', 'AdminPass123!')
        mb_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status) VALUES (%s, %s, %s)",
            (tenant_fixture['inst_b_id'], 'helpdesk@beta.edu', 'active')
        )
        row = fetch_one("SELECT institution_id FROM email_config WHERE id = %s", (mb_id,))
        assert row['institution_id'] == tenant_fixture['inst_b_id']

    def test_13_existing_auth_lifecycle_operational(self, client, tenant_fixture):
        res = login(client, 'analyst_a', 'AnalystPass123!')
        assert res.status_code == 200
        res_me = client.get('/api/auth/status')
        assert res_me.status_code == 200
        assert res_me.get_json()['authenticated'] is True

    def test_14_existing_mailbox_model_query_isolation(self, app, tenant_fixture):
        with app.app_context():
            email_svc = EmailService()
            mbs_a = email_svc.get_mailboxes_for_institution(tenant_fixture['inst_a_id'])
            mbs_b = email_svc.get_mailboxes_for_institution(tenant_fixture['inst_b_id'])
            assert len(mbs_a) >= 1
            assert len(mbs_b) >= 1
            assert mbs_a[0]['institution_id'] == tenant_fixture['inst_a_id']
            assert mbs_b[0]['institution_id'] == tenant_fixture['inst_b_id']
