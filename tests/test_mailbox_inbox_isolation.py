import pytest
import json
from bullymail.database.connection import execute_query, fetch_one
from bullymail.models.institution import InstitutionModel
from bullymail.models.user import UserModel
from bullymail.services.email_service import EmailService
from bullymail.models.analysis import AnalysisModel

@pytest.fixture
def mailbox_inbox_fixture(app, client):
    """
    Sets up two isolated mailboxes under Institution Alpha (Mailbox A1 and Mailbox A2),
    and one mailbox under Institution Beta (Mailbox B1), populated with distinct email telemetry.
    """
    with app.app_context():
        # Provision Institutions
        inst_a_id = InstitutionModel.create_institution("University Alpha", "alpha.edu", code="ALPHA")
        inst_b_id = InstitutionModel.create_institution("University Beta", "beta.edu", code="BETA")

        # Provision Users
        admin_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email, status) VALUES (%s, %s, %s, %s, %s)",
            ("admin_mb", UserModel.hash_password("AdminPass123!"), "admin", "admin@alpha.edu", "ACTIVE")
        )
        analyst_a_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s)",
            ("analyst_mb_a", UserModel.hash_password("AnalystPass123!"), "analyst", "analyst@alpha.edu", "ACTIVE", inst_a_id)
        )
        analyst_b_id = execute_query(
            "INSERT INTO users (username, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s)",
            ("analyst_mb_b", UserModel.hash_password("AnalystPass123!"), "analyst", "analyst@beta.edu", "ACTIVE", inst_b_id)
        )

        # Provision Mailboxes under Institution A
        mb_a1_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status, imap_server) VALUES (%s, %s, %s, %s)",
            (inst_a_id, "cloudkeys1@gmail.com", "active", "imap.gmail.com")
        )
        mb_a2_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status, imap_server) VALUES (%s, %s, %s, %s)",
            (inst_a_id, "temptemp14564561@gmail.com", "active", "imap.gmail.com")
        )

        # Provision Mailbox under Institution B
        mb_b1_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status, imap_server) VALUES (%s, %s, %s, %s)",
            (inst_b_id, "security@beta.edu", "active", "imap.gmail.com")
        )

        # Ingest Email for Mailbox A1 (cloudkeys1@gmail.com)
        report_a1 = {
            'email_subject': 'Cloudkeys Secret Update',
            'email_from': 'alexa@gmail.com',
            'email_to': 'cloudkeys1@gmail.com',
            'email_text': 'Please check your cloud configuration keys immediately.',
            'overall_risk_level': 'LOW',
            'overall_confidence': 0.95,
            'threat_score': 0.10,
            'bullying_analysis': {'is_bullying': False, 'confidence': 0.0, 'rule_based_matches': [], 'rule_based_score': 0.0, 'ml_prediction': False, 'ml_confidence': 0.0, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'indicators': []},
            'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'techniques': []},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_a1_id = AnalysisModel.save_analysis(report_a1, institution_id=inst_a_id, user_id=analyst_a_id, email_config_id=mb_a1_id)

        # Ingest Email for Mailbox A2 (temptemp14564561@gmail.com)
        report_a2 = {
            'email_subject': 'Hey stupid',
            'email_from': 'attacker@gmail.com',
            'email_to': 'temptemp14564561@gmail.com',
            'email_text': 'You stupid, You unskilled',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.88,
            'threat_score': 0.88,
            'bullying_analysis': {'is_bullying': True, 'confidence': 0.88, 'rule_based_matches': ['stupid', 'unskilled'], 'rule_based_score': 0.88, 'ml_prediction': True, 'ml_confidence': 0.85, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'indicators': []},
            'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'techniques': []},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_a2_id = AnalysisModel.save_analysis(report_a2, institution_id=inst_a_id, user_id=analyst_a_id, email_config_id=mb_a2_id)

        # Ingest Email for Mailbox B1 (security@beta.edu)
        report_b1 = {
            'email_subject': 'Phishing Scam Beta',
            'email_from': 'hacker@beta.edu',
            'email_to': 'security@beta.edu',
            'email_text': 'Urgent account lockout notice',
            'overall_risk_level': 'CRITICAL',
            'overall_confidence': 0.96,
            'threat_score': 0.96,
            'bullying_analysis': {'is_bullying': False, 'confidence': 0.0, 'rule_based_matches': [], 'rule_based_score': 0.0, 'ml_prediction': False, 'ml_confidence': 0.0, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'CRITICAL', 'confidence': 0.96, 'indicators': ['lockout']},
            'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'HIGH', 'confidence': 0.90, 'techniques': ['urgency']},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_b1_id = AnalysisModel.save_analysis(report_b1, institution_id=inst_b_id, user_id=analyst_b_id, email_config_id=mb_b1_id)

        return {
            'inst_a_id': inst_a_id,
            'inst_b_id': inst_b_id,
            'mb_a1_id': mb_a1_id,
            'mb_a2_id': mb_a2_id,
            'mb_b1_id': mb_b1_id,
            'analysis_a1_id': analysis_a1_id,
            'analysis_a2_id': analysis_a2_id,
            'analysis_b1_id': analysis_b1_id
        }

def login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

class TestMailboxInboxIsolation:
    """Automated Mailbox-Level Inbox & Isolation Invariants Test Suite (10 Requirements)."""

    def test_01_mailbox_a1_inbox_returns_only_mailbox_a1_emails(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_a', 'AnalystPass123!')
        res = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_a1_id']}/emails")
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        assert data['mailbox']['email_address'] == 'cloudkeys1@gmail.com'
        subjects = [e['email_subject'] for e in data['emails']]
        assert 'Cloudkeys Secret Update' in subjects
        assert 'Hey stupid' not in subjects
        assert 'Phishing Scam Beta' not in subjects

    def test_02_mailbox_a2_inbox_returns_only_mailbox_a2_emails(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_a', 'AnalystPass123!')
        res = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_a2_id']}/emails")
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        assert data['mailbox']['email_address'] == 'temptemp14564561@gmail.com'
        subjects = [e['email_subject'] for e in data['emails']]
        assert 'Hey stupid' in subjects
        assert 'Cloudkeys Secret Update' not in subjects
        assert 'Phishing Scam Beta' not in subjects

    def test_03_mailbox_a_cannot_access_mailbox_b_emails(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_a', 'AnalystPass123!')
        # Analyst from Institution A attempts to read Mailbox B1's inbox
        res = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_b1_id']}/emails")
        assert res.status_code == 404

    def test_04_mailbox_id_tampering_rejected(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_a', 'AnalystPass123!')
        # Attempting to fetch non-existent or un-owned mailbox returns 404
        res = client.get('/api/mailboxes/99999/emails')
        assert res.status_code == 404

    def test_05_email_inspection_returns_correct_email(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_a', 'AnalystPass123!')
        res = client.get(f"/api/analysis/{mailbox_inbox_fixture['analysis_a2_id']}?mailbox_id={mailbox_inbox_fixture['mb_a2_id']}")
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        assert data['analysis']['email_subject'] == 'Hey stupid'
        assert data['analysis']['email_to'] == 'temptemp14564561@gmail.com'

    def test_06_incident_inspection_matches_mailbox(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_a', 'AnalystPass123!')
        # Cross-mailbox tampering check: requesting Analysis A1 with mailbox_id A2
        res = client.get(f"/api/analysis/{mailbox_inbox_fixture['analysis_a1_id']}?mailbox_id={mailbox_inbox_fixture['mb_a2_id']}")
        assert res.status_code == 404

    def test_07_search_restricted_to_selected_mailbox(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_a', 'AnalystPass123!')
        # Search for "stupid" in Mailbox A1 (should return empty)
        res_a1 = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_a1_id']}/emails?search=stupid")
        assert res_a1.status_code == 200
        assert len(res_a1.get_json()['emails']) == 0

        # Search for "stupid" in Mailbox A2 (should return 1 email)
        res_a2 = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_a2_id']}/emails?search=stupid")
        assert res_a2.status_code == 200
        assert len(res_a2.get_json()['emails']) == 1
        assert res_a2.get_json()['emails'][0]['email_subject'] == 'Hey stupid'

    def test_08_sync_operates_on_selected_mailbox(self, client, mailbox_inbox_fixture, monkeypatch):
        login(client, 'admin_mb', 'AdminPass123!')
        monkeypatch.setattr("bullymail.worker.processor.MailboxProcessor.process_mailbox", lambda self, mb, lease_id=None, return_summary=True: {'success': True, 'emails_found': 0, 'emails_processed': 0, 'threats_detected': 0, 'duplicates_skipped': 0, 'failures': 0, 'status': 'OK', 'email_config_id': mb['id']})
        res = client.post(f"/api/mailbox/{mailbox_inbox_fixture['mb_a2_id']}/sync")
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        assert data['email_config_id'] == mailbox_inbox_fixture['mb_a2_id']

    def test_09_newly_synced_email_appears_in_correct_inbox(self, app, client, mailbox_inbox_fixture):
        with app.app_context():
            # Manually insert a new ingested email for Mailbox A2
            report_new = {
                'email_subject': 'New Harassment Message',
                'email_from': 'bully@gmail.com',
                'email_to': 'temptemp14564561@gmail.com',
                'email_text': 'Get out of here',
                'overall_risk_level': 'MEDIUM',
                'overall_confidence': 0.80,
                'threat_score': 0.50,
                'bullying_analysis': {'is_bullying': True, 'confidence': 0.80, 'rule_based_matches': [], 'rule_based_score': 0.50, 'ml_prediction': True, 'ml_confidence': 0.80, 'model_used': 'Hybrid'},
                'phishing_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'indicators': []},
                'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
                'domain_analysis': {},
                'social_eng_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'techniques': []},
                'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
                'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
                'top_risk_factors': []
            }
            new_id = AnalysisModel.save_analysis(report_new, institution_id=mailbox_inbox_fixture['inst_a_id'], user_id=None, email_config_id=mailbox_inbox_fixture['mb_a2_id'])

        login(client, 'analyst_mb_a', 'AnalystPass123!')
        res_a2 = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_a2_id']}/emails")
        assert res_a2.status_code == 200
        subjects_a2 = [e['email_subject'] for e in res_a2.get_json()['emails']]
        assert 'New Harassment Message' in subjects_a2

        res_a1 = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_a1_id']}/emails")
        assert res_a1.status_code == 200
        subjects_a1 = [e['email_subject'] for e in res_a1.get_json()['emails']]
        assert 'New Harassment Message' not in subjects_a1

    def test_10_institution_isolation_remains_enforced(self, client, mailbox_inbox_fixture):
        login(client, 'analyst_mb_b', 'AnalystPass123!')
        # Analyst B attempts to fetch Mailbox A1 emails or stats
        res_emails = client.get(f"/api/mailboxes/{mailbox_inbox_fixture['mb_a1_id']}/emails")
        assert res_emails.status_code == 404

        res_stats = client.get(f"/api/institutions/{mailbox_inbox_fixture['inst_a_id']}/stats")
        assert res_stats.status_code == 403

    def test_11_sync_all_institution_mailboxes(self, client, mailbox_inbox_fixture, monkeypatch):
        monkeypatch.setattr("bullymail.worker.processor.MailboxProcessor.process_mailbox", lambda self, mb, lease_id=None, return_summary=True: {'success': True, 'emails_found': 0, 'emails_processed': 0, 'threats_detected': 0, 'duplicates_skipped': 0, 'failures': 0, 'status': 'OK', 'email_config_id': mb['id']})
        login(client, 'admin_mb', 'AdminPass123!')
        res = client.post(f"/api/institutions/{mailbox_inbox_fixture['inst_a_id']}/sync-all")
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        assert data['mailboxes_processed'] == 2

    def test_12_disabled_mailbox_skipped_in_sync_all(self, app, client, mailbox_inbox_fixture, monkeypatch):
        monkeypatch.setattr("bullymail.worker.processor.MailboxProcessor.process_mailbox", lambda self, mb, lease_id=None, return_summary=True: {'success': True, 'emails_found': 0, 'emails_processed': 0, 'threats_detected': 0, 'duplicates_skipped': 0, 'failures': 0, 'status': 'OK', 'email_config_id': mb['id']})
        login(client, 'admin_mb', 'AdminPass123!')
        # Disable Mailbox A2
        res_dis = client.post(f"/api/mailbox/{mailbox_inbox_fixture['mb_a2_id']}/disable")
        assert res_dis.status_code == 200

        res_sync = client.post(f"/api/institutions/{mailbox_inbox_fixture['inst_a_id']}/sync-all")
        assert res_sync.status_code == 200
        data = res_sync.get_json()
        assert data['success'] is True
        # Only Mailbox A1 should be processed (1 active mailbox)
        assert data['mailboxes_processed'] == 1

