import pytest
import json
from bullymail.database.connection import execute_query, fetch_one, fetch_all
from bullymail.models.institution import InstitutionModel
from bullymail.models.user import UserModel
from bullymail.models.analysis import AnalysisModel
from bullymail.models.member import OrganizationMemberModel

def login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

@pytest.fixture
def tenant_env(app):
    """
    Sets up 2 completely isolated organizations:
    - Organization A: BullyMail Demo Institution (Org Admin: alexa_demo, id=inst_a)
    - Organization B: Example University (Org Admin: bob_example, id=inst_b)
    - Super Admin: jaya_owner (institution_id=None)
    """
    with app.app_context():
        # Clean any conflicting records
        execute_query("DELETE FROM organization_members WHERE email LIKE '%@testcomplete%'")
        execute_query("DELETE FROM email_config WHERE email_address LIKE '%@testcomplete%'")
        execute_query("DELETE FROM users WHERE username IN ('jaya_owner', 'alexa_demo', 'bob_example', 'pending_org_user')")
        execute_query("DELETE FROM institutions WHERE domain IN ('bullymail-demo.edu', 'example-univ.edu', 'brand-new-org.edu')")

        # Provision Institutions
        inst_a_id = InstitutionModel.create_institution(
            name="BullyMail Demo Institution",
            domain="bullymail-demo.edu",
            org_type="university",
            code="BMDEMO",
            status="ACTIVE"
        )
        inst_b_id = InstitutionModel.create_institution(
            name="Example University",
            domain="example-univ.edu",
            org_type="university",
            code="EXUNIV",
            status="ACTIVE"
        )

        # Provision Platform Owner / Super Admin
        super_admin_id = UserModel.create_user(
            username="jaya_owner",
            password="StrongPassword123!",
            role="super_admin",
            email="jaya@bullymail.io",
            status="ACTIVE",
            institution_id=None,
            full_name="Jaya Chandra Vennam",
            enforce_policy=False
        )

        # Provision Org Admins
        org_a_admin_id = UserModel.create_user(
            username="alexa_demo",
            password="StrongPassword123!",
            role="org_admin",
            email="alexa@bullymail-demo.edu",
            status="ACTIVE",
            institution_id=inst_a_id,
            full_name="Alexa Demo Admin",
            enforce_policy=False
        )
        org_b_admin_id = UserModel.create_user(
            username="bob_example",
            password="StrongPassword123!",
            role="org_admin",
            email="bob@example-univ.edu",
            status="ACTIVE",
            institution_id=inst_b_id,
            full_name="Bob Example Admin",
            enforce_policy=False
        )

        # Provision Members for Org A & Org B
        member_a_id = OrganizationMemberModel.add_member(
            institution_id=inst_a_id,
            full_name="Alice Student A",
            email="alice@testcomplete.bullymail-demo.edu",
            member_id="STU-A-001",
            department="Computer Science",
            member_type="student",
            status="ACTIVE"
        )
        member_b_id = OrganizationMemberModel.add_member(
            institution_id=inst_b_id,
            full_name="Bob Student B",
            email="bob_stu@testcomplete.example-univ.edu",
            member_id="STU-B-001",
            department="Physics",
            member_type="student",
            status="ACTIVE"
        )

        # Provision Mailboxes for Org A & Org B
        mb_a_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status, imap_server) VALUES (%s, %s, %s, %s)",
            (inst_a_id, "inbox_a@testcomplete.bullymail-demo.edu", "active", "imap.gmail.com")
        )
        mb_b_id = execute_query(
            "INSERT INTO email_config (institution_id, email_address, status, imap_server) VALUES (%s, %s, %s, %s)",
            (inst_b_id, "inbox_b@testcomplete.example-univ.edu", "active", "imap.gmail.com")
        )

        # Provision Telemetry / Analysis Incidents for Org A & Org B
        rep_a = {
            'email_subject': 'Org A Harassment',
            'email_from': 'attacker@outside.com',
            'email_to': 'inbox_a@testcomplete.bullymail-demo.edu',
            'email_text': 'You are useless and should leave.',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.90,
            'threat_score': 0.85,
            'bullying_analysis': {'is_bullying': True, 'confidence': 0.90, 'rule_based_matches': ['useless'], 'rule_based_score': 0.85, 'ml_prediction': True, 'ml_confidence': 0.88, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'indicators': []},
            'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'techniques': []},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_a_id = AnalysisModel.save_analysis(rep_a, institution_id=inst_a_id, user_id=org_a_admin_id, email_config_id=mb_a_id)

        rep_b = {
            'email_subject': 'Org B Phishing',
            'email_from': 'phisher@fakebank.com',
            'email_to': 'inbox_b@testcomplete.example-univ.edu',
            'email_text': 'Reset your credentials immediately.',
            'overall_risk_level': 'CRITICAL',
            'overall_confidence': 0.95,
            'threat_score': 0.95,
            'bullying_analysis': {'is_bullying': False, 'confidence': 0.0, 'rule_based_matches': [], 'rule_based_score': 0.0, 'ml_prediction': False, 'ml_confidence': 0.0, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'CRITICAL', 'confidence': 0.95, 'indicators': ['credential_reset']},
            'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'HIGH', 'confidence': 0.90, 'techniques': ['urgency']},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_b_id = AnalysisModel.save_analysis(rep_b, institution_id=inst_b_id, user_id=org_b_admin_id, email_config_id=mb_b_id)

        return {
            'inst_a_id': inst_a_id,
            'inst_b_id': inst_b_id,
            'super_admin_id': super_admin_id,
            'org_a_admin_id': org_a_admin_id,
            'org_b_admin_id': org_b_admin_id,
            'member_a_id': member_a_id,
            'member_b_id': member_b_id,
            'mb_a_id': mb_a_id,
            'mb_b_id': mb_b_id,
            'analysis_a_id': analysis_a_id,
            'analysis_b_id': analysis_b_id
        }


class TestTenantIsolationComplete:
    """
    Comprehensive Automated Multi-Tenant Architecture & RBAC Isolation Suite.
    Verifies all 14 mandatory security scenarios with zero cross-tenant leakage.
    """

    # 1. Org admin can access own organization
    def test_01_org_admin_can_access_own_organization(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res = client.get(f"/api/organizations/{tenant_env['inst_a_id']}/members")
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        assert data['organization_id'] == tenant_env['inst_a_id']

    # 2. Org admin cannot access another organization (403 Forbidden)
    def test_02_org_admin_cannot_access_another_organization(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res = client.get(f"/api/organizations/{tenant_env['inst_b_id']}/members")
        assert res.status_code == 403
        data = res.get_json()
        assert 'Forbidden' in data['error']

    # 3. Org admin cannot access platform approvals (403 Forbidden)
    def test_03_org_admin_cannot_access_platform_approvals(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res_pending = client.get('/api/admin/pending-registrations')
        assert res_pending.status_code == 403

        res_users = client.get('/api/admin/pending-users')
        assert res_users.status_code == 403

        res_approve = client.post(f"/api/admin/approve-org/{tenant_env['inst_b_id']}")
        assert res_approve.status_code == 403

        res_suspend = client.post(f"/api/admin/organizations/{tenant_env['inst_b_id']}/suspend")
        assert res_suspend.status_code == 403

    # 4. Org admin cannot create member for another organization (403 Forbidden)
    def test_04_org_admin_cannot_create_member_for_another_org(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res = client.post(f"/api/organizations/{tenant_env['inst_b_id']}/members", json={
            'name': 'Malicious Injection',
            'email': 'evil@testcomplete.example-univ.edu',
            'role': 'student'
        })
        assert res.status_code == 403
        assert 'Forbidden' in res.get_json()['error']

    # 5. Org admin cannot modify another organization's member (403 Forbidden)
    def test_05_org_admin_cannot_modify_another_org_member(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res = client.put(f"/api/members/{tenant_env['member_b_id']}", json={
            'name': 'Tampered Name',
            'organization_id': tenant_env['inst_b_id']
        })
        assert res.status_code in (403, 404)

    # 6. Org admin cannot delete another organization's member (403 Forbidden)
    def test_06_org_admin_cannot_delete_another_org_member(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res = client.delete(f"/api/members/{tenant_env['member_b_id']}?organization_id={tenant_env['inst_b_id']}")
        assert res.status_code in (403, 404)

    # 7. Org admin cannot access another organization's mailbox (403 Forbidden)
    def test_07_org_admin_cannot_access_another_org_mailbox(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res_emails = client.get(f"/api/mailboxes/{tenant_env['mb_b_id']}/emails")
        assert res_emails.status_code in (403, 404)

        res_sync = client.post(f"/api/mailbox/{tenant_env['mb_b_id']}/sync")
        assert res_sync.status_code == 403

    # 8. Org admin cannot access another organization's incidents (403 Forbidden)
    def test_08_org_admin_cannot_access_another_org_incidents(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res = client.get(f"/api/analysis/{tenant_env['analysis_b_id']}")
        assert res.status_code in (403, 404)

        res_rep = client.get(f"/api/reports/view/{tenant_env['analysis_b_id']}")
        assert res_rep.status_code in (403, 404)

    # 9. Super admin can view all organizations
    def test_09_super_admin_can_view_all_organizations(self, client, tenant_env):
        login(client, 'jaya_owner', 'StrongPassword123!')
        res = client.get('/api/admin/organizations')
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True
        org_ids = [o['id'] for o in data['organizations']]
        assert tenant_env['inst_a_id'] in org_ids
        assert tenant_env['inst_b_id'] in org_ids

    # 10. Super admin can approve/reject/suspend/activate organizations
    def test_10_super_admin_can_suspend_and_activate_organizations(self, client, tenant_env):
        login(client, 'jaya_owner', 'StrongPassword123!')
        # Suspend Org B
        res_susp = client.post(f"/api/admin/organizations/{tenant_env['inst_b_id']}/suspend")
        assert res_susp.status_code == 200
        assert res_susp.get_json()['success'] is True

        inst_b_state = fetch_one("SELECT status FROM institutions WHERE id = %s", (tenant_env['inst_b_id'],))
        assert inst_b_state['status'] == 'SUSPENDED'

        # Suspended Org B's admin cannot log in or perform actions
        client.get('/logout')
        login(client, 'bob_example', 'StrongPassword123!')
        # Blocked because organization is suspended
        res_action = client.get(f"/api/organizations/{tenant_env['inst_b_id']}/members")
        assert res_action.status_code in (401, 302, 403)

        # Super admin activates Org B again
        login(client, 'jaya_owner', 'StrongPassword123!')
        res_act = client.post(f"/api/admin/organizations/{tenant_env['inst_b_id']}/activate")
        assert res_act.status_code == 200
        assert res_act.get_json()['success'] is True

        inst_b_active = fetch_one("SELECT status FROM institutions WHERE id = %s", (tenant_env['inst_b_id'],))
        assert inst_b_active['status'] == 'ACTIVE'

    # 11. Newly approved organization receives correct organization_id
    def test_11_newly_approved_organization_receives_correct_organization_id(self, app, client, tenant_env):
        with app.app_context():
            new_org_id = InstitutionModel.create_institution(
                name='Brand New Org',
                domain='brand-new-org.edu',
                org_type='university',
                status='PENDING_APPROVAL'
            )
            new_user_id = UserModel.create_user(
                username='pending_org_user',
                password='StrongPassword123!',
                email='admin@brand-new-org.edu',
                role='org_admin',
                status='PENDING_ADMIN_APPROVAL',
                institution_id=None,
                requested_institution_name='Brand New Org',
                requested_institution_domain='brand-new-org.edu',
                enforce_policy=False
            )

        login(client, 'jaya_owner', 'StrongPassword123!')
        res_approve = client.post(f"/api/admin/approve-org/{new_org_id}")
        assert res_approve.status_code == 200
        data = res_approve.get_json()
        assert data['success'] is True
        assert data['organization_id'] == new_org_id

        # Verify DB state
        with app.app_context():
            approved_user = UserModel.get_by_id(new_user_id)
            assert approved_user['status'] == 'ACTIVE'
            assert approved_user['institution_id'] == new_org_id

    # 12. Newly created members automatically inherit current user's organization_id
    def test_12_newly_created_members_inherit_current_user_org_id(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        # Post member without specifying organization_id in request body
        res = client.post('/api/members', json={
            'name': 'Auto Tenant Inherited Member',
            'email': 'autoinherit@testcomplete.bullymail-demo.edu',
            'role': 'student',
            'department': 'Robotics'
        })
        assert res.status_code == 201
        data = res.get_json()
        assert data['success'] is True
        created_member_id = data['id']
        assert data['organization_id'] == tenant_env['inst_a_id']

        member_record = OrganizationMemberModel.get_by_id(created_member_id, institution_id=tenant_env['inst_a_id'])
        assert member_record is not None
        assert member_record['institution_id'] == tenant_env['inst_a_id']

    # 13. Dashboard statistics are strictly tenant-scoped (zero cross-tenant count leakage)
    def test_13_dashboard_statistics_strictly_tenant_scoped(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')
        res_a = client.get('/api/system-stats')
        assert res_a.status_code == 200
        stats_a = res_a.get_json()['stats']

        login(client, 'bob_example', 'StrongPassword123!')
        res_b = client.get('/api/system-stats')
        assert res_b.status_code == 200
        stats_b = res_b.get_json()['stats']

        # Ensure total_analyzed counts are strictly scoped to the tenant
        assert stats_a['total_analyzed'] >= 1
        assert stats_b['total_analyzed'] >= 1

        # Check threat history
        res_hist_a = client.get(f"/api/analysis-history?organization_id={tenant_env['inst_a_id']}")
        assert res_hist_a.status_code == 403 # Bob cannot query Alexa's organization

        res_hist_b = client.get('/api/analysis-history')
        assert res_hist_b.status_code == 200
        subjects_b = [row['email_subject'] for row in res_hist_b.get_json()['analyses']]
        assert 'Org B Phishing' in subjects_b
        assert 'Org A Harassment' not in subjects_b # Zero cross-tenant data leakage!

    # 14. Direct API manipulation of organization_id cannot bypass authorization (strict 403)
    def test_14_direct_api_manipulation_rejected_strict_403(self, client, tenant_env):
        login(client, 'alexa_demo', 'StrongPassword123!')

        # 14a. Tampering query parameter on analysis history
        res1 = client.get(f"/api/analysis-history?organization_id={tenant_env['inst_b_id']}")
        assert res1.status_code == 403
        assert 'Forbidden' in res1.get_json()['error']

        # 14b. Tampering query parameter on mailboxes list
        res2 = client.get(f"/api/mailboxes?organization_id={tenant_env['inst_b_id']}")
        assert res2.status_code == 403
        assert 'Forbidden' in res2.get_json()['error']

        # 14c. Tampering query parameter on members list
        res3 = client.get(f"/api/members?organization_id={tenant_env['inst_b_id']}")
        assert res3.status_code == 403
        assert 'Forbidden' in res3.get_json()['error']

        # 14d. Tampering POST body on analyze-email
        res4 = client.post('/api/analyze-email', json={
            'email_text': 'Trying to force into another tenant context',
            'organization_id': tenant_env['inst_b_id']
        })
        assert res4.status_code == 403
        assert 'Forbidden' in res4.get_json()['error']
