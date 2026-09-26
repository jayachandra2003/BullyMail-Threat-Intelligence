import pytest
import json
import io
from bullymail.database.connection import execute_query, fetch_one
from bullymail.models.institution import InstitutionModel
from bullymail.models.user import UserModel
from bullymail.models.member import OrganizationMemberModel
from bullymail.models.analysis import AnalysisModel
from bullymail.services.admin_warning_service import admin_warning_service

@pytest.fixture
def multi_tenant_fixture(app, client):
    """
    Sets up a complete multi-tenant SaaS environment:
    - Platform Owner: Jaya Chandra Vennam
    - Institution Alpha (e.g. VIT University) with Org Admin Alpha and Analyst Alpha
    - Institution Beta (e.g. ABC Corp) with Org Admin Beta and Analyst Beta
    - Pending Institution Gamma awaiting approval
    """
    with app.app_context():
        # 1. Institutions
        inst_a_id = InstitutionModel.create_institution(
            "VIT University", "vit.ac.in", org_type="university",
            contact_name="VIT Dean", contact_email="dean@vit.ac.in", code="VIT"
        )
        inst_b_id = InstitutionModel.create_institution(
            "ABC Corporation", "abccorp.com", org_type="company",
            contact_name="ABC CISO", contact_email="ciso@abccorp.com", code="ABC"
        )
        inst_gamma_id = InstitutionModel.create_institution(
            "Gamma Institute", "gamma.edu", org_type="college",
            contact_name="Gamma Admin", contact_email="admin@gamma.edu", code="GAMMA"
        )
        InstitutionModel.update_status(inst_gamma_id, 'PENDING_APPROVAL')

        # 2. Users
        # Platform Owner (Jaya Chandra Vennam)
        owner_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status) VALUES (%s, %s, %s, %s, %s, %s)",
            ("jayachandra", "Jaya Chandra Vennam", UserModel.hash_password("OwnerPass123!"), "platform_owner", "jaya@bullymail.io", "ACTIVE")
        )

        # Org Admin Alpha (VIT University)
        admin_a_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ("vit_admin", "VIT Administrator", UserModel.hash_password("AdminPass123!"), "org_admin", "admin@vit.ac.in", "ACTIVE", inst_a_id)
        )

        # Analyst Alpha (VIT University)
        analyst_a_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ("vit_analyst", "VIT Analyst", UserModel.hash_password("AnalystPass123!"), "analyst", "analyst@vit.ac.in", "ACTIVE", inst_a_id)
        )

        # Org Admin Beta (ABC Corporation)
        admin_b_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ("abc_admin", "ABC Administrator", UserModel.hash_password("AdminPass123!"), "org_admin", "admin@abccorp.com", "ACTIVE", inst_b_id)
        )

        # Analyst Beta (ABC Corporation)
        analyst_b_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ("abc_analyst", "ABC Analyst", UserModel.hash_password("AnalystPass123!"), "analyst", "analyst@abccorp.com", "ACTIVE", inst_b_id)
        )

        # Pending User for Gamma
        pending_user_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ("gamma_admin", "Gamma Administrator", UserModel.hash_password("Pass123!"), "org_admin", "admin@gamma.edu", "PENDING_ADMIN_APPROVAL", inst_gamma_id)
        )

        # 3. Seed Members for Institution Alpha
        member_a_id = OrganizationMemberModel.add_member(
            institution_id=inst_a_id,
            full_name="Alice Student",
            email="alice@vit.ac.in",
            member_type="student",
            department="CSE",
            identifier="21BCE001"
        )

        # 4. Seed Members for Institution Beta
        member_b_id = OrganizationMemberModel.add_member(
            institution_id=inst_b_id,
            full_name="Bob Employee",
            email="bob@abccorp.com",
            member_type="employee",
            department="Security Operations",
            identifier="EMP-902"
        )

        # 5. Seed Analysis Incidents
        sample_report = {
            'email_subject': 'Threat Test Incident',
            'email_from': 'attacker@external.com',
            'email_to': 'victim@vit.ac.in',
            'email_text': 'You will pay for this.',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.88,
            'threat_score': 0.88,
            'bullying_analysis': {'is_bullying': True, 'confidence': 0.88, 'rule_based_matches': ['pay for this'], 'rule_based_score': 0.88, 'ml_prediction': True, 'ml_confidence': 0.85, 'model_used': 'Hybrid'},
            'phishing_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'indicators': []},
            'url_analysis': {'total_urls': 0, 'suspicious_count': 0, 'urls': []},
            'domain_analysis': {},
            'social_eng_analysis': {'risk_level': 'LOW', 'confidence': 0.0, 'techniques': []},
            'malware_analysis': {'total_attachments': 0, 'malware_detected': False, 'malicious_count': 0, 'risk_level': 'LOW', 'attachments': []},
            'image_analysis': {'total_images': 0, 'suspicious_count': 0, 'images': []},
            'top_risk_factors': []
        }
        analysis_a_id = AnalysisModel.save_analysis(sample_report, institution_id=inst_a_id, user_id=admin_a_id)

        return {
            'inst_a_id': inst_a_id,
            'inst_b_id': inst_b_id,
            'inst_gamma_id': inst_gamma_id,
            'owner_id': owner_id,
            'admin_a_id': admin_a_id,
            'analyst_a_id': analyst_a_id,
            'admin_b_id': admin_b_id,
            'analyst_b_id': analyst_b_id,
            'pending_user_id': pending_user_id,
            'member_a_id': member_a_id,
            'member_b_id': member_b_id,
            'analysis_a_id': analysis_a_id
        }


def login_as(client, user_id, username, role, institution_id=None, full_name=""):
    """Helper to set up authenticated session cookies directly."""
    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['username'] = username
        sess['role'] = role
        sess['institution_id'] = institution_id
        sess['full_name'] = full_name


# =========================================================================
# 1. Platform Owner Privileges & Isolation Tests
# =========================================================================

def test_platform_owner_can_access_governance_endpoints(client, multi_tenant_fixture):
    """Platform Owner (Jaya Chandra Vennam) has exclusive access to pending approvals and platform overview."""
    f = multi_tenant_fixture
    login_as(client, f['owner_id'], 'jayachandra', 'platform_owner', full_name="Jaya Chandra Vennam")

    # 1. Pending registrations & alias /pending-approvals
    res = client.get('/api/admin/pending-registrations')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'pending_users' in data
    assert 'pending_orgs' in data
    assert any(o['id'] == f['inst_gamma_id'] for o in data['pending_orgs'])

    res_alias = client.get('/pending-approvals')
    assert res_alias.status_code == 200
    assert res_alias.get_json()['success'] is True

    # 2. Platform overview metrics
    res_ov = client.get('/api/admin/platform-overview')
    assert res_ov.status_code == 200
    ov_data = res_ov.get_json()
    assert ov_data['success'] is True
    assert 'stats' in ov_data
    assert ov_data['stats']['total_institutions'] >= 3

    # 3. Approve Organization Application via POST /approve-organization with JSON payload
    res_app = client.post('/approve-organization', json={'organization_id': f['inst_gamma_id']})
    assert res_app.status_code == 200
    app_data = res_app.get_json()
    assert app_data['success'] is True
    # Confirm org is now active
    gamma = InstitutionModel.get_by_id(f['inst_gamma_id'])
    assert gamma['status'] == 'ACTIVE'

    # 4. Reject Organization Application via POST /reject-organization with JSON payload
    with client.application.app_context():
        inst_delta_id = InstitutionModel.create_institution("Delta Org", "delta.io", org_type="company")
    res_rej = client.post('/reject-organization', json={'organization_id': inst_delta_id})
    assert res_rej.status_code == 200
    delta = InstitutionModel.get_by_id(inst_delta_id)
    assert delta['status'] == 'REJECTED'


def test_org_admin_cannot_access_platform_owner_endpoints(client, multi_tenant_fixture):
    """Org Admin cannot access pending approvals, org approvals, or platform overview (Fail Closed 403)."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'], full_name="VIT Admin")

    # 1. Cannot view pending registrations or /pending-approvals
    res1 = client.get('/api/admin/pending-registrations')
    assert res1.status_code == 403

    res1_alias = client.get('/pending-approvals')
    assert res1_alias.status_code == 403

    # 2. Cannot view platform overview
    res2 = client.get('/api/admin/platform-overview')
    assert res2.status_code == 403

    # 3. Cannot approve organization (both path and payload endpoints)
    res3 = client.post(f"/api/admin/approve-org/{f['inst_gamma_id']}")
    assert res3.status_code == 403

    res3_payload = client.post('/approve-organization', json={'organization_id': f['inst_gamma_id']})
    assert res3_payload.status_code == 403

    # 4. Cannot reject organization (both path and payload endpoints)
    res4 = client.post(f"/api/admin/reject-org/{f['inst_gamma_id']}")
    assert res4.status_code == 403

    res4_payload = client.post('/reject-organization', json={'organization_id': f['inst_gamma_id']})
    assert res4_payload.status_code == 403

    # 5. Cannot approve pending users
    res5 = client.post('/api/admin/approve-user', json={'user_id': f['pending_user_id'], 'action': 'approve'})
    assert res5.status_code == 403


def test_analyst_cannot_access_platform_or_admin_endpoints(client, multi_tenant_fixture):
    """Analyst cannot access administrative endpoints (Fail Closed 403)."""
    f = multi_tenant_fixture
    login_as(client, f['analyst_a_id'], 'vit_analyst', 'analyst', institution_id=f['inst_a_id'])

    res1 = client.get('/api/admin/pending-registrations')
    assert res1.status_code == 403

    res2 = client.get('/api/admin/mailboxes')
    assert res2.status_code == 403

    res3 = client.post('/api/members', json={'full_name': 'Test', 'email': 't@vit.ac.in', 'member_type': 'student'})
    assert res3.status_code == 403

    res4 = client.put('/api/org/settings', json={'name': 'Hacked VIT'})
    assert res4.status_code == 403


# =========================================================================
# 2. Strict Cross-Tenant Isolation Tests
# =========================================================================

def test_cross_tenant_stats_access_forbidden(client, multi_tenant_fixture):
    """Org Admin A attempting to access stats or sync of Institution B must fail with 403 Forbidden."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    # Access own stats -> OK
    res_own = client.get(f"/api/institutions/{f['inst_a_id']}/stats")
    assert res_own.status_code == 200

    res_own_org = client.get(f"/api/organizations/{f['inst_a_id']}/stats")
    assert res_own_org.status_code == 200

    # Cross-tenant access to Institution B -> 403 Forbidden
    res_cross = client.get(f"/api/institutions/{f['inst_b_id']}/stats")
    assert res_cross.status_code == 403

    res_cross_org = client.get(f"/api/organizations/{f['inst_b_id']}/stats")
    assert res_cross_org.status_code == 403

    # Cross-tenant sync-all -> 403 Forbidden
    res_cross_sync = client.post(f"/api/organizations/{f['inst_b_id']}/sync-all")
    assert res_cross_sync.status_code == 403

    # Own tenant sync-all -> 200 OK
    res_own_sync = client.post(f"/api/organizations/{f['inst_a_id']}/sync-all")
    assert res_own_sync.status_code == 200


def test_cross_tenant_analysis_history_tampering(client, multi_tenant_fixture):
    """Org Admin B attempting to delete or access analysis belonging to Institution A must fail closed."""
    f = multi_tenant_fixture
    login_as(client, f['admin_b_id'], 'abc_admin', 'org_admin', institution_id=f['inst_b_id'])

    # Attempt to delete Institution A's analysis record
    res_del = client.delete(f"/api/analysis/history/{f['analysis_a_id']}")
    # Must fail: 404 (not found in tenant scope) or 403
    assert res_del.status_code in (403, 404)

    # Verification: record still exists in database
    rec = AnalysisModel.get_by_id(f['analysis_a_id'], institution_id=f['inst_a_id'], role='org_admin')
    assert rec is not None


# =========================================================================
# 3. Organization Member Management Tests
# =========================================================================

def test_member_crud_isolated_to_tenant(client, multi_tenant_fixture):
    """Org Admin can create, view, update, and delete members strictly within their tenant."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    # 1. List members for Institution A (sees Alice, not Bob)
    res_list = client.get('/api/members')
    assert res_list.status_code == 200
    data = res_list.get_json()
    assert data['success'] is True
    member_emails = [m['email'] for m in data['members']]
    assert 'alice@vit.ac.in' in member_emails
    assert 'bob@abccorp.com' not in member_emails

    # 2. Add Member for Institution A
    res_add = client.post('/api/members', json={
        'full_name': 'Charlie Faculty',
        'email': 'charlie@vit.ac.in',
        'member_type': 'faculty',
        'department': 'Physics',
        'identifier': 'FAC-101'
    })
    assert res_add.status_code == 201
    add_data = res_add.get_json()
    assert add_data['success'] is True
    charlie_id = add_data['member_id']

    # 3. Update Member
    res_upd = client.put(f'/api/members/{charlie_id}', json={
        'full_name': 'Prof. Charlie',
        'email': 'charlie@vit.ac.in',
        'member_type': 'faculty',
        'department': 'Applied Physics',
        'status': 'ACTIVE'
    })
    assert res_upd.status_code == 200

    # 4. Cross-tenant tampering: Org Admin B tries to update Charlie
    login_as(client, f['admin_b_id'], 'abc_admin', 'org_admin', institution_id=f['inst_b_id'])
    res_cross_upd = client.put(f'/api/members/{charlie_id}', json={
        'full_name': 'Hacked Charlie',
        'status': 'SUSPENDED'
    })
    assert res_cross_upd.status_code == 404

    # Org Admin B tries to delete Charlie
    res_cross_del = client.delete(f'/api/members/{charlie_id}')
    assert res_cross_del.status_code == 404

    # 5. Org Admin A deletes Charlie successfully
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])
    res_del = client.delete(f'/api/members/{charlie_id}')
    assert res_del.status_code == 200


def test_member_bulk_csv_import(client, multi_tenant_fixture):
    """Org Admin can upload CSV to bulk import members, all scoped to tenant."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    csv_content = (
        "full_name,email,member_type,department,identifier\n"
        "David Dave,david@vit.ac.in,student,CSE,21BCE045\n"
        "Emma Watson,emma@vit.ac.in,student,ECE,21BEC012\n"
        "Dr. Smith,smith@vit.ac.in,faculty,Mathematics,FAC-090\n"
    )

    data = {
        'file': (io.BytesIO(csv_content.encode('utf-8')), 'members.csv')
    }

    res = client.post('/api/members/import-csv', data=data, content_type='multipart/form-data')
    assert res.status_code == 200
    res_data = res.get_json()
    assert res_data['success'] is True
    assert res_data['imported'] == 3

    # Check imported members exist and are assigned to Institution A
    m = OrganizationMemberModel.get_by_email('david@vit.ac.in', f['inst_a_id'])
    assert m is not None
    assert m['full_name'] == 'David Dave'
    assert m['institution_id'] == f['inst_a_id']


def test_csv_template_download(client, multi_tenant_fixture):
    """Org Admin can download CSV template."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    res = client.get('/api/members/template-csv')
    assert res.status_code == 200
    assert 'text/csv' in res.content_type
    assert b'full_name,email,member_type,department,identifier' in res.data


# =========================================================================
# 4. Organization Profile & Settings Tests
# =========================================================================

def test_organization_settings_management(client, multi_tenant_fixture):
    """Org Admin can view and modify their organization profile and settings."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    # 1. View settings
    res = client.get('/api/org/settings')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['organization']['name'] == 'VIT University'
    assert data['organization']['domain'] == 'vit.ac.in'

    # 2. Update settings
    res_upd = client.put('/api/org/settings', json={
        'name': 'VIT University Updated',
        'contact_name': 'VIT Registrar',
        'contact_email': 'registrar@vit.ac.in',
        'settings': {
            'threat_sensitivity': 'strict',
            'auto_quarantine': True
        }
    })
    assert res_upd.status_code == 200
    upd_data = res_upd.get_json()
    assert upd_data['success'] is True

    # Confirm updated in DB
    inst = InstitutionModel.get_by_id(f['inst_a_id'])
    assert inst['name'] == 'VIT University Updated'
    assert inst['contact_name'] == 'VIT Registrar'


# =========================================================================
# 5. Warning Service Integrity Verification
# =========================================================================

def test_warning_service_remains_functional(client, multi_tenant_fixture):
    """Admin warning service diagnostics and preview work seamlessly with tenant isolation."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    # Warning preview
    rec = AnalysisModel.get_by_id(f['analysis_a_id'], institution_id=f['inst_a_id'], role='org_admin')
    assert rec is not None

    preview = admin_warning_service.get_warning_preview(rec)
    assert 'target_recipient' in preview
    assert 'warning_subject' in preview
    assert 'warning_body' in preview


# =========================================================================
# 6. Explicit 13-Point Multi-Tenant Verification Tests
# =========================================================================

def test_super_admin_role_alias_and_approvals(client, multi_tenant_fixture):
    """TEST 1 & 3: SUPER_ADMIN role alias can view pending approvals and approve organizations."""
    f = multi_tenant_fixture
    login_as(client, f['owner_id'], 'jayachandra', 'SUPER_ADMIN', full_name="Jaya Chandra Vennam")

    # 1. SUPER_ADMIN can view pending approvals
    res = client.get('/api/admin/pending-registrations')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'pending_orgs' in data

    # 2. SUPER_ADMIN can approve organization
    res_app = client.post(f"/api/admin/approve-org/{f['inst_gamma_id']}")
    assert res_app.status_code == 200
    assert res_app.get_json()['success'] is True


def test_organization_admin_role_alias_rejections(client, multi_tenant_fixture):
    """TEST 2 & 4 & 11: ORGANIZATION_ADMIN cannot view pending approvals or approve organizations (HTTP 403)."""
    f = multi_tenant_fixture
    login_as(client, f['admin_a_id'], 'vit_admin', 'ORGANIZATION_ADMIN', institution_id=f['inst_a_id'], full_name="Alexa")

    # 1. ORGANIZATION_ADMIN cannot view pending approvals
    res1 = client.get('/api/admin/pending-registrations')
    assert res1.status_code == 403

    # 2. ORGANIZATION_ADMIN cannot approve organizations
    res2 = client.post(f"/api/admin/approve-org/{f['inst_gamma_id']}")
    assert res2.status_code == 403

    # 3. ORGANIZATION_ADMIN cannot access platform overview
    res3 = client.get('/api/admin/platform-overview')
    assert res3.status_code == 403


def test_org_admin_cannot_access_other_org_mailboxes_threats_incidents(client, multi_tenant_fixture):
    """TEST 8, 9, 10: Organization Admin cannot access another organization's mailboxes, incidents, or threats."""
    f = multi_tenant_fixture
    login_as(client, f['admin_b_id'], 'abc_admin', 'org_admin', institution_id=f['inst_b_id'])

    # 1. Cross-tenant incident details (Institution A incident requested by Org Admin B)
    res_inc = client.get(f"/api/analysis/history/{f['analysis_a_id']}")
    assert res_inc.status_code in (403, 404)

    # 2. Cross-tenant threat statistics (Org Admin B cannot query Institution A stats)
    res_threats = client.get(f"/api/institutions/{f['inst_a_id']}/stats")
    assert res_threats.status_code == 403

    # 3. Cross-tenant mailbox emails
    res_mb_emails = client.get(f"/api/mailboxes/999/emails?institution_id={f['inst_a_id']}")
    # Even with parameter tampering, user B is confined to inst B (returns 404 for mailbox not in tenant B)
    assert res_mb_emails.status_code in (403, 404)


def test_member_categories_support_universities_and_companies(client, multi_tenant_fixture):
    """TEST 5, 6, 7: Organization Admin can add and view members across categories (student, faculty, staff, employee, worker, other)."""
    f = multi_tenant_fixture

    # University Admin (Institution A) adds student, faculty, staff
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])
    for cat, email in [('student', 's1@vit.ac.in'), ('faculty', 'f1@vit.ac.in'), ('staff', 'st1@vit.ac.in')]:
        res = client.post('/api/members', json={
            'full_name': f'Test {cat.capitalize()}',
            'email': email,
            'member_type': cat,
            'department': 'Campus Ops'
        })
        assert res.status_code == 201

    # Company Admin (Institution B) adds employee, worker, other
    login_as(client, f['admin_b_id'], 'abc_admin', 'org_admin', institution_id=f['inst_b_id'])
    for cat, email in [('employee', 'e1@abccorp.com'), ('worker', 'w1@abccorp.com'), ('other', 'o1@abccorp.com')]:
        res = client.post('/api/members', json={
            'full_name': f'Corp {cat.capitalize()}',
            'email': email,
            'member_type': cat,
            'department': 'Corporate Ops'
        })
        assert res.status_code == 201

    # Cross-tenant isolation verification: Admin B cannot see Admin A's members
    res_b_list = client.get('/api/members')
    assert res_b_list.status_code == 200
    b_emails = [m['email'] for m in res_b_list.get_json()['members']]
    assert 'e1@abccorp.com' in b_emails
    assert 'w1@abccorp.com' in b_emails
    assert 's1@vit.ac.in' not in b_emails
    assert 'f1@vit.ac.in' not in b_emails


def test_org_admin_mailbox_full_lifecycle(client, multi_tenant_fixture, monkeypatch):
    """TEST 3, 4, 5, 10: Organization Admin can create, test, update, toggle, sync, and delete mailboxes for their org, but never other orgs."""
    f = multi_tenant_fixture

    # Mock preflight and sync to isolate from external networks
    monkeypatch.setattr(admin_warning_service, 'send_warning_email', lambda *args, **kwargs: (True, "Mocked"))
    from bullymail.services.email_service import EmailService, email_service
    from bullymail.routes.email_integration import mailbox_processor
    monkeypatch.setattr(EmailService, 'test_preflight_connection', lambda *args, **kwargs: (True, "Connection OK"))
    monkeypatch.setattr(email_service, 'test_preflight_connection', lambda *args, **kwargs: (True, "Connection OK"))
    monkeypatch.setattr(mailbox_processor, 'process_mailbox', lambda *args, **kwargs: {'success': True, 'emails_processed': 1, 'threats_detected': 0, 'duplicates_skipped': 0})

    # Org Admin Alpha logs in
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    # 1. Create mailbox for Organization A
    res_create = client.post('/api/mailbox', json={
        'email_address': 'soc-inbox@vit.ac.in',
        'app_password': 'vit_app_password_123',
        'imap_server': 'imap.gmail.com'
    })
    assert res_create.status_code == 200
    mb_a_id = res_create.get_json()['mailbox_id']
    assert mb_a_id is not None

    # 2. Test Connection
    res_test = client.post(f'/api/mailbox/{mb_a_id}/test')
    assert res_test.status_code == 200
    assert res_test.get_json()['success'] is True

    # 3. Update mailbox credentials
    res_update = client.put(f'/api/admin/mailboxes/{mb_a_id}', json={
        'email_address': 'soc-updated@vit.ac.in',
        'app_password': 'vit_updated_password_456'
    })
    assert res_update.status_code == 200
    assert res_update.get_json()['success'] is True

    # 4. Disable and Enable mailbox
    res_dis = client.post(f'/api/mailbox/{mb_a_id}/disable')
    assert res_dis.status_code == 200
    res_en = client.post(f'/api/mailbox/{mb_a_id}/enable')
    assert res_en.status_code == 200

    # 5. Sync mailbox
    res_sync = client.post(f'/api/mailbox/{mb_a_id}/sync')
    assert res_sync.status_code == 200
    assert res_sync.get_json()['success'] is True

    # 6. Cross-Tenant Tampering Check: Org Admin B attempts to access, sync, or delete Org A's mailbox
    login_as(client, f['admin_b_id'], 'abc_admin', 'org_admin', institution_id=f['inst_b_id'])
    
    # Org Admin B cannot access Org A's mailbox
    res_b_get = client.get(f'/api/mailbox/{mb_a_id}')
    assert res_b_get.status_code == 404

    # Org Admin B cannot sync Org A's mailbox
    res_b_sync = client.post(f'/api/mailbox/{mb_a_id}/sync')
    assert res_b_sync.status_code in (403, 404)

    # Org Admin B cannot disable Org A's mailbox
    res_b_dis = client.post(f'/api/mailbox/{mb_a_id}/disable')
    assert res_b_dis.status_code in (403, 404)

    # Org Admin B cannot delete Org A's mailbox
    res_b_del = client.delete(f'/api/admin/mailboxes/{mb_a_id}')
    assert res_b_del.status_code in (403, 404)

    # 7. Org Admin A logs back in and deletes the mailbox successfully
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])
    res_a_del = client.delete(f'/api/admin/mailboxes/{mb_a_id}')
    assert res_a_del.status_code == 200
    assert res_a_del.get_json()['success'] is True


def test_org_admin_member_update_and_remove(client, multi_tenant_fixture):
    """TEST 6, 7, 8, 9: Organization Admin can update and remove their members, but cannot touch other orgs' members."""
    f = multi_tenant_fixture

    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])

    # 1. Update Member A
    res_up = client.put(f"/api/members/{f['member_a_id']}", json={
        'full_name': 'Alice Student Updated',
        'department': 'Cyber Security',
        'status': 'ACTIVE'
    })
    assert res_up.status_code == 200

    # 2. Admin B attempts to update Member A -> fails closed (404 or 403)
    login_as(client, f['admin_b_id'], 'abc_admin', 'org_admin', institution_id=f['inst_b_id'])
    res_b_up = client.put(f"/api/members/{f['member_a_id']}", json={'full_name': 'Hacked Alice'})
    assert res_b_up.status_code in (403, 404)

    # 3. Admin B attempts to delete Member A -> fails closed (404 or 403)
    res_b_del = client.delete(f"/api/members/{f['member_a_id']}")
    assert res_b_del.status_code in (403, 404)

    # 4. Admin A deletes Member A -> succeeds
    login_as(client, f['admin_a_id'], 'vit_admin', 'org_admin', institution_id=f['inst_a_id'])
    res_a_del = client.delete(f"/api/members/{f['member_a_id']}")
    assert res_a_del.status_code == 200

    # Verify Member A is deleted
    res_verify = client.get(f"/api/members/{f['member_a_id']}")
    assert res_verify.status_code == 404


def test_disabled_organization_denied_access(client, multi_tenant_fixture):
    """TEST 15: Disabled / Inactive accounts cannot access protected tenant resources."""
    f = multi_tenant_fixture

    # Pending user (status PENDING_ADMIN_APPROVAL) cannot access tenant APIs
    login_as(client, f['pending_user_id'], 'gamma_admin', 'org_admin', institution_id=f['inst_gamma_id'])
    res = client.get('/api/mailboxes')
    assert res.status_code in (401, 403)

    res_members = client.get('/api/members')
    assert res_members.status_code in (401, 403)


def test_acceptance_scenario_a_to_q(client, monkeypatch):
    """
    TEST 16 & ACCEPTANCE SCENARIO:
    A. Register: Organization: Test University, Admin: testadmin
    B. Log in as Jaya Chandra (Platform Owner).
    C. Open Pending Approvals.
    D. Approve Test University.
    E. Log out.
    F. Log in as testadmin.
    G. Confirm testadmin sees independent organization dashboard.
    H. Confirm testadmin does NOT see Pending Approvals.
    I. Open Secure Mailbox.
    J. Confirm testadmin can: Add, Edit, Test, Sync, Disable, Delete, Open Inbox, Activity Details.
    K. Open Organization / Members.
    L. Confirm testadmin can add student, faculty, staff.
    M. Confirm these records belong only to Test University.
    N. Log in as Jaya.
    O. Confirm Jaya can still see platform-wide organization management and Pending Approvals.
    P. Create a second test organization.
    Q. Confirm Test University admin cannot see or access the second organization's data.
    """
    from bullymail.services.email_service import EmailService, email_service
    from bullymail.routes.email_integration import mailbox_processor
    monkeypatch.setattr(EmailService, 'test_preflight_connection', lambda *args, **kwargs: (True, "Connection Verified"))
    monkeypatch.setattr(email_service, 'test_preflight_connection', lambda *args, **kwargs: (True, "Connection Verified"))
    monkeypatch.setattr(mailbox_processor, 'process_mailbox', lambda *args, **kwargs: {'success': True, 'emails_processed': 2, 'threats_detected': 0, 'duplicates_skipped': 0})

    # A. Register Organization: Test University, Admin: testadmin
    with client.application.app_context():
        # Setup Jaya Chandra Vennam as Platform Owner
        owner_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status) VALUES (%s, %s, %s, %s, %s, %s)",
            ("jayachandra_acc", "Jaya Chandra Vennam", UserModel.hash_password("JayaPass123!"), "platform_owner", "jaya_acc@bullymail.io", "ACTIVE")
        )
        # Register new org
        reg_org_id = InstitutionModel.create_institution("Test University", "testuniv.edu", org_type="university", code="TUNIV")
        InstitutionModel.update_status(reg_org_id, 'PENDING_APPROVAL')
        testadmin_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status, institution_id, requested_institution_domain) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            ("testadmin", "Test Admin", UserModel.hash_password("AdminPass123!"), "org_admin", "admin@testuniv.edu", "PENDING_ADMIN_APPROVAL", reg_org_id, "testuniv.edu")
        )

    # B. Log in as Jaya Chandra
    login_as(client, owner_id, 'jayachandra_acc', 'platform_owner', full_name="Jaya Chandra Vennam")

    # C. Open Pending Approvals
    res_pend = client.get('/pending-approvals')
    assert res_pend.status_code == 200
    pend_data = res_pend.get_json()
    assert pend_data['success'] is True
    assert any(o['id'] == reg_org_id for o in pend_data['pending_orgs'])

    # D. Approve Test University
    res_app = client.post('/approve-organization', json={'organization_id': reg_org_id})
    assert res_app.status_code == 200
    assert res_app.get_json()['success'] is True

    # E. Log out
    client.get('/logout')

    # F. Log in as testadmin
    login_as(client, testadmin_id, 'testadmin', 'org_admin', institution_id=reg_org_id, full_name="Test Admin")

    # G. Confirm testadmin sees independent organization dashboard
    res_dash = client.get('/dashboard')
    assert res_dash.status_code == 200
    res_status = client.get('/api/auth/status')
    assert res_status.get_json()['institution_id'] == reg_org_id
    assert res_status.get_json()['role'] == 'org_admin'

    # H. Confirm testadmin does NOT see Pending Approvals (HTTP 403 Forbidden)
    res_no_pend = client.get('/pending-approvals')
    assert res_no_pend.status_code == 403
    res_no_app = client.post('/approve-organization', json={'organization_id': reg_org_id})
    assert res_no_app.status_code == 403

    # I. Open Secure Mailbox
    res_mbs = client.get('/api/mailboxes')
    assert res_mbs.status_code == 200
    assert res_mbs.get_json()['success'] is True

    # J. Confirm testadmin can perform all mailbox actions
    # 1. Add Secure Mailbox
    res_add_mb = client.post('/api/mailbox', json={
        'email_address': 'threats@testuniv.edu',
        'app_password': 'secret_password_99',
        'imap_server': 'imap.testuniv.edu'
    })
    assert res_add_mb.status_code == 200
    test_mb_id = res_add_mb.get_json()['mailbox_id']

    # 2. Activity Details
    res_mb_act = client.get(f'/api/mailbox/{test_mb_id}')
    assert res_mb_act.status_code == 200

    # 3. Test Connection
    res_mb_test = client.post(f'/api/mailbox/{test_mb_id}/test')
    assert res_mb_test.status_code == 200

    # 4. Sync
    res_mb_sync = client.post(f'/api/mailbox/{test_mb_id}/sync')
    assert res_mb_sync.status_code == 200

    # 5. Disable and Enable
    assert client.post(f'/api/mailbox/{test_mb_id}/disable').status_code == 200
    assert client.post(f'/api/mailbox/{test_mb_id}/enable').status_code == 200

    # 6. Edit Credentials
    res_mb_edit = client.put(f'/api/admin/mailboxes/{test_mb_id}', json={
        'email_address': 'threats-updated@testuniv.edu'
    })
    assert res_mb_edit.status_code == 200

    # 7. Open Inbox
    res_inbox = client.get(f'/api/mailboxes/{test_mb_id}/emails')
    assert res_inbox.status_code == 200

    # K. Open Organization / Members
    res_mem_list = client.get('/api/members')
    assert res_mem_list.status_code == 200

    # L. Confirm testadmin can add student, faculty, staff
    for cat, email in [
        ('student', 'student@example.com'),
        ('faculty', 'faculty@example.com'),
        ('staff', 'staff@example.com')
    ]:
        res_add_m = client.post('/api/members', json={
            'full_name': f'Test {cat.capitalize()}',
            'email': email,
            'member_type': cat,
            'department': 'Academics'
        })
        assert res_add_m.status_code == 201

    # M. Confirm these records belong only to Test University
    members_data = client.get('/api/members').get_json()
    assert members_data['total'] == 3
    for m in members_data['members']:
        assert m['institution_id'] == reg_org_id

    # N. Log in as Jaya
    login_as(client, owner_id, 'jayachandra_acc', 'platform_owner', full_name="Jaya Chandra Vennam")

    # O. Confirm Jaya can still see platform-wide organization management and Pending Approvals
    res_jaya_orgs = client.get('/api/institutions')
    assert res_jaya_orgs.status_code == 200
    assert len(res_jaya_orgs.get_json()['institutions']) >= 2

    # P. Create a second test organization
    with client.application.app_context():
        sec_org_id = InstitutionModel.create_institution("Second Org", "second.org", org_type="company", code="SEC")
        InstitutionModel.update_status(sec_org_id, 'ACTIVE')
        sec_admin_id = execute_query(
            "INSERT INTO users (username, full_name, password_hash, role, email, status, institution_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            ("secadmin", "Second Admin", UserModel.hash_password("Pass123!"), "org_admin", "admin@second.org", "ACTIVE", sec_org_id)
        )
        sec_mb = email_service.configure_mailbox(sec_org_id, 'sec-mailbox@second.org', 'sec_pass')
        sec_mb_id = sec_mb['id']
        OrganizationMemberModel.add_member(sec_org_id, "Sec Worker", "worker@second.org", member_type="worker")

    # Q. Confirm Test University admin cannot see or access the second organization's users, mailboxes, emails, incidents or data
    login_as(client, testadmin_id, 'testadmin', 'org_admin', institution_id=reg_org_id)

    # 1. Members: cannot see second org's worker
    tuniv_members = client.get('/api/members').get_json()['members']
    assert not any(m['email'] == 'worker@second.org' for m in tuniv_members)

    # 2. Cannot query second org members via parameter tampering
    res_tamper_mem = client.get(f'/api/members?institution_id={sec_org_id}')
    assert res_tamper_mem.status_code == 403

    # 3. Mailboxes: cannot see second org's mailbox
    tuniv_mbs = client.get('/api/mailboxes').get_json()['mailboxes']
    assert not any(mb['id'] == sec_mb_id for mb in tuniv_mbs)

    # 4. Cannot sync or delete second org's mailbox
    assert client.post(f'/api/mailbox/{sec_mb_id}/sync').status_code in (403, 404)
    assert client.delete(f'/api/admin/mailboxes/{sec_mb_id}').status_code in (403, 404)

