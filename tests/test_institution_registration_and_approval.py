import pytest
from bullymail.models.user import UserModel
from bullymail.models.institution import InstitutionModel
from bullymail.services.auth_token_service import AuthTokenService
from bullymail.config import TestConfig

def test_institution_admin_registration_creates_pending_org_and_user(client):
    """
    Test that registering as an institution admin creates:
    1. A pending institution in institutions table with status PENDING_APPROVAL.
    2. A pending user in users table with status PENDING_EMAIL_VERIFICATION linked to the institution.
    3. Direct verification URL in response.
    """
    email = "cocanvascontact@gmail.com"
    pw = "StrongPass_2026_Key!"
    res = client.post('/signup', json={
        'organization_name': 'CoCanvas Online',
        'organization_type': 'university',
        'organization_domain': '',  # Left blank to test domain derivation from org name
        'full_name': 'CoCanvas Admin',
        'username': 'cocanvas_admin',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'verification_url' in data
    assert '/verify-email?token=' in data['verification_url']

    # Verify user record created
    user = UserModel.get_by_email(email)
    assert user is not None
    assert user['username'] == 'cocanvas_admin'
    assert user['status'] == 'PENDING_EMAIL_VERIFICATION'
    assert user['role'] == 'org_admin'
    assert user['institution_id'] is None  # CRITICAL: MUST BE NULL BEFORE APPROVAL!
    assert user['requested_institution_name'] == 'CoCanvas Online'
    assert user['requested_institution_domain'] == 'cocanvasonline.org'

    # Verify institution record created with PENDING_APPROVAL and derived domain
    inst = InstitutionModel.get_by_domain('cocanvasonline.org')
    assert inst is not None
    assert inst['name'] == 'CoCanvas Online'
    assert inst['status'] == 'PENDING_APPROVAL'
    assert inst['domain'] == 'cocanvasonline.org'
    assert inst['domain'] != 'gmail.com'

def test_pending_registrations_visible_to_super_admin(client, auth_client):
    """
    Verify that both pending organizations and unverified pending users appear
    in the Super Admin's /api/admin/pending-registrations queue.
    """
    email = "dean_science@vit.ac.in"
    pw = "StrongPass_2026_Key!"
    res = client.post('/signup', json={
        'organization_name': 'VIT University',
        'organization_type': 'university',
        'organization_domain': 'vit.ac.in',
        'full_name': 'Dean Science',
        'username': 'vit_dean',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })
    assert res.status_code == 200

    # Query pending registrations as Super Admin (platform_owner)
    admin_res = auth_client.get('/api/admin/pending-registrations')
    assert admin_res.status_code == 200
    data = admin_res.get_json()
    assert data['success'] is True

    # 1. Pending user must be in pending_users list
    pending_users = data['pending_users']
    user_emails = [u['email'] for u in pending_users]
    assert email in user_emails

    pending_user = next(u for u in pending_users if u['email'] == email)
    assert pending_user['status'] == 'PENDING_EMAIL_VERIFICATION'
    assert pending_user['role'] == 'org_admin'
    assert pending_user['institution_name'] == 'VIT University'

    # 2. Pending organization must be in pending_orgs list
    pending_orgs = data['pending_orgs']
    org_names = [o['name'] for o in pending_orgs]
    assert 'VIT University' in org_names

    # 3. Overall pending_count must include both
    assert data['pending_count'] >= 2

def test_super_admin_can_approve_pending_user_directly(client, auth_client):
    """
    Verify that Super Admin can directly approve a user who is in
    PENDING_EMAIL_VERIFICATION state, which activates both user and institution.
    """
    email = "prof_brown@oxford.edu"
    pw = "StrongPass_2026_Key!"
    res = client.post('/signup', json={
        'organization_name': 'Oxford Security Lab',
        'organization_type': 'university',
        'organization_domain': 'oxford.edu',
        'full_name': 'Prof Brown',
        'username': 'prof_brown',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })
    assert res.status_code == 200

    user = UserModel.get_by_email(email)
    assert user['status'] == 'PENDING_EMAIL_VERIFICATION'
    assert user['institution_id'] is None
    user_id = user['id']
    inst = InstitutionModel.get_by_domain('oxford.edu')
    inst_id = inst['id']

    # Super Admin approves the user
    approve_res = auth_client.post('/api/admin/approve-user', json={
        'user_id': user_id,
        'action': 'approve',
        'provision_type': 'assign_existing',
        'institution_id': inst_id,
        'role': 'org_admin'
    })
    assert approve_res.status_code == 200
    assert approve_res.get_json()['success'] is True

    # Verify user is now ACTIVE with role org_admin and verified email
    updated_user = UserModel.get_by_id(user_id)
    assert updated_user['status'] == 'ACTIVE'
    assert updated_user['role'] == 'org_admin'
    assert updated_user['institution_id'] == inst_id
    assert updated_user['email_verified_at'] is not None

    # Verify institution is now ACTIVE
    updated_inst = InstitutionModel.get_by_id(inst_id)
    assert updated_inst['status'] == 'ACTIVE'

    # Verify the approved org admin can now log in
    login_res = client.post('/login', json={'username': 'prof_brown', 'password': pw})
    assert login_res.status_code == 200
    assert login_res.get_json()['success'] is True

def test_super_admin_can_approve_pending_org_directly(client, auth_client):
    """
    Verify that Super Admin approving an organization via /api/admin/approve-org/<id>
    activates the institution AND activates its applicant admin accounts.
    """
    email = "director@cambridge.edu"
    pw = "StrongPass_2026_Key!"
    res = client.post('/signup', json={
        'organization_name': 'Cambridge Cyber Centre',
        'organization_type': 'university',
        'organization_domain': 'cambridge.edu',
        'full_name': 'Director Cyber',
        'username': 'cam_director',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })
    assert res.status_code == 200

    user = UserModel.get_by_email(email)
    assert user['institution_id'] is None
    inst = InstitutionModel.get_by_domain('cambridge.edu')
    inst_id = inst['id']

    # Super Admin approves the organization
    approve_res = auth_client.post(f'/api/admin/approve-org/{inst_id}')
    assert approve_res.status_code == 200
    assert approve_res.get_json()['success'] is True

    # Institution is now ACTIVE
    inst = InstitutionModel.get_by_id(inst_id)
    assert inst['status'] == 'ACTIVE'

    # Associated user is now ACTIVE as org_admin
    updated_user = UserModel.get_by_id(user['id'])
    assert updated_user['status'] == 'ACTIVE'
    assert updated_user['role'] == 'org_admin'
    assert updated_user['institution_id'] == inst_id

    # Approved user can log in
    login_res = client.post('/login', json={'username': 'cam_director', 'password': pw})
    assert login_res.status_code == 200
    assert login_res.get_json()['success'] is True

def test_username_collision_gives_clear_error(client):
    """
    Verify that trying to sign up with a username that already belongs to another
    user returns an informative 400 error rather than silently failing.
    """
    # Create an initial user
    UserModel.create_user('existing_admin_nick', 'StrongPass_2026_Key!', email='existing_nick@test.com', status='ACTIVE')

    # Another applicant tries using the same username
    res = client.post('/signup', json={
        'organization_name': 'New Tech Org',
        'username': 'existing_admin_nick',
        'email': 'different_email@test.com',
        'password': 'StrongPass_2026_Key!',
        'confirm_password': 'StrongPass_2026_Key!'
    })
    assert res.status_code == 400
    data = res.get_json()
    assert data['success'] is False
    assert 'already taken' in data['error'].lower()

def test_direct_email_verification_token_flow(client):
    """
    Verify that following the direct verification token (/verify-email?token=...)
    moves user from PENDING_EMAIL_VERIFICATION to PENDING_ADMIN_APPROVAL.
    """
    email = "token_flow_user@gmail.com"
    pw = "StrongPass_2026_Key!"
    res = client.post('/signup', json={
        'organization_name': 'Flow Test Org',
        'username': 'flow_user',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })
    assert res.status_code == 200
    verify_url = res.get_json()['verification_url']
    raw_token = verify_url.split('token=')[-1]

    # Verify token
    verify_res = client.get(f'/verify-email?token={raw_token}')
    assert verify_res.status_code == 200

    # User status is now PENDING_ADMIN_APPROVAL
    user = UserModel.get_by_email(email)
    assert user['status'] == 'PENDING_ADMIN_APPROVAL'
    assert user['email_verified_at'] is not None


def test_reapplying_rejected_or_pending_user_resets_status_and_reappears_in_super_admin_queue(client, auth_client):
    """
    Verify that an applicant whose account was previously in REJECTED status can re-apply,
    which resets status to PENDING_EMAIL_VERIFICATION, generates a fresh verification link,
    provisions the pending organization, and ensures the user appears in the Super Admin's
    pending approvals queue with institution_id = NULL.
    """
    email = "cocanvascontact@gmail.com"
    pw = "StrongPass_2026_Key!"

    # 1. Simulate previously rejected user account in the database
    old_uid = UserModel.create_user(
        username="cocanvas_old",
        password=pw,
        email=email,
        role="org_admin",
        status="REJECTED",
        institution_id=None,
        requested_institution_name="Old Canvas Corp",
        requested_institution_domain="oldcanvas.org"
    )
    assert old_uid is not None
    rejected_user = UserModel.get_by_email(email)
    assert rejected_user['status'] == 'REJECTED'

    # Super Admin should NOT see rejected users in pending approvals
    admin_pending_before = auth_client.get('/api/admin/pending-registrations').get_json()
    assert email not in [u['email'] for u in admin_pending_before.get('pending_users', [])]

    # 2. Applicant re-applies through /signup with their official email
    res = client.post('/signup', json={
        'organization_name': 'CoCanvas Online',
        'organization_type': 'university',
        'organization_domain': 'cocanvas.org',
        'full_name': 'CoCanvas Official Admin',
        'username': 'cocanvascontact',
        'email': email,
        'password': pw,
        'confirm_password': pw
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'verification_url' in data
    assert '/verify-email?token=' in data['verification_url']

    # 3. Database user status is successfully reset to PENDING_EMAIL_VERIFICATION
    updated_user = UserModel.get_by_email(email)
    assert updated_user['id'] == old_uid
    assert updated_user['status'] == 'PENDING_EMAIL_VERIFICATION'
    assert updated_user['requested_institution_name'] == 'CoCanvas Online'
    assert updated_user['requested_institution_domain'] == 'cocanvas.org'
    assert updated_user['institution_id'] is None  # CRITICAL: Tenant boundary isolation preserved!

    # 4. Super Admin now sees this applicant in /api/admin/pending-registrations
    admin_pending_after = auth_client.get('/api/admin/pending-registrations').get_json()
    pending_emails = [u['email'] for u in admin_pending_after.get('pending_users', [])]
    assert email in pending_emails

    pending_entry = next(u for u in admin_pending_after['pending_users'] if u['email'] == email)
    assert pending_entry['status'] == 'PENDING_EMAIL_VERIFICATION'
    assert pending_entry['institution_name'] == 'CoCanvas Online'

    # 5. Super Admin can approve the re-applied user directly
    approve_res = auth_client.post('/api/admin/approve-user', json={
        'user_id': old_uid,
        'action': 'approve',
        'provision_type': 'assign_existing'
    })
    assert approve_res.status_code == 200
    assert approve_res.get_json()['success'] is True

    # User is now ACTIVE
    final_user = UserModel.get_by_id(old_uid)
    assert final_user['status'] == 'ACTIVE'
    assert final_user['institution_id'] is not None

