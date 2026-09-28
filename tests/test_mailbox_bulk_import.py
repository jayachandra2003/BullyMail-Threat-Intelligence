import io
import pytest
from bullymail.models.user import UserModel
from bullymail.database.connection import fetch_all, fetch_one, execute_query
from bullymail.services.crypto_service import CryptoService

@pytest.fixture
def org_admin_session(client, app):
    """Sets up an Organization Admin session bound to institution 1."""
    with app.app_context():
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (1, 'Denver SOC', 'denver.edu')")
        execute_query("INSERT OR IGNORE INTO institutions (id, name, domain) VALUES (2, 'Boulder SOC', 'boulder.edu')")
        user_id = UserModel.create_user(
            username='denver_admin',
            password='TestPassword123!',
            email='denver_admin@denver.edu',
            status='ACTIVE',
            role='org_admin',
            institution_id=1
        )
    client.post('/login', json={'username': 'denver_admin', 'password': 'TestPassword123!'})
    return {'user_id': user_id, 'institution_id': 1}

def test_download_mailbox_template_unauthorized(client):
    """Unauthenticated users cannot download CSV template."""
    res = client.get('/api/mailboxes/template-csv')
    assert res.status_code in (401, 302)

def test_download_mailbox_template_success(client, org_admin_session):
    """Authenticated Org Admin can download mailbox CSV template."""
    res = client.get('/api/mailboxes/template-csv')
    assert res.status_code == 200
    assert 'text/csv' in res.content_type
    assert b'email_address,app_password' in res.data
    assert b'counseling@example.edu' in res.data

def test_import_mailboxes_csv_success(client, org_admin_session):
    """Verifies bulk CSV mailbox import end-to-end with password encryption."""
    csv_content = (
        "email_address,app_password,provider,imap_server,smtp_server,smtp_port\n"
        "counseling@denver.edu,SecretPass1!,gmail,imap.gmail.com,smtp.gmail.com,587\n"
        "helpdesk@denver.edu,SecretPass2!,outlook,outlook.office365.com,smtp.office365.com,587\n"
    )
    data = {
        'file': (io.BytesIO(csv_content.encode('utf-8')), 'test_mailboxes.csv'),
        'institution_id': '1'
    }
    res = client.post('/api/mailboxes/import-csv', data=data, content_type='multipart/form-data')
    assert res.status_code == 200
    resp_data = res.get_json()
    assert resp_data['success'] is True
    assert resp_data['imported'] == 2
    assert resp_data['updated'] == 0
    assert len(resp_data['errors']) == 0

    # Verify rows in DB
    rows = fetch_all("SELECT * FROM email_config WHERE institution_id = 1 AND email_address IN ('counseling@denver.edu', 'helpdesk@denver.edu')")
    assert len(rows) == 2
    for r in rows:
        assert r['status'] == 'active'
        assert r['encrypted_app_password'] is not None
        assert r['encrypted_app_password'].startswith('gAAAAA')
        # Check decryption works
        decrypted = CryptoService.decrypt(r['encrypted_app_password'])
        assert decrypted in ('SecretPass1!', 'SecretPass2!')

def test_import_mailboxes_csv_updates_existing(client, org_admin_session):
    """Verifies that re-importing an existing mailbox updates credentials without duplicating."""
    csv_initial = (
        "email_address,app_password\n"
        "desk@denver.edu,OldPassword123!\n"
    )
    client.post('/api/mailboxes/import-csv', data={'file': (io.BytesIO(csv_initial.encode('utf-8')), 'init.csv')}, content_type='multipart/form-data')

    # Re-import with new password
    csv_update = (
        "email_address,app_password\n"
        "desk@denver.edu,NewPassword456!\n"
    )
    res = client.post('/api/mailboxes/import-csv', data={'file': (io.BytesIO(csv_update.encode('utf-8')), 'update.csv')}, content_type='multipart/form-data')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['imported'] == 0
    assert data['updated'] == 1

    # Verify DB has only 1 record with new password
    rows = fetch_all("SELECT * FROM email_config WHERE institution_id = 1 AND email_address = 'desk@denver.edu'")
    assert len(rows) == 1
    assert CryptoService.decrypt(rows[0]['encrypted_app_password']) == 'NewPassword456!'

def test_import_mailboxes_csv_validation_errors(client, org_admin_session):
    """Verifies that rows with missing passwords or invalid emails are recorded in errors while valid rows succeed."""
    csv_mixed = (
        "email_address,app_password\n"
        "not-an-email,SomePass123!\n"
        "valid@denver.edu,\n"
        "good@denver.edu,ValidPass789!\n"
    )
    res = client.post('/api/mailboxes/import-csv', data={'file': (io.BytesIO(csv_mixed.encode('utf-8')), 'mixed.csv')}, content_type='multipart/form-data')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['imported'] == 1
    assert len(data['errors']) == 2
    assert "Invalid or missing email" in data['errors'][0]
    assert "Missing App Password" in data['errors'][1]

def test_import_mailboxes_csv_tenant_isolation(client, org_admin_session):
    """Verifies that an Org Admin cannot bulk import mailboxes into a different organization."""
    csv_content = (
        "email_address,app_password\n"
        "infiltrator@boulder.edu,Pass12345!\n"
    )
    res = client.post(
        '/api/mailboxes/import-csv',
        data={'file': (io.BytesIO(csv_content.encode('utf-8')), 'cross_tenant.csv'), 'institution_id': '2'},
        content_type='multipart/form-data'
    )
    assert res.status_code == 403
    assert res.get_json()['success'] is False
