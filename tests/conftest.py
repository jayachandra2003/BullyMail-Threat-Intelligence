import pytest
import os
import tempfile
from bullymail import create_app
from bullymail.config import Config
from bullymail.database.connection import get_db, init_db

class TestConfig(Config):
    TESTING = True
    DB_TYPE = 'sqlite'
    SQLITE_DB_PATH = ':memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test_secret_key_12345'
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'TestSecretPass_2026!Key'
    ADMIN_EMAIL = 'admin@bullymail.local'
    SESSION_COOKIE_SECURE = False
    MODEL_PATH = tempfile.mkdtemp()
    DATASET_PATH = tempfile.mkdtemp()
    UPLOAD_PATH = tempfile.mkdtemp()

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        init_db()
        yield app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_client(client):
    """Client with an active authenticated admin session."""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'admin'
        sess['role'] = 'admin'
    return client
