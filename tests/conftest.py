import pytest
import os
import tempfile
from bullymail import create_app
from bullymail.config import TestConfig
from bullymail.database.connection import get_db, init_db
from bullymail.services.rate_limiter import auth_rate_limiter, login_rate_limiter

@pytest.fixture(autouse=True)
def reset_rate_limiters():
    """Reset rate limiter state before and after each test for strict test isolation."""
    auth_rate_limiter.reset()
    login_rate_limiter.reset()
    yield
    auth_rate_limiter.reset()
    login_rate_limiter.reset()

@pytest.fixture(autouse=True)
def mock_default_email_delivery(monkeypatch):
    """Mocks outbound transactional emails during testing to prevent external SMTP network dependencies."""
    from bullymail.services.auth_email_service import auth_email_service
    monkeypatch.setattr(
        auth_email_service,
        'send_verification_email',
        lambda *args, **kwargs: (True, "Email sent successfully.")
    )
    monkeypatch.setattr(
        auth_email_service,
        'send_password_reset_email',
        lambda *args, **kwargs: (True, "Email sent successfully.")
    )

@pytest.fixture
def app():
    """Creates a fresh test application supporting isolated SQLite or isolated MySQL test database."""
    target_db_type = os.getenv('DB_TYPE', 'sqlite').strip().lower()

    os.environ['BULLYMAIL_MASTER_KEY'] = 'ghNXQBv5dpR4x5h5UCkhrnfBLXR3nKrZY2mHHTPGRGE='
    from bullymail.services.crypto_service import CryptoService
    CryptoService.reset_instance()

    temp_db_path = None

    if target_db_type == 'mysql':
        test_db_name = os.getenv('MYSQL_TEST_DB_NAME', 'bullymail_test_db')
        class RuntimeTestConfig(TestConfig):
            TESTING = True
            DB_TYPE = 'mysql'
            DB_HOST = os.getenv('DB_HOST', 'localhost')
            DB_PORT = int(os.getenv('DB_PORT', 3306))
            DB_USER = os.getenv('DB_USER', 'root')
            DB_PASSWORD = os.getenv('DB_PASSWORD', '')
            DB_NAME = test_db_name
            WTF_CSRF_ENABLED = False
            SECRET_KEY = 'test_secret_key_12345'
            BULLYMAIL_MASTER_KEY = 'ghNXQBv5dpR4x5h5UCkhrnfBLXR3nKrZY2mHHTPGRGE='
    else:
        temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        temp_db_path = temp_db.name
        temp_db.close()

        class RuntimeTestConfig(TestConfig):
            TESTING = True
            DB_TYPE = 'sqlite'
            SQLITE_DB_PATH = temp_db_path
            WTF_CSRF_ENABLED = False
            SECRET_KEY = 'test_secret_key_12345'
            BULLYMAIL_MASTER_KEY = 'ghNXQBv5dpR4x5h5UCkhrnfBLXR3nKrZY2mHHTPGRGE='

    app_instance = create_app(RuntimeTestConfig)
    with app_instance.app_context():
        init_db()
        yield app_instance

    if temp_db_path:
        try:
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)
        except Exception:
            pass

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
