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

@pytest.fixture
def app():
    """Creates a fresh test application with an isolated temporary SQLite database."""
    temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    temp_db_path = temp_db.name
    temp_db.close()

    class RuntimeTestConfig(TestConfig):
        TESTING = True
        DB_TYPE = 'sqlite'
        SQLITE_DB_PATH = temp_db_path
        WTF_CSRF_ENABLED = False
        SECRET_KEY = 'test_secret_key_12345'

    app_instance = create_app(RuntimeTestConfig)
    with app_instance.app_context():
        init_db()
        yield app_instance

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
