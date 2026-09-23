import pytest
import json
import os
from bullymail.config import Config
from bullymail.database.connection import fetch_all
from bullymail.models.user import UserModel

def test_train_model_requires_admin_role(client, app):
    """Verifies that unauthenticated or non-admin users cannot trigger model training."""
    # 1. Unauthenticated request
    res_unauth = client.post('/api/train-model', json={'model_type': 'logistic', 'training_samples': 1000})
    assert res_unauth.status_code == 401
    res_load_unauth = client.post('/api/load-model', json={'model_type': 'latest'})
    assert res_load_unauth.status_code == 401

    # 2. Analyst role request
    with app.app_context():
        user_id = UserModel.create_user(
            username='analyst_user',
            password='TestPassword123!',
            email='analyst@test.com',
            status='PENDING_EMAIL_VERIFICATION'
        )
        UserModel.activate_user_email(user_id)
        UserModel.approve_user_by_admin(user_id, role='analyst', institution_id=1)

    with client.session_transaction() as sess:
        sess['user_id'] = user_id
        sess['username'] = 'analyst_user'
        sess['role'] = 'analyst'
        
    res_analyst = client.post('/api/train-model', json={'model_type': 'logistic', 'training_samples': 1000})
    assert res_analyst.status_code == 403
    res_load_analyst = client.post('/api/load-model', json={'model_type': 'latest'})
    assert res_load_analyst.status_code == 403

def test_train_model_logistic_success_2000_samples(auth_client):
    """Verifies that training Logistic Regression with 2,000 samples succeeds end-to-end."""
    res = auth_client.post('/api/train-model', json={
        'model_type': 'logistic',
        'training_samples': 2000
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'results' in data
    assert 'dataset_telemetry' in data
    
    results = data['results']
    assert results['model_type'] == 'Logistic Regression'
    assert 0.0 <= results['accuracy'] <= 1.0
    assert 0.0 <= results['precision'] <= 1.0
    assert 0.0 <= results['recall'] <= 1.0
    assert 0.0 <= results['f1_score'] <= 1.0
    assert isinstance(results['confusion_matrix'], list)
    assert len(results['confusion_matrix']) == 2
    assert results['training_samples'] == 1500  # 75% of 2000
    assert results['test_samples'] == 500       # 25% of 2000

def test_train_model_svm_success(auth_client):
    """Verifies that training Support Vector Machine with 1,000 samples succeeds end-to-end."""
    res = auth_client.post('/api/train-model', json={
        'model_type': 'svm',
        'training_samples': 1000
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['results']['model_type'] == 'Support Vector Machine (SVM)'
    assert data['results']['training_samples'] == 750
    assert data['results']['test_samples'] == 250

def test_train_model_flexible_payload_aliases(auth_client):
    """Verifies that parameter aliases ('algorithm', 'sample_size') work interchangeably."""
    res = auth_client.post('/api/train-model', json={
        'algorithm': 'logistic',
        'sample_size': 1000
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['results']['model_type'] == 'Logistic Regression'

def test_train_model_records_in_model_history_table(auth_client):
    """Verifies that model evaluation metrics are accurately stored in model_history table."""
    res = auth_client.post('/api/train-model', json={
        'model_type': 'logistic',
        'training_samples': 1000
    })
    assert res.status_code == 200
    
    rows = fetch_all("SELECT * FROM model_history ORDER BY id DESC LIMIT 1")
    assert len(rows) > 0
    latest = rows[0]
    assert latest['model_type'] == 'Logistic Regression'
    assert latest['training_samples'] == 750
    assert latest['test_samples'] == 250
    assert 'confusion_matrix' in latest
    cm = json.loads(latest['confusion_matrix']) if isinstance(latest['confusion_matrix'], str) else latest['confusion_matrix']
    assert isinstance(cm, list)
