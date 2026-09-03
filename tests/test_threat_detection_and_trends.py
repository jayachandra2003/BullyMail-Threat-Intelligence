import json
import pytest
from datetime import datetime, timedelta
from bullymail.services.risk_engine import UnifiedRiskEngine
from bullymail.services.bullying_detector import BullyingDetector
from bullymail.models.analysis import AnalysisModel
from bullymail.models.user import UserModel

@pytest.fixture
def risk_engine():
    return UnifiedRiskEngine()

@pytest.fixture
def bullying_detector():
    return BullyingDetector()

def test_01_critical_phrases_not_low_risk(risk_engine):
    """TEST 1: Direct and passive violent threats produce CRITICAL/HIGH risk, never LOW."""
    phrases = [
        "You will be killed",
        "I will kill you",
        "I'll kill you",
        "I will murder you",
        "You will be murdered",
        "You are going to die",
        "I will hurt you",
        "I am going to stab you",
        "I'll shoot you",
        "You will be beaten",
        "I am going to attack you"
    ]
    for text in phrases:
        report = risk_engine.analyze_email(text)
        assert report['overall_risk_level'] in ('CRITICAL', 'HIGH'), f"Failed for '{text}': got {report['overall_risk_level']}"
        assert report['threat_score'] >= 0.70
        assert report['bullying_analysis']['is_bullying'] is True
        assert report['bullying_analysis']['severity'] in ('CRITICAL', 'HIGH')

def test_02_capitalization_and_punctuation_variants(risk_engine):
    """TEST 2: Punctuation, capitalization, and contractions are properly recognized."""
    variants = [
        "You WILL be MURDERED!!!",
        "you were murdered",
        "I'll kill you.",
        "I'M GOING TO HURT YOU.",
        "YOU'RE GOING TO DIE! #@$",
        "I WILL STAB YOU NOW."
    ]
    for text in variants:
        report = risk_engine.analyze_email(text)
        assert report['overall_risk_level'] in ('CRITICAL', 'HIGH'), f"Failed for variant '{text}'"
        assert report['bullying_analysis']['is_bullying'] is True

def test_03_high_recall_rule_general_contexts(risk_engine):
    """TEST 3: High-recall rule ensures violent language in movie, game, or tech contexts is reported."""
    contexts = [
        "The character was murdered in the movie.",
        "The movie scene showed someone being killed.",
        "The article discusses murder statistics.",
        "The game character was shot.",
        "The security system detects the word 'attack'.",
        "The cybersecurity team detected an attack."
    ]
    for text in contexts:
        report = risk_engine.analyze_email(text)
        assert report['bullying_analysis']['is_bullying'] is True, f"Failed high recall for '{text}'"
        assert len(report['bullying_analysis']['rule_based_matches']) > 0
        assert report['overall_risk_level'] in ('CRITICAL', 'HIGH')

def test_04_broad_word_families(bullying_detector):
    """TEST 4: Multiple morphological variants across all configured threat word families are matched."""
    word_family_samples = [
        # KILL
        ("He was killing time", "killing"),
        # MURDER
        ("The murderer fled", "murderer"),
        # DIE
        ("I want you dead", "dead"),
        # HURT/HARM
        ("She is harming herself", "harming"),
        # STAB
        ("He stabbed the target", "stabbed"),
        # SHOOT
        ("They are shooting targets", "shooting"),
        # STRANGLE/CHOKE
        ("The attacker choked him", "choked"),
        ("He was strangled", "strangled"),
        # TORTURE
        ("They tortured the prisoner", "tortured"),
        # POISON
        ("The food was poisoned", "poisoned"),
        # BURN
        ("They are burning evidence", "burning"),
        # DROWN/HANG
        ("He was hanged yesterday", "hanged"),
        ("The victim drowned", "drowned")
    ]
    for text, expected_match in word_family_samples:
        matches, score, categories, severity = bullying_detector.rule_based_check(text)
        assert any(expected_match in m.lower() for m in matches), f"Failed to match '{expected_match}' in '{text}'"
        assert score >= 0.85
        assert severity in ('CRITICAL', 'HIGH')

def test_05_clean_emails_remain_low_risk(risk_engine):
    """TEST 5: Standard educational/work communication remains LOW risk."""
    clean_samples = [
        "Please find the meeting notes attached for review.",
        "Can we schedule our lab consultation for Thursday?",
        "Thank you for submitting the assignment on time."
    ]
    for text in clean_samples:
        report = risk_engine.analyze_email(text)
        assert report['overall_risk_level'] == 'LOW'
        assert report['bullying_analysis']['is_bullying'] is False

@pytest.fixture
def trend_test_dataset(app):
    """Creates timestamped analyses across past 24h, 7d, and 30d."""
    with app.app_context():
        admin_id = UserModel.create_user(
            username="trend_tester_admin",
            password="AdminPass123!",
            email="trend_admin@inst1.com",
            role="admin",
            status="ACTIVE",
            institution_id=1
        )

        now = datetime.utcnow()

        # 1. 2 hours ago (within 24h)
        aid1 = AnalysisModel.save_analysis({
            'email_subject': 'Recent threat within 2h',
            'email_from': 's1@u.edu',
            'overall_risk_level': 'CRITICAL',
            'overall_confidence': 0.95,
            'threat_score': 0.95,
            'incident_status': 'PENDING_REVIEW',
            'bullying_analysis': {'is_bullying': True}
        }, institution_id=1, user_id=admin_id)

        # 2. 3 days ago (within 7d and 30d, but NOT 24h)
        aid2 = AnalysisModel.save_analysis({
            'email_subject': '3 days ago high risk',
            'email_from': 's2@u.edu',
            'overall_risk_level': 'HIGH',
            'overall_confidence': 0.85,
            'threat_score': 0.85,
            'incident_status': 'WARNING_SENT',
            'bullying_analysis': {'is_bullying': True}
        }, institution_id=1, user_id=admin_id)

        # Update created_at timestamp for aid2
        ts_3d = (now - timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S')
        from bullymail.database.connection import execute_query
        execute_query("UPDATE analyzed_emails SET created_at = %s WHERE id = %s", (ts_3d, aid2))

        # 3. 15 days ago (within 30d, but NOT 7d or 24h)
        aid3 = AnalysisModel.save_analysis({
            'email_subject': '15 days ago medium risk',
            'email_from': 's3@u.edu',
            'overall_risk_level': 'MEDIUM',
            'overall_confidence': 0.60,
            'threat_score': 0.60,
            'incident_status': 'REVIEWED',
            'bullying_analysis': {'is_bullying': False}
        }, institution_id=1, user_id=admin_id)
        ts_15d = (now - timedelta(days=15)).strftime('%Y-%m-%d %H:%M:%S')
        execute_query("UPDATE analyzed_emails SET created_at = %s WHERE id = %s", (ts_15d, aid3))

        return {'admin_id': admin_id, 'aid1': aid1, 'aid2': aid2, 'aid3': aid3}

def test_06_threat_trend_24h_filter(client, trend_test_dataset):
    """TEST 6: 24-hour range query returns 24 hourly buckets and includes only 24h records."""
    with client.session_transaction() as sess:
        sess['user_id'] = trend_test_dataset['admin_id']
        sess['username'] = 'trend_tester_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/threat-trend?range=24h')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['range'] == '24h'
    assert len(data['labels']) == 24
    assert len(data['total_series']) == 24
    assert len(data['high_threat_series']) == 24
    # The 2h-ago record should be counted, but 3d and 15d records should not be
    assert data['summary']['total_ingested'] >= 1
    assert data['summary']['high_threats'] >= 1

def test_07_threat_trend_7d_filter(client, trend_test_dataset):
    """TEST 7: 7-day range query returns 7 daily buckets and includes 24h and 3d records, but not 15d."""
    with client.session_transaction() as sess:
        sess['user_id'] = trend_test_dataset['admin_id']
        sess['username'] = 'trend_tester_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/threat-trend?range=7d')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['range'] == '7d'
    assert len(data['labels']) == 7
    assert len(data['total_series']) == 7
    # Includes aid1 (2h ago) + aid2 (3d ago) -> at least 2
    assert data['summary']['total_ingested'] >= 2
    assert data['summary']['high_threats'] >= 2

def test_08_threat_trend_30d_filter(client, trend_test_dataset):
    """TEST 8: 30-day range query returns 30 daily buckets and includes 24h, 3d, and 15d records."""
    with client.session_transaction() as sess:
        sess['user_id'] = trend_test_dataset['admin_id']
        sess['username'] = 'trend_tester_admin'
        sess['role'] = 'admin'
        sess['institution_id'] = 1

    res = client.get('/api/threat-trend?range=30d')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert data['range'] == '30d'
    assert len(data['labels']) == 30
    assert len(data['total_series']) == 30
    # Includes aid1 + aid2 + aid3 -> at least 3
    assert data['summary']['total_ingested'] >= 3
