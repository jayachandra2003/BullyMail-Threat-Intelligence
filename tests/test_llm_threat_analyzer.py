import os
import json
import pytest
from unittest.mock import patch, MagicMock
import urllib.error
from bullymail.services.llm_threat_analyzer import LLMThreatAnalyzer, LLMThreatAnalyzerError
from bullymail.database.connection import fetch_one

@pytest.fixture
def mock_openrouter_success():
    def _make_response(content_dict):
        raw_json = json.dumps(content_dict)
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": raw_json}}],
            "model": "nvidia/nemotron-3.5-lightning:free"
        }).encode('utf-8')
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        return mock_resp
    return _make_response

def test_llm_analyzer_explicit_threat_prompts(mock_openrouter_success):
    threat_prompts = [
        "You will be killed.",
        "I will murder you.",
        "I'll kill you.",
        "I am going to stab you.",
        "I'll shoot you.",
        "You are going to die.",
        "I will hurt you.",
        "I am going to attack you."
    ]

    for prompt in threat_prompts:
        mock_data = {
            "threat_detected": True,
            "severity": "CRITICAL",
            "confidence": 0.95,
            "threat_categories": ["Physical Threat"],
            "explanation": f"Direct threat detected: {prompt}"
        }
        with patch('urllib.request.urlopen', return_value=mock_openrouter_success(mock_data)):
            with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_mock_key"}):
                result = LLMThreatAnalyzer.analyze(email_text=prompt, email_subject="Warning")
                assert result['threat_detected'] is True
                assert result['severity'] == "CRITICAL"
                assert result['confidence'] >= 0.90
                assert "Physical Threat" in result['threat_categories']

def test_llm_analyzer_clean_email(mock_openrouter_success):
    clean_text = "Dear Team, please find the attached lecture notes for tomorrow."
    mock_data = {
        "threat_detected": False,
        "severity": "LOW",
        "confidence": 0.98,
        "threat_categories": [],
        "explanation": "Benign academic email."
    }
    with patch('urllib.request.urlopen', return_value=mock_openrouter_success(mock_data)):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_mock_key"}):
            result = LLMThreatAnalyzer.analyze(email_text=clean_text)
            assert result['threat_detected'] is False
            assert result['severity'] == "LOW"
            assert result['confidence'] >= 0.90
            assert result['threat_categories'] == []

def test_llm_analyzer_missing_api_key():
    with patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}, clear=True):
        with pytest.raises(LLMThreatAnalyzerError) as exc_info:
            LLMThreatAnalyzer.analyze(email_text="Hello world")
        assert "OPENROUTER_API_KEY is not configured" in exc_info.value.message

def test_llm_analyzer_http_401_error():
    err = urllib.error.HTTPError(
        url="https://openrouter.ai/api/v1/chat/completions",
        code=401,
        msg="Unauthorized",
        hdrs={},
        fp=MagicMock(read=lambda: b'{"error": "Invalid API Key"}')
    )
    with patch('urllib.request.urlopen', side_effect=err):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_mock_key"}):
            with pytest.raises(LLMThreatAnalyzerError) as exc_info:
                LLMThreatAnalyzer.analyze(email_text="Test message")
            assert exc_info.value.status_code == 401
            assert "Invalid API key" in exc_info.value.message

def test_llm_analyzer_http_429_error():
    err = urllib.error.HTTPError(
        url="https://openrouter.ai/api/v1/chat/completions",
        code=429,
        msg="Rate Limit",
        hdrs={},
        fp=MagicMock(read=lambda: b'{"error": "Rate limit exceeded"}')
    )
    with patch('urllib.request.urlopen', side_effect=err):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_mock_key"}):
            with pytest.raises(LLMThreatAnalyzerError) as exc_info:
                LLMThreatAnalyzer.analyze(email_text="Test message")
            assert exc_info.value.status_code == 429
            assert "Rate limit exceeded" in exc_info.value.message

def test_llm_analyzer_http_500_error():
    err = urllib.error.HTTPError(
        url="https://openrouter.ai/api/v1/chat/completions",
        code=502,
        msg="Bad Gateway",
        hdrs={},
        fp=MagicMock(read=lambda: b'{"error": "Upstream error"}')
    )
    with patch('urllib.request.urlopen', side_effect=err):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_mock_key"}):
            with pytest.raises(LLMThreatAnalyzerError) as exc_info:
                LLMThreatAnalyzer.analyze(email_text="Test message")
            assert exc_info.value.status_code == 502
            assert "upstream server error" in exc_info.value.message

def test_llm_analyzer_network_timeout():
    err = urllib.error.URLError(reason="Connection timed out")
    with patch('urllib.request.urlopen', side_effect=err):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_mock_key"}):
            with pytest.raises(LLMThreatAnalyzerError) as exc_info:
                LLMThreatAnalyzer.analyze(email_text="Test message")
            assert exc_info.value.status_code == 504
            assert "timeout or connection error" in exc_info.value.message

def test_llm_route_normal_mode(auth_client):
    # Ensure Normal mode does NOT invoke LLMThreatAnalyzer and saves analysis
    with patch('bullymail.services.llm_threat_analyzer.LLMThreatAnalyzer.analyze') as mock_llm:
        resp = auth_client.post('/api/analyze-email', data={
            'email_text': 'You will be killed.',
            'email_subject': 'Disciplinary',
            'engine': 'normal'
        })

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['mode'] == 'normal'
        assert 'report' in data
        assert mock_llm.called is False

def test_llm_route_llm_mode(auth_client, mock_openrouter_success):
    mock_data = {
        "threat_detected": True,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "threat_categories": ["Physical Threat"],
        "explanation": "Explicit violent threat detected."
    }

    with patch('urllib.request.urlopen', return_value=mock_openrouter_success(mock_data)):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_mock_key"}):
            # Count records before
            before = fetch_one("SELECT COUNT(*) as count FROM analyzed_emails")
            before_count = before['count'] if before else 0

            resp = auth_client.post('/api/analyze-email', data={
                'email_text': 'You will be killed.',
                'email_subject': 'Warning',
                'engine': 'llm'
            })

            assert resp.status_code == 200
            data = resp.get_json()
            assert data['success'] is True
            assert data['mode'] == 'llm'
            assert 'llm_report' in data
            assert data['llm_report']['threat_detected'] is True
            assert data['llm_report']['severity'] == 'CRITICAL'
            assert data['llm_report']['confidence'] == 0.95

            # NO Database contamination check
            after = fetch_one("SELECT COUNT(*) as count FROM analyzed_emails")
            after_count = after['count'] if after else 0
            assert after_count == before_count
