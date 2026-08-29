import pytest
import os
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from unittest.mock import MagicMock

from bullymail.services.imap_client import (
    IMAPClient, IMAPConnectionError, IMAPAuthenticationError, IMAPMailboxError, IMAPFetchError
)
from bullymail.services.mime_parser import SafeMIMEParser, MIMEParserError, MIMESizeLimitExceeded
from bullymail.models.ingested_message import IngestedMessageModel

# -----------------------------------------------------------------------------
# 1. IMAP CLIENT TESTS (MOCKED NETWORK)
# -----------------------------------------------------------------------------

def test_imap_client_successful_connection(monkeypatch):
    """Verifies successful IMAP connection and login using mocked IMAP4_SSL."""
    mock_imap = MagicMock()
    mock_imap.login.return_value = ('OK', [b'Logged in'])
    monkeypatch.setattr('imaplib.IMAP4_SSL', lambda *args, **kwargs: mock_imap)

    mock_email_svc = MagicMock()
    mock_email_svc._get_credentials.return_value = ('test@inst.com', 'EncryptedPass123', 'smtp.gmail.com', 587, 'imap.gmail.com')

    client = IMAPClient(institution_id=1, email_service=mock_email_svc)
    assert client.connect() is True
    mock_imap.login.assert_called_once_with('test@inst.com', 'EncryptedPass123')

def test_imap_client_authentication_failure(monkeypatch):
    """Verifies authentication failure raises IMAPAuthenticationError."""
    mock_imap = MagicMock()
    import imaplib
    mock_imap.login.side_effect = imaplib.IMAP4.error("AUTHENTICATIONFAILED Bad credentials")
    monkeypatch.setattr('imaplib.IMAP4_SSL', lambda *args, **kwargs: mock_imap)

    mock_email_svc = MagicMock()
    mock_email_svc._get_credentials.return_value = ('test@inst.com', 'BadPass', 'smtp.gmail.com', 587, 'imap.gmail.com')

    client = IMAPClient(institution_id=1, email_service=mock_email_svc)
    with pytest.raises(IMAPAuthenticationError) as exc:
        client.connect()
    assert "authentication failed" in str(exc.value).lower()

def test_imap_client_mailbox_selection_and_uidvalidity(monkeypatch):
    """Verifies mailbox selection, message count, and UIDVALIDITY extraction."""
    mock_imap = MagicMock()
    mock_imap.login.return_value = ('OK', [b'Logged in'])
    mock_imap.select.return_value = ('OK', [b'42'])
    mock_imap.response.return_value = ('OK', [b'987654321'])
    monkeypatch.setattr('imaplib.IMAP4_SSL', lambda *args, **kwargs: mock_imap)

    mock_email_svc = MagicMock()
    mock_email_svc._get_credentials.return_value = ('t@inst.com', 'p', 's', 587, 'i')

    client = IMAPClient(institution_id=1, email_service=mock_email_svc)
    client.connect()

    status, uidvalidity, count = client.select_mailbox('INBOX')
    assert status == 'OK'
    assert uidvalidity == 987654321
    assert count == 42

def test_imap_client_uid_search_and_rfc822_fetch(monkeypatch):
    """Verifies fetching unseen UIDs and raw RFC822 bytes."""
    mock_imap = MagicMock()
    mock_imap.login.return_value = ('OK', [b'Logged in'])
    mock_imap.uid.side_effect = [
        ('OK', [b'101 102 103']),  # SEARCH response
        ('OK', [b'101 (RFC822.SIZE 100)']), # FETCH SIZE response
        ('OK', [(b'101 (RFC822 {100})', b'From: test@example.com\r\nSubject: Test\r\n\r\nHello World')]) # FETCH response
    ]
    monkeypatch.setattr('imaplib.IMAP4_SSL', lambda *args, **kwargs: mock_imap)

    mock_email_svc = MagicMock()
    mock_email_svc._get_credentials.return_value = ('t@inst.com', 'p', 's', 587, 'i')

    client = IMAPClient(institution_id=1, email_service=mock_email_svc)
    client.connect()

    uids = client.fetch_unseen_uids()
    assert uids == [101, 102, 103]

    raw_bytes = client.fetch_rfc822_message(101)
    assert b'From: test@example.com' in raw_bytes
    assert b'Hello World' in raw_bytes

# -----------------------------------------------------------------------------
# 2. SAFE MIME PARSER TESTS
# -----------------------------------------------------------------------------

def test_parse_plain_text_email():
    """Verifies parsing standard plain-text RFC822 email."""
    msg = MIMEText("This is a test email body.", "plain")
    msg['Subject'] = "Simple Test"
    msg['From'] = "sender@test.com"
    msg['To'] = "recipient@test.com"
    msg['Message-ID'] = "<msg123@test.com>"

    parsed = SafeMIMEParser.parse_email_bytes(msg.as_bytes())

    assert parsed['subject'] == "Simple Test"
    assert parsed['from'] == "sender@test.com"
    assert parsed['to'] == "recipient@test.com"
    assert parsed['raw_msg_id'] == "<msg123@test.com>"
    assert parsed['text_body'] == "This is a test email body."
    assert parsed['body_for_ml'] == "This is a test email body."
    assert parsed['attachments'] == []

def test_parse_html_only_email_safely():
    """Verifies converting HTML-only email to plain text without JS or network loading."""
    html_content = "<html><body><h1>Title</h1><p>Hello <b>World</b>!</p><script>alert('hack');</script></body></html>"
    msg = MIMEText(html_content, "html")
    msg['Subject'] = "HTML Test"
    msg['From'] = "sender@test.com"

    parsed = SafeMIMEParser.parse_email_bytes(msg.as_bytes())

    assert "Title" in parsed['body_for_ml']
    assert "Hello World!" in parsed['body_for_ml']
    assert "alert('hack')" not in parsed['body_for_ml']
    assert "<script>" not in parsed['body_for_ml']

def test_parse_encoded_subject_header():
    """Verifies decoding RFC2047 encoded subject headers."""
    raw_bytes = b"From: test@test.com\r\nSubject: =?utf-8?B?VVRGLTggRW5jb2RlZCBTVUJKRUNU?=\r\n\r\nBody text"
    parsed = SafeMIMEParser.parse_email_bytes(raw_bytes)
    assert parsed['subject'] == "UTF-8 Encoded SUBJECT"

def test_parse_missing_message_id_uses_fallback():
    """Verifies missing Message-ID delegates to IngestedMessageModel content fallback."""
    msg = MIMEText("Fallback test body", "plain")
    msg['Subject'] = "Missing Message ID"
    msg['From'] = "from@test.com"
    msg['To'] = "to@test.com"

    parsed = SafeMIMEParser.parse_email_bytes(msg.as_bytes())

    assert parsed['raw_msg_id'] == ""
    expected_hash = IngestedMessageModel.compute_message_id_hash(
        raw_msg_id="",
        from_addr="from@test.com",
        to_addr="to@test.com",
        subject="Missing Message ID",
        body_snippet="Fallback test body"
    )
    assert parsed['message_id_hash'] == expected_hash

def test_parse_attachments_kept_strictly_in_memory_and_sanitized(tmp_path):
    """Verifies attachments stay in memory buffers, path traversal is sanitized, and zero files are written to disk."""
    msg = MIMEMultipart()
    msg['Subject'] = "Attachment Test"
    msg['From'] = "sender@test.com"
    msg.attach(MIMEText("Body with attachment", "plain"))

    att = MIMEBase('application', 'octet-stream')
    att.set_payload(b"Fake PDF Content Bytes 12345")
    att.add_header('Content-Disposition', 'attachment', filename='../../traversal_invoice.pdf')
    msg.attach(att)

    parsed = SafeMIMEParser.parse_email_bytes(msg.as_bytes())

    assert len(parsed['attachments']) == 1
    attachment = parsed['attachments'][0]

    # Path traversal sanitized
    assert attachment['filename'] == 'traversal_invoice.pdf'
    assert attachment['size'] == len(b"Fake PDF Content Bytes 12345")
    assert attachment['content'] == b"Fake PDF Content Bytes 12345"

    # Confirm no file was written to disk
    assert not os.path.exists(os.path.join(tmp_path, '../../traversal_invoice.pdf'))

def test_parse_oversized_attachment_raises_error():
    """Verifies attachment exceeding 5MB single limit raises MIMESizeLimitExceeded."""
    msg = MIMEMultipart()
    msg['Subject'] = "Oversized Attachment"

    att = MIMEBase('application', 'octet-stream')
    # Generate 6MB payload (exceeds 5MB per-attachment cap)
    large_payload = b"A" * (6 * 1024 * 1024)
    att.set_payload(large_payload)
    att.add_header('Content-Disposition', 'attachment', filename='large.bin')
    msg.attach(att)

    with pytest.raises(MIMESizeLimitExceeded) as exc:
        SafeMIMEParser.parse_email_bytes(msg.as_bytes())
    assert "exceeds maximum limit of 5242880 bytes" in str(exc.value)

def test_parse_excessive_mime_nesting_depth():
    """Verifies recursive MIME nesting depth exceeding 10 levels raises MIMEParserError."""
    outer = MIMEMultipart()
    curr = outer
    for _ in range(12):  # 12 nesting levels
        sub = MIMEMultipart()
        curr.attach(sub)
        curr = sub

    with pytest.raises(MIMEParserError) as exc:
        SafeMIMEParser.parse_email_bytes(outer.as_bytes())
    assert "MIME nesting depth exceeds maximum limit" in str(exc.value)

def test_imap_client_pre_fetch_size_limit_rejection(monkeypatch):
    """Verifies IMAPClient rejects RFC822 payloads exceeding 10MB BEFORE fetching full body."""
    mock_imap = MagicMock()
    mock_imap.login.return_value = ('OK', [b'Logged in'])
    # Pre-fetch RFC822.SIZE returns 15MB
    mock_imap.uid.side_effect = [
        ('OK', [b'101 (RFC822.SIZE 15728640)'])
    ]
    monkeypatch.setattr('imaplib.IMAP4_SSL', lambda *args, **kwargs: mock_imap)

    mock_email_svc = MagicMock()
    mock_email_svc._get_credentials.return_value = ('t@inst.com', 'p', 's', 587, 'i')

    client = IMAPClient(institution_id=1, email_service=mock_email_svc)
    client.connect()

    with pytest.raises(IMAPFetchError) as exc:
        client.fetch_rfc822_message(101)
    assert "exceeds maximum limit of 10485760 bytes" in str(exc.value)

def test_safe_mime_parser_to_unified_risk_engine_integration(app):
    """VERIFICATION TEST: Verifies parsed MIME output directly integrates with UnifiedRiskEngine."""
    from bullymail.services.risk_engine import UnifiedRiskEngine

    msg = MIMEMultipart()
    msg['Subject'] = "Security Audit Test"
    msg['From'] = "sender@external.com"
    msg['To'] = "user@bullymail.local"
    msg['Message-ID'] = "<msg_audit_99@external.com>"
    msg.attach(MIMEText("Please verify your account details at http://suspicious-login.com", "plain"))

    att = MIMEBase('application', 'pdf')
    att.set_payload(b"%PDF-1.4 Fake PDF Content")
    att.add_header('Content-Disposition', 'attachment', filename='statement.pdf')
    msg.attach(att)

    parsed = SafeMIMEParser.parse_email_bytes(msg.as_bytes())

    with app.app_context():
        engine = UnifiedRiskEngine()
        report = engine.analyze_email(
            email_text=parsed['body_for_ml'],
            email_subject=parsed['subject'],
            email_from=parsed['from'],
            email_to=parsed['to'],
            attachments=parsed['attachments'],
            images=parsed['images']
        )

    assert report is not None
    assert 'overall_risk_level' in report
    assert 'threat_score' in report
    assert 'phishing_analysis' in report
    assert 'bullying_analysis' in report
    assert report['overall_risk_level'] in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
