import email
import email.header
import email.utils
import html.parser
import io
import os
import re
from werkzeug.utils import secure_filename
from ..models.ingested_message import IngestedMessageModel

class MIMEParserError(Exception):
    """Base exception for MIME parsing errors."""
    pass

class MIMESizeLimitExceeded(MIMEParserError):
    """Raised when an email or attachment exceeds configured resource limits."""
    pass

class HTMLTextExtractor(html.parser.HTMLParser):
    """Safe, lightweight HTML tag stripper. Never executes JS or fetches remote URLs."""
    def __init__(self):
        super().__init__()
        self.result = []
        self.skip = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() in ('script', 'style', 'head'):
            self.skip = True

    def handle_endtag(self, tag):
        if tag.lower() in ('script', 'style', 'head'):
            self.skip = False
        elif tag.lower() in ('p', 'br', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'tr'):
            self.result.append('\n')

    def handle_data(self, data):
        if not self.skip and data:
            self.result.append(data)

    def get_text(self):
        raw = "".join(self.result)
        lines = [line.strip() for line in raw.splitlines()]
        return "\n".join(chunk for chunk in lines if chunk)

class SafeMIMEParser:
    """
    Security-hardened MIME Parser.
    Extracts text, HTML, headers, Message-ID, and memory-bounded attachment buffers.
    Enforces safe resource limits (10MB total msg, 5MB per attachment, max 10 attachments).
    """

    MAX_MESSAGE_BYTES = 10 * 1024 * 1024       # 10 MB limit
    MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024    # 5 MB per attachment
    MAX_TOTAL_ATTACHMENTS_BYTES = 10 * 1024 * 1024  # 10 MB total
    MAX_ATTACHMENTS_COUNT = 10                # Max 10 attachments
    MAX_NESTING_DEPTH = 10                    # Max MIME recursion depth

    EXECUTABLE_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
        '.ps1', '.ps1xml', '.psc1', '.jar', '.reg', '.scr', '.pif', '.cpl', '.hta'
    }

    @classmethod
    def parse_header_text(cls, raw_header: str) -> str:
        """Safely decodes RFC2047 encoded email headers."""
        if not raw_header:
            return ""
        decoded_parts = []
        try:
            parts = email.header.decode_header(raw_header)
            for content, encoding in parts:
                if isinstance(content, bytes):
                    decoded_parts.append(content.decode(encoding or 'utf-8', errors='ignore'))
                else:
                    decoded_parts.append(str(content))
            return "".join(decoded_parts).strip()
        except Exception:
            return str(raw_header).strip()

    @classmethod
    def html_to_text(cls, html_content: str) -> str:
        """Safely strips HTML tags into plain text without executing JS or loading URLs."""
        if not html_content or not isinstance(html_content, str):
            return ""
        parser = HTMLTextExtractor()
        try:
            parser.feed(html_content)
            return parser.get_text()
        except Exception:
            clean = re.sub(r'<[^>]+>', ' ', html_content)
            return " ".join(clean.split())

    @classmethod
    def parse_email_bytes(cls, raw_bytes: bytes) -> dict:
        """
        Parses raw RFC822 bytes into structured metadata, body, and attachment memory buffers.
        Raises MIMESizeLimitExceeded or MIMEParserError on failure.
        """
        if not raw_bytes or not isinstance(raw_bytes, bytes):
            raise MIMEParserError("Raw email content must be a non-empty bytes object.")

        if len(raw_bytes) > cls.MAX_MESSAGE_BYTES:
            raise MIMESizeLimitExceeded(f"Email size ({len(raw_bytes)} bytes) exceeds maximum limit of {cls.MAX_MESSAGE_BYTES} bytes.")

        try:
            msg = email.message_from_bytes(raw_bytes)
        except Exception as e:
            raise MIMEParserError(f"Failed to parse RFC822 email structure: {str(e)}")

        raw_msg_id = msg.get("Message-ID", "").strip()
        subject = cls.parse_header_text(msg.get("Subject", ""))
        from_addr = cls.parse_header_text(msg.get("From", ""))
        to_addr = cls.parse_header_text(msg.get("To", ""))
        date_str = cls.parse_header_text(msg.get("Date", ""))

        text_body = ""
        html_body = ""
        attachments = []
        images = []

        total_attachments_size = 0

        def walk_parts(part, depth=0):
            nonlocal text_body, html_body, total_attachments_size

            if depth > cls.MAX_NESTING_DEPTH:
                raise MIMEParserError(f"MIME nesting depth exceeds maximum limit of {cls.MAX_NESTING_DEPTH}.")

            if part.is_multipart():
                for subpart in part.get_payload():
                    if isinstance(subpart, email.message.Message):
                        walk_parts(subpart, depth + 1)
                return

            content_type = part.get_content_type().lower()
            disposition = str(part.get("Content-Disposition", "")).lower()
            filename = part.get_filename()

            if filename or "attachment" in disposition:
                if len(attachments) + len(images) >= cls.MAX_ATTACHMENTS_COUNT:
                    raise MIMESizeLimitExceeded(f"Total attachments count exceeds limit of {cls.MAX_ATTACHMENTS_COUNT}.")

                raw_filename = filename or "unnamed_attachment"
                clean_filename = cls.parse_header_text(raw_filename)
                safe_name = secure_filename(os.path.basename(clean_filename)) or "attachment.bin"

                payload = part.get_payload(decode=True)
                if not payload:
                    payload = b""

                att_size = len(payload)
                if att_size > cls.MAX_ATTACHMENT_BYTES:
                    raise MIMESizeLimitExceeded(f"Attachment '{safe_name}' ({att_size} bytes) exceeds maximum limit of {cls.MAX_ATTACHMENT_BYTES} bytes.")

                total_attachments_size += att_size
                if total_attachments_size > cls.MAX_TOTAL_ATTACHMENTS_BYTES:
                    raise MIMESizeLimitExceeded(f"Total attachments size ({total_attachments_size} bytes) exceeds maximum limit of {cls.MAX_TOTAL_ATTACHMENTS_BYTES} bytes.")

                _, ext = os.path.splitext(safe_name.lower())
                is_executable = ext in cls.EXECUTABLE_EXTENSIONS

                att_obj = {
                    'filename': safe_name,
                    'content_type': content_type,
                    'size': att_size,
                    'content': payload,
                    'is_executable': is_executable
                }

                if content_type.startswith('image/'):
                    images.append(att_obj)
                else:
                    attachments.append(att_obj)

            elif content_type == "text/plain" and not text_body:
                payload = part.get_payload(decode=True)
                if payload:
                    text_body = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
            elif content_type == "text/html" and not html_body:
                payload = part.get_payload(decode=True)
                if payload:
                    html_body = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')

        walk_parts(msg)

        if text_body and text_body.strip():
            body_for_ml = text_body.strip()
        elif html_body and html_body.strip():
            body_for_ml = cls.html_to_text(html_body)
        else:
            body_for_ml = ""

        message_id_hash = IngestedMessageModel.compute_message_id_hash(
            raw_msg_id=raw_msg_id,
            from_addr=from_addr,
            to_addr=to_addr,
            date_str=date_str,
            subject=subject,
            body_snippet=body_for_ml[:512]
        )

        return {
            'raw_msg_id': raw_msg_id,
            'message_id_hash': message_id_hash,
            'subject': subject or "No Subject",
            'from': from_addr or "Unknown Sender",
            'to': to_addr or "",
            'date': date_str or "",
            'text_body': text_body,
            'html_body': html_body,
            'body_for_ml': body_for_ml,
            'attachments': attachments,
            'images': images
        }
