import ssl
import smtplib
import logging
from email.utils import parseaddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ..config import Config

logger = logging.getLogger("bullymail.admin_warning")

class AdminWarningService:
    """
    Dedicated service for generating and dispatching administrator warning emails
    to original senders of detected harmful communications (Human-in-the-loop).
    """

    DEFAULT_WARNING_SUBJECT = "Notice Regarding University Communication Guidelines"

    DEFAULT_WARNING_TEMPLATE = (
        "Hello,\n\n"
        "Our communication monitoring system has identified language in a recent email that may "
        "be inconsistent with the university's standards for respectful and professional communication.\n\n"
        "The detected communication contained language associated with potentially inappropriate or "
        "harmful communication.\n\n"
        "You are requested to review the university's communication guidelines and ensure that future "
        "communications remain respectful and professional.\n\n"
        "This notification is intended as an advisory warning. If you believe this notification was issued "
        "incorrectly, please contact the appropriate administrator.\n\n"
        "Regards,\n"
        "BullyMail Administration"
    )

    @classmethod
    def get_smtp_config(cls) -> dict:
        """
        Resolves active SMTP configuration from current Flask application context or Config.
        Never returns or logs sensitive passwords outside internal smtplib usage.
        """
        host = getattr(Config, 'SMTP_HOST', 'smtp.gmail.com')
        port = getattr(Config, 'SMTP_PORT', 587)
        username = getattr(Config, 'SMTP_USERNAME', '')
        password = getattr(Config, 'SMTP_PASSWORD', '')
        use_tls = getattr(Config, 'SMTP_USE_TLS', True)
        from_email = getattr(Config, 'SMTP_FROM_EMAIL', username or 'admin@bullymail.local')
        from_name = getattr(Config, 'SMTP_FROM_NAME', 'BullyMail Administration')

        try:
            from flask import current_app
            if current_app and current_app.config:
                host = current_app.config.get('SMTP_HOST') or current_app.config.get('EMAIL_SMTP_SERVER') or host
                port = int(current_app.config.get('SMTP_PORT') or current_app.config.get('EMAIL_SMTP_PORT') or port)
                username = current_app.config.get('SMTP_USERNAME') or current_app.config.get('EMAIL_ADDRESS') or username
                password = current_app.config.get('SMTP_PASSWORD') or current_app.config.get('EMAIL_APP_PASSWORD') or password
                use_tls = current_app.config.get('SMTP_USE_TLS', use_tls)
                from_email = current_app.config.get('SMTP_FROM_EMAIL') or username or from_email
                from_name = current_app.config.get('SMTP_FROM_NAME') or from_name
        except Exception:
            pass

        return {
            'host': host,
            'port': port,
            'username': (username or '').strip(),
            'password': (password or '').strip(),
            'use_tls': bool(use_tls),
            'from_email': (from_email or '').strip(),
            'from_name': (from_name or '').strip()
        }

    @classmethod
    def is_smtp_configured(cls) -> bool:
        """Checks if minimum SMTP credentials and host are configured."""
        cfg = cls.get_smtp_config()
        return bool(cfg['host'] and (cfg['username'] or cfg['from_email']) and cfg['password'])

    @classmethod
    def extract_clean_email(cls, raw_address: str) -> str:
        """
        Extracts clean email address from RFC 5322 formatted address
        e.g. 'John Doe <johndoe@university.edu>' -> 'johndoe@university.edu'.
        """
        if not raw_address or not isinstance(raw_address, str):
            return ''
        name, addr = parseaddr(raw_address.strip())
        return addr.strip() if addr else raw_address.strip()

    @classmethod
    def get_warning_preview(cls, analysis_record: dict) -> dict:
        """
        Constructs warning preview data for administrative review and confirmation modal.
        """
        cfg = cls.get_smtp_config()
        raw_from = analysis_record.get('email_from', '')
        target_recipient = cls.extract_clean_email(raw_from)

        from_display = f"{cfg['from_name']} <{cfg['from_email']}>" if cfg['from_name'] else cfg['from_email']

        return {
            'analysis_id': analysis_record.get('id'),
            'original_sender': raw_from,
            'target_recipient': target_recipient,
            'original_recipient': analysis_record.get('email_to', ''),
            'email_subject': analysis_record.get('email_subject', 'No Subject'),
            'from_display': from_display,
            'warning_from_email': cfg['from_email'],
            'warning_from_name': cfg['from_name'],
            'warning_subject': cls.DEFAULT_WARNING_SUBJECT,
            'warning_body': cls.DEFAULT_WARNING_TEMPLATE,
            'is_smtp_configured': cls.is_smtp_configured(),
            'incident_status': analysis_record.get('incident_status', 'PENDING_REVIEW')
        }

    @classmethod
    def send_warning_email(cls, recipient_email: str, subject: str = None, body: str = None) -> tuple[bool, str]:
        """
        Transmits warning email to the original sender over secure TLS.
        Returns:
            tuple[bool, str]: (is_success, status_message)
        """
        clean_recipient = cls.extract_clean_email(recipient_email)
        if not clean_recipient or '@' not in clean_recipient:
            return False, "Invalid recipient email address for warning dispatch."

        cfg = cls.get_smtp_config()
        if not cfg['host'] or not cfg['password'] or not (cfg['username'] or cfg['from_email']):
            return False, "SMTP server credentials are not fully configured in environment. Please configure SMTP_HOST, SMTP_USERNAME, and SMTP_PASSWORD."

        sub = subject or cls.DEFAULT_WARNING_SUBJECT
        msg_body = body or cls.DEFAULT_WARNING_TEMPLATE
        sender_email = cfg['from_email'] or cfg['username']
        sender_name = cfg['from_name']

        try:
            msg = MIMEMultipart()
            msg['From'] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
            msg['To'] = clean_recipient
            msg['Subject'] = sub
            msg.attach(MIMEText(msg_body, 'plain', 'utf-8'))

            context = ssl.create_default_context()
            server = smtplib.SMTP(cfg['host'], cfg['port'], timeout=15)
            if cfg['use_tls']:
                server.starttls(context=context)

            if cfg['username'] and cfg['password']:
                server.login(cfg['username'], cfg['password'])

            server.sendmail(sender_email, [clean_recipient], msg.as_string())
            server.quit()

            logger.info(f"Admin warning email dispatched successfully to {clean_recipient[:3]}***@{clean_recipient.split('@')[-1]}")
            return True, "Warning email sent successfully."

        except Exception as e:
            err_str = str(e)
            if cfg['password'] and cfg['password'] in err_str:
                err_str = err_str.replace(cfg['password'], '********')
            logger.error(f"Failed to dispatch warning email to target sender: {err_str}")
            return False, f"SMTP transmission failed: {err_str}"

admin_warning_service = AdminWarningService()
