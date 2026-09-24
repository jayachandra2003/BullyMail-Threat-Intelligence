import ssl
import smtplib
import socket
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
    def get_smtp_config(cls, institution_id: int = None) -> dict:
        """
        Resolves active SMTP configuration from active database mailbox first, then Config/environment fallback.
        Never returns or logs sensitive passwords outside internal smtplib usage.
        """
        username = ""
        password = ""
        host = "smtp.gmail.com"
        port = 587
        use_tls = True
        from_email = ""
        from_name = "BullyMail Administration"
        credential_source = "environment_fallback"

        # 1. Query active connected institutional mailbox from database FIRST
        inst_id = institution_id
        if inst_id is None:
            try:
                from flask import session, g
                inst_id = (getattr(g, 'current_user', {}) or {}).get('institution_id') or session.get('institution_id') or 1
            except Exception:
                inst_id = 1

        try:
            from .email_service import EmailService
            email_svc = EmailService()
            mb_addr, mb_pw, mb_smtp, mb_port, _ = email_svc._get_credentials(institution_id=inst_id)
            if mb_addr and mb_pw:
                username = mb_addr
                password = mb_pw
                host = mb_smtp or 'smtp.gmail.com'
                port = int(mb_port or 587)
                from_email = mb_addr
                credential_source = "connected_mailbox"
        except Exception as e:
            logger.debug(f"Active mailbox SMTP resolution notice: {e}")

        # 2. Fallback to Config / environment variables only if active mailbox credentials were not found in database
        if not (username and password):
            host = getattr(Config, 'SMTP_HOST', 'smtp.gmail.com')
            port = getattr(Config, 'SMTP_PORT', 587)
            username = getattr(Config, 'SMTP_USERNAME', '')
            password = getattr(Config, 'SMTP_PASSWORD', '')
            use_tls = getattr(Config, 'SMTP_USE_TLS', True)
            from_email = getattr(Config, 'SMTP_FROM_EMAIL', username or '')
            from_name = getattr(Config, 'SMTP_FROM_NAME', 'BullyMail Administration')

            try:
                from flask import current_app
                if current_app and current_app.config:
                    host = current_app.config.get('SMTP_HOST') or current_app.config.get('EMAIL_SMTP_SERVER') or host
                    port = int(current_app.config.get('SMTP_PORT') or current_app.config.get('EMAIL_SMTP_PORT') or port)
                    username = current_app.config.get('SMTP_USERNAME') or current_app.config.get('EMAIL_ADDRESS') or username
                    raw_pw = current_app.config.get('SMTP_PASSWORD') or current_app.config.get('EMAIL_APP_PASSWORD') or password
                    if raw_pw:
                        try:
                            from .crypto_service import CryptoService
                            if CryptoService.is_encrypted(raw_pw):
                                password = CryptoService.decrypt(raw_pw)
                            else:
                                password = raw_pw
                        except Exception:
                            password = raw_pw
                    use_tls = current_app.config.get('SMTP_USE_TLS', use_tls)
                    from_email = current_app.config.get('SMTP_FROM_EMAIL') or username or from_email
                    from_name = current_app.config.get('SMTP_FROM_NAME') or from_name
            except Exception:
                pass

        if not from_email or '@bullymail.local' in from_email or '@' not in from_email:
            from_email = username or 'admin@bullymail.local'

        return {
            'host': (host or 'smtp.gmail.com').strip(),
            'port': int(port or 587),
            'username': (username or '').strip(),
            'password': (password or '').strip(),
            'use_tls': bool(use_tls),
            'from_email': (from_email or '').strip(),
            'from_name': (from_name or '').strip(),
            'credential_source': credential_source
        }

    @classmethod
    def is_smtp_configured(cls, institution_id: int = None) -> bool:
        """Checks if minimum SMTP credentials and host are configured."""
        cfg = cls.get_smtp_config(institution_id=institution_id)
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
        inst_id = analysis_record.get('institution_id')
        cfg = cls.get_smtp_config(institution_id=inst_id)
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
            'is_smtp_configured': cls.is_smtp_configured(institution_id=inst_id),
            'incident_status': analysis_record.get('incident_status', 'PENDING_REVIEW')
        }

    @classmethod
    def send_warning_email(cls, recipient_email: str, subject: str = None, body: str = None, institution_id: int = None) -> tuple[bool, str]:
        """
        Transmits warning email to the original sender over secure TLS.
        Returns:
            tuple[bool, str]: (is_success, status_message)
        """
        clean_recipient = cls.extract_clean_email(recipient_email)
        if not clean_recipient or '@' not in clean_recipient:
            logger.warning(f"[SMTP WARN] Warning email send rejected: Invalid recipient email address '{recipient_email}'")
            return False, "Invalid recipient email address for warning dispatch."

        cfg = cls.get_smtp_config(institution_id=institution_id)
        if not cfg['host'] or not cfg['password'] or not (cfg['username'] or cfg['from_email']):
            logger.error("[SMTP WARN] Warning email send failed: SMTP server credentials are not configured in environment or active mailbox.")
            return False, "SMTP server credentials are not configured. Please configure SMTP_HOST, SMTP_USERNAME, and SMTP_PASSWORD or connect an active institutional mailbox."

        sub = subject or cls.DEFAULT_WARNING_SUBJECT
        msg_body = body or cls.DEFAULT_WARNING_TEMPLATE

        # Gmail SMTP requires From header to match authenticated username
        auth_user = cfg['username']
        auth_pw = cfg['password']
        sender_email = auth_user if ('gmail.com' in cfg['host'].lower() or not cfg['from_email']) else cfg['from_email']
        sender_name = cfg['from_name'] or 'BullyMail Administration'
        sender_matches_username = (sender_email.lower() == auth_user.lower())

        logger.info(
            f"[SMTP WARN] Dispatching advisory warning | Host: {cfg['host']}:{cfg['port']} | "
            f"Auth User: {auth_user[:3]}***@{auth_user.split('@')[-1] if '@' in auth_user else 'local'} | "
            f"Source: {cfg.get('credential_source', 'unknown')} | Credential Present: {bool(auth_pw)} | "
            f"Credential Length: {len(auth_pw)} | WhiteSpace: {any(c.isspace() for c in auth_pw)} | "
            f"From: {sender_email[:3]}***@{sender_email.split('@')[-1] if '@' in sender_email else 'local'} | "
            f"SenderMatchesUsername: {sender_matches_username} | "
            f"To: {clean_recipient[:3]}***@{clean_recipient.split('@')[-1] if '@' in clean_recipient else 'local'}"
        )

        try:
            import html
            import email.utils

            msg = MIMEMultipart('alternative')
            msg['From'] = f"{sender_name} <{sender_email}>"
            msg['To'] = clean_recipient
            msg['Subject'] = sub
            msg['Date'] = email.utils.formatdate(localtime=True)
            domain_part = sender_email.split('@')[-1] if '@' in sender_email else 'gmail.com'
            msg['Message-ID'] = email.utils.make_msgid(domain=domain_part)
            msg['MIME-Version'] = '1.0'

            text_part = MIMEText(msg_body, 'plain', 'utf-8')
            msg.attach(text_part)

            html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }}
.container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 30px; }}
.header {{ font-weight: bold; font-size: 18px; color: #0f172a; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
.content {{ white-space: pre-wrap; font-size: 14px; color: #334155; }}
.footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; }}
</style>
</head>
<body>
<div class="container">
<div class="header">{html.escape(sub)}</div>
<div class="content">{html.escape(msg_body)}</div>
<div class="footer">BullyMail Security Governance & Operational Monitoring</div>
</div>
</body>
</html>"""
            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)

            context = ssl.create_default_context()

            if cfg['port'] == 465:
                server = smtplib.SMTP_SSL(cfg['host'], cfg['port'], timeout=15, context=context)
            else:
                server = smtplib.SMTP(cfg['host'], cfg['port'], timeout=15)
                if cfg['use_tls']:
                    server.starttls(context=context)

            if auth_user and auth_pw:
                server.login(auth_user, auth_pw)

            refused = server.sendmail(sender_email, [clean_recipient], msg.as_string())
            server.quit()

            if refused and clean_recipient in refused:
                err_code, err_msg_bytes = refused[clean_recipient]
                err_str = err_msg_bytes.decode('utf-8', errors='ignore') if isinstance(err_msg_bytes, bytes) else str(err_msg_bytes)
                logger.error(f"[SMTP WARN] Recipient refused by SMTP server: {clean_recipient[:3]}***: Code {err_code} - {err_str}")
                return False, f"Recipient refused by mail server (Code {err_code}): {err_str}"

            logger.info(f"[SMTP WARN] Admin warning email accepted by SMTP server for delivery to {clean_recipient[:3]}***@{clean_recipient.split('@')[-1]}")
            return True, "Warning email sent successfully."

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"[SMTP WARN] SMTP Authentication Failed for user {auth_user[:3]}***: {e.smtp_code} {e.smtp_error}")
            return False, "Gmail SMTP authentication failed. Verify the connected mailbox App Password/credentials."

        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"[SMTP WARN] Recipient email refused by server: {e}")
            return False, "Recipient address was refused by target mail server."

        except (smtplib.SMTPConnectError, socket.error, TimeoutError) as e:
            logger.error(f"[SMTP WARN] SMTP Connection Failed to {cfg['host']}:{cfg['port']}: {e}")
            return False, f"Could not connect to SMTP server ({cfg['host']}:{cfg['port']}). Network or firewall error."

        except smtplib.SMTPException as e:
            err_str = str(e)
            if cfg['password'] and cfg['password'] in err_str:
                err_str = err_str.replace(cfg['password'], '********')
            logger.error(f"[SMTP WARN] SMTP Protocol Exception: {err_str}")
            return False, f"SMTP Protocol Error: {err_str}"

        except Exception as e:
            err_str = str(e)
            if cfg['password'] and cfg['password'] in err_str:
                err_str = err_str.replace(cfg['password'], '********')
            logger.error(f"[SMTP WARN] Unexpected Exception during warning email dispatch: {err_str}")
            return False, f"Failed to dispatch warning email: {err_str}"

admin_warning_service = AdminWarningService()
