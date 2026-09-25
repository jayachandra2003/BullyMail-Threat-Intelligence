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
    def get_smtp_config(cls, institution_id: int = None, mailbox_id: int = None) -> dict:
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
            mb_addr, mb_pw, mb_smtp, mb_port, _ = email_svc._get_credentials(institution_id=inst_id, mailbox_id=mailbox_id)
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
    def is_smtp_configured(cls, institution_id: int = None, mailbox_id: int = None) -> bool:
        """Checks if minimum SMTP credentials and host are configured."""
        cfg = cls.get_smtp_config(institution_id=institution_id, mailbox_id=mailbox_id)
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
        mb_id = analysis_record.get('email_config_id')
        cfg = cls.get_smtp_config(institution_id=inst_id, mailbox_id=mb_id)
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
            'is_smtp_configured': cls.is_smtp_configured(institution_id=inst_id, mailbox_id=mb_id),
            'incident_status': analysis_record.get('incident_status', 'PENDING_REVIEW')
        }

    @classmethod
    def run_smtp_diagnostics(cls, institution_id: int = None, mailbox_id: int = None, target_port: int = None) -> dict:
        """
        Tests DNS resolution, TCP reachability, TLS/SSL handshake, and SMTP authentication
        WITHOUT transmitting any email. Bounded short timeouts (5s per check).
        Never returns or logs sensitive passwords.
        """
        import time
        import socket
        import smtplib
        import ssl

        cfg = cls.get_smtp_config(institution_id=institution_id, mailbox_id=mailbox_id)
        host = cfg['host'] or 'smtp.gmail.com'
        user = cfg['username']
        pw = cfg['password']

        diag = {
            'host': host,
            'dns': False,
            'dns_ip': None,
            'dns_ms': None,
            'dns_error': None,
            'port_587': {
                'tcp': False,
                'tcp_ms': None,
                'smtp_greeting': False,
                'starttls': False,
                'tls_ms': None,
                'error': None
            },
            'port_465': {
                'tcp': False,
                'tcp_ms': None,
                'ssl_connected': False,
                'ssl_ms': None,
                'error': None
            },
            'smtp_auth': {
                'attempted': False,
                'port': None,
                'success': False,
                'auth_ms': None,
                'error': None
            },
            'credential_status': {
                'configured': bool(user and pw),
                'source': cfg.get('credential_source', 'none'),
                'user_masked': f"{user[:3]}***@{user.split('@')[-1]}" if ('@' in user and len(user) > 3) else ('configured' if user else 'missing')
            }
        }

        # 1. DNS Resolution
        t0 = time.time()
        try:
            addr_info = socket.getaddrinfo(host, 587, socket.AF_INET, socket.SOCK_STREAM)
            diag['dns'] = True
            diag['dns_ms'] = round((time.time() - t0) * 1000, 2)
            diag['dns_ip'] = addr_info[0][4][0] if addr_info else None
            logger.info(f"[SMTP_DIAG] [DNS_SUCCESS] host={host} ip={diag['dns_ip']} elapsed={diag['dns_ms']}ms")
        except Exception as e:
            diag['dns'] = False
            diag['dns_ms'] = round((time.time() - t0) * 1000, 2)
            diag['dns_error'] = str(e)
            logger.error(f"[SMTP_DIAG] [DNS_FAILED] host={host} error={e} elapsed={diag['dns_ms']}ms")
            return diag

        # 2. Port 587 Check
        if target_port is None or target_port == 587:
            t0 = time.time()
            try:
                sock = socket.create_connection((host, 587), timeout=5)
                sock.close()
                diag['port_587']['tcp'] = True
                diag['port_587']['tcp_ms'] = round((time.time() - t0) * 1000, 2)
                logger.info(f"[SMTP_DIAG] [PORT_587_TCP_SUCCESS] elapsed={diag['port_587']['tcp_ms']}ms")
            except Exception as e:
                diag['port_587']['tcp'] = False
                diag['port_587']['tcp_ms'] = round((time.time() - t0) * 1000, 2)
                diag['port_587']['error'] = str(e)
                logger.warning(f"[SMTP_DIAG] [PORT_587_TCP_FAILED] error={e} elapsed={diag['port_587']['tcp_ms']}ms")

            if diag['port_587']['tcp']:
                t_smtp = time.time()
                try:
                    s587 = smtplib.SMTP(host, 587, timeout=5)
                    diag['port_587']['smtp_greeting'] = True
                    s587.ehlo()
                    ctx = ssl.create_default_context()
                    s587.starttls(context=ctx)
                    s587.ehlo()
                    diag['port_587']['starttls'] = True
                    diag['port_587']['tls_ms'] = round((time.time() - t_smtp) * 1000, 2)
                    logger.info(f"[SMTP_DIAG] [PORT_587_STARTTLS_SUCCESS] elapsed={diag['port_587']['tls_ms']}ms")

                    # Test auth on 587 if credentials exist
                    if user and pw and not diag['smtp_auth']['attempted']:
                        t_auth = time.time()
                        try:
                            s587.login(user, pw)
                            diag['smtp_auth']['attempted'] = True
                            diag['smtp_auth']['port'] = 587
                            diag['smtp_auth']['success'] = True
                            diag['smtp_auth']['auth_ms'] = round((time.time() - t_auth) * 1000, 2)
                            logger.info(f"[SMTP_DIAG] [PORT_587_AUTH_SUCCESS] elapsed={diag['smtp_auth']['auth_ms']}ms")
                        except Exception as ae:
                            diag['smtp_auth']['attempted'] = True
                            diag['smtp_auth']['port'] = 587
                            diag['smtp_auth']['success'] = False
                            diag['smtp_auth']['auth_ms'] = round((time.time() - t_auth) * 1000, 2)
                            err_str = str(ae)
                            if pw in err_str:
                                err_str = err_str.replace(pw, '********')
                            diag['smtp_auth']['error'] = err_str
                            logger.error(f"[SMTP_DIAG] [PORT_587_AUTH_FAILED] error={err_str} elapsed={diag['smtp_auth']['auth_ms']}ms")
                    try:
                        s587.quit()
                    except Exception:
                        pass
                except Exception as e:
                    diag['port_587']['starttls'] = False
                    diag['port_587']['tls_ms'] = round((time.time() - t_smtp) * 1000, 2)
                    err_str = str(e)
                    if pw and pw in err_str:
                        err_str = err_str.replace(pw, '********')
                    diag['port_587']['error'] = err_str
                    logger.warning(f"[SMTP_DIAG] [PORT_587_STARTTLS_FAILED] error={err_str} elapsed={diag['port_587']['tls_ms']}ms")

        # 3. Port 465 Check
        if target_port is None or target_port == 465:
            t0 = time.time()
            try:
                sock = socket.create_connection((host, 465), timeout=5)
                sock.close()
                diag['port_465']['tcp'] = True
                diag['port_465']['tcp_ms'] = round((time.time() - t0) * 1000, 2)
                logger.info(f"[SMTP_DIAG] [PORT_465_TCP_SUCCESS] elapsed={diag['port_465']['tcp_ms']}ms")
            except Exception as e:
                diag['port_465']['tcp'] = False
                diag['port_465']['tcp_ms'] = round((time.time() - t0) * 1000, 2)
                diag['port_465']['error'] = str(e)
                logger.warning(f"[SMTP_DIAG] [PORT_465_TCP_FAILED] error={e} elapsed={diag['port_465']['tcp_ms']}ms")

            if diag['port_465']['tcp']:
                t_ssl = time.time()
                try:
                    ctx = ssl.create_default_context()
                    s465 = smtplib.SMTP_SSL(host, 465, timeout=5, context=ctx)
                    diag['port_465']['ssl_connected'] = True
                    diag['port_465']['ssl_ms'] = round((time.time() - t_ssl) * 1000, 2)
                    logger.info(f"[SMTP_DIAG] [PORT_465_SSL_SUCCESS] elapsed={diag['port_465']['ssl_ms']}ms")

                    # Test auth on 465 if not already succeeded on 587, or if testing 465 explicitly
                    if user and pw and not diag['smtp_auth']['success']:
                        t_auth = time.time()
                        try:
                            s465.login(user, pw)
                            diag['smtp_auth']['attempted'] = True
                            diag['smtp_auth']['port'] = 465
                            diag['smtp_auth']['success'] = True
                            diag['smtp_auth']['auth_ms'] = round((time.time() - t_auth) * 1000, 2)
                            logger.info(f"[SMTP_DIAG] [PORT_465_AUTH_SUCCESS] elapsed={diag['smtp_auth']['auth_ms']}ms")
                        except Exception as ae:
                            diag['smtp_auth']['attempted'] = True
                            diag['smtp_auth']['port'] = 465
                            diag['smtp_auth']['success'] = False
                            diag['smtp_auth']['auth_ms'] = round((time.time() - t_auth) * 1000, 2)
                            err_str = str(ae)
                            if pw in err_str:
                                err_str = err_str.replace(pw, '********')
                            diag['smtp_auth']['error'] = err_str
                            logger.error(f"[SMTP_DIAG] [PORT_465_AUTH_FAILED] error={err_str} elapsed={diag['smtp_auth']['auth_ms']}ms")
                    try:
                        s465.quit()
                    except Exception:
                        pass
                except Exception as e:
                    diag['port_465']['ssl_connected'] = False
                    diag['port_465']['ssl_ms'] = round((time.time() - t_ssl) * 1000, 2)
                    err_str = str(e)
                    if pw and pw in err_str:
                        err_str = err_str.replace(pw, '********')
                    diag['port_465']['error'] = err_str
                    logger.warning(f"[SMTP_DIAG] [PORT_465_SSL_FAILED] error={err_str} elapsed={diag['port_465']['ssl_ms']}ms")

        return diag

    @classmethod
    def send_warning_email(cls, recipient_email: str, subject: str = None, body: str = None,
                           institution_id: int = None, mailbox_id: int = None,
                           target_port: int = None) -> tuple[bool, str]:
        """
        Transmits warning email to the original sender over secure TLS.
        Uses explicit 10s bounded timeout. Tests ports separately without indefinite chaining.
        Returns:
            tuple[bool, str]: (is_success, status_message)
        """
        import time
        import html
        import email.utils

        clean_recipient = cls.extract_clean_email(recipient_email)
        if not clean_recipient or '@' not in clean_recipient:
            logger.warning(f"[WARN_DIAG] Warning email send rejected: Invalid recipient email address '{recipient_email}'")
            return False, "Invalid recipient email address for warning dispatch."

        if mailbox_id is not None:
            cfg = cls.get_smtp_config(institution_id=institution_id, mailbox_id=mailbox_id)
        else:
            cfg = cls.get_smtp_config(institution_id=institution_id)
        if not cfg['host'] or not cfg['password'] or not (cfg['username'] or cfg['from_email']):
            logger.error("[WARN_DIAG] Warning email send failed: SMTP server credentials are not configured in environment or active mailbox.")
            return False, "SMTP server credentials are not configured. Please configure an active institutional mailbox."

        sub = subject or cls.DEFAULT_WARNING_SUBJECT
        msg_body = body or cls.DEFAULT_WARNING_TEMPLATE

        # Gmail SMTP requires From header to match authenticated username
        auth_user = cfg['username']
        auth_pw = cfg['password']
        sender_email = auth_user if ('gmail.com' in cfg['host'].lower() or not cfg['from_email']) else cfg['from_email']
        sender_name = cfg['from_name'] or 'BullyMail Administration'
        sender_matches_username = (sender_email.lower() == auth_user.lower())

        port_to_use = int(target_port or cfg.get('port') or 587)
        timeout = 10  # Bounded 10-second timeout

        masked_user = f"{auth_user[:3]}***@{auth_user.split('@')[-1]}" if ('@' in auth_user and len(auth_user) > 3) else '***'
        masked_recip = f"{clean_recipient[:3]}***@{clean_recipient.split('@')[-1]}" if ('@' in clean_recipient and len(clean_recipient) > 3) else '***'

        logger.info(
            f"[WARN_DIAG] Preparing warning dispatch | Host: {cfg['host']}:{port_to_use} | "
            f"Auth User: {masked_user} | Source: {cfg.get('credential_source', 'unknown')} | "
            f"Credential Present: {bool(auth_pw)} | "
            f"SenderMatchesUsername: {sender_matches_username} | "
            f"Recipient: {masked_recip} | Timeout: {timeout}s"
        )

        try:
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

            # Stage 1: DNS Resolution Pre-check
            t_dns = time.time()
            try:
                addr_info = socket.getaddrinfo(cfg['host'], port_to_use, socket.AF_INET, socket.SOCK_STREAM)
                dns_ip = addr_info[0][4][0] if addr_info else 'unknown'
                dns_elapsed = round((time.time() - t_dns) * 1000, 2)
                logger.info(f"[WARN_DIAG] [DNS_RESOLUTION_SUCCESS] host={cfg['host']} ip={dns_ip} elapsed={dns_elapsed}ms")
            except Exception as e:
                dns_elapsed = round((time.time() - t_dns) * 1000, 2)
                logger.warning(f"[WARN_DIAG] [DNS_RESOLUTION_NOTE] host={cfg['host']} elapsed={dns_elapsed}ms: {e}")

            # Stage 2: SMTP Connection & TLS Handshake
            t_conn = time.time()
            logger.info(f"[WARN_DIAG] [SMTP_CONNECTION_START] host={cfg['host']}:{port_to_use} timeout={timeout}s")

            server = None
            if port_to_use == 465:
                server = smtplib.SMTP_SSL(cfg['host'], port_to_use, timeout=timeout, context=context)
                conn_elapsed = round((time.time() - t_conn) * 1000, 2)
                logger.info(f"[WARN_DIAG] [SMTP_CONNECTION_SUCCESS] host={cfg['host']}:{port_to_use} SSL connected elapsed={conn_elapsed}ms")
                logger.info(f"[WARN_DIAG] [SMTP_TLS_SUCCESS] host={cfg['host']}:{port_to_use} SSL handshake verified")
            else:
                server = smtplib.SMTP(cfg['host'], port_to_use, timeout=timeout)
                conn_elapsed = round((time.time() - t_conn) * 1000, 2)
                logger.info(f"[WARN_DIAG] [SMTP_CONNECTION_SUCCESS] host={cfg['host']}:{port_to_use} TCP connected elapsed={conn_elapsed}ms")
                if cfg['use_tls']:
                    t_tls = time.time()
                    server.starttls(context=context)
                    tls_elapsed = round((time.time() - t_tls) * 1000, 2)
                    logger.info(f"[WARN_DIAG] [SMTP_TLS_SUCCESS] host={cfg['host']}:{port_to_use} STARTTLS established elapsed={tls_elapsed}ms")

            # Stage 3: SMTP Authentication
            if auth_user and auth_pw:
                t_auth = time.time()
                logger.info(f"[WARN_DIAG] [SMTP_AUTH_START] user={masked_user} host={cfg['host']}:{port_to_use}")
                server.login(auth_user, auth_pw)
                auth_elapsed = round((time.time() - t_auth) * 1000, 2)
                logger.info(f"[WARN_DIAG] [SMTP_AUTH_SUCCESS] user={masked_user} elapsed={auth_elapsed}ms")

            # Stage 4: SMTP Message Transmission
            t_send = time.time()
            logger.info(f"[WARN_DIAG] [SMTP_SEND_START] recipient={masked_recip}")
            refused = server.sendmail(sender_email, [clean_recipient], msg.as_string())
            send_elapsed = round((time.time() - t_send) * 1000, 2)
            logger.info(f"[WARN_DIAG] [SMTP_SEND_SUCCESS] recipient={masked_recip} elapsed={send_elapsed}ms")

            try:
                server.quit()
            except Exception:
                pass

            if refused and clean_recipient in refused:
                err_code, err_msg_bytes = refused[clean_recipient]
                err_str = err_msg_bytes.decode('utf-8', errors='ignore') if isinstance(err_msg_bytes, bytes) else str(err_msg_bytes)
                logger.error(f"[WARN_DIAG] [RECIPIENT_REFUSED] {masked_recip}: Code {err_code} - {err_str}")
                return False, f"Recipient refused by mail server (Code {err_code}): {err_str}"

            return True, "Warning email sent successfully."

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"[WARN_DIAG] [SMTP_AUTH_FAILED] user={masked_user}: {e.smtp_code} {e.smtp_error}")
            return False, "Gmail SMTP authentication failed. Verify the connected mailbox App Password/credentials."

        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"[WARN_DIAG] [RECIPIENT_REFUSED] Recipient email refused by server: {e}")
            return False, "Recipient address was refused by target mail server."

        except (smtplib.SMTPConnectError, socket.error, TimeoutError, OSError) as e:
            err_msg = str(e)
            if auth_pw and auth_pw in err_msg:
                err_msg = err_msg.replace(auth_pw, '********')
            if cfg.get('password') and cfg['password'] in err_msg:
                err_msg = err_msg.replace(cfg['password'], '********')
            logger.error(f"[WARN_DIAG] [SMTP_CONNECTION_FAILED] host={cfg['host']}:{port_to_use} timeout={timeout}s error={err_msg}")
            return False, f"Could not connect to SMTP server ({cfg['host']}:{port_to_use}) within {timeout}s: {err_msg}"

        except smtplib.SMTPException as e:
            err_str = str(e)
            if auth_pw and auth_pw in err_str:
                err_str = err_str.replace(auth_pw, '********')
            if cfg.get('password') and cfg['password'] in err_str:
                err_str = err_str.replace(cfg['password'], '********')
            logger.error(f"[WARN_DIAG] [SMTP_PROTOCOL_ERROR] {err_str}")
            return False, f"SMTP Protocol Error: {err_str}"

        except Exception as e:
            err_str = str(e)
            if auth_pw and auth_pw in err_str:
                err_str = err_str.replace(auth_pw, '********')
            if cfg.get('password') and cfg['password'] in err_str:
                err_str = err_str.replace(cfg['password'], '********')
            logger.error(f"[WARN_DIAG] [UNEXPECTED_ERROR] {err_str}")
            return False, f"Failed to dispatch warning email: {err_str}"

admin_warning_service = AdminWarningService()
