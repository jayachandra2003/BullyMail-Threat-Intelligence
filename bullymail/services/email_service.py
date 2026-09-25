import os
import ssl
import email
import socket
import html
import logging
import imaplib
import smtplib
import datetime
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import parseaddr, formatdate, make_msgid
from ..config import Config
from ..database.connection import execute_query, fetch_one, fetch_all

from .crypto_service import CryptoService

logger = logging.getLogger("bullymail.email_service")

class EmailService:
    """Secure IMAP / SMTP Email Integration Service (Tenant Scoped & Fernet Encrypted)"""
    
    def __init__(self):
        self.imap_server = Config.EMAIL_IMAP_SERVER
        self.smtp_server = Config.EMAIL_SMTP_SERVER
        self.smtp_port = Config.EMAIL_SMTP_PORT
        self._email = Config.EMAIL_ADDRESS
        self._password = Config.EMAIL_APP_PASSWORD

    def get_mailbox_credentials(self, mailbox_id, institution_id=1):
        """Resolves active email credentials dynamically for a specific mailbox_id."""
        if not mailbox_id:
            return self._get_credentials(institution_id=institution_id)

        try:
            row = fetch_one(
                "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE id = %s",
                (mailbox_id,)
            )
            if row and row.get('email_address') and row.get('encrypted_app_password'):
                email_addr = row['email_address']
                enc_pw = row['encrypted_app_password']
                try:
                    dec_pw = CryptoService.decrypt(enc_pw)
                except Exception:
                    dec_pw = ""
                imap_host = row.get('imap_server') or self.imap_server
                smtp_host = row.get('smtp_server') or self.smtp_server
                smtp_p = row.get('smtp_port') or self.smtp_port
                return email_addr.strip(), dec_pw.strip(), smtp_host, int(smtp_p), imap_host
        except Exception:
            pass

        return self._get_credentials(institution_id=institution_id)

    def _get_credentials(self, institution_id=None, mailbox_id=None):
        """Resolves active email credentials dynamically from database for target institution or Config."""
        inst_id = institution_id

        # Check database first for institution-scoped configuration
        try:
            if mailbox_id is not None:
                if inst_id is not None:
                    row = fetch_one(
                        "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE id = %s AND institution_id = %s",
                        (mailbox_id, inst_id)
                    )
                else:
                    row = fetch_one(
                        "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE id = %s",
                        (mailbox_id,)
                    )
            elif inst_id is not None:
                row = fetch_one(
                    "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE institution_id = %s AND (LOWER(status) = 'active' OR status IS NULL) ORDER BY id DESC LIMIT 1",
                    (inst_id,)
                )
                if not row:
                    row = fetch_one(
                        "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE institution_id = %s ORDER BY id DESC LIMIT 1",
                        (inst_id,)
                    )
            else:
                # System-wide resolution (e.g. Auth emails, unassigned registration verification):
                # Try institution 1 first, then any active connected mailbox in the database
                row = fetch_one(
                    "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE institution_id = 1 AND (LOWER(status) = 'active' OR status IS NULL) ORDER BY id DESC LIMIT 1"
                )
                if not row:
                    row = fetch_one(
                        "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE (LOWER(status) = 'active' OR status IS NULL) ORDER BY id DESC LIMIT 1"
                    )
                if not row:
                    row = fetch_one(
                        "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config ORDER BY id DESC LIMIT 1"
                    )

            if row and row.get('email_address') and row.get('encrypted_app_password'):
                email_addr = row['email_address']
                enc_pw = row['encrypted_app_password']
                try:
                    dec_pw = CryptoService.decrypt(enc_pw)
                except Exception:
                    dec_pw = ""
                if dec_pw:
                    imap_host = row.get('imap_server') or self.imap_server
                    smtp_host = row.get('smtp_server') or self.smtp_server
                    smtp_p = row.get('smtp_port') or self.smtp_port
                    return email_addr.strip(), dec_pw.strip(), smtp_host, int(smtp_p), imap_host
                else:
                    logger.warning("[SMTP_CREDENTIALS] Database mailbox password decryption failed; proceeding to environment fallback.")
        except Exception:
            pass

        # Fallback to in-memory / Flask current_app config / Config
        email_addr = getattr(Config, 'SMTP_USERNAME', '') or getattr(Config, 'EMAIL_ADDRESS', '') or self._email
        app_pw = getattr(Config, 'SMTP_PASSWORD', '') or getattr(Config, 'EMAIL_APP_PASSWORD', '') or self._password
        smtp_host = getattr(Config, 'SMTP_HOST', '') or getattr(Config, 'EMAIL_SMTP_SERVER', '') or self.smtp_server
        smtp_p = getattr(Config, 'SMTP_PORT', '') or getattr(Config, 'EMAIL_SMTP_PORT', '') or self.smtp_port
        imap_host = getattr(Config, 'EMAIL_IMAP_SERVER', '') or self.imap_server

        try:
            from flask import current_app
            if current_app and current_app.config:
                email_addr = (
                    current_app.config.get('SMTP_USERNAME')
                    or current_app.config.get('EMAIL_ADDRESS')
                    or email_addr
                )
                raw_pw = (
                    current_app.config.get('SMTP_PASSWORD')
                    or current_app.config.get('EMAIL_APP_PASSWORD')
                    or app_pw
                )
                if raw_pw:
                    if CryptoService.is_encrypted(raw_pw):
                        try:
                            app_pw = CryptoService.decrypt(raw_pw)
                        except Exception:
                            app_pw = raw_pw
                    else:
                        app_pw = raw_pw
                smtp_host = current_app.config.get('SMTP_HOST') or current_app.config.get('EMAIL_SMTP_SERVER') or smtp_host
                smtp_p = current_app.config.get('SMTP_PORT') or current_app.config.get('EMAIL_SMTP_PORT') or smtp_p
                imap_host = current_app.config.get('EMAIL_IMAP_SERVER') or imap_host
        except Exception:
            pass

        return (email_addr or '').strip(), (app_pw or '').strip(), smtp_host, int(smtp_p or 587), imap_host

    def get_mailboxes_for_institution(self, institution_id):
        """Returns all email configurations assigned strictly to institution_id."""
        if institution_id is None:
            return []

        # Auto-heal orphaned/expired leases where lease expiration has passed
        try:
            from ..database.connection import get_engine_type
            engine = get_engine_type()
            if engine == 'postgres':
                now_sql = "CURRENT_TIMESTAMP"
            elif engine == 'mysql':
                now_sql = "NOW()"
            else:
                now_sql = "datetime('now')"
            execute_query(
                f"""UPDATE email_config
                   SET sync_status = 'OK', sync_lease_id = NULL, sync_lease_expires_at = NULL
                   WHERE institution_id = %s AND sync_status = 'SYNCING' AND (sync_lease_expires_at IS NULL OR sync_lease_expires_at < {now_sql})""",
                (institution_id,)
            )
        except Exception:
            pass

        rows = fetch_all(
            """SELECT id, institution_id, email_address, imap_server, smtp_server, smtp_port, status,
                      sync_status, sync_lease_id, sync_lease_expires_at, last_synced_at, last_error,
                      total_ingested_count, configured_at, monitoring_started_at, initial_uid, last_processed_uid, uid_validity, mailbox_initialized
               FROM email_config WHERE institution_id = %s ORDER BY id ASC""",
            (institution_id,)
        )
        if not rows:
            return []

        for m in rows:
            mb_id = m.get('id')
            try:
                ing_row = fetch_one("SELECT COUNT(*) AS cnt FROM ingested_messages WHERE email_config_id = %s", (mb_id,))
                ing_cnt = ing_row['cnt'] if isinstance(ing_row, dict) else (ing_row[0] if ing_row else 0)
                an_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE email_config_id = %s", (mb_id,))
                an_cnt = an_row['cnt'] if isinstance(an_row, dict) else (an_row[0] if an_row else 0)
                m['total_ingested_count'] = max(ing_cnt, an_cnt, m.get('total_ingested_count') or 0)
            except Exception:
                pass
        return rows

    def get_mailbox_by_id(self, mailbox_id, institution_id):
        """Returns a single mailbox if and only if it belongs to institution_id; otherwise returns None (404)."""
        if institution_id is None or mailbox_id is None:
            return None
        m = fetch_one(
            """SELECT id, institution_id, email_address, imap_server, smtp_server, smtp_port, status,
                      sync_status, sync_lease_id, sync_lease_expires_at, last_synced_at, last_error,
                      total_ingested_count, configured_at, monitoring_started_at, initial_uid, last_processed_uid, uid_validity, mailbox_initialized
               FROM email_config WHERE id = %s AND institution_id = %s""",
            (mailbox_id, institution_id)
        )
        if m:
            try:
                ing_row = fetch_one("SELECT COUNT(*) AS cnt FROM ingested_messages WHERE email_config_id = %s", (mailbox_id,))
                ing_cnt = ing_row['cnt'] if isinstance(ing_row, dict) else (ing_row[0] if ing_row else 0)
                an_row = fetch_one("SELECT COUNT(*) AS cnt FROM analyzed_emails WHERE email_config_id = %s", (mailbox_id,))
                an_cnt = an_row['cnt'] if isinstance(an_row, dict) else (an_row[0] if an_row else 0)
                m['total_ingested_count'] = max(ing_cnt, an_cnt, m.get('total_ingested_count') or 0)
            except Exception:
                pass
        return m

    def configure_mailbox(self, institution_id, email_address, app_password, imap_server=None, smtp_server=None, smtp_port=None):
        """Configures a new mailbox with Fernet encryption assigned strictly to institution_id."""
        if institution_id is None:
            raise ValueError("institution_id is required to configure a mailbox.")
        clean_email = email_address.strip()
        clean_password = app_password.strip()

        enc_password = CryptoService.encrypt(clean_password)
        imap_host = imap_server or self.imap_server
        smtp_host = smtp_server or self.smtp_server
        smtp_p = int(smtp_port) if smtp_port else self.smtp_port
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        execute_query(
            '''INSERT INTO email_config (
                   institution_id, email_address, encrypted_app_password, imap_server, smtp_server, smtp_port,
                   status, sync_status, configured_at, monitoring_started_at, mailbox_initialized
               )
               VALUES (%s, %s, %s, %s, %s, %s, 'active', 'IDLE', %s, %s, 0)''',
            (institution_id, clean_email, enc_password, imap_host, smtp_host, smtp_p, now_utc, now_utc)
        )
        mb = self.get_mailboxes_for_institution(institution_id)[-1]

        # Try initializing boundary immediately if IMAP is reachable
        try:
            from .imap_client import IMAPClient
            client = IMAPClient(institution_id=institution_id, mailbox_id=mb['id'])
            if client.connect():
                _, uidvalidity, msg_count = client.select_mailbox('INBOX')
                max_uid = client.get_max_uid()
                execute_query(
                    '''UPDATE email_config
                       SET initial_uid = %s, last_processed_uid = %s, uid_validity = %s, mailbox_initialized = 1
                       WHERE id = %s''',
                    (max_uid, max_uid, uidvalidity, mb['id'])
                )
                client.disconnect()
                mb = self.get_mailbox_by_id(mb['id'], institution_id)
        except Exception:
            pass

        return mb

    def update_mailbox_status(self, mailbox_id, institution_id, new_status):
        """Updates mailbox status ('active' or 'disabled') for tenant-owned mailbox."""
        mailbox = self.get_mailbox_by_id(mailbox_id, institution_id)
        if not mailbox:
            return False
        execute_query(
            "UPDATE email_config SET status = %s WHERE id = %s AND institution_id = %s",
            (new_status, mailbox_id, institution_id)
        )
        return True

    def update_mailbox_credentials(self, mailbox_id, institution_id, email_address=None, app_password=None, imap_server=None, smtp_server=None, smtp_port=None):
        """
        Updates credentials and configuration for an existing tenant-owned mailbox.
        Preserves existing mailbox ID and preserves existing encrypted password if app_password is empty/None.
        Encrypts new app_password using current CryptoService master key.
        """
        mailbox = self.get_mailbox_by_id(mailbox_id, institution_id)
        if not mailbox:
            return None, "Mailbox not found or cross-tenant access denied."

        clean_email = (email_address.strip() if (email_address and isinstance(email_address, str)) else mailbox.get('email_address', '')).strip()
        imap_host = (imap_server.strip() if (imap_server and isinstance(imap_server, str)) else (mailbox.get('imap_server') or 'imap.gmail.com')).strip()
        smtp_host = (smtp_server.strip() if (smtp_server and isinstance(smtp_server, str)) else (mailbox.get('smtp_server') or 'smtp.gmail.com')).strip()
        smtp_p = int(smtp_port) if smtp_port else (mailbox.get('smtp_port') or 587)

        if app_password and isinstance(app_password, str) and app_password.strip():
            clean_pw = app_password.strip()
            enc_password = CryptoService.encrypt(clean_pw)
            execute_query(
                '''UPDATE email_config
                   SET email_address = %s, encrypted_app_password = %s, imap_server = %s, smtp_server = %s, smtp_port = %s, last_error = NULL
                   WHERE id = %s AND institution_id = %s''',
                (clean_email, enc_password, imap_host, smtp_host, smtp_p, mailbox_id, institution_id)
            )
        else:
            execute_query(
                '''UPDATE email_config
                   SET email_address = %s, imap_server = %s, smtp_server = %s, smtp_port = %s
                   WHERE id = %s AND institution_id = %s''',
                (clean_email, imap_host, smtp_host, smtp_p, mailbox_id, institution_id)
            )

        updated_mb = self.get_mailbox_by_id(mailbox_id, institution_id)
        return updated_mb, "Mailbox credentials updated successfully."

    def delete_mailbox(self, mailbox_id, institution_id):
        """
        Deletes/removes a tenant-owned mailbox configuration safely.
        Wipes credentials, releases active sync leases, detaches analyzed email references, and removes record.
        """
        mailbox = self.get_mailbox_by_id(mailbox_id, institution_id)
        if not mailbox:
            return False, "Mailbox not found."

        try:
            # Release active sync lease if present
            if mailbox.get('sync_lease_id'):
                self.release_sync_lease(mailbox_id, mailbox['sync_lease_id'], final_status='RELEASED')
        except Exception as e:
            logger.warning(f"Error releasing sync lease for mailbox {mailbox_id}: {e}")

        try:
            # Safe detachment from analyzed_emails to preserve threat analysis records
            execute_query("UPDATE analyzed_emails SET email_config_id = NULL WHERE email_config_id = %s", (mailbox_id,))
        except Exception as e:
            logger.warning(f"Note updating analyzed_emails email_config_id: {e}")

        try:
            execute_query("DELETE FROM email_sync_audit WHERE email_config_id = %s", (mailbox_id,))
        except Exception:
            pass

        try:
            execute_query("DELETE FROM ingested_messages WHERE email_config_id = %s", (mailbox_id,))
        except Exception:
            pass

        execute_query("DELETE FROM email_config WHERE id = %s AND institution_id = %s", (mailbox_id, institution_id))
        return True, "Mailbox deleted successfully."


    def acquire_sync_lease(self, mailbox_id, institution_id):
        """
        Atomically acquires a 2-minute synchronization lease for a tenant mailbox.
        Returns lease_id string on success, or None on lease conflict.
        """
        import uuid
        from ..database.connection import get_engine_type
        lease_id = str(uuid.uuid4())
        engine = get_engine_type()

        if engine == 'postgres':
            sql = """UPDATE email_config
                     SET sync_status = 'SYNCING',
                         sync_lease_id = %s,
                         sync_lease_expires_at = CURRENT_TIMESTAMP + INTERVAL '2 minutes',
                         last_synced_at = CURRENT_TIMESTAMP
                     WHERE id = %s AND institution_id = %s
                       AND (sync_status NOT IN ('SYNCING') OR sync_lease_expires_at < CURRENT_TIMESTAMP)"""
        elif engine == 'mysql':
            sql = """UPDATE email_config
                     SET sync_status = 'SYNCING',
                         sync_lease_id = %s,
                         sync_lease_expires_at = DATE_ADD(NOW(), INTERVAL 2 MINUTE),
                         last_synced_at = CURRENT_TIMESTAMP
                     WHERE id = %s AND institution_id = %s
                       AND (sync_status NOT IN ('SYNCING') OR sync_lease_expires_at < NOW())"""
        else:
            sql = """UPDATE email_config
                     SET sync_status = 'SYNCING',
                         sync_lease_id = %s,
                         sync_lease_expires_at = datetime('now', '+2 minutes'),
                         last_synced_at = CURRENT_TIMESTAMP
                     WHERE id = %s AND institution_id = %s
                       AND (sync_status NOT IN ('SYNCING') OR sync_lease_expires_at < datetime('now'))"""

        count = execute_query(sql, (lease_id, mailbox_id, institution_id))
        if count > 0:
            return lease_id
        return None

    def release_sync_lease(self, mailbox_id, lease_id, final_status='OK', last_error=None):
        """
        Releases/completes synchronization lease ONLY if sync_lease_id matches current lease_id.
        Prevents stale/expired lease owners from overwriting newer lease states.
        """
        sql = """UPDATE email_config
                 SET sync_status = %s,
                     sync_lease_id = NULL,
                     sync_lease_expires_at = NULL,
                     last_error = %s,
                     last_synced_at = CURRENT_TIMESTAMP
                 WHERE id = %s AND sync_lease_id = %s"""
        count = execute_query(sql, (final_status, last_error, mailbox_id, lease_id))
        return count > 0

    def test_preflight_connection(self, email_address, app_password, imap_server='imap.gmail.com', imap_port=993):
        """Pre-flight connection test via IMAP TLS. Never logs or persists credentials."""
        clean_email = email_address.strip()
        clean_password = app_password.strip()

        try:
            mail = imaplib.IMAP4_SSL(imap_server, port=int(imap_port), timeout=15)
            mail.login(clean_email, clean_password)
            mail.logout()
            return True, "IMAP TLS pre-flight connection test succeeded."
        except Exception as e:
            err_str = str(e)
            if clean_password and clean_password in err_str:
                err_str = err_str.replace(clean_password, '********')
            return False, f"IMAP connection test error: {err_str}"

    def configure(self, email_address, app_password, imap_server=None, smtp_server=None, smtp_port=None, institution_id=1):
        """Legacy configure wrapper maintaining backward compatibility."""
        inst_id = institution_id if institution_id is not None else 1
        self.configure_mailbox(
            institution_id=inst_id,
            email_address=email_address,
            app_password=app_password,
            imap_server=imap_server,
            smtp_server=smtp_server,
            smtp_port=smtp_port
        )
        return True

    def test_connection(self, institution_id=1):
        """Tests IMAP connection securely for target institution."""
        email_addr, app_pw, smtp_host, smtp_p, imap_host = self._get_credentials(institution_id=institution_id)
        if not email_addr or not app_pw:
            return False, "Email address and App Password must be configured."
        return self.test_preflight_connection(email_addr, app_pw, imap_server=imap_host)

    def fetch_emails(self, mailbox='INBOX', limit=10):
        """Fetches and parses the latest emails with full multipart body & attachment extraction."""
        if not self._email or not self._password:
            return []
            
        try:
            mail = imaplib.IMAP4_SSL(self.imap_server, timeout=15)
            mail.login(self._email, self._password)
            mail.select(mailbox)
            
            result, data = mail.search(None, 'ALL')
            if result != 'OK':
                mail.logout()
                return []
                
            email_ids = data[0].split()
            fetched_emails = []
            
            # Read in reverse (newest first)
            for email_id in reversed(email_ids[-limit:]):
                try:
                    res, msg_data = mail.fetch(email_id, '(RFC822)')
                    if res != 'OK':
                        continue
                    parsed = self._parse_raw_email(msg_data[0][1])
                    parsed['id'] = email_id.decode('utf-8', errors='ignore')
                    fetched_emails.append(parsed)
                except Exception as e:
                    print(f"[EmailService] Error parsing message {email_id}: {e}")
                    continue
                    
            mail.close()
            mail.logout()
            return fetched_emails
        except Exception as e:
            print(f"[EmailService] IMAP fetch error: {e}")
            return []

    def _parse_raw_email(self, raw_bytes):
        """Decodes RFC822 email bytes into structured metadata, body, and attachment objects."""
        msg = email.message_from_bytes(raw_bytes)
        
        # Decode Subject
        subject = ""
        raw_subj = msg.get("Subject", "")
        if raw_subj:
            for part, encoding in decode_header(raw_subj):
                if isinstance(part, bytes):
                    subject += part.decode(encoding or 'utf-8', errors='ignore')
                else:
                    subject += str(part)
        else:
            subject = "No Subject"
            
        sender = msg.get("From", "Unknown Sender")
        to = msg.get("To", "")
        date_str = msg.get("Date", "")
        
        body = ""
        attachments = []
        images = []
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()
                
                # Check for attachments
                if filename or "attachment" in disposition:
                    fn = filename or "unnamed_attachment"
                    payload = part.get_payload(decode=True)
                    if payload:
                        att_dict = {'filename': fn, 'content': payload, 'size': len(payload)}
                        if content_type.startswith('image/'):
                            images.append(att_dict)
                        else:
                            attachments.append(att_dict)
                elif content_type == "text/plain" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
            else:
                body = str(msg.get_payload() or '')

        return {
            'subject': subject,
            'from': sender,
            'to': to,
            'date': date_str,
            'body': body.strip() or 'No text content',
            'attachments': attachments,
            'images': images
        }

    def send_email(self, to_email, subject, body, html_body=None, institution_id=None, mailbox_id=None, timeout=10, log_prefix="[REGISTRATION EMAIL]"):
        """
        Sends an alert or notification email over secure TLS/SSL with bounded timeout and automatic fallback.
        Supports both port 587 (STARTTLS) and port 465 (SSL).
        Complies strictly with RFC 5322 (Date, Message-ID, MIME-Version, From headers).
        """
        import time

        clean_to = to_email.strip() if isinstance(to_email, str) else ''
        if not clean_to or '@' not in clean_to:
            logger.warning(f"{log_prefix} [CONFIG] Invalid recipient address rejected: '{to_email}'")
            return False, f"Invalid recipient email address: '{to_email}'"

        email_addr, app_pw, smtp_host, smtp_p, _ = self._get_credentials(institution_id=institution_id, mailbox_id=mailbox_id)
        from_email = None
        from_name = "BullyMail Security"

        # Fallback to AdminWarningService SMTP configuration if credentials remain empty
        if not email_addr or not app_pw:
            try:
                from .admin_warning_service import AdminWarningService
                cfg = AdminWarningService.get_smtp_config(institution_id=institution_id, mailbox_id=mailbox_id)
                if cfg.get('username') and cfg.get('password'):
                    email_addr = cfg['username']
                    app_pw = cfg['password']
                    smtp_host = cfg.get('host') or smtp_host
                    smtp_p = int(cfg.get('port') or smtp_p or 587)
                    from_email = cfg.get('from_email')
                    from_name = cfg.get('from_name') or from_name
            except Exception:
                pass

        if not email_addr or not app_pw:
            logger.error(f"{log_prefix} [CONFIG] FAILED: Email integration is not configured in database or environment.")
            return False, "Email integration is not configured."

        # Align sender_email with authenticated username for Gmail SMTP
        auth_user = email_addr
        auth_pw = app_pw
        sender_email = auth_user if ('gmail.com' in (smtp_host or '').lower() or not from_email) else from_email

        masked_user = f"{auth_user[:3]}***@{auth_user.split('@')[-1]}" if ('@' in auth_user and len(auth_user) > 3) else '***'
        masked_to = f"{clean_to[:3]}***@{clean_to.split('@')[-1]}" if ('@' in clean_to and len(clean_to) > 3) else '***'

        # Construct RFC 5322 compliant multipart message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{from_name} <{sender_email}>"
        msg['To'] = clean_to
        msg['Subject'] = subject
        msg['Date'] = email.utils.formatdate(localtime=True)
        domain_part = sender_email.split('@')[-1] if '@' in sender_email else 'gmail.com'
        msg['Message-ID'] = email.utils.make_msgid(domain=domain_part)
        msg['MIME-Version'] = '1.0'

        text_part = MIMEText(body or '', 'plain', 'utf-8')
        msg.attach(text_part)

        if html_body:
            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)
        else:
            # Generate clean HTML wrapper from plain text
            escaped_body = html.escape(body or '').replace('\n', '<br>')
            simple_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; margin: 0; padding: 20px; background-color: #f8fafc;">
<div style="max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 28px;">
<div style="font-size: 16px; font-weight: 600; color: #0f172a; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; margin-bottom: 20px;">BullyMail Security Platform</div>
<div style="font-size: 14px; color: #334155; line-height: 1.6;">{escaped_body}</div>
<div style="margin-top: 28px; padding-top: 14px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b;">BullyMail Threat Intelligence Platform • Automated Security Governance</div>
</div>
</body>
</html>"""
            html_part = MIMEText(simple_html, 'html', 'utf-8')
            msg.attach(html_part)

        primary_port = int(smtp_p or 587)
        logger.info(f"{log_prefix} [CONFIG] recipient={masked_to} sender={masked_user} host={smtp_host} port={primary_port}")

        # Port fallback strategy: if configured port fails, attempt alternative TLS/SSL port
        ports_to_try = [primary_port]
        fallback_port = 465 if primary_port == 587 else (587 if primary_port == 465 else None)
        if fallback_port and fallback_port not in ports_to_try:
            ports_to_try.append(fallback_port)

        last_error = None
        for port in ports_to_try:
            try:
                context = ssl.create_default_context()
                server = None
                mode_str = 'SSL' if port == 465 else 'STARTTLS'

                # Stage 1: Connection Stage
                t_conn = time.time()
                logger.info(f"{log_prefix} [CONNECTION_STAGE] host={smtp_host} port={port} mode={mode_str} timeout={timeout}s")
                if port == 465:
                    server = smtplib.SMTP_SSL(smtp_host, port, timeout=timeout, context=context)
                else:
                    server = smtplib.SMTP(smtp_host, port, timeout=timeout)
                conn_ms = round((time.time() - t_conn) * 1000, 2)
                logger.info(f"{log_prefix} [CONNECTION_STAGE] connected successfully host={smtp_host} port={port} elapsed={conn_ms}ms")

                # Stage 2: TLS Stage
                t_tls = time.time()
                logger.info(f"{log_prefix} [TLS_STAGE] initiating handshake on port {port} mode={mode_str}")
                if port != 465:
                    server.starttls(context=context)
                tls_ms = round((time.time() - t_tls) * 1000, 2)
                logger.info(f"{log_prefix} [TLS_STAGE] TLS established successfully elapsed={tls_ms}ms")

                # Stage 3: Authentication Stage
                t_auth = time.time()
                logger.info(f"{log_prefix} [AUTH_STAGE] authenticating sender={masked_user} host={smtp_host}:{port}")
                server.login(auth_user, auth_pw)
                auth_ms = round((time.time() - t_auth) * 1000, 2)
                logger.info(f"{log_prefix} [AUTH_STAGE] authentication successful elapsed={auth_ms}ms")

                # Stage 4: Send Stage
                t_send = time.time()
                logger.info(f"{log_prefix} [SEND_STAGE] transmitting email to recipient={masked_to}")
                refused = server.sendmail(sender_email, [clean_to], msg.as_string())
                send_ms = round((time.time() - t_send) * 1000, 2)

                try:
                    server.quit()
                except Exception:
                    pass

                if refused and clean_to in refused:
                    err_code, err_msg_bytes = refused[clean_to]
                    err_str = err_msg_bytes.decode('utf-8', errors='ignore') if isinstance(err_msg_bytes, bytes) else str(err_msg_bytes)
                    logger.error(f"{log_prefix} [SEND_STAGE] REFUSED for recipient={masked_to} on port {port}: Code {err_code} - {err_str}")
                    logger.error(f"{log_prefix} [FINAL_RESULT] FAILED: recipient refused by mail server")
                    return False, f"Recipient refused by mail server (Code {err_code}): {err_str}"

                logger.info(f"{log_prefix} [SEND_STAGE] sendmail accepted elapsed={send_ms}ms")
                logger.info(f"{log_prefix} [FINAL_RESULT] SUCCESS: verification email delivered to {masked_to} via {smtp_host}:{port}")
                return True, "Email sent successfully."

            except smtplib.SMTPAuthenticationError as e:
                logger.error(f"{log_prefix} [AUTH_STAGE] FAILED for sender={masked_user} on port {port}: {e.smtp_code} {e.smtp_error}")
                logger.error(f"{log_prefix} [FINAL_RESULT] FAILED: SMTP authentication rejected credentials")
                return False, "SMTP authentication failed. Verify the mailbox credentials."

            except smtplib.SMTPRecipientsRefused as e:
                logger.error(f"{log_prefix} [SEND_STAGE] REFUSED for recipient={masked_to} on port {port}: {e}")
                logger.error(f"{log_prefix} [FINAL_RESULT] FAILED: recipient address was refused")
                return False, "Recipient address was refused by target mail server."

            except (smtplib.SMTPConnectError, socket.error, TimeoutError, OSError) as e:
                safe_err = str(e)
                if auth_pw and auth_pw in safe_err:
                    safe_err = safe_err.replace(auth_pw, '********')
                logger.warning(f"{log_prefix} [CONNECTION_STAGE] FAILED on {smtp_host}:{port} timeout={timeout}s: {safe_err}")
                last_error = f"Connection to {smtp_host}:{port} failed: {safe_err}"
                continue

            except Exception as e:
                safe_err = str(e)
                if auth_pw and auth_pw in safe_err:
                    safe_err = safe_err.replace(auth_pw, '********')
                logger.error(f"{log_prefix} [FINAL_RESULT] FAILED on {smtp_host}:{port}: {safe_err}")
                last_error = f"Failed to send email: {safe_err}"
                continue

        logger.error(f"{log_prefix} [FINAL_RESULT] FAILED: all ports exhausted ({last_error})")
        return False, last_error or "Failed to deliver email through all configured SMTP ports."

# Singleton EmailService instance for application export
email_service = EmailService()
