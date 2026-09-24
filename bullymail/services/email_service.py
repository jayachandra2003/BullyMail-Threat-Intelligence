import os
import ssl
import email
import imaplib
import smtplib
import datetime
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ..config import Config
from ..database.connection import execute_query, fetch_one, fetch_all

from .crypto_service import CryptoService

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

    def _get_credentials(self, institution_id=1):
        """Resolves active email credentials dynamically from database for target institution or Config."""
        inst_id = institution_id if institution_id is not None else 1

        # Check database first for institution-scoped configuration
        try:
            row = fetch_one(
                "SELECT email_address, encrypted_app_password, imap_server, smtp_server, smtp_port FROM email_config WHERE institution_id = %s AND status = 'active' ORDER BY id DESC LIMIT 1",
                (inst_id,)
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

        # Fallback to in-memory / Flask current_app config / Config
        email_addr = self._email
        app_pw = self._password
        smtp_host = self.smtp_server
        smtp_p = self.smtp_port
        imap_host = self.imap_server

        try:
            from flask import current_app
            if current_app and current_app.config:
                email_addr = current_app.config.get('EMAIL_ADDRESS') or email_addr or getattr(Config, 'EMAIL_ADDRESS', '')
                raw_pw = current_app.config.get('EMAIL_APP_PASSWORD') or app_pw or getattr(Config, 'EMAIL_APP_PASSWORD', '')
                if CryptoService.is_encrypted(raw_pw):
                    try:
                        app_pw = CryptoService.decrypt(raw_pw)
                    except Exception:
                        app_pw = raw_pw
                else:
                    app_pw = raw_pw
                smtp_host = current_app.config.get('EMAIL_SMTP_SERVER') or smtp_host
                smtp_p = current_app.config.get('EMAIL_SMTP_PORT') or smtp_p
                imap_host = current_app.config.get('EMAIL_IMAP_SERVER') or imap_host
        except Exception:
            pass

        return (email_addr or '').strip(), (app_pw or '').strip(), smtp_host, int(smtp_p), imap_host

    def get_mailboxes_for_institution(self, institution_id):
        """Returns all email configurations assigned strictly to institution_id."""
        if institution_id is None:
            return []

        # Auto-heal orphaned/expired leases where lease expiration has passed
        try:
            from ..database.connection import get_engine_type
            engine = get_engine_type()
            now_sql = "NOW()" if engine == 'mysql' else "datetime('now')"
            execute_query(
                f"""UPDATE email_config
                   SET sync_status = 'OK', sync_lease_id = NULL, sync_lease_expires_at = NULL
                   WHERE institution_id = %s AND sync_status = 'SYNCING' AND (sync_lease_expires_at IS NULL OR sync_lease_expires_at < {now_sql})""",
                (institution_id,)
            )
        except Exception:
            pass

        return fetch_all(
            """SELECT id, institution_id, email_address, imap_server, smtp_server, smtp_port, status,
                      sync_status, sync_lease_id, sync_lease_expires_at, last_synced_at, last_error,
                      total_ingested_count, configured_at, monitoring_started_at, initial_uid, last_processed_uid, uid_validity, mailbox_initialized
               FROM email_config WHERE institution_id = %s ORDER BY id ASC""",
            (institution_id,)
        )

    def get_mailbox_by_id(self, mailbox_id, institution_id):
        """Returns a single mailbox if and only if it belongs to institution_id; otherwise returns None (404)."""
        if institution_id is None or mailbox_id is None:
            return None
        return fetch_one(
            """SELECT id, institution_id, email_address, imap_server, smtp_server, smtp_port, status,
                      sync_status, sync_lease_id, sync_lease_expires_at, last_synced_at, last_error,
                      total_ingested_count, configured_at, monitoring_started_at, initial_uid, last_processed_uid, uid_validity, mailbox_initialized
               FROM email_config WHERE id = %s AND institution_id = %s""",
            (mailbox_id, institution_id)
        )

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

        if engine == 'mysql':
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

    def send_email(self, to_email, subject, body):
        """Sends an alert or notification email over TLS."""
        email_addr, app_pw, smtp_host, smtp_p, _ = self._get_credentials()
        if not email_addr or not app_pw:
            return False, "Email integration is not configured."
        try:
            msg = MIMEMultipart()
            msg['From'] = email_addr
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            context = ssl.create_default_context()
            server = smtplib.SMTP(smtp_host, smtp_p)
            server.starttls(context=context)
            server.login(email_addr, app_pw)
            server.sendmail(email_addr, to_email, msg.as_string())
            server.quit()
            return True, "Email sent successfully."
        except Exception as e:
            return False, f"Failed to send email: {str(e)}"

# Singleton EmailService instance for application export
email_service = EmailService()
