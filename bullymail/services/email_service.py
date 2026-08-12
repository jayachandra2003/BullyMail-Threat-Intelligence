import os
import ssl
import email
import imaplib
import smtplib
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ..config import Config
from ..database.connection import execute_query, fetch_one

class EmailService:
    """Secure IMAP / SMTP Email Integration Service"""
    
    def __init__(self):
        self.imap_server = Config.EMAIL_IMAP_SERVER
        self.smtp_server = Config.EMAIL_SMTP_SERVER
        self.smtp_port = Config.EMAIL_SMTP_PORT
        self._email = Config.EMAIL_ADDRESS
        self._password = Config.EMAIL_APP_PASSWORD

    def configure(self, email_address, app_password, imap_server=None, smtp_server=None, smtp_port=None):
        """Configures email credentials dynamically."""
        self._email = email_address.strip()
        self._password = app_password.strip()
        if imap_server:
            self.imap_server = imap_server
        if smtp_server:
            self.smtp_server = smtp_server
        if smtp_port:
            self.smtp_port = int(smtp_port)
            
        # Store in database
        try:
            execute_query(
                "INSERT INTO email_config (email_address, status) VALUES (%s, %s)",
                (self._email, 'active')
            )
        except Exception:
            pass
            
        return True

    def test_connection(self):
        """Tests both IMAP and SMTP connections securely."""
        if not self._email or not self._password:
            return False, "Email address and App Password must be configured."
            
        errors = []
        # Test IMAP
        try:
            mail = imaplib.IMAP4_SSL(self.imap_server)
            mail.login(self._email, self._password)
            mail.logout()
        except Exception as e:
            errors.append(f"IMAP connection failed: {str(e)}")
            
        # Test SMTP
        try:
            context = ssl.create_default_context()
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls(context=context)
            server.login(self._email, self._password)
            server.quit()
        except Exception as e:
            errors.append(f"SMTP connection failed: {str(e)}")
            
        if errors:
            return False, "; ".join(errors)
        return True, "Email credentials successfully verified for IMAP & SMTP."

    def fetch_emails(self, mailbox='INBOX', limit=10):
        """Fetches and parses the latest emails with full multipart body & attachment extraction."""
        if not self._email or not self._password:
            return []
            
        try:
            mail = imaplib.IMAP4_SSL(self.imap_server)
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
        if not self._email or not self._password:
            return False, "Email integration is not configured."
        try:
            msg = MIMEMultipart()
            msg['From'] = self._email
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            context = ssl.create_default_context()
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls(context=context)
            server.login(self._email, self._password)
            server.sendmail(self._email, to_email, msg.as_string())
            server.quit()
            return True, "Email sent successfully."
        except Exception as e:
            return False, f"Failed to send email: {str(e)}"
