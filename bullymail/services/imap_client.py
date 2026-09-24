import imaplib
import ssl
import re
from ..services.email_service import EmailService

class IMAPClientError(Exception):
    """Base exception for IMAP client operations."""
    pass

class IMAPConnectionError(IMAPClientError):
    """Raised when connecting to IMAP server fails."""
    pass

class IMAPAuthenticationError(IMAPClientError):
    """Raised when IMAP login authentication fails."""
    pass

class IMAPMailboxError(IMAPClientError):
    """Raised when selecting IMAP mailbox fails."""
    pass

class IMAPFetchError(IMAPClientError):
    """Raised when fetching message data fails."""
    pass

class IMAPClient:
    """
    Secure IMAP Client Service.
    Resolves tenant credentials transiently, connects via SSL, extracts UID/UIDVALIDITY,
    and fetches raw RFC822 bytes without persisting plaintext credentials.
    Enforces pre-fetch message size checks to prevent loading oversized payloads into memory.
    """
    MAX_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MB limit

    def __init__(self, institution_id=1, email_service=None, mailbox_id=None):
        self.institution_id = institution_id
        self.mailbox_id = mailbox_id
        self.email_service = email_service or EmailService()
        self.mail_session = None

    def connect(self):
        """
        Resolves tenant credentials via EmailService.get_mailbox_credentials(mailbox_id, institution_id)
        and authenticates with IMAP4_SSL.
        """
        if self.mailbox_id:
            email_addr, app_pw, _, _, imap_host = self.email_service.get_mailbox_credentials(self.mailbox_id, self.institution_id)
        else:
            email_addr, app_pw, _, _, imap_host = self.email_service._get_credentials(institution_id=self.institution_id)

        if not email_addr or not app_pw:
            raise IMAPAuthenticationError("Email address or App Password is missing for institution.")

        try:
            ctx = ssl.create_default_context()
            self.mail_session = imaplib.IMAP4_SSL(imap_host, port=993, ssl_context=ctx, timeout=15)
        except Exception as e:
            raise IMAPConnectionError(f"Failed to connect to IMAP host {imap_host}: {str(e)}")

        try:
            status, _ = self.mail_session.login(email_addr, app_pw)
            if status != 'OK':
                raise IMAPAuthenticationError(f"IMAP login failed for {email_addr}.")
        except imaplib.IMAP4.error as e:
            raise IMAPAuthenticationError(f"IMAP authentication failed for {email_addr}: {str(e)}")
        except Exception as e:
            raise IMAPConnectionError(f"Error during IMAP authentication: {str(e)}")

        return True

    def select_mailbox(self, mailbox_name='INBOX') -> tuple:
        """
        Selects target mailbox folder.
        Returns tuple: (status: str, uidvalidity: int, message_count: int).
        """
        if not self.mail_session:
            raise IMAPConnectionError("IMAP session is not connected.")

        try:
            res, data = self.mail_session.select(mailbox_name)
            if res != 'OK':
                raise IMAPMailboxError(f"Failed to select mailbox '{mailbox_name}'.")

            msg_count = int(data[0]) if data and data[0] else 0

            uidvalidity = None
            try:
                res_val, data_val = self.mail_session.response('UIDVALIDITY')
                if data_val and data_val[0]:
                    raw_val = data_val[0].decode('utf-8') if isinstance(data_val[0], bytes) else str(data_val[0])
                    if raw_val.isdigit():
                        uidvalidity = int(raw_val)
            except Exception:
                uidvalidity = None

            return res, uidvalidity, msg_count
        except Exception as e:
            raise IMAPMailboxError(f"Error selecting mailbox '{mailbox_name}': {str(e)}")

    def get_max_uid(self) -> int:
        """
        Returns the highest IMAP UID currently in the selected folder, or 0 if empty.
        Used to establish baseline boundary when a mailbox is registered or initialized.
        """
        if not self.mail_session:
            raise IMAPConnectionError("IMAP session is not connected.")
        try:
            res, data = self.mail_session.uid('SEARCH', None, 'ALL')
            if res != 'OK' or not data or not data[0]:
                return 0
            raw_uids = [int(u) for u in data[0].split() if u.isdigit()]
            return max(raw_uids) if raw_uids else 0
        except Exception as e:
            raise IMAPFetchError(f"Error searching max IMAP UID: {str(e)}")

    def fetch_unseen_uids(self, last_known_uid=None) -> list:
        """
        Fetches list of IMAP UIDs (integers) matching search criteria.
        If last_known_uid is provided, searches for UIDs >= last_known_uid + 1.
        Otherwise, searches ALL messages to ensure read/seen messages in INBOX are not missed.
        """
        if not self.mail_session:
            raise IMAPConnectionError("IMAP session is not connected.")

        try:
            if last_known_uid and isinstance(last_known_uid, int) and last_known_uid > 0:
                search_criterion = f'UID {last_known_uid + 1}:*'
            else:
                search_criterion = 'ALL'

            res, data = self.mail_session.uid('SEARCH', None, search_criterion)
            if res != 'OK' or not data or not data[0]:
                return []

            raw_uids = [int(u) for u in data[0].split() if u.isdigit()]
            if last_known_uid and isinstance(last_known_uid, int) and last_known_uid > 0:
                uids = [u for u in raw_uids if u > last_known_uid]
            else:
                uids = raw_uids
            return sorted(uids)
        except Exception as e:
            raise IMAPFetchError(f"Error searching IMAP UIDs: {str(e)}")

    def fetch_rfc822_message(self, uid: int) -> bytes:
        """
        Fetches raw RFC822 email bytes for given IMAP UID after verifying message size.
        Raises IMAPFetchError if RFC822.SIZE exceeds 10MB BEFORE fetching full body.
        """
        if not self.mail_session:
            raise IMAPConnectionError("IMAP session is not connected.")

        try:
            # 1. Pre-fetch RFC822.SIZE to prevent loading oversized messages into memory
            res_size, data_size = self.mail_session.uid('FETCH', str(uid), '(RFC822.SIZE)')
            if res_size == 'OK' and data_size and data_size[0]:
                raw_size_resp = str(data_size[0])
                size_match = re.search(r'RFC822\.SIZE\s+(\d+)', raw_size_resp, re.IGNORECASE)
                if size_match:
                    msg_size = int(size_match.group(1))
                    if msg_size > self.MAX_MESSAGE_BYTES:
                        raise IMAPFetchError(f"Email RFC822 size ({msg_size} bytes) exceeds maximum limit of {self.MAX_MESSAGE_BYTES} bytes.")

            # 2. Fetch RFC822 full message bytes if size check passed
            res, data = self.mail_session.uid('FETCH', str(uid), '(RFC822)')
            if res != 'OK' or not data or not data[0]:
                raise IMAPFetchError(f"Failed to fetch RFC822 content for UID {uid}.")

            raw_bytes = None
            for item in data:
                if isinstance(item, tuple) and len(item) > 1:
                    raw_bytes = item[1]
                    break

            if not raw_bytes:
                raise IMAPFetchError(f"Empty payload returned for UID {uid}.")

            if len(raw_bytes) > self.MAX_MESSAGE_BYTES:
                raise IMAPFetchError(f"Email size ({len(raw_bytes)} bytes) exceeds maximum limit of {self.MAX_MESSAGE_BYTES} bytes.")

            return raw_bytes
        except IMAPFetchError:
            raise
        except Exception as e:
            raise IMAPFetchError(f"Error fetching RFC822 bytes for UID {uid}: {str(e)}")

    def fetch_message_with_metadata(self, uid: int) -> tuple:
        """
        Fetches raw RFC822 email bytes and INTERNALDATE string for given IMAP UID after verifying size.
        Returns tuple: (raw_bytes: bytes, internal_date: str or None).
        """
        if not self.mail_session:
            raise IMAPConnectionError("IMAP session is not connected.")

        try:
            # 1. Pre-fetch RFC822.SIZE to prevent loading oversized messages
            res_size, data_size = self.mail_session.uid('FETCH', str(uid), '(RFC822.SIZE)')
            if res_size == 'OK' and data_size and data_size[0]:
                raw_size_resp = str(data_size[0])
                size_match = re.search(r'RFC822\.SIZE\s+(\d+)', raw_size_resp, re.IGNORECASE)
                if size_match:
                    msg_size = int(size_match.group(1))
                    if msg_size > self.MAX_MESSAGE_BYTES:
                        raise IMAPFetchError(f"Email RFC822 size ({msg_size} bytes) exceeds maximum limit of {self.MAX_MESSAGE_BYTES} bytes.")

            # 2. Fetch INTERNALDATE and RFC822 full message bytes
            res, data = self.mail_session.uid('FETCH', str(uid), '(INTERNALDATE RFC822)')
            if res != 'OK' or not data or not data[0]:
                raw_bytes = self.fetch_rfc822_message(uid)
                return raw_bytes, None

            raw_bytes = None
            internal_date = None

            for item in data:
                if isinstance(item, tuple) and len(item) > 1:
                    raw_bytes = item[1]
                    raw_meta = str(item[0])
                    date_match = re.search(r'INTERNALDATE\s+"([^"]+)"', raw_meta, re.IGNORECASE)
                    if date_match:
                        internal_date = date_match.group(1)
                    break

            if not raw_bytes:
                raw_bytes = self.fetch_rfc822_message(uid)

            return raw_bytes, internal_date
        except IMAPFetchError:
            raise
        except Exception as e:
            try:
                raw_bytes = self.fetch_rfc822_message(uid)
                return raw_bytes, None
            except Exception:
                raise IMAPFetchError(f"Error fetching RFC822 email for UID {uid}: {str(e)}")

    def disconnect(self):
        """Safely closes mailbox and logs out of IMAP session."""
        if self.mail_session:
            try:
                self.mail_session.close()
            except Exception:
                pass
            try:
                self.mail_session.logout()
            except Exception:
                pass
            self.mail_session = None
