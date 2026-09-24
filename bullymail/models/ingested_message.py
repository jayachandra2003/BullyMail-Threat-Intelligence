import hashlib
import email.utils
import datetime
from ..database.connection import get_db, get_engine_type, execute_query, fetch_one, fetch_all

class IngestedMessageModel:
    """
    DAO / Model for Ingested Email State & Deduplication Identity.
    Provides cross-database (SQLite & MySQL) state management, tenant-bound deduplication,
    and engine-aware stale processing recovery.
    """

    @staticmethod
    def compute_message_id_hash(raw_msg_id=None, from_addr="", to_addr="", date_str="", subject="", body_snippet="") -> str:
        """
        Computes SHA-256 deduplication key.
        Primary Authoritative Identity: Standard RFC822 Message-ID header (when available).
        Fallback Identity: Normalized content tuple (from, to, date, subject, body_snippet).
        
        NOTE: Content fallback is a BEST-EFFORT deduplication key for emails missing Message-ID headers.
        """
        if raw_msg_id and str(raw_msg_id).strip():
            clean_msg_id = str(raw_msg_id).strip()
            # Remove angle brackets if present: <msgid@domain> -> msgid@domain
            if clean_msg_id.startswith('<') and clean_msg_id.endswith('>'):
                clean_msg_id = clean_msg_id[1:-1].strip()
            return hashlib.sha256(clean_msg_id.encode('utf-8')).hexdigest()

        # Best-effort normalized content fallback
        _, clean_from = email.utils.parseaddr(str(from_addr or ""))
        _, clean_to = email.utils.parseaddr(str(to_addr or ""))
        norm_from = (clean_from or str(from_addr or "")).strip().lower()
        norm_to = (clean_to or str(to_addr or "")).strip().lower()
        norm_date = str(date_str or "").strip().lower()
        norm_subject = " ".join(str(subject or "").strip().split()).lower()
        
        # Take first 512 bytes of body snippet, whitespace normalized
        snippet = str(body_snippet or "")[:512]
        norm_snippet = " ".join(snippet.strip().split()).lower()

        fallback_str = f"{norm_from}\n{norm_to}\n{norm_date}\n{norm_subject}\n{norm_snippet}"
        return hashlib.sha256(fallback_str.encode('utf-8')).hexdigest()

    @staticmethod
    def claim_message_for_processing(institution_id: int, email_config_id: int, message_id_hash: str, imap_uid=None, uidvalidity=None, max_attempts=3) -> tuple:
        """
        Atomically claims or re-claims an email for processing.
        Returns tuple: (claimed: bool, record_id: int or None, attempt_count: int).
        
        Rules:
        1. New message -> Atomically INSERT with status='PROCESSING', attempt_count=1.
        2. Existing message in 'FAILED' or 'DISCOVERED' status with attempt_count < max_attempts -> Atomically UPDATE to 'PROCESSING', attempt_count = attempt_count + 1.
        3. Existing message in 'PROCESSED' or attempt_count >= max_attempts -> Returns (False, existing_id, attempt_count).
        """
        if not institution_id or not email_config_id or not message_id_hash:
            raise ValueError("institution_id, email_config_id, and message_id_hash are required.")

        try:
            record_id = execute_query(
                '''INSERT INTO ingested_messages 
                   (institution_id, email_config_id, message_id_hash, imap_uid, uidvalidity, processing_status, attempt_count)
                   VALUES (%s, %s, %s, %s, %s, 'PROCESSING', 1)''',
                (institution_id, email_config_id, message_id_hash, imap_uid, uidvalidity)
            )
            return True, record_id, 1
        except Exception:
            # Duplicate entry exists. Check if eligible for retry.
            existing = fetch_one(
                '''SELECT id, processing_status, attempt_count FROM ingested_messages 
                   WHERE institution_id = %s AND email_config_id = %s AND message_id_hash = %s''',
                (institution_id, email_config_id, message_id_hash)
            )
            if not existing:
                return False, None, 0

            ex_id = existing['id']
            status = existing.get('processing_status')
            curr_attempts = existing.get('attempt_count', 1)

            # Atomic Retry Claim for FAILED or DISCOVERED messages with attempts remaining
            if status in ('FAILED', 'DISCOVERED') and curr_attempts < max_attempts:
                next_attempts = curr_attempts + 1
                rows_updated = execute_query(
                    '''UPDATE ingested_messages
                       SET processing_status = 'PROCESSING', attempt_count = %s, imap_uid = %s, uidvalidity = %s, updated_at = CURRENT_TIMESTAMP
                       WHERE id = %s AND processing_status = %s AND attempt_count = %s''',
                    (next_attempts, imap_uid, uidvalidity, ex_id, status, curr_attempts)
                )
                if rows_updated > 0:
                    return True, ex_id, next_attempts

            return False, ex_id, curr_attempts

    @staticmethod
    def update_processing_status(record_id: int, status: str, error_message=None, analysis_id=None, expected_status='PROCESSING') -> bool:
        """
        Updates status of an ingested message record ('PROCESSED', 'FAILED', etc.).
        Enforces expected_status precondition (default 'PROCESSING') to prevent stale recovery race conditions.
        Returns True if row was updated, False if state transition lost ownership.
        """
        valid_statuses = {'DISCOVERED', 'PROCESSING', 'PROCESSED', 'FAILED'}
        if status not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}")

        if expected_status:
            rows = execute_query(
                '''UPDATE ingested_messages 
                   SET processing_status = %s, error_message = %s, analysis_id = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s AND processing_status = %s''',
                (status, error_message, analysis_id, record_id, expected_status)
            )
        else:
            rows = execute_query(
                '''UPDATE ingested_messages 
                   SET processing_status = %s, error_message = %s, analysis_id = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s''',
                (status, error_message, analysis_id, record_id)
            )
        return bool(rows > 0)

    @staticmethod
    def get_stale_recovery_query(engine_type: str, institution_id=None, timeout_minutes=15) -> tuple:
        """
        Generates database-engine-specific query and parameter tuple for stale processing recovery.
        Supports both SQLite and MySQL.
        """
        stale_msg = "Reset after stale processing timeout"
        if engine_type == 'sqlite':
            # SQLite uses datetime('now', '-N minutes') or parameterized ISO cutoff
            cutoff = (datetime.datetime.utcnow() - datetime.timedelta(minutes=timeout_minutes)).strftime('%Y-%m-%d %H:%M:%S')
            if institution_id is not None:
                query = '''UPDATE ingested_messages 
                           SET processing_status = 'DISCOVERED', error_message = %s, updated_at = CURRENT_TIMESTAMP 
                           WHERE processing_status = 'PROCESSING' AND attempt_count < 3 AND updated_at < %s AND institution_id = %s'''
                params = (stale_msg, cutoff, institution_id)
            else:
                query = '''UPDATE ingested_messages 
                           SET processing_status = 'DISCOVERED', error_message = %s, updated_at = CURRENT_TIMESTAMP 
                           WHERE processing_status = 'PROCESSING' AND attempt_count < 3 AND updated_at < %s'''
                params = (stale_msg, cutoff)
        elif engine_type == 'postgres':
            if institution_id is not None:
                query = '''UPDATE ingested_messages
                           SET processing_status = 'DISCOVERED', error_message = %s, updated_at = CURRENT_TIMESTAMP
                           WHERE processing_status = 'PROCESSING' AND attempt_count < 3 AND updated_at < CURRENT_TIMESTAMP - (INTERVAL '1 minute' * %s) AND institution_id = %s'''
                params = (stale_msg, timeout_minutes, institution_id)
            else:
                query = '''UPDATE ingested_messages
                           SET processing_status = 'DISCOVERED', error_message = %s, updated_at = CURRENT_TIMESTAMP
                           WHERE processing_status = 'PROCESSING' AND attempt_count < 3 AND updated_at < CURRENT_TIMESTAMP - (INTERVAL '1 minute' * %s)'''
                params = (stale_msg, timeout_minutes)
        else:
            # MySQL engine query using DATE_SUB(NOW(), INTERVAL %s MINUTE)
            if institution_id is not None:
                query = '''UPDATE ingested_messages 
                           SET processing_status = 'DISCOVERED', error_message = %s, updated_at = CURRENT_TIMESTAMP 
                           WHERE processing_status = 'PROCESSING' AND attempt_count < 3 AND updated_at < DATE_SUB(NOW(), INTERVAL %s MINUTE) AND institution_id = %s'''
                params = (stale_msg, timeout_minutes, institution_id)
            else:
                query = '''UPDATE ingested_messages 
                           SET processing_status = 'DISCOVERED', error_message = %s, updated_at = CURRENT_TIMESTAMP 
                           WHERE processing_status = 'PROCESSING' AND attempt_count < 3 AND updated_at < DATE_SUB(NOW(), INTERVAL %s MINUTE)'''
                params = (stale_msg, timeout_minutes)
        return query, params

    @classmethod
    def recover_stale_processing(cls, institution_id=None, timeout_minutes=15) -> int:
        """
        Executes engine-aware stale processing recovery.
        Resets records stuck in 'PROCESSING' for > timeout_minutes with attempt_count < 3 back to 'DISCOVERED'.
        """
        engine = get_engine_type()
        query, params = cls.get_stale_recovery_query(engine, institution_id=institution_id, timeout_minutes=timeout_minutes)
        return execute_query(query, params)
