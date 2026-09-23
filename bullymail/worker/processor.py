import logging
import datetime
from ..database.connection import execute_query, fetch_one
from ..services.imap_client import IMAPClient, IMAPClientError, IMAPAuthenticationError, IMAPConnectionError
from ..services.mime_parser import SafeMIMEParser, MIMEParserError
from ..services.risk_engine import UnifiedRiskEngine
from ..models.analysis import AnalysisModel
from ..models.ingested_message import IngestedMessageModel

logger = logging.getLogger('bullymail.worker.processor')

def _parse_datetime(val):
    if not val:
        return None
    if isinstance(val, datetime.datetime):
        dt = val
    else:
        try:
            val_str = str(val).split('.')[0]
            dt = datetime.datetime.fromisoformat(val_str.replace('Z', ''))
        except Exception:
            try:
                import email.utils
                dt = email.utils.parsedate_to_datetime(str(val))
            except Exception:
                return None
    if dt is not None:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        else:
            dt = dt.astimezone(datetime.timezone.utc)
    return dt

def _parse_email_date(date_str):
    if not date_str:
        return None
    try:
        import email.utils
        dt = email.utils.parsedate_to_datetime(str(date_str))
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt = dt.astimezone(datetime.timezone.utc)
        return dt
    except Exception:
        try:
            val_str = str(date_str).split('.')[0]
            dt = datetime.datetime.fromisoformat(val_str.replace('Z', ''))
            if dt is not None:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    dt = dt.astimezone(datetime.timezone.utc)
            return dt
        except Exception:
            return None

class MailboxProcessor:
    """
    Processes institutional email inboxes sequentially.
    Enforces JIT credential resolution, atomic message claims, failure isolation,
    auth failure exponential backoff, and ownership-aware state transitions.
    """

    def __init__(self, risk_engine=None):
        self.risk_engine = risk_engine or UnifiedRiskEngine()
        self.auth_failures = {}  # Tracks config_id -> {'count': int, 'backoff_until': datetime}

    def _is_in_auth_backoff(self, config_id: int) -> bool:
        """Checks if a mailbox is currently in exponential authentication backoff window."""
        info = self.auth_failures.get(config_id)
        if not info:
            return False
        if datetime.datetime.utcnow() < info['backoff_until']:
            return True
        return False

    def _record_auth_failure(self, config_id: int):
        """Increments auth failure counter and sets exponential backoff window (300s, 600s, 1200s... max 3600s)."""
        info = self.auth_failures.get(config_id, {'count': 0, 'backoff_until': datetime.datetime.utcnow()})
        new_count = info['count'] + 1
        backoff_sec = min(300 * (2 ** (new_count - 1)), 3600)
        until = datetime.datetime.utcnow() + datetime.timedelta(seconds=backoff_sec)
        self.auth_failures[config_id] = {'count': new_count, 'backoff_until': until}
        logger.warning(f"Mailbox config {config_id} authentication failed {new_count} time(s). Backoff active until {until.isoformat()} UTC ({backoff_sec}s).")

    def _clear_auth_failure(self, config_id: int):
        """Resets auth failure counter on successful connection."""
        if config_id in self.auth_failures:
            del self.auth_failures[config_id]

    @staticmethod
    def update_telemetry(config_id: int, sync_status: str, last_error: str = None, increment_count: bool = False, lease_id: str = None) -> bool:
        """Updates email_config telemetry metrics cleanly without secret exposure, enforcing lease_id ownership when provided."""
        valid_statuses = {'IDLE', 'SYNCING', 'OK', 'ERROR'}
        if sync_status not in valid_statuses:
            sync_status = 'ERROR'

        last_error_clean = str(last_error)[:500] if last_error else None

        if lease_id:
            from ..database.connection import get_engine_type
            engine = get_engine_type()
            lease_expire_sql = "DATE_ADD(NOW(), INTERVAL 2 MINUTE)" if engine == 'mysql' else "datetime('now', '+2 minutes')"

            if increment_count:
                sql = f'''UPDATE email_config 
                         SET sync_status = %s, last_error = %s, last_synced_at = CURRENT_TIMESTAMP,
                             sync_lease_expires_at = {lease_expire_sql}, total_ingested_count = total_ingested_count + 1 
                         WHERE id = %s AND sync_lease_id = %s'''
                count = execute_query(sql, (sync_status, last_error_clean, config_id, lease_id))
            else:
                sql = f'''UPDATE email_config 
                         SET sync_status = %s, last_error = %s, last_synced_at = CURRENT_TIMESTAMP,
                             sync_lease_expires_at = {lease_expire_sql} 
                         WHERE id = %s AND sync_lease_id = %s'''
                count = execute_query(sql, (sync_status, last_error_clean, config_id, lease_id))

            if count == 0:
                logger.warning(f"Mailbox {config_id} telemetry update ignored: sync lease ownership was lost or reclaimed by another process.")
                return False
            return True
        else:
            if increment_count:
                execute_query(
                    '''UPDATE email_config 
                       SET sync_status = %s, last_error = %s, last_synced_at = CURRENT_TIMESTAMP, total_ingested_count = total_ingested_count + 1 
                       WHERE id = %s''',
                    (sync_status, last_error_clean, config_id)
                )
            else:
                execute_query(
                    '''UPDATE email_config 
                       SET sync_status = %s, last_error = %s, last_synced_at = CURRENT_TIMESTAMP 
                       WHERE id = %s''',
                    (sync_status, last_error_clean, config_id)
                )
            return True

    def process_mailbox(self, config_row: dict, should_stop=None, lease_id: str = None, return_summary: bool = False):
        """
        Processes all unseen messages for a single institutional mailbox.
        Respects authentication failure backoff, mid-batch shutdown requests, and sync lease ownership.
        """
        start_time = datetime.datetime.utcnow()
        summary = {
            'success': False,
            'emails_found': 0,
            'emails_processed': 0,
            'threats_detected': 0,
            'duplicates_skipped': 0,
            'failures': 0,
            'sync_start_time': start_time.isoformat(),
            'sync_completion_time': None,
            'status': 'ERROR',
            'error': None
        }

        if not config_row or not config_row.get('institution_id') or not config_row.get('id'):
            logger.warning("Invalid configuration row provided to MailboxProcessor.")
            summary['error'] = "Invalid configuration row"
            return summary if return_summary else False

        if not lease_id:
            logger.warning(f"Mailbox processing rejected: missing required lease_id for config {config_row.get('id')}.")
            summary['error'] = "Missing lease ownership"
            return summary if return_summary else False

        inst_id = config_row['institution_id']
        cfg_id = config_row['id']
        email_addr = config_row.get('email_address', 'Unknown Mailbox')

        if self._is_in_auth_backoff(cfg_id):
            logger.info(f"Skipping mailbox processing for Institution {inst_id} ({email_addr}): Active auth backoff window.")
            summary['error'] = "Authentication backoff active"
            return summary if return_summary else False

        logger.info(f"[SYNC] Start mailbox sync: config_id={cfg_id}, institution_id={inst_id} ({email_addr})")
        if not self.update_telemetry(cfg_id, sync_status='SYNCING', lease_id=lease_id):
            logger.warning(f"[SYNC] Mailbox {cfg_id} processing halted: sync lease ownership was lost at start.")
            summary['error'] = "Lost sync lease at start"
            return summary if return_summary else False

        try:
            imap_client = IMAPClient(institution_id=inst_id, mailbox_id=cfg_id)
        except TypeError:
            imap_client = IMAPClient(institution_id=inst_id)
        try:
            imap_client.connect()
            self._clear_auth_failure(cfg_id)
        except IMAPAuthenticationError as e:
            logger.warning(f"[SYNC] IMAP authentication failed for Institution {inst_id} ({email_addr}): {e}")
            self._record_auth_failure(cfg_id)
            self.update_telemetry(cfg_id, sync_status='ERROR', last_error="IMAP authentication failed", lease_id=lease_id)
            summary['error'] = "IMAP authentication failed"
            summary['sync_completion_time'] = datetime.datetime.utcnow().isoformat()
            return summary if return_summary else False
        except IMAPConnectionError as e:
            logger.warning(f"[SYNC] IMAP connection failed for Institution {inst_id} ({email_addr}): {e}")
            self.update_telemetry(cfg_id, sync_status='ERROR', last_error="IMAP connection failed", lease_id=lease_id)
            summary['error'] = "IMAP connection failed"
            summary['sync_completion_time'] = datetime.datetime.utcnow().isoformat()
            return summary if return_summary else False
        except Exception as e:
            logger.error(f"[SYNC] Unexpected error connecting to IMAP for Institution {inst_id}: {e}")
            self.update_telemetry(cfg_id, sync_status='ERROR', last_error=str(e), lease_id=lease_id)
            summary['error'] = str(e)
            summary['sync_completion_time'] = datetime.datetime.utcnow().isoformat()
            return summary if return_summary else False

        try:
            _, uidvalidity, msg_count = imap_client.select_mailbox('INBOX')

            # Fetch mailbox initialization state and UID boundaries
            mb_cfg = fetch_one(
                "SELECT mailbox_initialized, initial_uid, last_processed_uid, uid_validity, configured_at, monitoring_started_at FROM email_config WHERE id = %s",
                (cfg_id,)
            ) or {}

            is_initialized = bool(mb_cfg.get('mailbox_initialized'))
            stored_uid_validity = str(mb_cfg.get('uid_validity')) if mb_cfg.get('uid_validity') is not None else None
            current_uid_validity = str(uidvalidity) if uidvalidity is not None else None
            dt1 = _parse_datetime(mb_cfg.get('configured_at'))
            dt2 = _parse_datetime(mb_cfg.get('monitoring_started_at'))
            baseline_dt = min(dt1, dt2) if (dt1 and dt2) else (dt1 or dt2)

            # Handle initial baseline setup for newly added/uninitialized mailboxes
            if not is_initialized or stored_uid_validity is None or stored_uid_validity != current_uid_validity:
                raw_max_uid = imap_client.get_max_uid()
                try:
                    max_inbox_uid = int(raw_max_uid)
                except (TypeError, ValueError):
                    max_inbox_uid = 0
                logger.info(f"[SYNC] Baseline initialization for config_id={cfg_id}: establishing starting UID boundary at {max_inbox_uid}")

                execute_query(
                    '''UPDATE email_config
                       SET mailbox_initialized = 1,
                           initial_uid = %s,
                           last_processed_uid = %s,
                           uid_validity = %s,
                           monitoring_started_at = COALESCE(monitoring_started_at, CURRENT_TIMESTAMP)
                       WHERE id = %s''',
                    (max_inbox_uid, max_inbox_uid, current_uid_validity, cfg_id)
                )

                self.update_telemetry(cfg_id, sync_status='OK', lease_id=lease_id)
                imap_client.disconnect()
                summary['success'] = True
                summary['status'] = 'OK'
                summary['emails_found'] = 0
                summary['emails_processed'] = 0
                summary['sync_completion_time'] = datetime.datetime.utcnow().isoformat()
                logger.info(f"[SYNC] Baseline boundary established for config_id={cfg_id} (UID boundary: {max_inbox_uid}). Historical backfill suppressed.")
                return summary if return_summary else True

            # Incremental Sync for initialized mailboxes (only process UIDs > last_processed_uid)
            last_known_uid = mb_cfg.get('last_processed_uid')
            if last_known_uid is None:
                db_max = fetch_one(
                    "SELECT MAX(imap_uid) as max_uid FROM ingested_messages WHERE institution_id = %s AND email_config_id = %s",
                    (inst_id, cfg_id)
                )
                last_known_uid = db_max.get('max_uid') if db_max else 0

            last_known_uid = int(last_known_uid or 0)
            try:
                max_inbox_uid = int(imap_client.get_max_uid())
            except (ValueError, TypeError):
                max_inbox_uid = 0

            # Safety check: if stored last_known_uid exceeds current inbox max_uid, correct it
            if max_inbox_uid > 0 and last_known_uid > max_inbox_uid:
                logger.warning(f"[SYNC] Stored last_processed_uid ({last_known_uid}) exceeds inbox max_uid ({max_inbox_uid}). Correcting watermark to {max_inbox_uid}.")
                last_known_uid = max_inbox_uid
                execute_query("UPDATE email_config SET last_processed_uid = %s WHERE id = %s", (last_known_uid, cfg_id))

            uids = imap_client.fetch_unseen_uids(last_known_uid=last_known_uid)
            uids = [u for u in uids if u > last_known_uid]

            logger.info(f"[SYNC] IMAP check complete for config_id={cfg_id}: {len(uids)} new candidate messages in INBOX (cutoff UID > {last_known_uid})")
            summary['emails_found'] = len(uids)

            if not uids:
                self.update_telemetry(cfg_id, sync_status='OK', lease_id=lease_id)
                imap_client.disconnect()
                summary['success'] = True
                summary['status'] = 'OK'
                summary['sync_completion_time'] = datetime.datetime.utcnow().isoformat()
                logger.info(f"[SYNC] Complete: 0 new messages to ingest for config {cfg_id}")
                return summary if return_summary else True

            contiguous_watermark_uid = last_known_uid
            encountered_failure = False

            for uid in uids:
                if should_stop and should_stop():
                    logger.info(f"[SYNC] Mid-batch shutdown requested for Institution {inst_id}. Halting message loop.")
                    break

                record_id = None
                msg_handled = False
                try:
                    logger.info(f"[SYNC] New message candidate: UID={uid} for config_id={cfg_id}")

                    # 1. Fetch raw RFC822 bytes and IMAP internal date
                    try:
                        meta_res = imap_client.fetch_message_with_metadata(uid)
                        if isinstance(meta_res, (list, tuple)) and len(meta_res) == 2:
                            raw_bytes, internal_date = meta_res
                        elif isinstance(meta_res, (bytes, bytearray)):
                            raw_bytes, internal_date = meta_res, None
                        else:
                            raw_bytes = imap_client.fetch_rfc822_message(uid)
                            internal_date = None
                    except Exception:
                        raw_bytes = imap_client.fetch_rfc822_message(uid)
                        internal_date = None

                    logger.info(f"[SYNC] Fetched raw RFC822 for UID={uid} ({len(raw_bytes) if raw_bytes else 0} bytes, internal_date={internal_date})")

                    # 2. Parse MIME structure safely
                    parsed = SafeMIMEParser.parse_email_bytes(raw_bytes)
                    msg_hash = parsed['message_id_hash']

                    # 2b. Strict Baseline Date Boundary Enforcement
                    if baseline_dt:
                        email_dt = _parse_email_date(parsed.get('date'))
                        if not email_dt and internal_date:
                            email_dt = _parse_email_date(internal_date)
                        if email_dt and email_dt < baseline_dt:
                            logger.info(f"[SYNC] Skipping historical email UID={uid} for config {cfg_id}: date ({email_dt.isoformat()}) is prior to baseline ({baseline_dt.isoformat()})")
                            msg_handled = True
                            if not encountered_failure and uid > contiguous_watermark_uid:
                                contiguous_watermark_uid = uid
                            continue

                    # 3. Atomic Claim or Retry in IngestedMessageModel
                    claimed, record_id, attempt_cnt = IngestedMessageModel.claim_message_for_processing(
                        institution_id=inst_id,
                        email_config_id=cfg_id,
                        message_id_hash=msg_hash,
                        imap_uid=uid,
                        uidvalidity=uidvalidity,
                        max_attempts=3
                    )

                    if not claimed:
                        logger.debug(f"[SYNC] Skipping duplicate/in-progress message (Hash: {msg_hash[:12]}...) for Institution {inst_id}")
                        summary['duplicates_skipped'] += 1
                        msg_handled = True
                        if not encountered_failure and uid > contiguous_watermark_uid:
                            contiguous_watermark_uid = uid
                        continue

                    logger.info(f"[SYNC] Ingested and claimed UID={uid} for processing")

                    # 4. Multi-Vector Threat Analysis via UnifiedRiskEngine
                    report = self.risk_engine.analyze_email(
                        email_text=parsed['body_for_ml'],
                        email_subject=parsed['subject'],
                        email_from=parsed['from'],
                        email_to=parsed['to'],
                        attachments=parsed['attachments'],
                        images=parsed['images']
                    )
                    logger.info(f"[SYNC] Threat analysis completed for UID={uid}: Overall Risk={report.get('overall_risk_level')}")

                    # 5. Database Persistence (Transactional Consistency)
                    analysis_id = AnalysisModel.save_analysis(report, institution_id=inst_id, user_id=None, email_config_id=cfg_id)
                    logger.info(f"[SYNC] Saved analysis to database (Analysis ID: {analysis_id}) for UID={uid}")

                    # 6. Ownership-Aware Status Update to PROCESSED
                    updated = IngestedMessageModel.update_processing_status(
                        record_id, status='PROCESSED', analysis_id=analysis_id, expected_status='PROCESSING'
                    )
                    if updated:
                        summary['emails_processed'] += 1
                        msg_handled = True
                        if not encountered_failure and uid > contiguous_watermark_uid:
                            contiguous_watermark_uid = uid
                        if report.get('overall_risk_level') in ('HIGH', 'CRITICAL') or report.get('bullying_analysis', {}).get('is_bullying'):
                            summary['threats_detected'] += 1
                        lease_ok = self.update_telemetry(cfg_id, sync_status='SYNCING', increment_count=True, lease_id=lease_id)
                        if not lease_ok:
                            logger.warning(f"[SYNC] Halting email batch loop for Mailbox {cfg_id}: lost sync lease ownership during message ingestion.")
                            break
                        logger.info(f"[SYNC] Successfully processed and finalized email UID {uid} (Analysis ID: {analysis_id})")
                    else:
                        logger.warning(f"[SYNC] Lost processing ownership for UID {uid} due to stale recovery timeout reset.")
                        summary['failures'] += 1
                        encountered_failure = True

                except Exception as e:
                    summary['failures'] += 1
                    encountered_failure = True
                    logger.error(f"[SYNC] Error processing message UID {uid} for Institution {inst_id}: {e}")
                    if record_id:
                        try:
                            IngestedMessageModel.update_processing_status(
                                record_id, status='FAILED', error_message=str(e), expected_status='PROCESSING'
                            )
                        except Exception:
                            pass
                    continue

            if contiguous_watermark_uid > last_known_uid:
                execute_query(
                    "UPDATE email_config SET last_processed_uid = %s WHERE id = %s",
                    (contiguous_watermark_uid, cfg_id)
                )

            self.update_telemetry(cfg_id, sync_status='OK', lease_id=lease_id)
            summary['success'] = True
            summary['status'] = 'OK'
            summary['sync_completion_time'] = datetime.datetime.utcnow().isoformat()
            logger.info(f"[SYNC] Complete: {summary['emails_processed']} processed, {summary['duplicates_skipped']} skipped, {summary['threats_detected']} threats detected (high watermark UID: {contiguous_watermark_uid})")
            return summary if return_summary else True
        except Exception as e:
            logger.error(f"[SYNC] Error during mailbox loop for Institution {inst_id}: {e}")
            self.update_telemetry(cfg_id, sync_status='ERROR', last_error=str(e), lease_id=lease_id)
            summary['error'] = str(e)
            summary['sync_completion_time'] = datetime.datetime.utcnow().isoformat()
            return summary if return_summary else False
        finally:
            imap_client.disconnect()
