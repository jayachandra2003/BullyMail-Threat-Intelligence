import os
import sys
import time
import signal
import logging
from ..database.connection import fetch_all
from ..models.ingested_message import IngestedMessageModel
from .processor import MailboxProcessor

logger = logging.getLogger('bullymail.worker.daemon')

class WorkerDaemon:
    """
    Standalone Automated IMAP Ingestion Daemon.
    Polls active institutional mailboxes periodically, recovers stale processing claims,
    and isolates failures while supporting graceful SIGINT/SIGTERM shutdown.
    """

    def __init__(self, poll_interval=None, processor=None):
        env_interval = os.environ.get('WORKER_POLL_INTERVAL', '15')
        try:
            self.poll_interval = int(poll_interval) if poll_interval is not None else int(env_interval)
        except ValueError:
            self.poll_interval = 15

        self.processor = processor or MailboxProcessor()
        self.running = True
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Registers SIGINT (Ctrl+C) and SIGTERM for graceful shutdown."""
        try:
            signal.signal(signal.SIGINT, self._handle_shutdown)
            signal.signal(signal.SIGTERM, self._handle_shutdown)
        except (ValueError, AttributeError):
            # Signal handling might not be available in non-main threads or some environments
            pass

    def _handle_shutdown(self, signum, frame):
        """Signal handler setting self.running to False."""
        logger.info(f"Received shutdown signal ({signum}). Gracefully stopping IMAP worker daemon...")
        self.running = False

    def run_once(self) -> int:
        """
        Executes a single polling iteration across all active institutional mailboxes.
        Returns the number of active mailboxes processed.
        """
        logger.info("Executing ingestion daemon poll iteration...")

        # 1. Recover stale processing claims older than 15 minutes
        try:
            recovered_count = IngestedMessageModel.recover_stale_processing(timeout_minutes=15)
            if recovered_count > 0:
                logger.info(f"Recovered {recovered_count} stale processing message claims.")
        except Exception as e:
            logger.error(f"Error during stale processing recovery: {e}")

        # 2. Fetch active institutional mailboxes
        try:
            active_configs = fetch_all("SELECT * FROM email_config WHERE status = 'active'")
        except Exception as e:
            logger.error(f"Error querying active email_config records: {e}")
            return 0

        if not active_configs:
            logger.info("No active institutional mailboxes configured.")
            return 0

        logger.info(f"Discovered {len(active_configs)} active institutional mailboxes.")
        processed_count = 0

        for config_row in active_configs:
            if not self.running:
                logger.info("Shutdown requested mid-loop. Halting mailbox polling cycle.")
                break

            cfg_id = config_row.get('id')
            inst_id = config_row.get('institution_id')
            if not cfg_id or not inst_id:
                continue

            from ..services.email_service import email_service
            lease_id = email_service.acquire_sync_lease(cfg_id, inst_id)
            if not lease_id:
                logger.info(f"Skipping mailbox {cfg_id} for Institution {inst_id}: Synchronization lease currently held by another process.")
                continue

            success = False
            try:
                success = self.processor.process_mailbox(config_row, should_stop=lambda: not self.running, lease_id=lease_id)
                if success:
                    processed_count += 1
            except Exception as e:
                logger.error(f"Unhandled error processing mailbox {cfg_id}: {e}")
            finally:
                email_service.release_sync_lease(cfg_id, lease_id, final_status=('OK' if success else 'ERROR'))

        return processed_count

    def start(self):
        """
        Starts continuous daemon polling loop until interrupted.
        Sleeps in 1-second ticks for immediate response to Ctrl+C (SIGINT).
        """
        logger.info(f"BullyMail V2 IMAP Ingestion Worker Daemon started (Polling Interval: {self.poll_interval}s)")

        while self.running:
            self.run_once()

            # Responsive sleep loop
            sleep_ticks = 0
            while self.running and sleep_ticks < self.poll_interval:
                time.sleep(1)
                sleep_ticks += 1

        logger.info("BullyMail V2 IMAP Ingestion Worker Daemon shutdown complete.")

def main():
    """CLI entry point for running the worker daemon standalone: python -m bullymail.worker.daemon"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    # Initialize app context if running standalone
    try:
        from bullymail import create_app
        app = create_app()
        with app.app_context():
            daemon = WorkerDaemon()
            daemon.start()
    except Exception as e:
        logger.error(f"Failed to launch Worker Daemon: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
