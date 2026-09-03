"""
BullyMail V2 — Automated IMAP Ingestion Worker Package
Provides standalone background mailbox polling, failure isolation, and transactionally consistent threat ingestion.
"""
from .processor import MailboxProcessor
from .daemon import WorkerDaemon

__all__ = ['MailboxProcessor', 'WorkerDaemon']
