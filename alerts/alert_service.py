"""
NetGuardian Alert Service
Orchestrates notification delivery across Email, Discord, and Dashboard logs.
"""

import logging
import queue
import threading
from typing import Any, Dict, Optional

from alerts.discord_notifier import DiscordNotifier
from alerts.email_notifier import EmailNotifier
from database.db import Database, db as default_db

logger = logging.getLogger(__name__)


class AlertService:
    """
    Asynchronous notification manager for confirmed security anomalies.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        email_notifier: Optional[EmailNotifier] = None,
        discord_notifier: Optional[DiscordNotifier] = None,
    ):
        self.db = database or default_db
        self.email_notifier = email_notifier or EmailNotifier()
        self.discord_notifier = discord_notifier or DiscordNotifier()

        self._queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def trigger_alert(self, anomaly: Dict[str, Any]) -> None:
        """Asynchronously enqueues an anomaly for notification delivery."""
        self._queue.put(anomaly)

    def _worker_loop(self) -> None:
        """Background worker delivering alerts."""
        while not self._stop_event.is_set():
            try:
                anomaly = self._queue.get(timeout=1.0)
                self._dispatch(anomaly)
                self._queue.task_done()
            except queue.Empty:
                continue

    def _dispatch(self, anomaly: Dict[str, Any]) -> None:
        """Delivers anomaly notifications across all enabled channels."""
        anomaly_id = anomaly.get("id")

        # 1. Dashboard In-App Alert record (always logged)
        self.db.record_alert(
            anomaly_id=anomaly_id,
            channel="DASHBOARD",
            status="SENT",
            message=anomaly.get("description", "Security anomaly flagged"),
        )

        # 2. Email SMTP Notification
        if self.email_notifier.enabled:
            success, msg = self.email_notifier.send_alert(anomaly)
            self.db.record_alert(
                anomaly_id=anomaly_id,
                channel="EMAIL",
                status="SENT" if success else "FAILED",
                message=msg if success else "Failed to send email",
                error_message=None if success else msg,
            )

        # 3. Discord Webhook Notification
        if self.discord_notifier.enabled:
            success, msg = self.discord_notifier.send_alert(anomaly)
            self.db.record_alert(
                anomaly_id=anomaly_id,
                channel="DISCORD",
                status="SENT" if success else "FAILED",
                message=msg if success else "Failed to send Discord webhook",
                error_message=None if success else msg,
            )

    def start(self) -> None:
        """Start background alert worker thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._worker_loop, name="NetGuardian-AlertWorker", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop alert worker."""
        if self._thread is not None:
            self._stop_event.set()
            self._thread.join(timeout=3.0)
            self._thread = None


# Global singleton
alert_service = AlertService()
