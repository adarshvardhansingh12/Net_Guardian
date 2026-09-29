"""Unit tests for NetGuardian alert notifiers (Email and Discord)."""

import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from alerts.alert_service import AlertService
from alerts.discord_notifier import DiscordNotifier
from alerts.email_notifier import EmailNotifier
from database.db import Database


def test_email_notifier_mock_dispatch():
    notifier = EmailNotifier(
        server="smtp.example.com",
        port=587,
        username="netguardian@example.com",
        password="password123",
        recipient="admin@example.com",
        enabled=True,
    )

    anomaly = {
        "id": 1,
        "anomaly_type": "NEW_DEVICE",
        "severity": "MEDIUM",
        "mac_address": "00:11:22:33:44:55",
        "ip_address": "192.168.1.100",
        "description": "Unrecognized host detected",
    }

    with patch("smtplib.SMTP") as mock_smtp_class:
        mock_instance = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_instance

        success, msg = notifier.send_alert(anomaly)
        assert success is True
        assert "admin@example.com" in msg
        mock_instance.starttls.assert_called_once()
        mock_instance.login.assert_called_once_with("netguardian@example.com", "password123")
        mock_instance.sendmail.assert_called_once()


def test_discord_notifier_mock_dispatch():
    notifier = DiscordNotifier(
        webhook_url="https://discord.com/api/webhooks/test/123",
        enabled=True,
    )

    anomaly = {
        "id": 2,
        "anomaly_type": "OFF_HOURS_ACTIVITY",
        "severity": "HIGH",
        "mac_address": "11:22:33:44:55:66",
        "ip_address": "192.168.1.50",
        "description": "Late night traffic detected",
        "score": 0.95,
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 204

    with patch("requests.post", return_value=mock_resp) as mock_post:
        success, msg = notifier.send_alert(anomaly)
        assert success is True
        assert "delivered" in msg
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert "embeds" in payload
        assert payload["embeds"][0]["title"] == "🛡️ NetGuardian Security Alert: OFF_HOURS_ACTIVITY"


def test_alert_service_async_logging():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_alerts.db"
        test_db = Database(db_file)

        mock_email = MagicMock()
        mock_email.enabled = True
        mock_email.send_alert.return_value = (True, "Email ok")

        mock_discord = MagicMock()
        mock_discord.enabled = True
        mock_discord.send_alert.return_value = (True, "Discord ok")

        service = AlertService(
            database=test_db,
            email_notifier=mock_email,
            discord_notifier=mock_discord,
        )
        service.start()

        anomaly = {
            "id": 10,
            "anomaly_type": "ML_TRAFFIC_DEVIATION",
            "severity": "HIGH",
            "description": "Spike in packet throughput",
        }

        service.trigger_alert(anomaly)
        time.sleep(0.5)
        service.stop()

        # Check DB recorded alerts for DASHBOARD, EMAIL, DISCORD
        records = test_db.get_recent_alerts(limit=10)
        assert len(records) == 3
        channels = [r["channel"] for r in records]
        assert "DASHBOARD" in channels
        assert "EMAIL" in channels
        assert "DISCORD" in channels

        test_db.close()
