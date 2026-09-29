"""
NetGuardian Discord Webhook Notifier
Dispatches real-time security alerts to a Discord channel via free incoming webhooks.
Formats alerts into styled, color-coded Discord Embeds.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional, Tuple
import requests

import config

logger = logging.getLogger(__name__)


class DiscordNotifier:
    """
    Sends rich Discord embed notifications using Webhook URLs.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        enabled: Optional[bool] = None,
    ):
        self.webhook_url = webhook_url or config.DISCORD_WEBHOOK_URL
        self.enabled = config.ALERT_DISCORD_ENABLED if enabled is None else enabled

    def send_alert(self, anomaly: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Constructs and posts a Discord webhook embed.
        """
        if not self.enabled:
            return False, "Discord alerting is disabled in configuration."

        if not self.webhook_url:
            return False, "Discord Webhook URL is not configured."

        anomaly_type = anomaly.get("anomaly_type", "Security Alert")
        severity = anomaly.get("severity", "MEDIUM")
        mac = anomaly.get("mac_address", "Unknown")
        ip = anomaly.get("ip_address", "Unknown")
        desc = anomaly.get("description", "No details")
        score = anomaly.get("score", 0.0)

        # Color mapping (hex integer for Discord Embeds)
        # Red: 0xEF4444 (HIGH), Orange: 0xF59E0B (MEDIUM), Blue: 0x3B82F6 (LOW)
        color = 0xEF4444 if severity == "HIGH" else (0xF59E0B if severity == "MEDIUM" else 0x3B82F6)

        payload = {
            "username": "NetGuardian Sentinel",
            "avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.svg",
            "embeds": [
                {
                    "title": f"🛡️ NetGuardian Security Alert: {anomaly_type}",
                    "description": desc,
                    "color": color,
                    "fields": [
                        {"name": "Severity", "value": f"**{severity}**", "inline": True},
                        {"name": "Device IP", "value": f"`{ip}`", "inline": True},
                        {"name": "MAC Address", "value": f"`{mac}`", "inline": True},
                        {"name": "Anomaly Score", "value": f"{score:.3f}", "inline": True},
                        {
                            "name": "Timestamp (UTC)",
                            "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                            "inline": True,
                        },
                    ],
                    "footer": {
                        "text": "NetGuardian Autonomous Network Monitor • Zero Cost"
                    },
                }
            ],
        }

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=5)
            if resp.status_code in (200, 204):
                logger.info("Discord webhook alert posted successfully.")
                return True, "Discord webhook delivered."
            else:
                err = f"Discord webhook returned status {resp.status_code}: {resp.text}"
                logger.error(err)
                return False, err
        except Exception as e:
            err = f"Failed to send Discord webhook: {e}"
            logger.error(err)
            return False, err
