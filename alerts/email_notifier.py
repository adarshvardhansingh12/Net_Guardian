"""
NetGuardian Email Alert Notifier
Sends automated security alert emails via standard SMTP (e.g. Gmail, Outlook, private SMTP).
Uses Python's built-in smtplib for zero cost and zero external dependencies.
"""

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import smtplib
from typing import Any, Dict, Optional, Tuple

import config

logger = logging.getLogger(__name__)


class EmailNotifier:
    """
    Handles formatting and sending email alerts via SMTP.
    """

    def __init__(
        self,
        server: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        recipient: Optional[str] = None,
        enabled: Optional[bool] = None,
    ):
        self.server = server or config.SMTP_SERVER
        self.port = port or config.SMTP_PORT
        self.username = username or config.SMTP_USERNAME
        self.password = password or config.SMTP_PASSWORD
        self.recipient = recipient or config.ALERT_EMAIL_TO
        self.enabled = config.ALERT_EMAIL_ENABLED if enabled is None else enabled

    def send_alert(self, anomaly: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Constructs and sends an alert email for the given anomaly dictionary.
        Returns: (success: bool, message: str)
        """
        if not self.enabled:
            return False, "Email alerting is disabled in configuration."

        if not self.username or not self.recipient:
            return False, "SMTP username or recipient email address is not configured."

        anomaly_type = anomaly.get("anomaly_type", "Security Alert")
        severity = anomaly.get("severity", "MEDIUM")
        mac = anomaly.get("mac_address", "Unknown")
        ip = anomaly.get("ip_address", "Unknown")
        desc = anomaly.get("description", "No description provided.")

        subject = f"[NetGuardian Alert - {severity}] {anomaly_type} detected on {ip}"

        # HTML formatted email body
        html_content = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 24px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; border: 1px solid #334155; overflow: hidden;">
                <div style="background: linear-gradient(135deg, #0ea5e9, #6366f1); padding: 20px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; letter-spacing: 0.5px;">🛡️ NetGuardian Security Alert</h1>
                </div>
                <div style="padding: 24px;">
                    <p style="font-size: 16px; line-height: 1.5; color: #cbd5e1;">A network security anomaly was detected by NetGuardian:</p>
                    <table style="width: 100%; border-collapse: collapse; margin-top: 16px;">
                        <tr>
                            <td style="padding: 8px; color: #94a3b8; font-weight: bold;">Anomaly Type:</td>
                            <td style="padding: 8px; color: #f1f5f9;">{anomaly_type}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; color: #94a3b8; font-weight: bold;">Severity:</td>
                            <td style="padding: 8px; color: {'#ef4444' if severity=='HIGH' else '#f59e0b'}; font-weight: bold;">{severity}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; color: #94a3b8; font-weight: bold;">Target Device:</td>
                            <td style="padding: 8px; color: #f1f5f9;">{ip} ({mac})</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; color: #94a3b8; font-weight: bold;">Details:</td>
                            <td style="padding: 8px; color: #f1f5f9;">{desc}</td>
                        </tr>
                    </table>
                </div>
                <div style="background-color: #0f172a; padding: 12px; text-align: center; color: #64748b; font-size: 12px;">
                    NetGuardian Autonomous Network Monitor • Zero-Cost College Minor Project
                </div>
            </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.username
        msg["To"] = self.recipient
        msg.attach(MIMEText(desc, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            with smtplib.SMTP(self.server, self.port, timeout=10) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.username, [self.recipient], msg.as_string())
            logger.info("Alert email successfully dispatched to %s", self.recipient)
            return True, f"Email sent to {self.recipient}"
        except Exception as e:
            err_msg = f"Failed to send email alert via {self.server}:{self.port}: {e}"
            logger.error(err_msg)
            return False, err_msg
