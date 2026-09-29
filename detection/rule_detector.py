"""
NetGuardian Rule-Based Detection Engine
Evaluates deterministic network security rules:
  Rule A: Unrecognized Device Detection (never seen before on local network)
  Rule B: Off-Hours Activity Detection (traffic outside device's configured normal schedule)

Includes rate-limiting suppression to prevent alert fatigue when noisy devices stream traffic.
"""

from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, Optional, Tuple

import config
from database.db import Database, db as default_db

logger = logging.getLogger(__name__)


class RuleDetector:
    """
    Deterministic rule evaluation module for instant detection of zero-day device arrivals
    and temporal traffic policy violations.
    """

    def __init__(self, database: Optional[Database] = None):
        self.db = database or default_db
        # In-memory tracking for rate-limiting duplicate alerts (mac:rule_type -> last_alert_time)
        self._rate_limit_cache: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._rate_limit_seconds = 3600  # 1 hour suppression window per device per rule

    def check_new_device(
        self, device_record: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Rule A: Evaluates if a device is newly discovered and untrusted.
        Flags an anomaly if this is the device's first network appearance.
        """
        mac = device_record.get("mac_address", "").lower().strip()
        ip = device_record.get("ip_address", "")
        vendor = device_record.get("vendor") or "Unknown Vendor"
        is_trusted = bool(device_record.get("is_trusted", 0))

        if is_trusted:
            logger.debug("Device %s is trusted; skipping new device alert.", mac)
            return None

        rule_key = f"{mac}:NEW_DEVICE"
        with self._lock:
            now_sec = datetime.now(timezone.utc).timestamp()
            last_time = self._rate_limit_cache.get(rule_key, 0.0)
            if now_sec - last_time < self._rate_limit_seconds:
                return None
            self._rate_limit_cache[rule_key] = now_sec

        description = (
            f"New unrecognized device joined local network: "
            f"MAC={mac}, IP={ip}, Vendor='{vendor}'"
        )
        anomaly_id = self.db.record_anomaly(
            mac_address=mac,
            ip_address=ip,
            anomaly_type="NEW_DEVICE",
            description=description,
            severity="MEDIUM",
            score=0.8,
        )

        logger.warning("ANOMALY FLAGGED: %s", description)
        return {
            "id": anomaly_id,
            "mac_address": mac,
            "ip_address": ip,
            "anomaly_type": "NEW_DEVICE",
            "description": description,
            "severity": "MEDIUM",
            "score": 0.8,
        }

    def check_off_hours_activity(
        self,
        device_record: Dict[str, Any],
        packet_timestamp: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Rule B: Checks if device network activity occurs outside configured active hours.
        Configured via active_hours_start (0-23) and active_hours_end (0-23).
        """
        mac = device_record.get("mac_address", "").lower().strip()
        ip = device_record.get("ip_address", "")
        start_hour = device_record.get("active_hours_start", 0)
        end_hour = device_record.get("active_hours_end", 23)

        # 0 to 23 implies 24/7 normal operation
        if start_hour == 0 and end_hour == 23:
            return None

        ts = packet_timestamp or datetime.now()
        current_hour = ts.hour

        is_off_hours = False
        if start_hour <= end_hour:
            # Standard single-day window (e.g. 08:00 to 18:00)
            if current_hour < start_hour or current_hour > end_hour:
                is_off_hours = True
        else:
            # Overnight window (e.g. 22:00 to 06:00)
            if end_hour < current_hour < start_hour:
                is_off_hours = True

        if not is_off_hours:
            return None

        # Check rate-limiting cache
        rule_key = f"{mac}:OFF_HOURS"
        with self._lock:
            now_sec = datetime.now(timezone.utc).timestamp()
            last_time = self._rate_limit_cache.get(rule_key, 0.0)
            if now_sec - last_time < self._rate_limit_seconds:
                return None
            self._rate_limit_cache[rule_key] = now_sec

        description = (
            f"Off-hours traffic detected for device {mac} ({ip}) at {current_hour:02d}:00. "
            f"Normal schedule is {start_hour:02d}:00 - {end_hour:02d}:00."
        )
        anomaly_id = self.db.record_anomaly(
            mac_address=mac,
            ip_address=ip,
            anomaly_type="OFF_HOURS_ACTIVITY",
            description=description,
            severity="HIGH",
            score=0.9,
        )

        logger.warning("ANOMALY FLAGGED: %s", description)
        return {
            "id": anomaly_id,
            "mac_address": mac,
            "ip_address": ip,
            "anomaly_type": "OFF_HOURS_ACTIVITY",
            "description": description,
            "severity": "HIGH",
            "score": 0.9,
        }


# Global singleton
rule_detector_service = RuleDetector()
