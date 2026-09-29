"""
NetGuardian Detection Manager & False-Positive Filter
Coordinates deterministic rules and statistical ML evaluation with false-positive controls:
  1. Trust-marking feedback: Known friendly devices bypass new-device alerts and reinforce baselines.
  2. Consecutive Window Confirmation: ML anomalies must persist across >1 observation window before triggering alerts.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, Optional

import config
from database.db import Database, db as default_db
from detection.ml_engine import DeviceMLEngine, device_ml_engine as default_ml
from detection.rule_detector import RuleDetector, rule_detector_service as default_rules

logger = logging.getLogger(__name__)


class DetectionManager:
    """
    Central orchestration engine for network anomaly detection and alert filtering.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        rule_detector: Optional[RuleDetector] = None,
        ml_engine: Optional[DeviceMLEngine] = None,
        on_anomaly_confirmed: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.db = database or default_db
        self.rule_detector = rule_detector or default_rules
        self.ml_engine = ml_engine or default_ml
        self.on_anomaly_confirmed = on_anomaly_confirmed

    def process_device_discovery(self, device_record: Dict[str, Any], is_new: bool) -> None:
        """
        Invoked by scanner when a device is seen.
        If is_new is True, evaluates Rule A (unrecognized device).
        """
        if not is_new:
            return

        anomaly = self.rule_detector.check_new_device(device_record)
        if anomaly and self.on_anomaly_confirmed:
            try:
                self.on_anomaly_confirmed(anomaly)
            except Exception as e:
                logger.error("Error dispatching rule anomaly alert: %s", e)

    def process_packet_traffic(self, packet_meta: Dict[str, Any]) -> None:
        """
        Invoked on captured packets to test Rule B (off-hours schedule violations).
        """
        src_mac = packet_meta.get("src_mac")
        if not src_mac:
            return

        device = self.db.get_device(src_mac)
        if not device:
            return

        anomaly = self.rule_detector.check_off_hours_activity(device)
        if anomaly and self.on_anomaly_confirmed:
            try:
                self.on_anomaly_confirmed(anomaly)
            except Exception as e:
                logger.error("Error dispatching off-hours anomaly alert: %s", e)

    def evaluate_device_window_ml(
        self,
        mac_address: str,
        packet_count: int,
        byte_volume: int,
        hour_of_day: int,
        protocol_variety: int = 1,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates recent window metrics with consecutive anomaly threshold filtering.

        False-Positive Reduction Strategy:
        ---------------------------------
        Transient traffic bursts (e.g. an OS update or speed test) often trigger isolated
        outlier scores. To prevent false alarms, NetGuardian requires the anomaly to persist
        across consecutive observation windows before generating an alert.
        """
        mac = mac_address.lower().strip()
        device = self.db.get_device(mac)
        if not device:
            return None

        result = self.ml_engine.evaluate_observation(
            mac_address=mac,
            packet_count=packet_count,
            byte_volume=byte_volume,
            hour_of_day=hour_of_day,
            protocol_variety=protocol_variety,
        )

        score = result["score"]
        is_anomalous = result["is_anomalous"]
        consecutive = device.get("consecutive_ml_anomalies", 0)

        if is_anomalous:
            consecutive += 1
            self.db.update_device_ml_state(
                mac, anomaly_score=score, consecutive_ml_anomalies=consecutive
            )
            logger.info(
                "Device %s ML anomaly score=%.3f (Streak: %d/%d)",
                mac,
                score,
                consecutive,
                config.CONSECUTIVE_ANOMALIES_FOR_ALERT,
            )

            # Check consecutive window threshold
            if consecutive >= config.CONSECUTIVE_ANOMALIES_FOR_ALERT:
                # Confirmed persistent anomaly
                ip = device.get("ip_address", "Unknown")
                desc = (
                    f"Persistent ML Anomaly on {mac} ({device.get('hostname') or ip}): "
                    f"Traffic deviation persisted across {consecutive} observation windows "
                    f"(Score: {score:.3f}). {result['description']}"
                )

                anomaly_id = self.db.record_anomaly(
                    mac_address=mac,
                    ip_address=ip,
                    anomaly_type="ML_TRAFFIC_DEVIATION",
                    description=desc,
                    severity="HIGH" if score < -0.25 else "MEDIUM",
                    score=score,
                )

                confirmed = {
                    "id": anomaly_id,
                    "mac_address": mac,
                    "ip_address": ip,
                    "anomaly_type": "ML_TRAFFIC_DEVIATION",
                    "description": desc,
                    "severity": "HIGH" if score < -0.25 else "MEDIUM",
                    "score": score,
                }

                if self.on_anomaly_confirmed:
                    try:
                        self.on_anomaly_confirmed(confirmed)
                    except Exception as e:
                        logger.error("Error dispatching ML anomaly alert: %s", e)

                return confirmed
        else:
            # Observation is normal; reset streak to suppress transient noise
            if consecutive > 0:
                logger.debug("Device %s traffic returned to normal baseline.", mac)
            self.db.update_device_ml_state(
                mac, anomaly_score=score, consecutive_ml_anomalies=0
            )

        return None


# Global singleton
detection_manager_service = DetectionManager()
