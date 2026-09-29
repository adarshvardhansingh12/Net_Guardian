"""Unit tests for NetGuardian rule-based and ML detection engines."""

from datetime import datetime
import tempfile
from pathlib import Path
import pytest

from database.db import Database
from detection.detection_manager import DetectionManager
from detection.ml_engine import DeviceMLEngine
from detection.rule_detector import RuleDetector


def test_rule_detector_new_device():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_rules.db"
        test_db = Database(db_file)
        rules = RuleDetector(database=test_db)

        # 1. Untrusted new device -> triggers anomaly
        dev_untrusted = {
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.101",
            "vendor": "Unknown Vendor",
            "is_trusted": 0,
        }
        res = rules.check_new_device(dev_untrusted)
        assert res is not None
        assert res["anomaly_type"] == "NEW_DEVICE"
        assert res["severity"] == "MEDIUM"

        # 2. Trusted device -> suppressed
        dev_trusted = {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.1.102",
            "vendor": "Apple, Inc.",
            "is_trusted": 1,
        }
        res_trusted = rules.check_new_device(dev_trusted)
        assert res_trusted is None

        test_db.close()


def test_rule_detector_off_hours():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_rules2.db"
        test_db = Database(db_file)
        rules = RuleDetector(database=test_db)

        # Normal hours: 09:00 to 17:00
        device = {
            "mac_address": "11:22:33:44:55:66",
            "ip_address": "192.168.1.55",
            "active_hours_start": 9,
            "active_hours_end": 17,
        }

        # Activity at 03:00 AM (off-hours) -> should flag HIGH severity
        ts_off = datetime(2026, 9, 29, 3, 30, 0)
        res = rules.check_off_hours_activity(device, packet_timestamp=ts_off)
        assert res is not None
        assert res["anomaly_type"] == "OFF_HOURS_ACTIVITY"
        assert res["severity"] == "HIGH"

        # Activity at 12:00 PM (normal business hours) -> should be None
        ts_normal = datetime(2026, 9, 29, 12, 0, 0)
        res_normal = rules.check_off_hours_activity(device, packet_timestamp=ts_normal)
        assert res_normal is None

        test_db.close()


def test_ml_engine_isolation_forest():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_ml.db"
        test_db = Database(db_file)
        mac = "50:85:69:11:22:33"
        test_db.upsert_device(mac, "192.168.1.90")

        # Simulate historical traffic for baseline training (e.g. 30 hourly windows)
        for i in range(30):
            # Normal pattern: 50-100 packets, 50KB-100KB, day hours
            test_db.log_traffic(
                src_mac=mac,
                dst_mac="192.168.1.1",
                src_ip="192.168.1.90",
                dst_ip="192.168.1.1",
                protocol="TCP",
                src_port=50000,
                dst_port=443,
                packet_size=1000,
            )

        ml = DeviceMLEngine(database=test_db)
        trained, msg = ml.train_baseline(mac, hours_back=48)
        assert trained is True

        # Test normal observation: within baseline distribution
        eval_normal = ml.evaluate_observation(
            mac_address=mac,
            packet_count=1,
            byte_volume=1000,
            hour_of_day=14,
            protocol_variety=1,
        )
        assert eval_normal["has_baseline"] is True

        # Test anomalous observation: extreme 1000x traffic volume burst
        eval_spike = ml.evaluate_observation(
            mac_address=mac,
            packet_count=50000,
            byte_volume=80000000,
            hour_of_day=3,
            protocol_variety=10,
        )
        assert eval_spike["is_anomalous"] is True
        assert eval_spike["score"] < 0

        test_db.close()


def test_consecutive_ml_anomaly_filtering():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_manager.db"
        test_db = Database(db_file)
        mac = "78:4b:87:aa:bb:cc"
        test_db.upsert_device(mac, "192.168.1.80")

        alerts_dispatched = []

        def on_alert(anom):
            alerts_dispatched.append(anom)

        manager = DetectionManager(
            database=test_db,
            on_anomaly_confirmed=on_alert,
        )

        # Mock ML engine returning anomalous on demand
        class MockML:
            def evaluate_observation(self, **kwargs):
                return {
                    "is_anomalous": True,
                    "score": -0.35,
                    "has_baseline": True,
                    "description": "Mocked deviation",
                }

        manager.ml_engine = MockML()

        # Window 1: Anomaly occurs, but consecutive count = 1 -> should NOT alert yet
        res1 = manager.evaluate_device_window_ml(mac, 500, 1000000, 2)
        assert res1 is None
        assert len(alerts_dispatched) == 0
        dev = test_db.get_device(mac)
        assert dev["consecutive_ml_anomalies"] == 1

        # Window 2: Anomaly persists across 2nd window -> threshold reached! Alert dispatched!
        res2 = manager.evaluate_device_window_ml(mac, 500, 1000000, 3)
        assert res2 is not None
        assert len(alerts_dispatched) == 1
        assert res2["anomaly_type"] == "ML_TRAFFIC_DEVIATION"

        test_db.close()
