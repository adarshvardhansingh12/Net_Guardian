"""Test suite for NetGuardian database operations."""

import os
import tempfile
from pathlib import Path
import pytest
from database.db import Database


@pytest.fixture
def temp_db():
    """Create an isolated temporary SQLite database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_netguardian.db"
        test_db = Database(db_file)
        try:
            yield test_db
        finally:
            test_db.close()


def test_schema_initialization(temp_db):
    """Verify that all required tables and indices are created successfully."""
    conn = temp_db.get_connection()
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    ]
    assert "devices" in tables
    assert "traffic_logs" in tables
    assert "anomalies" in tables
    assert "alerts" in tables


def test_upsert_device_new_and_update(temp_db):
    """Verify that a new device is flagged as is_new=True, and updates maintain state."""
    mac = "aa:bb:cc:dd:ee:01"
    ip = "192.168.1.50"

    # First insert: should be marked as new
    is_new, device = temp_db.upsert_device(mac, ip, hostname="workstation-1")
    assert is_new is True
    assert device["mac_address"] == mac
    assert device["ip_address"] == ip
    assert device["hostname"] == "workstation-1"
    assert device["is_trusted"] == 0

    # Second insert with updated IP: should not be new
    new_ip = "192.168.1.51"
    is_new, updated_device = temp_db.upsert_device(mac, new_ip)
    assert is_new is False
    assert updated_device["ip_address"] == new_ip
    # Hostname should have been preserved
    assert updated_device["hostname"] == "workstation-1"


def test_device_trust_and_identification(temp_db):
    """Verify trust toggle and vendor/hostname updates."""
    mac = "11:22:33:44:55:66"
    temp_db.upsert_device(mac, "192.168.1.100")

    # Set trusted
    assert temp_db.set_device_trust(mac, True) is True
    dev = temp_db.get_device(mac)
    assert dev["is_trusted"] == 1

    # Update identification
    assert (
        temp_db.update_device_identification(
            mac, vendor="Apple, Inc.", hostname="Adarsh-MacBook"
        )
        is True
    )
    dev = temp_db.get_device(mac)
    assert dev["vendor"] == "Apple, Inc."
    assert dev["hostname"] == "Adarsh-MacBook"


def test_traffic_logging_and_aggregation(temp_db):
    """Verify single and batch traffic logging and aggregation."""
    mac1 = "aa:bb:cc:11:22:33"
    mac2 = "dd:ee:ff:44:55:66"
    temp_db.upsert_device(mac1, "192.168.1.10")
    temp_db.upsert_device(mac2, "192.168.1.1")

    # Single packet log
    log_id = temp_db.log_traffic(
        src_mac=mac1,
        dst_mac=mac2,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        protocol="DNS",
        src_port=5353,
        dst_port=53,
        packet_size=78,
    )
    assert log_id > 0

    # Batch logging
    batch = [
        {
            "src_mac": mac1,
            "dst_mac": mac2,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 443,
            "packet_size": 1500,
        },
        {
            "src_mac": mac1,
            "dst_mac": mac2,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 443,
            "packet_size": 800,
        },
    ]
    inserted_count = temp_db.batch_log_traffic(batch)
    assert inserted_count == 2

    # Query recent traffic
    recent = temp_db.get_recent_traffic(limit=10)
    assert len(recent) == 3


def test_anomalies_and_alerts(temp_db):
    """Verify anomaly creation, resolution, and alert logging."""
    mac = "cc:dd:ee:ff:00:11"
    temp_db.upsert_device(mac, "192.168.1.75")

    anomaly_id = temp_db.record_anomaly(
        mac_address=mac,
        ip_address="192.168.1.75",
        anomaly_type="NEW_DEVICE",
        description="First-time device joined local network",
        severity="MEDIUM",
        score=0.5,
    )
    assert anomaly_id > 0

    anomalies = temp_db.get_anomalies(unresolved_only=True)
    assert len(anomalies) == 1
    assert anomalies[0]["anomaly_type"] == "NEW_DEVICE"

    # Record alert
    alert_id = temp_db.record_alert(
        anomaly_id=anomaly_id,
        channel="EMAIL",
        status="SENT",
        message="Alert email dispatched to user",
    )
    assert alert_id > 0

    alerts = temp_db.get_recent_alerts()
    assert len(alerts) == 1
    assert alerts[0]["channel"] == "EMAIL"
    assert alerts[0]["status"] == "SENT"

    # Resolve anomaly
    assert temp_db.resolve_anomaly(anomaly_id) is True
    unresolved = temp_db.get_anomalies(unresolved_only=True)
    assert len(unresolved) == 0


def test_dashboard_summary(temp_db):
    """Verify summary metrics calculation."""
    temp_db.upsert_device("11:11:11:11:11:11", "192.168.1.10")
    temp_db.upsert_device("22:22:22:22:22:22", "192.168.1.20")
    temp_db.log_traffic(
        src_mac="11:11:11:11:11:11",
        dst_mac="22:22:22:22:22:22",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        protocol="HTTP",
        src_port=1234,
        dst_port=80,
        packet_size=200,
    )
    summary = temp_db.get_dashboard_summary()
    assert summary["total_devices"] == 2
    assert summary["total_packets"] == 1
    assert len(summary["protocol_breakdown"]) >= 1
