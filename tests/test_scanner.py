"""Unit tests for the NetGuardian scanner package."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from database.db import Database
from scanner.network_utils import (
    is_valid_device_ip,
    is_valid_device_mac,
    normalize_mac,
)
from scanner.passive_scanner import parse_arp_output
from scanner.scanner_service import ScannerService


def test_normalize_mac():
    assert normalize_mac("00-14-22-01-23-45") == "00:14:22:01:23:45"
    assert normalize_mac("00:14:22:01:23:45") == "00:14:22:01:23:45"
    assert normalize_mac("A8-DA-0C-5B-66-76") == "a8:da:0c:5b:66:76"
    assert normalize_mac("001422012345") == "00:14:22:01:23:45"
    assert normalize_mac("invalid") is None
    assert normalize_mac("") is None


def test_mac_and_ip_validation():
    # Valid
    assert is_valid_device_mac("a8:da:0c:5b:66:76") is True
    assert is_valid_device_ip("192.168.1.1") is True
    assert is_valid_device_ip("10.0.0.5") is True

    # Broadcast / Multicast MACs
    assert is_valid_device_mac("ff:ff:ff:ff:ff:ff") is False
    assert is_valid_device_mac("00:00:00:00:00:00") is False
    assert is_valid_device_mac("01:00:5e:00:00:01") is False  # IPv4 multicast
    assert is_valid_device_mac("33:33:00:00:00:01") is False  # IPv6 multicast

    # Invalid IPs
    assert is_valid_device_ip("255.255.255.255") is False
    assert is_valid_device_ip("127.0.0.1") is False  # Loopback
    assert is_valid_device_ip("224.0.0.22") is False  # Multicast
    assert is_valid_device_ip("invalid-ip") is False


def test_parse_arp_output_windows():
    sample_windows_arp = """
Interface: 192.168.29.22 --- 0x8
  Internet Address      Physical Address      Type
  192.168.29.1          a8-da-0c-5b-66-76     dynamic   
  192.168.29.255        ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  255.255.255.255       ff-ff-ff-ff-ff-ff     static    
"""
    results = parse_arp_output(sample_windows_arp)
    assert len(results) == 1
    assert results[0]["ip"] == "192.168.29.1"
    assert results[0]["mac"] == "a8:da:0c:5b:66:76"


def test_parse_arp_output_linux():
    sample_linux_arp = """
? (192.168.1.1) at b8:27:eb:11:22:33 [ether] on eth0
? (192.168.1.50) at c0:ff:ee:44:55:66 [ether] on eth0
"""
    results = parse_arp_output(sample_linux_arp)
    assert len(results) == 2
    ips = [r["ip"] for r in results]
    assert "192.168.1.1" in ips
    assert "192.168.1.50" in ips


def test_scanner_service_scan_once():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_scan.db"
        test_db = Database(db_file)

        mock_passive = [
            {"mac": "aa:bb:cc:01:02:03", "ip": "192.168.1.20"},
            {"mac": "11:22:33:44:55:66", "ip": "192.168.1.30"},
        ]
        mock_active = [
            {"mac": "aa:bb:cc:01:02:03", "ip": "192.168.1.20"},  # duplicate
            {"mac": "77:88:99:aa:bb:cc", "ip": "192.168.1.40"},  # new
        ]

        callback_records = []

        def on_discovered(record, is_new):
            callback_records.append((record["mac_address"], is_new))

        with patch("scanner.scanner_service.scan_passive_arp", return_value=mock_passive):
            with patch("scanner.scanner_service.scan_subnet_arp", return_value=mock_active):
                with patch("scanner.scanner_service.get_active_subnets", return_value=["192.168.1.0/24"]):
                    service = ScannerService(
                        database=test_db,
                        scan_interval=60,
                        on_device_discovered=on_discovered,
                    )
                    devices = service.scan_once()

                    # 3 unique devices discovered
                    assert len(devices) == 3
                    assert len(callback_records) == 3
                    # All 3 were new on first scan
                    assert all(is_new is True for _, is_new in callback_records)

                    # Scan second time - is_new should be False
                    callback_records.clear()
                    service.scan_once()
                    assert len(callback_records) == 3
                    assert all(is_new is False for _, is_new in callback_records)

        test_db.close()
