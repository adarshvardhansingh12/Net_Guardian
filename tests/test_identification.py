"""Unit tests for the NetGuardian identification package."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from database.db import Database
from identification.device_identifier import DeviceIdentifier
from identification.hostname_resolver import HostnameResolver
from identification.vendor_lookup import VendorLookup


def test_offline_vendor_lookup():
    vl = VendorLookup()
    # Test known OUI prefixes in oui_cache.json
    assert "TP-Link" in vl.lookup("a8:da:0c:5b:66:76")
    assert "Raspberry Pi" in vl.lookup("b8:27:eb:11:22:33")
    assert "Intel" in vl.lookup("00:02:b3:12:34:56")
    assert "Apple" in vl.lookup("00:03:93:ab:cd:ef")


def test_vendor_online_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_file = Path(tmpdir) / "empty_oui.json"
        vl = VendorLookup(cache_file=cache_file)

        # Mock online API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Cisco Systems, Inc."

        with patch("requests.get", return_value=mock_response):
            vendor = vl.lookup("00:00:0c:11:22:33")
            assert vendor == "Cisco Systems, Inc."

            # Verify it was cached locally
            assert vl.lookup("00:00:0c:11:22:33") == "Cisco Systems, Inc."


def test_hostname_fallback_order():
    resolver = HostnameResolver()
    ip = "192.168.1.150"
    mac = "aa:bb:cc:dd:ee:ff"

    # Step 1: If DHCP is cached, returns DHCP
    resolver.record_dhcp_hostname(mac, "Adarsh-Laptop-DHCP")
    assert resolver.resolve(ip, mac) == "Adarsh-Laptop-DHCP"

    # Step 2: Without DHCP, falls back to mDNS
    resolver_no_dhcp = HostnameResolver()
    with patch.object(resolver_no_dhcp, "_resolve_via_mdns", return_value="smart-tv.local"):
        assert resolver_no_dhcp.resolve(ip, mac) == "smart-tv.local"

    # Step 3: Without DHCP and mDNS, falls back to Reverse DNS
    with patch.object(resolver_no_dhcp, "_resolve_via_mdns", return_value=None):
        with patch.object(
            resolver_no_dhcp, "_resolve_via_reverse_dns", return_value="gateway.home.arpa"
        ):
            assert resolver_no_dhcp.resolve(ip, mac) == "gateway.home.arpa"

    # Step 4: Falls back to NetBIOS if previous all fail
    with patch.object(resolver_no_dhcp, "_resolve_via_mdns", return_value=None):
        with patch.object(resolver_no_dhcp, "_resolve_via_reverse_dns", return_value=None):
            with patch.object(
                resolver_no_dhcp, "_resolve_via_netbios", return_value="WIN-SERVER-2022"
            ):
                assert resolver_no_dhcp.resolve(ip, mac) == "WIN-SERVER-2022"


def test_device_identifier_service():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_id.db"
        test_db = Database(db_file)
        mac = "a8:da:0c:11:22:33"
        ip = "192.168.1.55"

        test_db.upsert_device(mac, ip)

        mock_resolver = HostnameResolver()
        mock_resolver.record_dhcp_hostname(mac, "TP-Link-Archer")

        identifier = DeviceIdentifier(
            database=test_db,
            hostname_resolver=mock_resolver,
        )
        res = identifier.identify_device(mac, ip)

        assert "TP-Link" in res["vendor"]
        assert res["hostname"] == "TP-Link-Archer"

        # Check DB updated
        dev = test_db.get_device(mac)
        assert "TP-Link" in dev["vendor"]
        assert dev["hostname"] == "TP-Link-Archer"

        test_db.close()
