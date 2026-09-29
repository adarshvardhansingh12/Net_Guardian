"""Unit tests for the NetGuardian traffic metadata capture module."""

import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS
import pytest

from database.db import Database
from identification.hostname_resolver import HostnameResolver
from traffic.packet_parser import parse_packet_metadata
from traffic.sniffer import TrafficSniffer


def test_parse_arp_packet():
    pkt = Ether(src="aa:bb:cc:11:22:33", dst="ff:ff:ff:ff:ff:ff") / ARP(
        hwsrc="aa:bb:cc:11:22:33",
        psrc="192.168.1.50",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1",
    )
    meta = parse_packet_metadata(pkt)
    assert meta is not None
    assert meta["protocol"] == "ARP"
    assert meta["src_mac"] == "aa:bb:cc:11:22:33"
    assert meta["src_ip"] == "192.168.1.50"
    assert meta["dst_ip"] == "192.168.1.1"
    assert meta["src_port"] is None
    assert meta["dst_port"] is None


def test_parse_tcp_https_packet():
    pkt = (
        Ether(src="11:22:33:44:55:66", dst="a8:da:0c:5b:66:76")
        / IP(src="192.168.1.20", dst="142.250.190.46")
        / TCP(sport=54321, dport=443)
    )
    meta = parse_packet_metadata(pkt)
    assert meta is not None
    assert meta["protocol"] == "HTTPS"
    assert meta["src_port"] == 54321
    assert meta["dst_port"] == 443
    assert meta["src_ip"] == "192.168.1.20"
    assert meta["dst_ip"] == "142.250.190.46"


def test_parse_udp_dns_packet():
    pkt = (
        Ether(src="11:22:33:44:55:66", dst="a8:da:0c:5b:66:76")
        / IP(src="192.168.1.20", dst="8.8.8.8")
        / UDP(sport=51234, dport=53)
        / DNS()
    )
    meta = parse_packet_metadata(pkt)
    assert meta is not None
    assert meta["protocol"] == "DNS"
    assert meta["src_port"] == 51234
    assert meta["dst_port"] == 53


def test_parse_dhcp_hostname_option():
    # Build a DHCP request packet containing Option 12 (host name)
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\x00\x11\x22\x33\x44\x55")
        / DHCP(options=[("message-type", "request"), ("hostname", b"Adarsh-PC"), "end"])
    )
    meta = parse_packet_metadata(pkt)
    assert meta is not None
    assert meta["protocol"] == "DHCP"
    assert meta["dhcp_hostname"] == "Adarsh-PC"


def test_traffic_sniffer_batching():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_traffic.db"
        test_db = Database(db_file)
        resolver = HostnameResolver()
        try:
            captured = []

            def callback(meta):
                captured.append(meta)

            sniffer = TrafficSniffer(
                database=test_db,
                hostname_resolver=resolver,
                on_packet_captured=callback,
                batch_size=5,
                flush_interval=0.2,
            )

            with patch.object(sniffer, "_sniffer_loop", return_value=None):
                sniffer.start()

                # Generate test packets and push through process_packet
                for i in range(10):
                    pkt = (
                        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
                        / IP(src=f"192.168.1.{10+i}", dst="192.168.1.1")
                        / TCP(sport=1000 + i, dport=80)
                    )
                    sniffer.process_packet(pkt)

                # Give batch writer a short moment to flush
                time.sleep(0.4)
                sniffer.stop()

            # Verify packets reached callback
            assert len(captured) == 10

            # Verify packets written to SQLite
            logs = test_db.get_recent_traffic(limit=50)
            assert len(logs) == 10
            assert logs[0]["protocol"] == "HTTP"
        finally:
            test_db.close()
