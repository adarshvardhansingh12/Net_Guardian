"""
NetGuardian Passive Scanner
Extracts active host IP and MAC pairs from the operating system's ARP cache.
Does not emit packets, making it silent, lightweight, and zero-overhead.
"""

import logging
import os
import re
import subprocess
import sys
from typing import Dict, List

from scanner.network_utils import is_valid_device_ip, is_valid_device_mac, normalize_mac

logger = logging.getLogger(__name__)


def parse_arp_output(output: str) -> List[Dict[str, str]]:
    """
    Parses output of the 'arp -a' command across Windows, macOS, and Linux.
    Extracts IP address and MAC address pairs.
    """
    devices: Dict[str, str] = {}  # mac -> ip map to avoid duplicates

    # Pattern matching IPv4 followed by standard MAC formats
    # Handles:
    # Windows:  192.168.1.1    a8-da-0c-5b-66-76     dynamic
    # Linux:    ? (192.168.1.1) at a8:da:0c:5b:66:76 [ether] on eth0
    # macOS:    ? (192.168.1.1) at a8:da:c:5b:66:76 on en0 ifscope [ethernet]
    ip_regex = r"(\b\d{1,3}(?:\.\d{1,3}){3}\b)"
    mac_regex = r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})"

    for line in output.splitlines():
        line = line.strip()
        if not line or "Interface:" in line or "Internet Address" in line:
            continue

        ip_match = re.search(ip_regex, line)
        mac_match = re.search(mac_regex, line)

        if ip_match and mac_match:
            ip = ip_match.group(1)
            raw_mac = mac_match.group(1)
            mac = normalize_mac(raw_mac)

            if mac and is_valid_device_mac(mac) and is_valid_device_ip(ip):
                devices[mac] = ip

    return [{"mac": mac, "ip": ip} for mac, ip in devices.items()]


def read_proc_net_arp() -> List[Dict[str, str]]:
    """Reads Linux /proc/net/arp directly when running on Linux."""
    devices: Dict[str, str] = {}
    arp_file = "/proc/net/arp"
    if not os.path.exists(arp_file):
        return []

    try:
        with open(arp_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = normalize_mac(parts[3])
                if mac and is_valid_device_mac(mac) and is_valid_device_ip(ip):
                    devices[mac] = ip
    except Exception as e:
        logger.debug("Could not read /proc/net/arp: %s", e)

    return [{"mac": mac, "ip": ip} for mac, ip in devices.items()]


def scan_passive_arp() -> List[Dict[str, str]]:
    """
    Executes passive ARP table reading.
    Returns a list of dicts with keys 'mac' and 'ip'.
    """
    # 1. Try reading Linux /proc/net/arp first if available
    if sys.platform.startswith("linux"):
        res = read_proc_net_arp()
        if res:
            return res

    # 2. Invoke 'arp -a'
    try:
        cmd = ["arp", "-a"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return parse_arp_output(result.stdout)
    except Exception as e:
        logger.warning("Failed to execute arp -a command: %s", e)

    return []
