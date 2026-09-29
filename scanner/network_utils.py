"""
NetGuardian Network Utilities
Helper functions for interface detection, subnet calculation,
and MAC/IP address normalization and filtering.
"""

import ipaddress
import re
import socket
import subprocess
import sys
from typing import List, Optional, Tuple


def normalize_mac(mac: str) -> Optional[str]:
    """
    Normalizes a MAC address string into lowercase colon-separated format (e.g., aa:bb:cc:dd:ee:ff).
    Returns None if the MAC is invalid or malformed.
    """
    if not mac:
        return None
    # Remove hyphens, colons, dots, spaces
    clean = re.sub(r"[^a-fA-F0-9]", "", mac.strip())
    if len(clean) != 12:
        return None
    pairs = [clean[i : i + 2].lower() for i in range(0, 12, 2)]
    return ":".join(pairs)


def is_valid_device_mac(mac: str) -> bool:
    """
    Checks if a MAC address belongs to a real unicast device.
    Filters out broadcast (ff:ff:ff:ff:ff:ff), IPv4/IPv6 multicast, and all-zeros.
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return False

    # All zeros or all ones (broadcast)
    if normalized in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False

    # IPv4 multicast OUI: 01:00:5e:*
    if normalized.startswith("01:00:5e"):
        return False

    # IPv6 multicast prefix: 33:33:*
    if normalized.startswith("33:33"):
        return False

    return True


def is_valid_device_ip(ip: str) -> bool:
    """
    Checks if an IP address is a valid unicast host on a local network.
    Excludes loopback, multicast (224.0.0.0/4), and broadcast (255.255.255.255).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            return False
        # Broadcast address
        if str(addr) == "255.255.255.255":
            return False
        return True
    except ValueError:
        return False


def get_primary_local_ip() -> Optional[str]:
    """
    Determines the machine's primary local IPv4 address by probing an external route.
    Does NOT send actual network traffic to the target; merely opens an OS routing query.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Use an arbitrary public DNS IP to find the default outbound interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback to localhost hostname lookup
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def get_active_subnets() -> List[str]:
    """
    Discovers candidate IPv4 subnets (CIDR notation, e.g. '192.168.1.0/24')
    for active network probing.
    """
    subnets = set()
    local_ip = get_primary_local_ip()

    if local_ip and is_valid_device_ip(local_ip):
        try:
            # Assume /24 for standard home/small office class C network
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            subnets.add(str(net))
        except ValueError:
            pass

    # On Windows, try parsing PowerShell Get-NetIPAddress for accurate prefix lengths
    if sys.platform == "win32":
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notlike '169.254*' } | Select-Object -Property IPAddress, PrefixLength | ConvertTo-Csv -NoTypeInformation",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                lines = res.stdout.strip().splitlines()
                for line in lines[1:]:  # skip header
                    parts = [p.strip().replace('"', "") for p in line.split(",")]
                    if len(parts) >= 2:
                        ip_part, prefix_part = parts[0], parts[1]
                        if is_valid_device_ip(ip_part) and prefix_part.isdigit():
                            prefix = int(prefix_part)
                            # Avoid scanning overly broad subnets (like /8 or /16 which would be too slow)
                            if 20 <= prefix <= 30:
                                net = ipaddress.IPv4Network(
                                    f"{ip_part}/{prefix}", strict=False
                                )
                                subnets.add(str(net))
        except Exception:
            pass

    if not subnets:
        # Fallback to default private subnet
        subnets.add("192.168.1.0/24")

    return sorted(list(subnets))
