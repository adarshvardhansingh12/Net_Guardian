"""
NetGuardian Active ARP Scanner
Broadcasts ARP 'who-has' requests across the active local subnet using Scapy.
Discovers silent devices that haven't recently sent traffic to the host machine.
"""

import logging
from typing import Dict, List, Optional

from scanner.network_utils import is_valid_device_ip, is_valid_device_mac, normalize_mac

logger = logging.getLogger(__name__)


def scan_subnet_arp(
    subnet: str,
    timeout: float = 2.0,
    interface: Optional[str] = None,
) -> List[Dict[str, str]]:
    """
    Sends ARP requests to every IP in the specified CIDR subnet (e.g. '192.168.1.0/24')
    and listens for ARP replies.

    Args:
        subnet: Target subnet in CIDR notation (e.g. '192.168.1.0/24')
        timeout: Maximum seconds to wait for ARP responses
        interface: Specific network interface to bind to (None for auto)

    Returns:
        List of discovered device dictionaries with 'mac' and 'ip' keys.
    """
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
    except ImportError as e:
        logger.error("Scapy library is not installed: %s", e)
        return []

    discovered: Dict[str, str] = {}

    try:
        # Construct Layer 2 Ethernet broadcast frame encapsulating ARP request
        # dst="ff:ff:ff:ff:ff:ff" broadcasts to all devices on the local L2 segment
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

        kwargs = {"timeout": timeout, "verbose": 0, "retry": 1}
        if interface:
            kwargs["iface"] = interface

        # Send and receive packets at Layer 2 (srp)
        ans, _ = srp(arp_request, **kwargs)

        for _, rcv in ans:
            raw_mac = rcv.sprintf(r"%Ether.src%")
            raw_ip = rcv.sprintf(r"%ARP.psrc%")

            mac = normalize_mac(raw_mac)
            if mac and is_valid_device_mac(mac) and is_valid_device_ip(raw_ip):
                discovered[mac] = raw_ip

    except PermissionError:
        logger.warning(
            "Active ARP scan requires administrative / root privileges or Npcap/WinPcap."
        )
    except Exception as e:
        logger.warning("Active ARP scan encountered an error on subnet %s: %s", subnet, e)

    return [{"mac": mac, "ip": ip} for mac, ip in discovered.items()]
