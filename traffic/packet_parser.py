"""
NetGuardian Packet Parser
Extracts network Layer 2, Layer 3, and Layer 4 header metadata strictly.
Never inspects, decodes, or stores payload content, guaranteeing zero privacy intrusion.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional, Tuple

from scanner.network_utils import normalize_mac

logger = logging.getLogger(__name__)


def parse_packet_metadata(packet: Any) -> Optional[Dict[str, Any]]:
    """
    Parses a raw packet into structured header metadata without touching payload.

    Returns:
        Dict containing:
          - timestamp: UTC ISO timestamp
          - src_mac: Normalized source MAC address
          - dst_mac: Normalized destination MAC address
          - src_ip: Source IPv4 address
          - dst_ip: Destination IPv4 address
          - protocol: Categorized protocol string (TCP, UDP, DNS, HTTP, HTTPS, ARP, mDNS, etc.)
          - src_port: Source port number or None
          - dst_port: Destination port number or None
          - packet_size: Total wire length in bytes
          - dhcp_hostname: Captured Option 12 hostname if present in DHCP packet, else None
    """
    try:
        packet_size = len(packet)
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        src_mac = None
        dst_mac = None
        src_ip = None
        dst_ip = None
        protocol = "OTHER"
        src_port = None
        dst_port = None
        dhcp_hostname = None

        # Layer 2: Ethernet
        if packet.haslayer("Ether"):
            src_mac = normalize_mac(packet["Ether"].src)
            dst_mac = normalize_mac(packet["Ether"].dst)

        # Layer 2/3: ARP
        if packet.haslayer("ARP"):
            arp = packet["ARP"]
            protocol = "ARP"
            src_ip = arp.psrc
            dst_ip = arp.pdst
            if not src_mac and arp.hwsrc:
                src_mac = normalize_mac(arp.hwsrc)
            if not dst_mac and arp.hwdst:
                dst_mac = normalize_mac(arp.hwdst)

            return {
                "timestamp": now_ts,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": None,
                "dst_port": None,
                "packet_size": packet_size,
                "dhcp_hostname": None,
            }

        # Layer 3: IPv4
        if packet.haslayer("IP"):
            ip = packet["IP"]
            src_ip = ip.src
            dst_ip = ip.dst

            # Layer 4: TCP
            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                src_port = tcp.sport
                dst_port = tcp.dport

                # Header port classification
                if src_port == 443 or dst_port == 443 or src_port == 8443 or dst_port == 8443:
                    protocol = "HTTPS"
                elif src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080:
                    protocol = "HTTP"
                elif src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                elif src_port == 22 or dst_port == 22:
                    protocol = "SSH"
                else:
                    protocol = "TCP"

            # Layer 4: UDP
            elif packet.haslayer("UDP"):
                udp = packet["UDP"]
                src_port = udp.sport
                dst_port = udp.dport

                # Header port classification
                if src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                elif src_port == 5353 or dst_port == 5353:
                    protocol = "mDNS"
                elif src_port in (67, 68) or dst_port in (67, 68):
                    protocol = "DHCP"
                    # Passively extract DHCP Option 12 (Host Name) if present
                    if packet.haslayer("DHCP"):
                        try:
                            options = packet["DHCP"].options
                            for opt in options:
                                if isinstance(opt, tuple) and opt[0] == "hostname":
                                    val = opt[1]
                                    if isinstance(val, bytes):
                                        dhcp_hostname = val.decode("utf-8", errors="ignore")
                                    elif isinstance(val, str):
                                        dhcp_hostname = val
                        except Exception:
                            pass
                elif src_port == 123 or dst_port == 123:
                    protocol = "NTP"
                else:
                    protocol = "UDP"

            # Layer 4: ICMP
            elif packet.haslayer("ICMP"):
                protocol = "ICMP"
            else:
                protocol = "IP"

        if not src_ip or not dst_ip:
            # Non-IP / non-ARP packet, skip
            return None

        return {
            "timestamp": now_ts,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": packet_size,
            "dhcp_hostname": dhcp_hostname,
        }

    except Exception as e:
        logger.debug("Error parsing packet metadata: %s", e)
        return None
