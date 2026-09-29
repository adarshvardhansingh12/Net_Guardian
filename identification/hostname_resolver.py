"""
NetGuardian Hostname Resolution Engine
Implements a 4-tier fallback chain for robust local network device hostname resolution:
  1. DHCP sniffing cache (Option 12 Host Name)
  2. mDNS / Apple Bonjour / Zeroconf (.local)
  3. Reverse DNS lookup (socket gethostbyaddr)
  4. NetBIOS Name Query (nbtstat / RFC 1002 port 137)

Academic Rationale for Fallback Order:
-------------------------------------
1. DHCP First: DHCP Option 12 is explicitly provided by the device's OS when requesting
   an IP lease, making it the most authoritative name directly self-reported by the host.
2. mDNS Second: Zero-configuration networking (RFC 6762) is widely enabled on macOS,
   iOS, Android, Linux (Avahi), and modern Windows for local device discovery.
3. Reverse DNS Third: If the home router runs a local DNS proxy (e.g. Dnsmasq or Unbound),
   it resolves static and dynamic hostnames within the subnet.
4. NetBIOS Fourth: NetBIOS over TCP/IP (RFC 1002) is a resilient legacy mechanism supported
   by Windows and Samba file servers, succeeding even when DNS/mDNS is unconfigured or firewalled.
"""

import logging
import re
import socket
import struct
import subprocess
import sys
import threading
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class HostnameResolver:
    """
    Coordinates multi-protocol hostname discovery according to the priority chain.
    """

    def __init__(self):
        # Thread-safe in-memory cache for passively captured DHCP hostnames
        self._dhcp_cache: Dict[str, str] = {}  # mac/ip -> hostname
        self._cache_lock = threading.Lock()

    def record_dhcp_hostname(self, mac_or_ip: str, hostname: str) -> None:
        """
        Invoked by the traffic capture sniffer when DHCP Option 12 is observed.
        """
        if not hostname or not mac_or_ip:
            return
        clean_name = hostname.strip().rstrip(".")
        with self._cache_lock:
            self._dhcp_cache[mac_or_ip.lower().strip()] = clean_name
            logger.info("DHCP hostname recorded: %s -> %s", mac_or_ip, clean_name)

    def resolve(self, ip_address: str, mac_address: Optional[str] = None) -> Optional[str]:
        """
        Executes the resolution chain: DHCP -> mDNS -> Reverse DNS -> NetBIOS.
        Returns the first successfully resolved hostname, or None.
        """
        ip = ip_address.strip()
        mac = mac_address.lower().strip() if mac_address else None

        # -------------------------------------------------------------
        # Tier 1: DHCP Host Name Cache (Option 12)
        # -------------------------------------------------------------
        name = self._resolve_via_dhcp(ip, mac)
        if name:
            logger.info("Resolved %s via DHCP: %s", ip, name)
            return name

        # -------------------------------------------------------------
        # Tier 2: mDNS / Zeroconf (Multicast DNS port 5353)
        # -------------------------------------------------------------
        name = self._resolve_via_mdns(ip)
        if name:
            logger.info("Resolved %s via mDNS: %s", ip, name)
            return name

        # -------------------------------------------------------------
        # Tier 3: Reverse DNS (PTR query to local router / DNS)
        # -------------------------------------------------------------
        name = self._resolve_via_reverse_dns(ip)
        if name:
            logger.info("Resolved %s via Reverse DNS: %s", ip, name)
            return name

        # -------------------------------------------------------------
        # Tier 4: NetBIOS Node Status (nbtstat or UDP 137 query)
        # -------------------------------------------------------------
        name = self._resolve_via_netbios(ip)
        if name:
            logger.info("Resolved %s via NetBIOS: %s", ip, name)
            return name

        return None

    def _resolve_via_dhcp(self, ip: str, mac: Optional[str]) -> Optional[str]:
        """Check if hostname was captured from DHCP Option 12 packet."""
        with self._cache_lock:
            if mac and mac in self._dhcp_cache:
                return self._dhcp_cache[mac]
            if ip in self._dhcp_cache:
                return self._dhcp_cache[ip]
        return None

    def _resolve_via_mdns(self, ip: str) -> Optional[str]:
        """
        Queries mDNS using zeroconf or socket reverse PTR query (.in-addr.arpa on .local).
        """
        try:
            # Reverse pointer lookup for local mDNS: e.g. 1.29.168.192.in-addr.arpa
            rev_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            # Attempt zeroconf resolution if installed
            from zeroconf import Zeroconf
            zc = Zeroconf()
            try:
                # Zeroconf reverse lookup timeout is kept short (0.8s) to avoid UI/scan lag
                info = zc.get_service_info("_workstation._tcp.local.", f"{ip}._workstation._tcp.local.")
                if info and info.server:
                    name = info.server.rstrip(".").replace(".local", "")
                    if name:
                        return name
            finally:
                zc.close()
        except Exception as e:
            logger.debug("mDNS resolution error for %s: %s", ip, e)
        return None

    def _resolve_via_reverse_dns(self, ip: str) -> Optional[str]:
        """Performs standard socket gethostbyaddr reverse lookup with timeout."""
        # Set socket default timeout temporarily
        orig_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(1.5)
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname and hostname != ip:
                return hostname.strip().rstrip(".")
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(orig_timeout)
        return None

    def _resolve_via_netbios(self, ip: str) -> Optional[str]:
        """
        Resolves NetBIOS name using nbtstat on Windows or raw UDP port 137 query.
        """
        # On Windows, nbtstat -A <ip> is native and parses accurately
        if sys.platform == "win32":
            try:
                cmd = ["nbtstat", "-A", ip]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0)
                if res.returncode == 0 and res.stdout:
                    # Look for lines with <00> UNIQUE or similar workstation names
                    # Example line: "WORKSTATION   <00>  UNIQUE      Registered"
                    for line in res.stdout.splitlines():
                        match = re.search(r"^\s*([A-Za-z0-9_-]+)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
                        if match:
                            name = match.group(1).strip()
                            if name:
                                return name
            except Exception as e:
                logger.debug("nbtstat command failed for %s: %s", ip, e)

        # Cross-platform direct NetBIOS Node Status Query (RFC 1002 UDP 137)
        try:
            return self._query_netbios_udp(ip)
        except Exception as e:
            logger.debug("NetBIOS UDP query failed for %s: %s", ip, e)

        return None

    def _query_netbios_udp(self, ip: str) -> Optional[str]:
        """
        Direct NetBIOS Node Status Query over UDP port 137.
        Encodes standard NBSTAT wildcard query (*) and parses the primary name.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            # Transaction ID: 0x1337, Flags: 0x0000, Questions: 1, Answer RRs: 0
            # Query Name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (NetBIOS wildcard '*' encoded)
            query = (
                b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
                b"\x00\x21\x00\x01"  # Type: NBSTAT (0x0021), Class: IN (0x0001)
            )
            sock.sendto(query, (ip, 137))
            data, _ = sock.recvfrom(1024)

            # Minimum response size for NBSTAT reply is ~56 bytes
            if len(data) > 56:
                # Number of names returned is at offset 56
                num_names = data[56]
                if num_names > 0 and len(data) >= 57 + 18:
                    # First name is 15 bytes ASCII + 1 byte type
                    raw_name = data[57:72].decode("ascii", errors="ignore").strip()
                    if raw_name:
                        return raw_name
        except Exception:
            pass
        finally:
            sock.close()
        return None


# Global singleton
hostname_resolver_service = HostnameResolver()
