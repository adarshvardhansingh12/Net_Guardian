"""
NetGuardian Scanner Service
Manages continuous background device discovery via combined passive ARP cache
reading and active subnet ARP probing, writing results directly to the SQLite DB.
"""

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

import config
from database.db import Database, db as default_db
from scanner.active_scanner import scan_subnet_arp
from scanner.network_utils import get_active_subnets
from scanner.passive_scanner import scan_passive_arp

logger = logging.getLogger(__name__)


class ScannerService:
    """
    Background daemon running periodic passive and active ARP scans.
    Persists discovered devices and triggers lifecycle callbacks for identification and detection.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        scan_interval: Optional[int] = None,
        interface: Optional[str] = None,
        on_device_discovered: Optional[Callable[[Dict, bool], None]] = None,
    ):
        self.db = database or default_db
        self.scan_interval = scan_interval or config.SCAN_INTERVAL_SECONDS
        self.interface = interface or config.NETWORK_INTERFACE
        self.on_device_discovered = on_device_discovered

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def scan_once(self) -> List[Dict]:
        """
        Executes a single pass of passive ARP reading + active ARP probing.
        Returns newly or updated discovered devices.
        """
        discovered_map: Dict[str, str] = {}

        # 1. Passive ARP inspection (silent & instant)
        try:
            passive_devices = scan_passive_arp()
            for dev in passive_devices:
                discovered_map[dev["mac"]] = dev["ip"]
        except Exception as e:
            logger.error("Passive scan error: %s", e)

        # 2. Active ARP probing on detected local subnets
        try:
            subnets = get_active_subnets()
            for subnet in subnets:
                active_devices = scan_subnet_arp(
                    subnet=subnet,
                    timeout=config.ARP_PING_TIMEOUT,
                    interface=self.interface,
                )
                for dev in active_devices:
                    discovered_map[dev["mac"]] = dev["ip"]
        except Exception as e:
            logger.error("Active scan error: %s", e)

        processed_devices = []

        # 3. Persist to DB and trigger callbacks
        for mac, ip in discovered_map.items():
            try:
                is_new, record = self.db.upsert_device(mac_address=mac, ip_address=ip)
                processed_devices.append(record)

                if self.on_device_discovered:
                    try:
                        self.on_device_discovered(record, is_new)
                    except Exception as cb_err:
                        logger.error("Error in on_device_discovered callback: %s", cb_err)

                if is_new:
                    logger.info("Discovered NEW device: MAC=%s, IP=%s", mac, ip)
                else:
                    logger.debug("Device presence confirmed: MAC=%s, IP=%s", mac, ip)

            except Exception as db_err:
                logger.error("Failed to persist device %s (%s): %s", mac, ip, db_err)

        return processed_devices

    def _run_loop(self) -> None:
        """Internal background loop execution."""
        logger.info(
            "ScannerService started (interval=%d sec)", self.scan_interval
        )
        while not self._stop_event.is_set():
            try:
                self.scan_once()
            except Exception as e:
                logger.error("Unexpected error in scanner loop: %s", e)

            # Wait for next interval or until stopped
            self._stop_event.wait(timeout=self.scan_interval)

        logger.info("ScannerService stopped.")

    def start(self) -> None:
        """Start background scanner thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="NetGuardian-Scanner", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        """Signal scanner thread to terminate."""
        with self._lock:
            if self._thread is not None:
                self._stop_event.set()
                self._thread.join(timeout=3.0)
                self._thread = None

    @property
    def is_running(self) -> bool:
        """Check if background scanner is currently active."""
        return self._thread is not None and self._thread.is_alive()
