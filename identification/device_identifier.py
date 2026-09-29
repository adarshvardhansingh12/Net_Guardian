"""
NetGuardian Device Identifier Service
Coordinates manufacturer lookup and multi-protocol hostname resolution,
updating device profile records in the SQLite database asynchronously.
"""

import logging
import queue
import threading
from typing import Dict, Optional

from database.db import Database, db as default_db
from identification.hostname_resolver import (
    HostnameResolver,
    hostname_resolver_service as default_resolver,
)
from identification.vendor_lookup import (
    VendorLookup,
    vendor_lookup_service as default_vendor_lookup,
)

logger = logging.getLogger(__name__)


class DeviceIdentifier:
    """
    Asynchronous identification processor that resolves vendor and hostname
    in background threads to prevent latency in network scanning loops.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        vendor_lookup: Optional[VendorLookup] = None,
        hostname_resolver: Optional[HostnameResolver] = None,
    ):
        self.db = database or default_db
        self.vendor_lookup = vendor_lookup or default_vendor_lookup
        self.hostname_resolver = hostname_resolver or default_resolver

        self._queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

    def identify_device(
        self, mac: str, ip: str, force_refresh: bool = False
    ) -> Dict[str, Optional[str]]:
        """
        Synchronously resolves vendor and hostname for a device, updating the DB.
        """
        device = self.db.get_device(mac)
        existing_vendor = device.get("vendor") if device else None
        existing_hostname = device.get("hostname") if device else None

        vendor = existing_vendor
        if not vendor or vendor == "Unknown Vendor" or force_refresh:
            vendor = self.vendor_lookup.lookup(mac)

        hostname = existing_hostname
        if not hostname or force_refresh:
            hostname = self.hostname_resolver.resolve(ip, mac)

        self.db.update_device_identification(mac, vendor=vendor, hostname=hostname)
        logger.info(
            "Identified device %s (%s): Vendor='%s', Hostname='%s'",
            mac,
            ip,
            vendor,
            hostname,
        )
        return {"vendor": vendor, "hostname": hostname}

    def enqueue_identification(self, mac: str, ip: str) -> None:
        """Adds a device to the background identification work queue."""
        self._queue.put((mac, ip))

    def _worker_loop(self) -> None:
        """Background thread worker pulling devices from the queue."""
        while not self._stop_event.is_set():
            try:
                mac, ip = self._queue.get(timeout=1.0)
                try:
                    self.identify_device(mac, ip)
                except Exception as e:
                    logger.error("Error identifying device %s: %s", mac, e)
                finally:
                    self._queue.task_done()
            except queue.Empty:
                continue

    def start(self) -> None:
        """Start the identification worker thread."""
        if self._worker_thread is not None and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="NetGuardian-Identifier", daemon=True
        )
        self._worker_thread.start()

    def stop(self) -> None:
        """Stop worker thread."""
        if self._worker_thread is not None:
            self._stop_event.set()
            self._worker_thread.join(timeout=3.0)
            self._worker_thread = None


# Global singleton
device_identifier_service = DeviceIdentifier()
