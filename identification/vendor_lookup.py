"""
NetGuardian Vendor Identification Module
Performs MAC address hardware vendor lookup using an offline IEEE OUI database
with an automated fallback to the free api.macvendors.com service.
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Optional

import requests

import config
from scanner.network_utils import normalize_mac

logger = logging.getLogger(__name__)


class VendorLookup:
    """
    Two-tier MAC address vendor resolution engine:
    1. Offline OUI cache (fast, zero network latency, zero external reliance).
    2. Online free API fallback (api.macvendors.com) when local match misses.
       Newly discovered online vendors are automatically saved back to the local cache.
    """

    def __init__(self, cache_file: Optional[Path] = None):
        self.cache_file = Path(cache_file or config.OUI_CACHE_PATH)
        self._lock = threading.Lock()
        self._last_api_request_time = 0.0
        self._oui_db: Dict[str, str] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        """Loads offline OUI entries from JSON file."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self._oui_db = json.load(f)
                logger.debug("Loaded %d OUI vendor records from %s", len(self._oui_db), self.cache_file)
            except Exception as e:
                logger.error("Failed to load OUI cache from %s: %s", self.cache_file, e)
                self._oui_db = {}
        else:
            self._oui_db = {}

    def _save_cache(self) -> None:
        """Persists updated vendor mappings to disk."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self._oui_db, f, indent=2)
        except Exception as e:
            logger.error("Failed to save updated OUI cache: %s", e)

    def lookup(self, mac_address: str) -> str:
        """
        Resolves manufacturer name for a given MAC address.
        Returns vendor string or 'Unknown Vendor'.
        """
        mac = normalize_mac(mac_address)
        if not mac:
            return "Unknown Vendor"

        # Extract OUI (first 3 octets, e.g. '00:14:22')
        oui = ":".join(mac.split(":")[:3]).lower()

        # Step 1: Offline local lookup (O(1) memory hashmap)
        with self._lock:
            if oui in self._oui_db:
                return self._oui_db[oui]

        # Step 2: Online fallback via api.macvendors.com
        vendor = self._query_online_api(mac)
        if vendor:
            with self._lock:
                self._oui_db[oui] = vendor
                self._save_cache()
            return vendor

        return "Unknown Vendor"

    def _query_online_api(self, mac: str) -> Optional[str]:
        """
        Queries api.macvendors.com with rate-limiting protection (max 1 req/sec).
        """
        # Rate-limiting guard to stay safely within free-tier threshold
        with self._lock:
            now = time.time()
            elapsed = now - self._last_api_request_time
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
            self._last_api_request_time = time.time()

        try:
            url = f"{config.MAC_VENDORS_API_URL.rstrip('/')}/{mac}"
            resp = requests.get(url, timeout=config.MAC_VENDORS_TIMEOUT)
            if resp.status_code == 200 and resp.text.strip():
                vendor = resp.text.strip()
                logger.info("Online vendor resolved for %s: %s", mac, vendor)
                return vendor
            elif resp.status_code == 404:
                logger.debug("Vendor not found online for %s", mac)
        except Exception as e:
            logger.debug("Online MAC vendor lookup failed for %s: %s", mac, e)

        return None


# Global singleton
vendor_lookup_service = VendorLookup()
