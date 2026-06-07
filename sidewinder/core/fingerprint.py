"""Sidewinder Client Fingerprinting.

Provides MAC OUI lookups and basic OS fingerprinting
based on probe requests and MAC addresses.
"""
import logging
import os
import sqlite3
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Fingerprint:
    """Device fingerprint info."""
    mac: str
    vendor: str = "Unknown"
    os: str = "Unknown"
    device_type: str = "Unknown"


class Fingerprinter:
    """Maintains an OUI database and provides device fingerprinting."""

    def __init__(self, oui_db_path: str = "~/.sidewinder/oui.db") -> None:
        self.oui_db_path = os.path.expanduser(oui_db_path)
        self._cache = {}

    def _lookup_vendor(self, mac: str) -> str:
        """Lookup MAC vendor from OUI database."""
        prefix = mac.upper().replace(":", "")[:6]
        
        if prefix in self._cache:
            return self._cache[prefix]

        if not os.path.exists(self.oui_db_path):
            return "Unknown (No OUI DB)"

        try:
            conn = sqlite3.connect(self.oui_db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT vendor FROM oui WHERE prefix = ?", (prefix,))
                row = cursor.fetchone()
                if row:
                    vendor = row[0]
                    self._cache[prefix] = vendor
                    return vendor
            finally:
                conn.close()
        except Exception as e:
            logger.debug("OUI lookup failed: %s", e)
            
        return "Unknown"

    def fingerprint_client(self, mac: str, probe_requests: list[str] = None) -> Fingerprint:
        """Attempt to fingerprint a device."""
        fp = Fingerprint(mac=mac)
        
        # 1. Vendor Lookup
        fp.vendor = self._lookup_vendor(mac)

        # 2. Heuristics based on Vendor
        vendor_lower = fp.vendor.lower()
        if "apple" in vendor_lower:
            fp.device_type = "Mobile/Laptop"
            fp.os = "iOS/macOS"
        elif "samsung" in vendor_lower or "huawei" in vendor_lower or "xiaomi" in vendor_lower:
            fp.device_type = "Mobile"
            fp.os = "Android"
        elif "intel" in vendor_lower or "realtek" in vendor_lower or "qualcomm" in vendor_lower:
            fp.device_type = "PC/Laptop"
            fp.os = "Windows/Linux"
        elif "espressif" in vendor_lower or "tuya" in vendor_lower:
            fp.device_type = "IoT"
            fp.os = "Embedded/RTOS"
            
        # If we had probe requests (Information Elements), we could map specific
        # tags to OS (e.g. DHCP fingerprinting style but for 802.11 IEs)
        
        return fp
