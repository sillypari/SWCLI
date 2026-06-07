"""Sidewinder Cleanup System.

Restores system to pre-attack state:
1. Kill attack processes (airodump-ng, aireplay-ng, hashcat)
2. Delete monitor VIF
3. Recreate managed VIF
4. Restore killed services
5. Clean temporary files

Installs signal handlers for SIGINT/SIGTERM to ensure cleanup runs
even if the user Ctrl+Cs at any point.
"""
from __future__ import annotations

import asyncio
import glob
import logging
import os
import signal
from typing import Optional

from .monitor import exit_monitor_mode
from .services import ServiceManager
from .subprocess_mgr import run

logger = logging.getLogger(__name__)


CLEANUP_PATTERNS = [
    "/tmp/sidewinder_*",
]

ATTACK_PROCESSES = [
    "airodump-ng",
    "aireplay-ng",
    "hashcat",
    "aircrack-ng",
]


class CleanupManager:
    """Manages full system cleanup after a WiFi audit session."""

    def __init__(
        self,
        service_manager: Optional[ServiceManager] = None,
    ) -> None:
        from .services import get_service_manager
        self.service_manager = service_manager or get_service_manager()
        self._mon_iface: str = ""
        self._iface: str = ""
        self._phy: str = ""
        self._registered = False

    def register(
        self,
        mon_iface: str,
        iface: str,
        phy: str,
    ) -> None:
        """Register the current monitor interface for cleanup on signal."""
        self._mon_iface = mon_iface
        self._iface = iface
        self._phy = phy

    async def full_cleanup(
        self,
        mon_iface: str = "",
        iface: str = "",
        phy: str = "",
    ) -> bool:
        """Perform full system cleanup.
        
        Returns True if connectivity appears restored (iface has inet addr).
        """
        mon = mon_iface or self._mon_iface
        base = iface or self._iface
        p = phy or self._phy

        logger.info("Starting full cleanup...")

        # 1. Kill all attack processes
        await self._kill_attack_processes()

        # 2. Exit monitor mode (delete VIF, restore managed)
        if mon:
            try:
                await exit_monitor_mode(mon, base, p)
            except Exception as e:
                logger.warning("Monitor mode exit failed: %s", e)

        # 3. Restore services (NM, wpa_supplicant, etc.)
        await self.service_manager.restore()

        # 4. Verify connectivity
        connectivity = False
        if base:
            try:
                result = await run(["ip", "addr", "show", base], check=False)
                connectivity = "inet " in result.stdout
            except Exception:
                pass

        logger.info("Cleanup complete. Connectivity: %s", connectivity)
        return connectivity

    async def _kill_attack_processes(self) -> None:
        """Kill all attack-related processes."""
        for proc_name in ATTACK_PROCESSES:
            try:
                await run(["pkill", "-9", "-f", proc_name], check=False, timeout=5.0)
                logger.debug("Killed: %s", proc_name)
            except Exception:
                pass

    async def cleanup_files(
        self,
        extra_patterns: Optional[list[str]] = None,
        dry_run: bool = False,
    ) -> list[str]:
        """Clean up temporary files.
        
        Args:
            extra_patterns: Additional glob patterns to clean
            dry_run: If True, return files that would be deleted without deleting
        
        Returns:
            List of files deleted (or would delete if dry_run)
        """
        patterns = list(CLEANUP_PATTERNS)
        if extra_patterns:
            patterns.extend(extra_patterns)

        files_to_delete = []
        for pattern in patterns:
            files_to_delete.extend(glob.glob(os.path.expanduser(pattern)))

        if not dry_run:
            for f in files_to_delete:
                try:
                    os.remove(f)
                    logger.debug("Deleted: %s", f)
                except OSError as e:
                    logger.warning("Cannot delete %s: %s", f, e)

        return files_to_delete

    def install_signal_handlers(self, loop: asyncio.AbstractEventLoop) -> None:
        """Install SIGINT/SIGTERM handlers to ensure cleanup on Ctrl+C."""
        if self._registered:
            return
        self._registered = True

        def handle_signal(sig: signal.Signals) -> None:
            logger.info("Signal %s received — initiating cleanup", sig.name)
            asyncio.ensure_future(self.full_cleanup())

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: handle_signal(s))
            except NotImplementedError:
                pass  # Windows doesn't support loop signal handlers


_cleanup_manager: Optional[CleanupManager] = None


def get_cleanup_manager() -> CleanupManager:
    """Get the module-level CleanupManager singleton."""
    global _cleanup_manager
    if _cleanup_manager is None:
        _cleanup_manager = CleanupManager()
    return _cleanup_manager
