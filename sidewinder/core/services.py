"""Sidewinder Service Management.

Kill conflicting processes (NetworkManager, wpa_supplicant, dhclient),
track them for later restoration.

Design: graceful SIGTERM → systemctl stop, then SIGKILL if needed.
Restore: systemctl start with is-active polling (15s max per service).

Equivalent to airmon-ng scanProcesses() with restoration logic.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from dataclasses import dataclass, field
from typing import Optional

from .subprocess_mgr import run

logger = logging.getLogger(__name__)


# Processes known to interfere with monitor mode
CONFLICTING_SERVICES = [
    "NetworkManager",
    "wpa_supplicant",
    "wpa_cli",
    "dhclient",
    "dhcpcd",
    "avahi-daemon",
    "avahi-autoipd",
    "iwd",
]


@dataclass
class KilledProcess:
    """Record of a killed process for later restoration.

    Attributes:
        name: Process/service name (e.g., "NetworkManager")
        pid: Process ID at time of kill
        was_systemd: True if systemctl stop succeeded for this service
    """

    name: str
    pid: int
    was_systemd: bool = False  # True if managed by systemd


@dataclass
class KillResult:
    """Result of a kill_conflicting() call.

    Attributes:
        killed: Processes that were successfully killed
        skipped: Service names that were skipped (e.g., duplicates)
        errors: Error strings for any failures encountered
    """

    killed: list[KilledProcess] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ServiceManager:
    """Manage conflicting WiFi services.

    Tracks killed services so they can be restored after audit.
    """

    def __init__(self) -> None:
        """Initialise the service manager with an empty kill list."""
        self.killed_processes: list[KilledProcess] = []

    async def find_conflicting(self) -> list[tuple[int, str]]:
        """Find PIDs of conflicting processes.

        Reads the process table via ``ps`` and matches against
        CONFLICTING_SERVICES.

        Returns:
            List of (pid, name) tuples for conflicting processes found.
        """
        result = await run(
            ["ps", "-A", "-o", "pid=,args="],
            check=False,
        )
        found: list[tuple[int, str]] = []
        for line in result.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    pid = int(parts[0])
                    args = parts[1].strip()
                    for svc in CONFLICTING_SERVICES:
                        if svc in args:
                            found.append((pid, svc))
                            break
                except ValueError:
                    pass
        return found

    async def kill_conflicting(self) -> KillResult:
        """Kill all conflicting processes.

        Strategy:
        1. Try systemctl stop (graceful)
        2. Kill remaining PIDs with SIGKILL
        3. Track killed processes for restoration

        Returns:
            KillResult summarising killed, skipped, and error entries.
        """
        result = KillResult()
        found = await self.find_conflicting()

        if not found:
            logger.info("No conflicting services found")
            return result

        logger.info(
            "Found %d conflicting processes: %s",
            len(found),
            [n for _, n in found],
        )

        killed_names: set[str] = set()
        for pid, name in found:
            if name in killed_names:
                result.skipped.append(name)
                continue  # Already handled this service name

            # Try systemctl stop first (graceful)
            systemd_result = await run(
                ["systemctl", "stop", name],
                check=False,
                timeout=10.0,
            )

            # Force kill any remaining PIDs
            try:
                sig = getattr(signal, "SIGKILL", signal.SIGTERM)
                os.kill(pid, sig)
                logger.info("Killed %s (pid=%d)", name, pid)
            except ProcessLookupError:
                pass  # Already dead from systemctl stop


            kp = KilledProcess(
                name=name,
                pid=pid,
                was_systemd=systemd_result.success,
            )
            self.killed_processes.append(kp)
            result.killed.append(kp)
            killed_names.add(name)

        return result

    async def restore(self) -> None:
        """Restore killed services with readiness verification.

        Polls ``systemctl is-active`` every 0.5 s for up to 15 s per
        service.  Logs a warning if a service does not become active
        within that window.

        Services are restored in reverse kill order so lower-level
        services (e.g., wpa_supplicant) come up before higher-level
        ones (e.g., NetworkManager).
        """
        if not self.killed_processes:
            return

        logger.info("Restoring %d services...", len(self.killed_processes))

        for kp in reversed(self.killed_processes):
            logger.info("Restoring %s...", kp.name)
            await run(["systemctl", "start", kp.name], check=False, timeout=10.0)

            # Wait for service to become active (15s max)
            became_active = False
            for _ in range(30):  # 30 × 0.5s = 15s
                await asyncio.sleep(0.5)
                status_result = await run(
                    ["systemctl", "is-active", kp.name],
                    check=False,
                )
                if status_result.stdout.strip() == "active":
                    became_active = True
                    break

            if became_active:
                logger.info("%s restored successfully", kp.name)
            else:
                logger.warning(
                    "Service %s did not become active within 15s", kp.name
                )

        self.killed_processes.clear()

    async def kill_process_by_name(self, name: str) -> None:
        """Kill a specific process by name pattern using pkill.

        Args:
            name: Process name pattern to match (passed to pkill -f)
        """
        await run(["pkill", "-9", "-f", name], check=False)
        logger.debug("Killed processes matching: %s", name)


_service_manager: Optional[ServiceManager] = None


def get_service_manager() -> ServiceManager:
    """Get the module-level ServiceManager singleton.

    Creates the instance on first call; subsequent calls return the
    same object.

    Returns:
        The shared ServiceManager instance.
    """
    global _service_manager
    if _service_manager is None:
        _service_manager = ServiceManager()
    return _service_manager
