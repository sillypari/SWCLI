"""Sidewinder Adapters Package.

Manages multiple WiFi adapters simultaneously.
Priority: RTL8821AU (10) > RT5370 (5) > MT7902 (1)
"""
from __future__ import annotations

from typing import Optional

from ..core.adapter import AdapterInfo, discover_all_adapters, get_best_adapter, ADAPTER_PRIORITY


class AdapterManager:
    """Manage multiple wireless adapters with priority-based selection and failover."""

    def __init__(self) -> None:
        self.adapters: dict[str, AdapterInfo] = {}  # iface -> AdapterInfo
        self._primary: Optional[AdapterInfo] = None
        self._internet: Optional[AdapterInfo] = None

    async def discover(self) -> list[AdapterInfo]:
        """Discover all wireless adapters on the system.

        Returns sorted list (best first by ADAPTER_PRIORITY).
        """
        found = await discover_all_adapters()
        self.adapters = {a.iface: a for a in found}
        self._primary = None
        self._internet = None
        return found

    def get_best_for_operation(self, operation: str) -> Optional[AdapterInfo]:
        """Select best adapter for a given operation.

        Args:
            operation: "scan", "capture", "deauth", "inject", "internet"

        Returns:
            Best AdapterInfo for the operation, or None if none available.
        """
        adapters = list(self.adapters.values())
        return get_best_adapter(adapters, operation)

    def get_internet_adapter(self) -> Optional[AdapterInfo]:
        """Get the adapter designated for internet (MT7902 preferred)."""
        for a in self.adapters.values():
            if a.chipset == "MT7902":
                return a
        # Fallback: any non-monitor adapter
        for a in self.adapters.values():
            if not a.monitor_capable:
                return a
        return None

    def get_all(self) -> list[AdapterInfo]:
        """All discovered adapters, sorted by priority."""
        return sorted(
            self.adapters.values(),
            key=lambda a: ADAPTER_PRIORITY.get(a.chipset, 0),
            reverse=True,
        )

    async def refresh(self, iface: str) -> Optional[AdapterInfo]:
        """Re-detect a specific interface (e.g., after mode change)."""
        from ..core.adapter import detect_adapter
        info = await detect_adapter(iface)
        if info:
            self.adapters[iface] = info
        return info


class FailoverManager:
    """Execute operations with automatic adapter failover.

    If the primary adapter fails, transparently switches to backup.
    """

    def __init__(self, adapter_manager: AdapterManager) -> None:
        self.am = adapter_manager
        self.primary: Optional[AdapterInfo] = None
        self.backup: Optional[AdapterInfo] = None

    def setup(self, operation: str) -> None:
        """Setup primary and backup adapters for an operation."""
        self.primary = self.am.get_best_for_operation(operation)
        all_capable = [
            a for a in self.am.adapters.values()
            if a.monitor_capable and a != self.primary
        ]
        self.backup = all_capable[0] if all_capable else None

    async def execute_with_failover(self, func, *args, **kwargs):
        """Execute function with automatic failover to backup adapter.

        func must accept AdapterInfo as first argument.
        """
        from ..core.errors import SidewinderError
        try:
            return await func(self.primary, *args, **kwargs)
        except (SidewinderError, RuntimeError) as e:
            if self.backup:
                import logging
                logging.getLogger(__name__).warning(
                    "Primary adapter %s failed (%s), switching to %s",
                    self.primary.iface if self.primary else "?",
                    str(e)[:50],
                    self.backup.iface,
                )
                return await func(self.backup, *args, **kwargs)
            raise


# Module-level singleton
_adapter_manager: Optional[AdapterManager] = None


def get_adapter_manager() -> AdapterManager:
    """Get the module-level AdapterManager singleton."""
    global _adapter_manager
    if _adapter_manager is None:
        _adapter_manager = AdapterManager()
    return _adapter_manager
