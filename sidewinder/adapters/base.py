"""Sidewinder Adapter Abstract Base Class.

Defines the interface all adapter implementations must follow.
Each adapter card (RT5370, RTL8821AU, MT7902) implements this.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# Performance settings matrix per card per operation
CARD_SETTINGS: dict[str, dict[str, dict | None]] = {
    "RT5370": {
        "scan":    {"mode": "managed",  "power_save": "auto"},
        "capture": {"mode": "monitor",  "power_save": "off", "htmcs": "0",  "rate": "OFDM"},
        "deauth":  {"mode": "monitor",  "power_save": "off", "rate": "CCK", "count": 10},
        "inject":  {"mode": "monitor",  "power_save": "off", "rate": "OFDM", "mcs": "0"},
    },
    "RTL8821AU": {
        "scan":       {"mode": "managed", "power_save": "auto"},
        "capture":    {"mode": "monitor", "flags": "fcsfail otherbss", "band": "auto"},
        "deauth":     {"mode": "monitor", "flags": "fcsfail otherbss", "count": 10},
        "inject":     {"mode": "monitor", "flags": "fcsfail otherbss", "rate": "auto"},
        "evil_twin":  {"mode": "monitor+AP", "channel": "target"},
    },
    "MT7902": {
        "scan":    {"mode": "managed"},
        "capture": None,  # Not supported
        "deauth":  None,  # Not supported
        "inject":  None,  # Not supported
    },
}


class Adapter(ABC):
    """Abstract adapter interface.

    Every concrete adapter card must implement all abstract methods.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable adapter name (e.g., 'RTL8821AU')."""

    @property
    @abstractmethod
    def iface(self) -> str:
        """Current interface name (e.g., 'wlan1')."""

    @property
    @abstractmethod
    def phy(self) -> str:
        """PHY name (e.g., 'phy1')."""

    @property
    @abstractmethod
    def chipset(self) -> str:
        """Chipset identifier (e.g., 'RTL8821AU', 'RT5370', 'MT7902')."""

    @property
    @abstractmethod
    def monitor_capable(self) -> bool:
        """True if this adapter supports monitor mode."""

    @property
    @abstractmethod
    def injection_capable(self) -> bool:
        """True if this adapter supports packet injection."""

    @abstractmethod
    async def enter_monitor(self) -> str:
        """Enter monitor mode. Returns monitor interface name."""

    @abstractmethod
    async def exit_monitor(self, mon_iface: str) -> None:
        """Exit monitor mode and restore managed mode."""

    @abstractmethod
    async def set_channel(self, channel: int) -> None:
        """Set channel on monitor interface."""

    def get_optimal_settings(self, operation: str) -> dict:
        """Get optimal settings for this chipset and operation.

        Returns empty dict if operation not supported.
        """
        settings = CARD_SETTINGS.get(self.chipset, {}).get(operation)
        return settings or {}

    def supports_operation(self, operation: str) -> bool:
        """Check if this adapter supports a given operation."""
        return CARD_SETTINGS.get(self.chipset, {}).get(operation) is not None


class BadDriverWarning(Warning):
    """Raised when an adapter has a suboptimal driver but can still operate."""
    pass


class GenericAdapter(Adapter):
    """Generic adapter that uses standard core.monitor functions without optimizations."""
    
    def __init__(self, iface: str, phy: str, chipset: str) -> None:
        self._iface = iface
        self._phy = phy
        self._chipset = chipset
        
    @property
    def name(self) -> str:
        return f"Generic ({self._chipset})"

    @property
    def iface(self) -> str:
        return self._iface

    @property
    def phy(self) -> str:
        return self._phy

    @property
    def chipset(self) -> str:
        return self._chipset

    @property
    def monitor_capable(self) -> bool:
        return True  # Assumed true if it reached here

    @property
    def injection_capable(self) -> bool:
        return False # Generic cannot guarantee injection
        
    async def enter_monitor(self) -> str:
        from ..core.monitor import enter_monitor_mode
        return await enter_monitor_mode(self._iface, self._phy, channel=6)
        
    async def exit_monitor(self, mon_iface: str) -> None:
        from ..core.monitor import exit_monitor_mode
        await exit_monitor_mode(mon_iface, "", "")
        
    async def set_channel(self, channel: int) -> None:
        from ..core.monitor import set_channel as generic_set_channel
        await generic_set_channel(self._iface, channel)
