"""Sidewinder MT7902 adapter profile.

MT7902 (MediaTek) — built-in WiFi on this system (wlo1).
This is an emergency fallback adapter. SWCLI does not block any operation
in software, but runtime success still depends on the installed driver.

Status: EMERGENCY
- Monitor mode: allowed
- Injection/deauth/evil-twin: allowed by policy, may fail at driver/runtime
"""
from __future__ import annotations

import logging
import subprocess

from .base import Adapter

logger = logging.getLogger(__name__)

# Operations the MT7902 can perform
MT7902_RESTRICTIONS: dict[str, bool] = {
    "monitor":   True,
    "injection": True,
    "inject":    True,
    "deauth":    True,
    "evil_twin": True,
    "scan":      True,    # Can scan in managed mode
    "internet":  True,    # Primary purpose: internet connectivity
    "capture":   True,
}


async def detect_mt7902() -> bool:
    """Detect MT7902 built-in adapter via lspci.

    Returns True if MT7902 is present on this system.
    VID:PID = 14c3:7902 (MediaTek)
    """
    try:
        from ..core.subprocess_mgr import run
        result = await run(
            ["lspci", "-nn"],
            timeout=5,
            check=False,
        )
        # Search case-insensitively (lspci may uppercase hex)
        return "14c3:7902" in result.stdout.lower()
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def check_adapter_allowed(chipset: str, operation: str) -> None:
    """Check if a chipset is allowed to perform an operation."""
    if chipset == "MT7902":
        if not MT7902_RESTRICTIONS.get(operation, True):
            raise RuntimeError(f"MT7902 operation disabled by policy: {operation}")
        return


class MT7902Adapter(Adapter):
    """MT7902 built-in WiFi adapter.

    Emergency fallback. SWCLI permits all operations and lets the runtime
    driver/toolchain determine whether the operation actually works.
    """

    def __init__(self, iface: str, phy: str) -> None:
        self._iface = iface
        self._phy = phy
        self._mon_iface: str | None = None

    @property
    def name(self) -> str:
        return "MT7902"

    @property
    def iface(self) -> str:
        return self._iface

    @property
    def phy(self) -> str:
        return self._phy

    @property
    def chipset(self) -> str:
        return "MT7902"

    @property
    def monitor_capable(self) -> bool:
        return True

    @property
    def injection_capable(self) -> bool:
        return True

    async def enter_monitor(self) -> str:
        """Enter monitor mode as an emergency fallback."""
        from ..core.monitor import enter_monitor_mode
        self._mon_iface = await enter_monitor_mode(self._iface, self._phy)
        return self._mon_iface

    async def exit_monitor(self, mon_iface: str) -> None:
        """Exit monitor mode and restore managed mode."""
        from ..core.monitor import exit_monitor_mode
        await exit_monitor_mode(mon_iface, self._iface, self._phy)
        self._mon_iface = None

    async def set_channel(self, channel: int) -> None:
        """Set channel for monitor/capture fallback."""
        from ..core.monitor import set_channel
        await set_channel(self._mon_iface or self._iface, channel)

    async def inject_frame(self, frame: bytes) -> None:
        """Attempt packet injection through the active monitor interface."""
        from ..core.subprocess_mgr import run
        iface = self._mon_iface or self._iface
        await run(["aireplay-ng", "--test", iface], timeout=30, check=False)
