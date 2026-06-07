"""Sidewinder MT7902 Adapter — Detection + Protection.

MT7902 (MediaTek) — built-in WiFi on this system (wlo1).
This is the INTERNET adapter ONLY. It has NO packet injection support.

Status: INTERNET_ONLY
- Monitor mode: RX-only (cannot inject)
- Injection: NO
- All attack operations BLOCKED with clear error messages

Protection pattern:
  check_adapter_allowed(mt7902_adapter, "deauth")
  → raises SidewinderError with chipset-specific message
"""
from __future__ import annotations

import logging

from ..core.errors import Category, Severity, SidewinderError
from .base import Adapter

logger = logging.getLogger(__name__)

# Operations the MT7902 can perform
MT7902_RESTRICTIONS: dict[str, bool] = {
    "monitor":   False,   # RX-only, no injection
    "injection": False,   # No TX path in driver
    "deauth":    False,   # Cannot inject deauth frames
    "evil_twin": False,   # Cannot create AP
    "scan":      True,    # Can scan in managed mode
    "internet":  True,    # Primary purpose: internet connectivity
    "capture":   False,   # Cannot inject — passive RX only
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
    """Check if a chipset is allowed to perform an operation.

    Raises SidewinderError with chipset-specific message if blocked.

    Args:
        chipset: Chipset name ("MT7902", "RT5370", "RTL8821AU")
        operation: Operation to check ("deauth", "inject", "capture", etc.)
    """
    if chipset == "MT7902":
        if not MT7902_RESTRICTIONS.get(operation, False):
            raise SidewinderError(
                severity=Severity.ERROR,
                category=Category.HARDWARE,
                what=f"MT7902 (wlo1) cannot perform '{operation}'",
                why="Built-in WiFi card has RX-only monitor mode — no TX/injection path in driver",
                how_to_fix=[
                    "Use RT5370 (wlx001ea6c65744) for this operation",
                    "Or use RTL8821AU (wlx5c628b765de2) with morrownr driver",
                    "MT7902 is reserved for internet connectivity only",
                ],
            )


class MT7902Adapter(Adapter):
    """MT7902 built-in WiFi adapter.

    INTERNET_ONLY — all attack operations are blocked.
    Attempting any restricted operation raises a SidewinderError
    with a clear explanation and alternative suggestions.
    """

    def __init__(self, iface: str, phy: str) -> None:
        self._iface = iface
        self._phy = phy

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
        return False

    @property
    def injection_capable(self) -> bool:
        return False

    async def enter_monitor(self) -> str:
        """BLOCKED — MT7902 has no injection capability."""
        check_adapter_allowed("MT7902", "monitor")
        raise RuntimeError("unreachable")  # check_adapter_allowed raises

    async def exit_monitor(self, mon_iface: str) -> None:
        """No-op — MT7902 never enters monitor mode."""
        pass

    async def set_channel(self, channel: int) -> None:
        """BLOCKED — MT7902 cannot set channel for attack operations."""
        check_adapter_allowed("MT7902", "monitor")
        raise RuntimeError("unreachable")

    async def inject_frame(self, frame: bytes) -> None:
        """BLOCKED — MT7902 cannot perform packet injection."""
        check_adapter_allowed("MT7902", "injection")
        raise RuntimeError("unreachable")
