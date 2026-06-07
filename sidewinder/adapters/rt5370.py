"""Sidewinder RT5370 Adapter Implementation.

RT5370 (Ralink/MediaTek) — 2.4GHz only, USB adapter.
Driver: rt2800usb (built into kernel, no extra install needed).

Characteristics:
- Monitor mode: YES (full)
- Injection: YES (via aireplay-ng)
- 5GHz: NO (2.4GHz only)
- Channels: 1-14

Modern iw commands are used. iwpriv is legacy-only fallback
(deprecated in kernel 5.x, absent from Ubuntu 22.04+, Kali 2023+).
"""
from __future__ import annotations

import logging
from typing import Optional

from ..core.monitor import (
    enter_monitor_mode,
    enter_monitor_mode_bad_driver,
    exit_monitor_mode,
    set_channel,
    set_power_save,
)
from ..core.subprocess_mgr import run
from .base import Adapter

logger = logging.getLogger(__name__)

# Modern iw-based commands for RT5370
RT5370_COMMANDS: dict[str, str] = {
    "power_save_off": "iw dev <iface> set power_save off",
    "fixed_rate":     "iw dev <iface> set bitrates legacy-2.4 6",
    "set_channel":    "iw dev <iface> set channel <N>",
    "ht20":           "iw dev <iface> set channel <N> HT20",
}

# Legacy iwpriv commands — fallback for kernels < 5.0 only
RT5370_IWPRIV_COMMANDS: dict[str, str] = {
    "PSMode=CAM":        "Constantly Active Mode — no power save",
    "FixedTxMode=OFDM":  "Use OFDM (not CCK) for better range",
    "HtMcs=0":           "HT MCS 0 (6 Mbps) — most reliable",
    "CountryRegion=5":   "India (channels 1-13)",
}


class RT5370Adapter(Adapter):
    """RT5370 adapter implementation.

    Uses direct iw commands (no airmon-ng dependency).
    iwpriv used only as fallback for legacy kernels.
    """

    def __init__(self, iface: str, phy: str) -> None:
        self._iface = iface
        self._phy = phy
        self._mon_iface: Optional[str] = None

    @property
    def name(self) -> str:
        return "RT5370"

    @property
    def iface(self) -> str:
        return self._iface

    @property
    def phy(self) -> str:
        return self._phy

    @property
    def chipset(self) -> str:
        return "RT5370"

    @property
    def monitor_capable(self) -> bool:
        return True

    @property
    def injection_capable(self) -> bool:
        return True

    async def enter_monitor(self) -> str:
        """Enter monitor mode on RT5370.

        Uses standard mac80211 VIF path. Applies RT5370-specific
        optimizations after entering monitor mode.
        """
        logger.info("RT5370: entering monitor mode on %s", self._iface)
        mon_iface = await enter_monitor_mode(self._iface, self._phy)
        self._mon_iface = mon_iface

        # Apply RT5370 optimizations
        await self._apply_optimizations(mon_iface)
        return mon_iface

    async def exit_monitor(self, mon_iface: str) -> None:
        """Exit monitor mode and restore managed mode."""
        await exit_monitor_mode(mon_iface, self._iface, self._phy)
        self._mon_iface = None

    async def set_channel(self, channel: int) -> None:
        """Set channel. Uses HT20 for RT5370 (most reliable)."""
        iface = self._mon_iface or self._iface
        await set_channel(iface, channel, bandwidth="HT20")

    async def _apply_optimizations(self, mon_iface: str) -> None:
        """Apply RT5370-specific optimizations.

        1. Disable power save (modern iw method)
        2. Optional: iwpriv legacy commands (if available on old kernel)
        """
        # Modern power save control (kernel 5.x+)
        await set_power_save(mon_iface, enable=False)

        # Set monitor flags for better capture
        await run(
            ["iw", "dev", mon_iface, "set", "monitor", "fcsfail", "otherbss"],
            check=False,
        )

        # Check if iwpriv is available (legacy kernel fallback)
        try:
            which_result = await run(
                ["which", "iwpriv"],
                timeout=3,
                check=False,
            )
            if which_result.returncode == 0:
                # Legacy iwpriv — only if available
                for cmd_arg in ["PSMode=CAM", "FixedTxMode=OFDM", "HtMcs=0"]:
                    await run(
                        ["iwpriv", mon_iface, "set", cmd_arg],
                        check=False,
                    )
                logger.debug("RT5370: applied legacy iwpriv optimizations")
        except Exception:
            pass  # iwpriv not available — fine, modern iw is sufficient

        logger.info("RT5370: optimizations applied on %s", mon_iface)


def detect_rt5370(iface: str) -> bool:
    """Check if interface is an RT5370 adapter.

    Reads driver name from sysfs.
    """
    from pathlib import Path
    driver_link = Path(f"/sys/class/net/{iface}/device/driver")
    if driver_link.exists():
        try:
            driver_name = driver_link.resolve().name
            return driver_name in ("rt2800usb", "rt2870sta", "rt2x00usb")
        except OSError:
            pass

    # VID/PID check
    try:
        vid_path = Path(f"/sys/class/net/{iface}/device/idVendor")
        pid_path = Path(f"/sys/class/net/{iface}/device/idProduct")
        if vid_path.exists() and pid_path.exists():
            vid = int(vid_path.read_text().strip(), 16)
            pid = int(pid_path.read_text().strip(), 16)
            return (vid, pid) in [(0x148F, 0x5370), (0x148F, 0x5372)]
    except (ValueError, OSError):
        pass

    return False
