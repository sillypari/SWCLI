"""Sidewinder RTL8821AU Adapter Implementation.

RTL8821AU (Realtek) — 2.4+5GHz dual-band USB adapter.
Requires morrownr driver (NOT rtw88 which ships with Ubuntu).

Critical: rtw88 (Ubuntu default) has NO monitor mode support.
         morrownr 8821au driver provides full monitor + injection + VHT.

Characteristics:
- Monitor mode: YES (requires morrownr driver)
- Injection: YES (radiotap-iterator TX path)
- 5GHz: YES (80/160MHz VHT, MCS 0-9)
- USB VID:PID: 2357:0120 (TP-Link Archer T2U Plus)
"""
from __future__ import annotations

import logging
from typing import Optional

from ..core.monitor import (
    enter_monitor_mode_bad_driver,
    exit_monitor_mode,
    set_channel,
)
from ..core.subprocess_mgr import run
from .base import Adapter

logger = logging.getLogger(__name__)

# Installation steps shown to user if morrownr driver is absent
RTL8821AU_INSTALL_STEPS = [
    "sudo apt install build-essential dkms git",
    "git clone https://github.com/morrownr/8821au-20210708.git",
    "cd 8821au-20210708 && sudo ./install-driver.sh",
    "Reboot",
]


async def detect_rtl8821au_morrownr() -> bool:
    """Check if RTL8821AU is using the morrownr 8821au driver.

    Returns:
        True if morrownr driver is loaded (monitor mode supported).
        False if rtw88 is loaded (no monitor mode) or no driver.
    """
    try:
        from ..core.subprocess_mgr import run
        result = await run(
            ["lsmod"],
            timeout=5,
            check=False,
        )
        modules = result.stdout.lower()

        if "8821au" in modules:
            return True  # morrownr driver loaded [OK]

        if "rtw88" in modules or "rtw8821a" in modules:
            return False  # Wrong driver [FAIL]

    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return False


async def detect_rtw88_loaded() -> bool:
    """Check if the bad rtw88 driver is loaded for RTL8821AU."""
    try:
        from ..core.subprocess_mgr import run
        result = await run(
            ["lsmod"],
            timeout=5,
            check=False,
        )
        return "rtw88" in result.stdout.lower() or "rtw8821a" in result.stdout.lower()
    except Exception:
        return False


class RTL8821AUAdapter(Adapter):
    """RTL8821AU adapter implementation (morrownr driver required).

    Uses direct mode-in-place approach (not VIF creation) because
    morrownr driver supports iw dev <iface> set type monitor directly.

    Radiotap flags: fcsfail (capture FCS-failed frames) + otherbss
    (capture frames from other BSSes, essential for injection targeting).
    """

    def __init__(self, iface: str, phy: str) -> None:
        self._iface = iface
        self._phy = phy
        self._mon_iface: Optional[str] = None

    @property
    def name(self) -> str:
        return "RTL8821AU"

    @property
    def iface(self) -> str:
        return self._iface

    @property
    def phy(self) -> str:
        return self._phy

    @property
    def chipset(self) -> str:
        return "RTL8821AU"

    @property
    def monitor_capable(self) -> bool:
        return True

    @property
    def injection_capable(self) -> bool:
        return True

    async def enter_monitor(self) -> str:
        """Enter monitor mode on RTL8821AU (morrownr driver).

        Uses direct type change (not VIF creation).
        Verifies morrownr driver is present before proceeding.

        Raises:
            RuntimeError: If morrownr driver not loaded.
        """
        from .base import BadDriverWarning
        if not await detect_rtl8821au_morrownr():
            if await detect_rtw88_loaded():
                raise BadDriverWarning(
                    "RTL8821AU: Ubuntu's default rtw88 driver is loaded. "
                    "This driver does NOT natively support monitor mode.\n"
                    "For full features, install morrownr: https://github.com/morrownr/8821au-20210708"
                )
            raise BadDriverWarning(
                "RTL8821AU: no compatible driver loaded. "
                "Install morrownr driver and reboot."
            )

        logger.info("RTL8821AU: entering monitor mode on %s (morrownr)", self._iface)
        mon_iface = await enter_monitor_mode_bad_driver(self._iface)
        self._mon_iface = mon_iface

        # Set radiotap flags for full radiotap header capture
        await run(
            ["iw", "dev", mon_iface, "set", "monitor", "fcsfail", "otherbss"],
            check=False,
        )

        # Set initial channel
        await set_channel(mon_iface, 6)

        logger.info("RTL8821AU: monitor mode active on %s (radiotap enabled)", mon_iface)
        return mon_iface

    async def exit_monitor(self, mon_iface: str) -> None:
        """Restore managed mode.

        RTL8821AU uses in-place type change, so we just set type back to station.
        """
        from ..core.monitor import set_link
        from ..core.subprocess_mgr import run

        await set_link(mon_iface, "down")
        await run(["iw", "dev", mon_iface, "set", "type", "station"], check=False)
        await set_link(mon_iface, "up")
        self._mon_iface = None
        logger.info("RTL8821AU: restored managed mode on %s", mon_iface)

    async def set_channel(self, channel: int) -> None:
        """Set channel on RTL8821AU. Supports 2.4GHz (HT20) and 5GHz (80MHz)."""
        iface = self._mon_iface or self._iface
        # RTL8821AU supports HT40+/HT40- and VHT80 on 5GHz
        if channel >= 36:
            await set_channel(iface, channel, bandwidth="80MHz")
        else:
            await set_channel(iface, channel, bandwidth="HT20")

    async def inject_deauth(
        self,
        bssid: str,
        client: str,
        count: int = 10,
    ) -> bool:
        """Inject deauth frames via RTL8821AU's radiotap TX path.

        Args:
            bssid: Target AP MAC
            client: Target client MAC
            count: Number of deauth frames

        Returns:
            True if aireplay-ng reports success.
        """
        iface = self._mon_iface or self._iface
        from ..core.subprocess_mgr import get_manager
        mgr = get_manager()
        result = await mgr.run(
            ["aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", client, iface],
            timeout=30,
            check=False,
        )
        return result.returncode == 0
