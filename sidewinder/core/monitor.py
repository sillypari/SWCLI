"""Sidewinder Monitor Mode Manager.

Enter/exit monitor mode using direct iw/ip calls — bypasses airmon-ng entirely.

Implements these airmon-ng functions natively:
  setLink(), startMac80211Iface(), stopMac80211Iface(), setChannelMac80211()

Two paths:
  - Standard mac80211: creates monitor VIF (iw phy <phy> interface add <name> type monitor)
  - Bad driver fallback: direct mode change (iw dev <iface> set type monitor)
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from .subprocess_mgr import run

logger = logging.getLogger(__name__)

# ARPHRD_IEEE80211_RADIOTAP - what sysfs type field shows for monitor mode
ARPHRD_IEEE80211_RADIOTAP = "803"
# ARPHRD_ETHER - normal managed mode
ARPHRD_ETHER = "1"


async def set_link(iface: str, state: str) -> None:
    """Bring interface up or down.

    Equivalent to airmon-ng setLink().

    Args:
        iface: Interface name (e.g., "wlan0")
        state: "up" or "down"
    """
    await run(["ip", "link", "set", iface, state])
    logger.debug("Interface %s -> %s", iface, state)


async def enter_monitor_mode(
    iface: str,
    phy: str,
    channel: int = 6,
) -> str:
    """Enter monitor mode — tries standard path first, falls back to bad driver.

    Standard path: creates new monitor VIF named '<iface>mon'.
    Bad driver path: changes existing interface type in-place (no new VIF).

    Args:
        iface: Base interface name (e.g., "wlan0")
        phy: PHY name (e.g., "phy0")
        channel: Initial channel (default 6)

    Returns:
        Monitor interface name (e.g., "wlan0mon" or same iface for bad driver)
    """
    logger.info("Entering monitor mode: %s (phy=%s, ch=%d)", iface, phy, channel)

    # Try standard path first (creates new VIF)
    try:
        mon_iface = f"{iface}mon"

        # 1. Bring base interface down
        await set_link(iface, "down")

        # 2. Create monitor VIF (check=False to avoid verbose error output)
        result = await run(
            ["iw", "phy", phy, "interface", "add", mon_iface, "type", "monitor"],
            check=False,
        )

        # 3. Check if VIF creation succeeded
        if not result.success or not Path(f"/sys/class/net/{mon_iface}").exists():
            raise RuntimeError("VIF creation failed")

        # 4. Bring monitor interface up
        await set_link(mon_iface, "up")

        # 5. Set initial channel
        await set_channel(mon_iface, channel)

        # 6. Set TX power (3000 = 30 dBm in mBm)
        try:
            await run(["iw", "dev", mon_iface, "set", "txpower", "fixed", "3000"], check=False)
        except Exception:
            pass  # TX power setting may fail on some drivers, non-fatal

        # 7. Verify monitor mode is active
        mode = get_interface_mode_sync(mon_iface)
        if mode != "monitor":
            raise RuntimeError(
                f"Monitor mode verification failed: expected 'monitor', got '{mode}' on {mon_iface}"
            )

        logger.info("Monitor mode active: %s (ch %d)", mon_iface, channel)
        return mon_iface

    except (RuntimeError, Exception):
        # Standard path failed — fall back to bad driver path (mt7601u, etc.)
        logger.debug("Standard path failed for %s, using bad driver fallback", iface)
        return await enter_monitor_mode_bad_driver(iface, channel)


async def enter_monitor_mode_bad_driver(iface: str, channel: int = 6) -> str:
    """Enter monitor mode via direct type change (bad driver fallback).

    Equivalent to airmon-ng changeMac80211IfaceTypeMonitor().
    Does NOT create a new VIF — changes existing interface type in-place.
    Used for mt7601u, RTL8821AU with morrownr driver, etc.

    Args:
        iface: Interface name to modify
        channel: Initial channel (default 6)

    Returns:
        Same iface name (modified in-place)
    """
    logger.info("Entering monitor mode (bad driver path): %s", iface)

    await set_link(iface, "down")
    await run(["iw", "dev", iface, "set", "type", "monitor"])
    await run(["iw", "dev", iface, "set", "monitor", "otherbss"], check=False)
    await set_link(iface, "up")

    # Set channel
    await set_channel(iface, channel)

    # Set TX power (non-fatal)
    try:
        await run(["iw", "dev", iface, "set", "txpower", "fixed", "3000"], check=False)
    except Exception:
        pass

    mode = get_interface_mode_sync(iface)
    if mode != "monitor":
        raise RuntimeError(
            f"Direct monitor mode failed: expected 'monitor', got '{mode}' on {iface}"
        )

    logger.info("Monitor mode active (bad driver): %s (ch %d)", iface, channel)
    return iface


async def exit_monitor_mode(
    mon_iface: str,
    iface: str,
    phy: str,
) -> None:
    """Exit monitor mode, restore managed mode.

    Equivalent to airmon-ng stopMac80211Iface().
    Handles both standard VIF and bad driver in-place mode.

    Args:
        mon_iface: Monitor interface name (e.g., "wlan0mon" or "wlan0")
        iface: Managed interface to restore (e.g., "wlan0"). If empty, uses mon_iface.
        phy: PHY name for VIF recreation (e.g., "phy0"). If empty, best-effort.
    """
    # If iface not provided, assume bad driver path (mon_iface == iface)
    restore_iface = iface or mon_iface
    is_bad_driver_path = (mon_iface == restore_iface)
    logger.info("Exiting monitor mode: %s -> %s (bad_driver=%s)", mon_iface, restore_iface, is_bad_driver_path)

    # 1. Delete monitor VIF (only if it's a separate interface, not bad driver path)
    if not is_bad_driver_path:
        await run(["iw", "dev", mon_iface, "del"], check=False)

    # 2. Bring down before type change
    await set_link(restore_iface, "down")

    # 3. Set back to managed mode
    if is_bad_driver_path:
        # Bad driver path: change type in-place
        await run(["iw", "dev", restore_iface, "set", "type", "managed"], check=False)
    else:
        # Standard path: recreate station VIF
        try:
            await run(["iw", "phy", phy, "interface", "add", restore_iface, "type", "station"])
        except RuntimeError:
            pass  # Interface may already exist

    # 4. Bring up
    await set_link(restore_iface, "up")

    logger.info("Managed mode restored: %s", restore_iface)


async def set_channel(
    iface: str,
    channel: int,
    bandwidth: str = "",
) -> None:
    """Set channel on monitor interface.

    Equivalent to airmon-ng setChannelMac80211().

    Args:
        iface: Monitor interface name
        channel: Channel number (1-14 for 2.4GHz, 36-165 for 5GHz)
        bandwidth: Optional bandwidth ("HT20", "HT40+", "HT40-", "80MHz")
    """
    cmd = ["iw", "dev", iface, "set", "channel", str(channel)]
    if bandwidth:
        cmd.append(bandwidth)
    await run(cmd)
    logger.debug("Channel set: %s -> ch%d %s", iface, channel, bandwidth)


async def lock_channel(mon_iface: str, channel: int) -> bool:
    """Lock to specific channel and verify the lock succeeded.

    Args:
        mon_iface: Monitor interface name
        channel: Channel number to lock to

    Returns:
        True if channel was set and verified correctly.
    """
    await set_channel(mon_iface, channel)
    # Verify via iw dev info
    result = await run(["iw", "dev", mon_iface, "info"], check=False)
    return f"channel {channel}" in result.stdout.lower()


async def set_power_save(iface: str, enable: bool) -> None:
    """Enable or disable power save mode.

    Args:
        iface: Interface name
        enable: True to enable power save, False to disable
    """
    state = "on" if enable else "off"
    await run(["iw", "dev", iface, "set", "power_save", state], check=False)


def get_interface_mode_sync(iface: str) -> str:
    """Read current interface mode synchronously from sysfs type field.

    type=1   = ARPHRD_ETHER = managed/station
    type=803 = ARPHRD_IEEE80211_RADIOTAP = monitor

    Args:
        iface: Interface name to inspect

    Returns:
        "monitor", "managed", or "unknown(<type>)"
    """
    type_path = Path(f"/sys/class/net/{iface}/type")
    if not type_path.exists():
        return "unknown"
    iface_type = type_path.read_text().strip()
    if iface_type == ARPHRD_IEEE80211_RADIOTAP:
        return "monitor"
    if iface_type == ARPHRD_ETHER:
        return "managed"
    return f"unknown({iface_type})"


class MonitorWatcher:
    """Watch monitor mode status and report if lost.

    Runs as a background async task.
    Reports events but NEVER auto-fixes — recommendation only.
    """

    def __init__(self, iface: str, poll_interval: float = 2.0) -> None:
        """Initialise the watcher.

        Args:
            iface: Monitor interface name to watch
            poll_interval: Seconds between sysfs polls (default 2.0)
        """
        self.iface = iface
        self.poll_interval = poll_interval
        self._running = False

    async def watch(self):
        """Watch monitor mode. Yields events when mode is lost.

        Yields:
            dict with keys: type, iface, current_mode, message, recommendation
        """
        self._running = True
        while self._running:
            await asyncio.sleep(self.poll_interval)
            mode = get_interface_mode_sync(self.iface)
            if mode != "monitor":
                yield {
                    "type": "MODE_LOST",
                    "iface": self.iface,
                    "current_mode": mode,
                    "message": f"Monitor mode lost on {self.iface} (now: {mode})",
                    "recommendation": "Press [R] to re-enable monitor mode",
                }

    def stop(self) -> None:
        """Stop the watcher."""
        self._running = False
