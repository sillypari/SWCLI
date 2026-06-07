"""Sidewinder Adapter Detection System.

Detects all wireless adapters via sysfs, identifies chipset/driver/bands.
Bypasses airmon-ng — reads directly from /sys/class/net/.

Implements these airmon-ng functions natively:
  getPhy(), getDriver(), getChipset(), getBus(), getStack(),
  listInterfaces(), ifaceExists(), ifaceIsUp()
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Known USB/PCI device registry
# Format: (VID, PID) -> adapter metadata
KNOWN_DEVICES: dict[tuple[int, int], dict] = {
    # RT5370 family
    (0x148F, 0x5370): {"name": "RT5370",    "chipset": "RT5370",   "bands": ["2.4G"], "monitor": True,  "injection": True},
    (0x148F, 0x5372): {"name": "RT5372",    "chipset": "RT5370",   "bands": ["2.4G"], "monitor": True,  "injection": True},
    (0x148F, 0x7601): {"name": "MT7601U",   "chipset": "MT7601U",  "bands": ["2.4G"], "monitor": True,  "injection": False},
    # RTL8821AU family
    (0x2357, 0x0120): {"name": "RTL8821AU", "chipset": "RTL8821AU", "bands": ["2.4G", "5G"], "monitor": True, "injection": True},
    (0x2357, 0x011E): {"name": "RTL8821AU", "chipset": "RTL8821AU", "bands": ["2.4G", "5G"], "monitor": True, "injection": True},
    (0x0BDA, 0x8812): {"name": "RTL8812AU", "chipset": "RTL8812AU", "bands": ["2.4G", "5G"], "monitor": True, "injection": True},
    # MT7902 (PCIe built-in)
    (0x14C3, 0x7902): {"name": "MT7902",    "chipset": "MT7902",   "bands": ["2.4G", "5G", "6G"], "monitor": False, "injection": False},
}

ADAPTER_PRIORITY: dict[str, int] = {
    "RTL8821AU": 10,
    "RTL8812AU": 9,
    "RT5370": 5,
    "MT7902": 1,
    "MT7601U": 3,
}


@dataclass
class AdapterInfo:
    """Complete information about a wireless adapter."""

    iface: str
    phy: str = ""
    driver: str = ""
    chipset: str = ""
    name: str = ""
    bus: str = ""           # "usb", "pci", "sdio"
    vid: int = 0
    pid: int = 0
    mac: str = ""
    bands: list[str] = field(default_factory=list)
    monitor_capable: bool = False
    injection_capable: bool = False
    is_up: bool = False
    current_mode: str = ""  # "managed", "monitor", "unknown"
    status: str = "UNKNOWN"  # "OPTIMIZED", "WORKING", "LIMITED", "INTERNET_ONLY"

    def display_status(self) -> str:
        """Human-readable status with emoji."""
        match self.status:
            case "OPTIMIZED":
                return "[+] OPTIMIZED"
            case "WORKING":
                return "[~] WORKING"
            case "LIMITED":
                return "[-] LIMITED"
            case "INTERNET_ONLY":
                return "[i] INTERNET ONLY"
            case _:
                return "[?] UNKNOWN"


def list_interfaces() -> list[str]:
    """List all wireless interfaces from sysfs. Equivalent to airmon-ng listInterfaces()."""
    net_path = Path("/sys/class/net")
    ifaces: list[str] = []
    if not net_path.exists():
        return ifaces
    for iface_path in net_path.iterdir():
        phy_path = iface_path / "phy80211"
        if phy_path.exists():
            ifaces.append(iface_path.name)
    return sorted(ifaces)


def iface_exists(iface: str) -> bool:
    """Check if interface exists. Equivalent to airmon-ng ifaceExists()."""
    return Path(f"/sys/class/net/{iface}").exists()


def iface_is_up(iface: str) -> bool:
    """Check if interface is UP. Equivalent to airmon-ng ifaceIsUp()."""
    operstate = Path(f"/sys/class/net/{iface}/operstate")
    if not operstate.exists():
        return False
    return operstate.read_text().strip() in ("up", "unknown")


def get_phy(iface: str) -> str:
    """Read PHY name from sysfs. Equivalent to airmon-ng getPhy()."""
    phy_name = Path(f"/sys/class/net/{iface}/phy80211/name")
    if phy_name.exists():
        return phy_name.read_text().strip()
    return ""


def get_driver(iface: str) -> str:
    """Read driver name from sysfs. Equivalent to airmon-ng getDriver()."""
    driver_link = Path(f"/sys/class/net/{iface}/device/driver")
    if driver_link.exists():
        try:
            return driver_link.resolve().name
        except OSError:
            pass
    # Fallback: read uevent
    uevent = Path(f"/sys/class/net/{iface}/device/uevent")
    if uevent.exists():
        for line in uevent.read_text().splitlines():
            if line.startswith("DRIVER="):
                return line.split("=", 1)[1]
    return ""


def get_bus(iface: str) -> str:
    """Read bus type from sysfs modalias. Equivalent to airmon-ng getBus()."""
    modalias = Path(f"/sys/class/net/{iface}/device/modalias")
    if not modalias.exists():
        return "unknown"
    alias = modalias.read_text().strip()
    if alias.startswith("usb:"):
        return "usb"
    if alias.startswith("pci:"):
        return "pci"
    if alias.startswith("sdio:"):
        return "sdio"
    return "unknown"


def get_vid_pid(iface: str) -> tuple[int, int]:
    """Read USB or PCI vendor/product IDs from sysfs."""
    vid_path = Path(f"/sys/class/net/{iface}/device/idVendor")
    pid_path = Path(f"/sys/class/net/{iface}/device/idProduct")
    if vid_path.exists() and pid_path.exists():
        try:
            vid = int(vid_path.read_text().strip(), 16)
            pid = int(pid_path.read_text().strip(), 16)
            return vid, pid
        except (ValueError, OSError):
            pass
    # PCI fallback via vendor/device
    vendor_path = Path(f"/sys/class/net/{iface}/device/vendor")
    device_path = Path(f"/sys/class/net/{iface}/device/device")
    if vendor_path.exists() and device_path.exists():
        try:
            vid = int(vendor_path.read_text().strip(), 16)
            pid = int(device_path.read_text().strip(), 16)
            return vid, pid
        except (ValueError, OSError):
            pass
    return 0, 0


def get_mac(iface: str) -> str:
    """Read MAC address from sysfs."""
    mac_path = Path(f"/sys/class/net/{iface}/address")
    if mac_path.exists():
        return mac_path.read_text().strip().upper()
    return ""


def get_interface_mode(iface: str) -> str:
    """Read current interface mode from sysfs type field.

    type=1   = ARPHRD_ETHER               = managed/station
    type=803 = ARPHRD_IEEE80211_RADIOTAP  = monitor
    """
    type_path = Path(f"/sys/class/net/{iface}/type")
    if not type_path.exists():
        return "unknown"
    iface_type = type_path.read_text().strip()
    if iface_type == "803":
        return "monitor"
    if iface_type == "1":
        return "managed"
    return f"unknown({iface_type})"


async def detect_adapter(iface: str) -> Optional[AdapterInfo]:
    """Detect and classify a single wireless adapter.

    Returns None if interface is not wireless or cannot be identified.
    """
    phy_path = Path(f"/sys/class/net/{iface}/phy80211")
    if not phy_path.exists():
        return None  # Not a wireless interface

    info = AdapterInfo(iface=iface)
    info.phy = get_phy(iface)
    info.driver = get_driver(iface)
    info.bus = get_bus(iface)
    info.mac = get_mac(iface)
    info.vid, info.pid = get_vid_pid(iface)
    info.is_up = iface_is_up(iface)
    info.current_mode = get_interface_mode(iface)

    # Look up in known devices registry
    device_key = (info.vid, info.pid)
    if device_key in KNOWN_DEVICES:
        dev = KNOWN_DEVICES[device_key]
        info.name = dev["name"]
        info.chipset = dev["chipset"]
        info.bands = dev["bands"]
        info.monitor_capable = dev["monitor"]
        info.injection_capable = dev["injection"]
    else:
        # Unknown device — use driver name as chipset
        info.chipset = info.driver or "unknown"
        info.name = info.driver or iface
        # Try to detect monitor capability via iw
        info.monitor_capable = await _check_monitor_via_iw(iface)
        info.injection_capable = False

    # Set status based on capabilities
    if info.injection_capable and info.monitor_capable:
        info.status = "OPTIMIZED"
    elif info.monitor_capable:
        info.status = "WORKING"
    elif info.chipset == "MT7902":
        info.status = "INTERNET_ONLY"
    else:
        info.status = "LIMITED"

    return info


async def _check_monitor_via_iw(iface: str) -> bool:
    """Check if interface supports monitor mode via 'iw list'."""
    try:
        from .subprocess_mgr import run
        result = await run(
            ["iw", "list"],
            timeout=5,
            check=False,
        )
        return "* monitor" in result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


async def discover_all_adapters() -> list[AdapterInfo]:
    """Discover and classify all wireless adapters on the system."""
    adapters: list[AdapterInfo] = []
    for iface in list_interfaces():
        adapter = await detect_adapter(iface)
        if adapter:
            adapters.append(adapter)
    # Sort by priority (best first)
    adapters.sort(
        key=lambda a: ADAPTER_PRIORITY.get(a.chipset, 0),
        reverse=True,
    )
    return adapters


def get_best_adapter(
    adapters: list[AdapterInfo],
    operation: str,
) -> Optional[AdapterInfo]:
    """Select the best adapter for a given operation.

    Args:
        adapters: List of detected adapters, already sorted by priority.
        operation: One of "scan", "capture", "deauth", "inject", "internet".

    Returns:
        The most suitable AdapterInfo, or None if no capable adapter exists.
    """
    if not adapters:
        return None

    if operation == "internet":
        # MT7902 preferred for internet connectivity
        for a in adapters:
            if a.chipset == "MT7902":
                return a
        return adapters[-1]

    # For all attack/audit operations: need monitor capability, not the built-in NIC
    capable = [
        a for a in adapters
        if a.monitor_capable and a.chipset != "MT7902"
    ]
    if not capable:
        return None
    # Already sorted by priority — return highest ranked
    return capable[0]
