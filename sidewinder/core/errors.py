"""Sidewinder Error Classification System.

Structured error handling with What/Why/HowToFix — learned from Wcrack's 133 bugs.
Every error has: severity, category, what happened, why, how to fix, raw error.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity levels for Sidewinder errors."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Category(Enum):
    """High-level category for grouping errors by domain."""

    HARDWARE = "hardware"
    PROCESS = "process"
    NETWORK = "network"
    PERMISSION = "permission"
    RESOURCE = "resource"
    USER = "user"


@dataclass
class SidewinderError(Exception):
    """Structured error with What/Why/HowToFix triple for actionable diagnostics.

    Attributes:
        severity:    How serious the error is.
        category:    Domain the error belongs to.
        what:        One-line human-readable description of what went wrong.
        why:         Root-cause explanation.
        how_to_fix:  Ordered list of remediation steps.
        raw_error:   Optional raw exception or stderr string for debugging.
        timestamp:   When the error was created.
    """

    severity: Severity
    category: Category
    what: str
    why: str
    how_to_fix: list[str]
    raw_error: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def __str__(self) -> str:
        """Format the error as a human-readable multi-line string."""
        lines = [
            f"[{self.severity.value.upper()}] {self.what}",
            f"Why: {self.why}",
            "How to fix:",
        ]
        for step in self.how_to_fix:
            lines.append(f"  • {step}")
        if self.raw_error:
            lines.append(f"Raw: {self.raw_error}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialise this error to a plain dict (JSON-safe)."""
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "what": self.what,
            "why": self.why,
            "how_to_fix": self.how_to_fix,
            "raw_error": self.raw_error,
            "timestamp": self.timestamp.isoformat(),
        }





# ---------------------------------------------------------------------------
# Error database — canonical error definitions keyed by short error code.
# Values are SidewinderError instances used as templates; copy and populate
# raw_error at raise-time if needed.
# ---------------------------------------------------------------------------

ERROR_DB: dict[str, SidewinderError] = {
    "ADAPTER_NOT_FOUND": SidewinderError(
        severity=Severity.CRITICAL,
        category=Category.HARDWARE,
        what="No wireless adapter detected",
        why="USB adapter not plugged in or drivers not loaded",
        how_to_fix=[
            "Check USB connection",
            "Run: lsusb | grep -i wireless",
            "Install drivers: sudo apt install firmware-iwlwifi",
        ],
    ),
    "MONITOR_MODE_FAILED": SidewinderError(
        severity=Severity.ERROR,
        category=Category.HARDWARE,
        what="Failed to enter monitor mode",
        why="Driver doesn't support monitor mode or interface busy",
        how_to_fix=[
            "Kill conflicting processes: sudo airmon-ng check kill",
            "Try different adapter",
            "Check: iw list | grep -A 5 'Supported'",
        ],
    ),
    "ROOT_REQUIRED": SidewinderError(
        severity=Severity.CRITICAL,
        category=Category.PERMISSION,
        what="Root privileges required",
        why="WiFi monitor mode and packet injection require root access",
        how_to_fix=[
            "Run: sudo sidewinder",
            "Or: pkexec sidewinder",
        ],
    ),
    "DISK_FULL": SidewinderError(
        severity=Severity.ERROR,
        category=Category.RESOURCE,
        what="Cannot write capture file",
        why="Disk full or write permission denied",
        how_to_fix=[
            "Free space: df -h",
            "Check permissions: ls -la ~/.sidewinder/",
            "Use --capture-path to save elsewhere",
        ],
    ),
    "NO_HANDSHAKE": SidewinderError(
        severity=Severity.WARNING,
        category=Category.NETWORK,
        what="No EAPOL handshake captured after timeout",
        why="No active clients, AP has client isolation, or too far from target",
        how_to_fix=[
            "Wait longer (some APs have long reconnection delays)",
            "Try deauth method to force reconnection",
            "Move adapter closer to target",
            "Try passive capture during natural reconnection",
        ],
    ),
    "AIRODUMP_FAILED": SidewinderError(
        severity=Severity.ERROR,
        category=Category.PROCESS,
        what="airodump-ng exited unexpectedly",
        why="Invalid channel, adapter issue, or missing root",
        how_to_fix=[
            "Check adapter is in monitor mode",
            "Ensure running as root",
            "Try: sudo airodump-ng wlan1mon --channel 6",
        ],
    ),
    "AIRODUMP_STUCK": SidewinderError(
        severity=Severity.ERROR,
        category=Category.PROCESS,
        what="No output from airodump-ng for 30 seconds",
        why="Process may be hung or pipe deadlock",
        how_to_fix=[
            "Sidewinder will auto-restart in 5 seconds",
            "If persists, press Ctrl+C and try again",
            "Check adapter connection",
        ],
    ),
    "AIREPLAY_FAILED": SidewinderError(
        severity=Severity.ERROR,
        category=Category.PROCESS,
        what="Deauth attack failed",
        why="AP not responding, wrong channel, or adapter issue",
        how_to_fix=[
            "Verify target BSSID is correct",
            "Check adapter is on same channel as target",
            "Try increasing deauth count",
            "Check if AP has client isolation enabled",
        ],
    ),
    "RFKILL_BLOCKED": SidewinderError(
        severity=Severity.ERROR,
        category=Category.HARDWARE,
        what="Adapter blocked by rfkill",
        why="Software or hardware kill switch is active",
        how_to_fix=[
            "Run: rfkill unblock wifi",
            "Check hardware kill switch (laptop Fn key)",
            "Run: rfkill list",
        ],
    ),
    "ADAPTER_DISCONNECTED": SidewinderError(
        severity=Severity.CRITICAL,
        category=Category.HARDWARE,
        what="WiFi adapter vanished during operation",
        why="USB adapter physically removed or lost power",
        how_to_fix=[
            "Re-insert USB adapter",
            "Check USB cable connection",
            "Try different USB port",
            "Press Enter to rescan adapters",
        ],
    ),
    "WRONG_DRIVER": SidewinderError(
        severity=Severity.ERROR,
        category=Category.HARDWARE,
        what="RTL8821AU using rtw88 driver (no monitor mode)",
        why="Ubuntu default driver doesn't support monitor mode for this chipset",
        how_to_fix=[
            "Install morrownr driver:",
            "  git clone https://github.com/morrownr/8821au-20210708.git",
            "  cd 8821au-20210708 && sudo ./install-driver.sh",
            "  Reboot",
        ],
    ),
    "MT7902_NO_INJECTION": SidewinderError(
        severity=Severity.ERROR,
        category=Category.HARDWARE,
        what="MT7902 cannot perform packet injection",
        why="Built-in WiFi card has no TX path in monitor mode",
        how_to_fix=[
            "Use RT5370 or RTL8821AU USB adapter for injection",
            "MT7902 is for internet connectivity only",
        ],
    ),
    "WORDLIST_NOT_FOUND": SidewinderError(
        severity=Severity.ERROR,
        category=Category.USER,
        what="Wordlist file not found",
        why="Path does not exist or is not readable",
        how_to_fix=[
            "Check path: ls -la <path>",
            "Use rockyou.txt: /usr/share/wordlists/rockyou.txt",
            "Install wordlists: sudo apt install wordlists",
        ],
    ),
    "CRACK_NO_RESULT": SidewinderError(
        severity=Severity.WARNING,
        category=Category.NETWORK,
        what="Password not found in wordlist",
        why="Password is not in the wordlist",
        how_to_fix=[
            "Try a different wordlist",
            "Use hashcat with rules: --rules best64.rule",
            "Try a targeted wordlist for this AP",
        ],
    ),
    "WPS_LOCKED": SidewinderError(
        severity=Severity.ERROR,
        category=Category.NETWORK,
        what="WPS is locked on the target AP",
        why="Too many failed PIN attempts have locked the AP's WPS implementation",
        how_to_fix=[
            "Wait a few hours for the AP to unlock",
            "Try a deauth attack to see if the AP reboots and unlocks",
            "Abandon WPS and attempt a standard EAPOL handshake capture"
        ],
    ),
    "PMKID_TIMEOUT": SidewinderError(
        severity=Severity.WARNING,
        category=Category.NETWORK,
        what="hcxdumptool failed to capture PMKID",
        why="The AP does not support 802.11r roaming or PMKID caching",
        how_to_fix=[
            "Switch to Deauth + EAPOL capture mode",
            "Verify the target BSSID is correct"
        ],
    ),
    "VM_DETECTED": SidewinderError(
        severity=Severity.WARNING,
        category=Category.RESOURCE,
        what="Sidewinder is running inside a Virtual Machine",
        why="VirtualBox/VMware/WSL can interfere with USB WiFi adapter monitor mode and packet injection",
        how_to_fix=[
            "Ensure the USB adapter is physically passed through to the VM, not bridged",
            "If injection fails, run Sidewinder natively on Linux via live USB"
        ],
    ),
    "PCAP_CORRUPTED": SidewinderError(
        severity=Severity.ERROR,
        category=Category.RESOURCE,
        what="Capture file is corrupted or empty",
        why="airodump-ng exited abruptly or disk space was exhausted",
        how_to_fix=[
            "Check disk space: df -h",
            "Ensure the interface remained in monitor mode during capture",
            "Delete the corrupted file and try the capture again"
        ],
    ),
    "EVIL_TWIN_DHCP_FAILED": SidewinderError(
        severity=Severity.ERROR,
        category=Category.PROCESS,
        what="Failed to start DHCP server for Evil Twin",
        why="dnsmasq is missing or port 67 is already in use",
        how_to_fix=[
            "Install dnsmasq: sudo apt install dnsmasq",
            "Kill conflicting DHCP servers: sudo systemctl stop dnsmasq"
        ],
    ),
}

# ---------------------------------------------------------------------------
# Per-chipset adapter error database.
# Structure: { chipset: { error_key: { what, why, how_to_fix } } }
# ---------------------------------------------------------------------------

ADAPTER_ERRORS: dict[str, dict[str, dict]] = {
    "RT5370": {
        "MONITOR_FAILED": {
            "what": "RT5370 failed to enter monitor mode",
            "why": "Driver may be busy or rfkill blocked",
            "how_to_fix": [
                "Check rfkill: rfkill list",
                "Unblock: rfkill unblock wifi",
                "Reload driver: sudo modprobe -r rt2800usb && sudo modprobe rt2800usb",
            ],
        },
        "INJECTION_SLOW": {
            "what": "RT5370 injection rate is limited",
            "why": "USB bulk pipe limits throughput on this chipset",
            "how_to_fix": [
                "Reduce deauth count to 5-10",
                "Switch to RTL8821AU for faster injection",
            ],
        },
    },
    "RTL8821AU": {
        "WRONG_DRIVER": {
            "what": "RTL8821AU using rtw88 driver (no monitor mode)",
            "why": "Ubuntu default driver doesn't support monitor mode",
            "how_to_fix": [
                "Install morrownr driver:",
                "  git clone https://github.com/morrownr/8821au-20210708.git",
                "  cd 8821au-20210708 && sudo ./install-driver.sh",
                "  Reboot",
            ],
        },
        "USB_SURPRISE": {
            "what": "RTL8821AU disconnected during operation",
            "why": "USB connection unstable",
            "how_to_fix": [
                "Try different USB port (avoid USB hubs)",
                "Check USB cable integrity",
                "Try shorter USB cable",
            ],
        },
    },
    "MT7902": {
        "NO_INJECTION": {
            "what": "MT7902 cannot perform packet injection",
            "why": "Driver has no TX path for monitor mode",
            "how_to_fix": [
                "Use RT5370 or RTL8821AU for injection operations",
                "MT7902 (wlo1) is for internet connectivity only",
            ],
        },
        "KERNEL_PANIC": {
            "what": "MT7902 caused kernel panic",
            "why": "Known issue on some ASUS boards with this chipset",
            "how_to_fix": [
                "Blacklist module: echo 'blacklist mt7902' | sudo tee /etc/modprobe.d/blacklist-mt7902.conf",
                "Update BIOS to latest version",
                "Use USB adapter instead of built-in",
            ],
        },
    },
}


def make_adapter_error(
    chipset: str, error_key: str, raw_error: str = ""
) -> SidewinderError:
    """Create a chipset-specific SidewinderError from ADAPTER_ERRORS.

    Args:
        chipset:    Chipset identifier string (e.g. 'RT5370').
        error_key:  Key into that chipset's error dict (e.g. 'MONITOR_FAILED').
        raw_error:  Optional raw exception or stderr text for debugging.

    Returns:
        A fully populated SidewinderError (or a sensible fallback if not found).
    """
    info = ADAPTER_ERRORS.get(chipset, {}).get(error_key, {})
    return SidewinderError(
        severity=Severity.ERROR,
        category=Category.HARDWARE,
        what=info.get("what", f"{chipset}: {error_key}"),
        why=info.get("why", "Unknown cause"),
        how_to_fix=info.get("how_to_fix", ["Check adapter and driver"]),
        raw_error=raw_error,
    )
