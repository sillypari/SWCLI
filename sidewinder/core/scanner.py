"""Sidewinder Scan Engine.

Runs airodump-ng and parses its CSV output in real-time.
Extracts networks (APs) and clients using a line-by-line state machine.

Memory management:
  - Max 500 networks (evicts weakest signal when full)
  - Max 1000 clients (evicts oldest last_seen when full)
  - Stale eviction: removes entries not seen for >120s
  - Dedup callbacks: only fires on first seen or changed data
  - Reuses parser across poll cycles (no alloc per cycle)
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from enum import Enum, auto
from typing import Callable, Optional

from ..core.session import Client, Network
from .subprocess_mgr import SubprocessManager, get_manager

logger = logging.getLogger(__name__)

# --- Memory limits ---
MAX_NETWORKS = 500
MAX_CLIENTS = 1000
STALE_TIMEOUT_SECS = 120  # remove entries not seen for this long


class ParseState(Enum):
    IDLE = auto()
    AP_HEADER = auto()
    AP_DATA = auto()
    CLIENT_HEADER = auto()
    CLIENT_DATA = auto()


class AirodumpParser:
    """Parse airodump-ng CSV line-by-line into Network and Client objects."""

    def __init__(self) -> None:
        self.state = ParseState.IDLE

    def reset(self) -> None:
        """Reset parser state for a new CSV parse pass."""
        self.state = ParseState.IDLE

    def feed(self, line: str) -> Optional[Network | Client]:
        """Feed one line. Returns parsed object or None."""
        line = line.replace("\r", "").strip()

        low = line.lower()
        if "bssid" in low and "station" in low:
            self.state = ParseState.CLIENT_HEADER
            return None
        if "bssid" in low and ("pwr" in low or "power" in low) and "essid" in low:
            self.state = ParseState.AP_HEADER
            return None

        if not line:
            if self.state == ParseState.AP_HEADER:
                self.state = ParseState.AP_DATA
            elif self.state == ParseState.CLIENT_HEADER:
                self.state = ParseState.CLIENT_DATA
            return None

        if self.state == ParseState.AP_HEADER:
            self.state = ParseState.AP_DATA
        elif self.state == ParseState.CLIENT_HEADER:
            self.state = ParseState.CLIENT_DATA

        if self.state == ParseState.AP_DATA:
            return self._parse_ap_line(line)
        if self.state == ParseState.CLIENT_DATA:
            return self._parse_client_line(line)
        return None

    def _parse_ap_line(self, line: str) -> Optional[Network]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            return None
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', parts[0]):
            return None
        try:
            bssid = parts[0].upper()
            channel = int(parts[3]) if parts[3].strip().lstrip('-').isdigit() else 0
            speed = int(parts[4]) if parts[4].strip().lstrip('-').isdigit() else 0
            signal = int(parts[8]) if parts[8].strip().lstrip('-').isdigit() else -100
            privacy = parts[5].strip() or "OPN"
            cipher = parts[6].strip()
            auth = parts[7].strip()
            beacons = int(parts[9]) if parts[9].strip().isdigit() else 0
            data_packets = int(parts[10]) if parts[10].strip().isdigit() else 0
            essid_raw = parts[13].strip() if len(parts) > 13 else ""
            essid = essid_raw if essid_raw and essid_raw != "\x00" else ""
            first_seen = parts[1].strip()
            last_seen = parts[2].strip()

            return Network(
                bssid=bssid,
                channel=channel,
                signal=signal,
                privacy=privacy,
                cipher=cipher,
                auth=auth,
                essid=essid,
                speed=speed,
                beacons=beacons,
                data_packets=data_packets,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        except (ValueError, IndexError) as e:
            logger.debug("AP parse error: %s | line: %s", e, line[:80])
            return None

    def _parse_client_line(self, line: str) -> Optional[Client]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            return None
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', parts[0]):
            return None
        try:
            mac = parts[0].upper()
            signal = int(parts[3]) if parts[3].strip().lstrip('-').isdigit() else 0
            packets = int(parts[4]) if parts[4].strip().isdigit() else 0
            bssid = parts[5].upper() if len(parts) > 5 else ""
            probe = parts[6].strip() if len(parts) > 6 else ""
            first_seen = parts[1].strip()
            last_seen = parts[2].strip()

            return Client(
                mac=mac,
                bssid=bssid,
                signal=signal,
                packets=packets,
                probe=probe,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        except (ValueError, IndexError) as e:
            logger.debug("Client parse error: %s | line: %s", e, line[:80])
            return None


def _evict_stale(
    store: dict[str, Network | Client],
    now: float,
    stale_secs: int,
) -> int:
    """Remove entries whose last_seen is older than stale_secs. Returns count removed."""
    to_remove = []
    for key, entry in store.items():
        if not entry.last_seen:
            continue
        try:
            # Parse "YYYY-MM-DD HH:MM:SS"
            ts = time.mktime(time.strptime(entry.last_seen, "%Y-%m-%d %H:%M:%S"))
            if now - ts > stale_secs:
                to_remove.append(key)
        except (ValueError, OverflowError):
            pass
    for key in to_remove:
        del store[key]
    return len(to_remove)


def _evict_weakest_nets(store: dict[str, Network], cap: int) -> int:
    """If store exceeds cap, remove weakest-signal entries. Returns count removed."""
    excess = len(store) - cap
    if excess <= 0:
        return 0
    # Sort by signal ascending (weakest first), remove the weakest
    sorted_keys = sorted(store.keys(), key=lambda k: store[k].signal)
    for i in range(excess):
        del store[sorted_keys[i]]
    return excess


def _evict_oldest_clients(store: dict[str, Client], cap: int) -> int:
    """If store exceeds cap, remove oldest last_seen entries. Returns count removed."""
    excess = len(store) - cap
    if excess <= 0:
        return 0
    # Sort by last_seen ascending (oldest first), remove oldest
    sorted_keys = sorted(store.keys(), key=lambda k: store[k].last_seen or "")
    for i in range(excess):
        del store[sorted_keys[i]]
    return excess


def _network_changed(old: Optional[Network], new: Network, signal_threshold: int = 3) -> bool:
    """Check if a network's data has meaningfully changed.

    Signal must change by more than signal_threshold dB to count as changed.
    """
    if old is None:
        return True
    return (
        abs(new.signal - old.signal) > signal_threshold
        or new.channel != old.channel
        or new.essid != old.essid
    )


def _client_changed(old: Optional[Client], new: Client) -> bool:
    """Check if a client's data has meaningfully changed."""
    if old is None:
        return True
    return (
        new.signal != old.signal
        or new.packets != old.packets
        or new.bssid != old.bssid
    )


class ScanEngine:
    """Run airodump-ng and emit discovered networks and clients in real-time."""

    def __init__(self, mgr: Optional[SubprocessManager] = None) -> None:
        self.mgr = mgr or get_manager()
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._running = False

        # Persistent state (survives across poll cycles)
        self.networks: dict[str, Network] = {}
        self.clients: dict[str, Client] = {}

        # Reusable parser (no alloc per cycle)
        self._parser = AirodumpParser()

        # Dedup tracking: fire callback only on first seen or change
        self._nets_reported: dict[str, Network] = {}
        self._clis_reported: dict[str, Client] = {}

        # Data rate computation: tracks (prev_data_packets, timestamp) per BSSID
        self._data_rate_prev: dict[str, tuple[int, float]] = {}

        # Stats
        self._nets_evicted_stale = 0
        self._nets_evicted_cap = 0
        self._clis_evicted_stale = 0
        self._clis_evicted_cap = 0

    async def scan(
        self,
        mon_iface: str,
        capture_prefix: str = "/tmp/sidewinder_scan",
        band: str = "",
        channels: list[int] | None = None,
        update_secs: float = 0.1,
        hop_ms: int = 250,
        write_interval_secs: int = 0,
        poll_ms: int = 100,
        on_network: Optional[Callable[[Network], None]] = None,
        on_client: Optional[Callable[[Client], None]] = None,
        on_init: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Start scanning. Calls on_network/on_client for new/changed entities.

        Args:
            mon_iface: Monitor interface
            capture_prefix: Prefix for airodump-ng output files
            band: "a" for 5GHz, "bg" for 2.4GHz, "" for all
            channels: Specific channels to scan (optional)
            update_secs: Display/CSV update interval in seconds
            hop_ms: Channel hop interval in milliseconds
            write_interval_secs: CSV write interval in seconds (0 = same as update)
            poll_ms: Python CSV poll interval in milliseconds
            on_network: Callback for new/updated network
            on_client: Callback for new/updated client
            on_init: Callback for init status messages (e.g. countdown)
        """
        cmd = [
            "airodump-ng",
            mon_iface,
            "--write", capture_prefix,
            "--output-format", "csv",
            "-a",
            "--wps",
            "--update", str(update_secs),
            "-f", str(hop_ms),
        ]
        if write_interval_secs > 0:
            cmd.extend(["--write-interval", str(write_interval_secs)])
        if band:
            cmd.extend(["--band", band])
        if channels:
            cmd.extend(["--channel", ",".join(str(c) for c in channels)])

        logger.info("Starting scan on %s", mon_iface)
        self._running = True

        if "MOCK" in mon_iface:
            mock_nets = [
                Network(bssid="00:11:22:33:44:55", channel=1, signal=-45, privacy="WPA2", cipher="CCMP", auth="PSK", essid="HomeWiFi", wps=True),
                Network(bssid="66:77:88:99:AA:BB", channel=6, signal=-62, privacy="WPA2", cipher="CCMP", auth="PSK", essid="OfficeNet", wps=False),
                Network(bssid="CC:DD:EE:FF:00:11", channel=11, signal=-78, privacy="WEP", cipher="WEP", auth="NONE", essid="CoffeeShop", wps=False),
            ]
            mock_clients = [
                Client(mac="AA:BB:CC:DD:EE:FF", bssid="00:11:22:33:44:55", signal=-50, packets=250),
                Client(mac="11:22:33:44:55:66", bssid="66:77:88:99:AA:BB", signal=-65, packets=45),
            ]
            while self._running:
                await asyncio.sleep(1.0)
                if on_network:
                    for n in mock_nets:
                        self.networks[n.bssid] = n
                        on_network(n)
                if on_client:
                    for c in mock_clients:
                        self.clients[c.mac] = c
                        on_client(c)
            return

        self._proc = await self.mgr.start_background(cmd)

        # Wait for CSV to appear, then find the latest one
        import glob as globmod
        csv_file = None
        for i in range(50):  # 50 x 100ms = 5s max
            await asyncio.sleep(0.1)
            files = globmod.glob(f"{capture_prefix}-*.csv")
            # Pick the file with the most data
            best = None
            for f in files:
                sz = os.path.getsize(f)
                if best is None or sz > os.path.getsize(best):
                    best = f
            if best and os.path.getsize(best) > 100:
                csv_file = best
                if on_init:
                    on_init("ready")
                break
            if on_init and i % 10 == 0:
                remaining = 5 - (i // 10)
                on_init(f"init:{remaining}")
        if csv_file is None:
            csv_file = f"{capture_prefix}-01.csv"
            if on_init:
                on_init("ready")

        logger.info("Reading CSV: %s", csv_file)
        poll_interval = poll_ms / 1000.0
        cycle = 0
        while self._running:
            await asyncio.sleep(poll_interval)
            if os.path.exists(csv_file):
                try:
                    self._parse_csv(csv_file, on_network, on_client)
                except Exception as e:
                    logger.debug("CSV parse error: %s", e)

            # Run stale eviction every ~10 cycles (not every poll)
            cycle += 1
            if cycle % 10 == 0:
                self._evict_all()

    def _parse_csv(
        self,
        csv_file: str,
        on_network: Optional[Callable[[Network], None]],
        on_client: Optional[Callable[[Client], None]],
    ) -> None:
        """Parse airodump-ng CSV. Reuses parser, deduplicates callbacks."""
        self._parser.reset()
        now = time.time()

        with open(csv_file, errors="replace") as f:
            for line in f:
                result = self._parser.feed(line)
                if isinstance(result, Network):
                    # Update or insert
                    existing = self.networks.get(result.bssid)
                    self.networks[result.bssid] = result
                    # Fire callback only on first seen or changed data
                    if _network_changed(existing, result):
                        self._nets_reported[result.bssid] = result
                        if on_network:
                            on_network(result)
                elif isinstance(result, Client):
                    existing = self.clients.get(result.mac)
                    self.clients[result.mac] = result
                    if _client_changed(existing, result):
                        self._clis_reported[result.mac] = result
                        if on_client:
                            on_client(result)

    def _evict_all(self) -> None:
        """Run all memory management: stale eviction + cap enforcement."""
        now = time.time()

        # Stale eviction
        self._nets_evicted_stale += _evict_stale(self.networks, now, STALE_TIMEOUT_SECS)
        self._clis_evicted_stale += _evict_stale(self.clients, now, STALE_TIMEOUT_SECS)

        # Clean dedup tracking for evicted entries
        for bssid in list(self._nets_reported):
            if bssid not in self.networks:
                del self._nets_reported[bssid]
        for mac in list(self._clis_reported):
            if mac not in self.clients:
                del self._clis_reported[mac]

        # Cap enforcement
        self._nets_evicted_cap += _evict_weakest_nets(self.networks, MAX_NETWORKS)
        self._clis_evicted_cap += _evict_oldest_clients(self.clients, MAX_CLIENTS)

    def stop(self) -> None:
        """Stop scanning."""
        self._running = False

    async def stop_and_wait(self) -> None:
        """Stop scanning and clean up the background process."""
        self._running = False
        if self._proc:
            await self.mgr.kill_background(self._proc)
            self._proc = None

    def get_networks(self) -> list[Network]:
        """Get all discovered networks, sorted by signal strength."""
        return sorted(
            self.networks.values(),
            key=lambda n: n.signal,
            reverse=True,
        )

    def get_clients(self, bssid: Optional[str] = None) -> list[Client]:
        """Get clients, optionally filtered by AP BSSID."""
        clients = list(self.clients.values())
        if bssid:
            clients = [c for c in clients if c.bssid == bssid.upper()]
        return clients

    def get_stats(self) -> dict:
        """Return memory management statistics."""
        return {
            "networks": len(self.networks),
            "clients": len(self.clients),
            "nets_evicted_stale": self._nets_evicted_stale,
            "nets_evicted_cap": self._nets_evicted_cap,
            "clis_evicted_stale": self._clis_evicted_stale,
            "clis_evicted_cap": self._clis_evicted_cap,
        }
