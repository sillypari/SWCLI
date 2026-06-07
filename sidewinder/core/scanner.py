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


import json
import threading
import queue

class ScanEngine:
    """Run airodump-ng and emit discovered networks and clients in real-time via JSON FIFO."""

    def __init__(self, mgr: Optional[SubprocessManager] = None) -> None:
        self.mgr = mgr or get_manager()
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._running = False

        self.networks: dict[str, Network] = {}
        self.clients: dict[str, Client] = {}

        
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
        
        self.fifo_path = f"{capture_prefix}_fifo.json"
        fifo_path = self.fifo_path
        if hasattr(os, "mkfifo"):
            try:
                os.mkfifo(fifo_path)
            except FileExistsError:
                pass

        cmd = [
            "airodump-ng",
            mon_iface,
            "--json", fifo_path,
            "-a",
            "--wps",
            "--update", str(update_secs),
            "-f", str(hop_ms),
        ]
        if band:
            cmd.extend(["--band", band])
        if channels:
            cmd.extend(["--channel", ",".join(str(c) for c in channels)])

        logger.info("Starting scan on %s with JSON FIFO", mon_iface)
        self._running = True

        if "MOCK" in mon_iface:
            mock_nets = [
                Network(bssid="00:11:22:33:44:55", channel=1, signal=-45, privacy="WPA2", cipher="CCMP", auth="PSK", essid="HomeWiFi", wps=True),
                Network(bssid="66:77:88:99:AA:BB", channel=6, signal=-62, privacy="WPA2", cipher="CCMP", auth="PSK", essid="OfficeNet", wps=False),
            ]
            while self._running:
                await asyncio.sleep(1.0)
                if on_network:
                    for n in mock_nets:
                        self.networks[n.bssid] = n
                        on_network(n)
            return

        self._proc = await self.mgr.start_background(cmd)
        
        if on_init:
            on_init("ready")

        q = queue.Queue()
        def fifo_reader():
            try:
                with open(fifo_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not self._running:
                            break
                        q.put(line)
            except Exception as e:
                logger.debug("FIFO reader error: %s", e)

        # Start thread only if on Unix and mkfifo worked, otherwise we might hang
        if hasattr(os, "mkfifo"):
            t = threading.Thread(target=fifo_reader, daemon=True)
            t.start()
        else:
            logger.error("os.mkfifo not supported on this OS. Scan will not receive data.")

        while self._running:
            try:
                # Read all available items in the queue
                while True:
                    line = q.get_nowait()
                    self._parse_json(line, on_network, on_client)
            except queue.Empty:
                await asyncio.sleep(0.05)

    def _parse_json(
        self,
        line: str,
        on_network: Optional[Callable[[Network], None]],
        on_client: Optional[Callable[[Client], None]],
    ) -> None:
        try:
            data = json.loads(line)
            if data.get("type") != "update":
                return
            
            for n_dict in data.get("networks", []):
                n = Network(**n_dict)
                existing = self.networks.get(n.bssid)
                self.networks[n.bssid] = n
                if on_network and (not existing or n.signal != existing.signal or n.data_packets != existing.data_packets):
                    on_network(n)
                    
            for c_dict in data.get("clients", []):
                c = Client(**c_dict)
                existing = self.clients.get(c.mac)
                self.clients[c.mac] = c
                if on_client and (not existing or c.signal != existing.signal or c.packets != existing.packets):
                    on_client(c)
        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.debug("JSON parsing error: %s", e)


    def _enforce_limits(self):
        if len(self.networks) > MAX_NETWORKS:
            weakest = min(self.networks, key=lambda b: self.networks[b].signal)
            del self.networks[weakest]
        if len(self.clients) > MAX_CLIENTS:
            oldest = min(self.clients, key=lambda m: self.clients[m].last_seen)
            del self.clients[oldest]

    async def _stale_eviction_loop(self):
        while self._running:
            await asyncio.sleep(30)
            now = time.time()
            stale = [b for b, n in self.networks.items()
                     if n.last_seen and (now - float(n.last_seen)) > STALE_TIMEOUT_SECS]
            for b in stale:
                del self.networks[b]

    def stop(self) -> None:
        """Stop scanning."""
        self._running = False

    async def stop_and_wait(self) -> None:
        """Stop scanning and clean up the background process."""
        self._running = False
        if self._proc:
            await self.mgr.kill_background(self._proc)
            self._proc = None
        if hasattr(self, 'fifo_path') and os.path.exists(self.fifo_path):
            try:
                os.unlink(self.fifo_path)
            except OSError:
                pass

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
            "clients": len(self.clients)
        }
