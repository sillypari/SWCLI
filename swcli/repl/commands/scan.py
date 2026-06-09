import asyncio
import os
import time
from rich.live import Live
from rich.table import Table
from rich.console import Group
from rich.text import Text
from rich.panel import Panel
from rich import box
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_confirm, prompt_choice
from sidewinder.core.scanner import ScanEngine
from sidewinder.core.capture import delete_capture_segments, validate_handshake
from sidewinder.core.paths import scan_prefix
from sidewinder.core.config import SidewinderConfig
from sidewinder.core.adapter import list_interfaces, get_interface_mode, detect_adapter
from swcli.repl.renderer import console

# Timing presets: (update_secs, hop_ms, write_interval_secs, poll_ms)
TIMING_PRESETS = {
    "Fast":     (0.1,  150, 0, 50),
    "Default":  (0.1,  250, 0, 100),
    "Thorough": (0.2,  400, 0, 200),
}

BG_CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
A_CHANNELS = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
ABG_CHANNELS = BG_CHANNELS + A_CHANNELS





def _resolve_essid(engine, bssid):
    if bssid in engine.networks:
        return engine.networks[bssid].display_name()
    return "[UNKNOWN]"


def _signal_style(signal):
    if signal == -1:
        return "dim"
    if signal >= -50:
        return "bold bright_green"
    if signal >= -65:
        return "green"
    if signal >= -78:
        return "yellow"
    return "red"


def _fmt_signal(signal, color_mode="airodump"):
    if not _scan_colors_enabled(color_mode):
        return str(signal) if signal != -1 else "UNK"
    if signal == -1:
        return Text("UNK", style="dim")
    return Text(f"{signal:>4}", style=_signal_style(signal))


def _scan_color_mode():
    try:
        mode = SidewinderConfig.load().scan_color_mode.strip().lower()
    except Exception:
        mode = "airodump"
    if mode in ("none", "false", "disabled", "no"):
        return "off"
    if mode not in ("airodump", "standard", "off"):
        return "airodump"
    return mode


def _scan_colors_enabled(color_mode):
    return color_mode != "off"


def _fmt_essid(essid, color_mode="airodump", is_multiband=False):
    value = essid or "[HIDDEN]"
    if not _scan_colors_enabled(color_mode):
        return value + (" [MB]" if is_multiband else "")
    
    text = Text()
    if value == "[HIDDEN]":
        text.append(value, style="bold yellow")
    else:
        text.append(value, style="bold white" if color_mode == "airodump" else "white")
        
    if is_multiband:
        text.append(" [MB]", style="bold bright_magenta")
    return text


def _fmt_mac(value, style, color_mode="airodump"):
    return Text(value, style=style if _scan_colors_enabled(color_mode) else "")


def _fmt_channel(channel, color_mode="airodump"):
    if not _scan_colors_enabled(color_mode):
        return str(channel)
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return Text(str(channel), style="dim")
    style = "bright_cyan" if ch <= 14 else "bright_blue"
    return Text(str(ch), style=style)


def _fmt_yes(value, color_mode="airodump", yes_style="cyan"):
    if not value:
        return Text("--", style="dim" if _scan_colors_enabled(color_mode) else "")
    return Text("YES", style=yes_style if _scan_colors_enabled(color_mode) else "")


def _fmt_count(value, active_style="green", color_mode="airodump"):
    text = str(value)
    try:
        active = int(value) > 0
    except (TypeError, ValueError):
        active = False
    if active and _scan_colors_enabled(color_mode):
        return Text(text, style=active_style)
    return text


def _sec_style(value):
    v = (value or "").upper()
    if "WPA3" in v:
        return "bold bright_green"
    if "WPA2" in v:
        return "green"
    if "WPA" in v:
        return "yellow"
    if "OPN" in v or "OPEN" in v:
        return "bold red"
    return "white"


def _fmt_privacy(privacy, color_mode="airodump"):
    privacy = privacy or "-"
    return Text(privacy, style=_sec_style(privacy) if _scan_colors_enabled(color_mode) else "")


def _fmt_int(value, unknown="-"):
    return str(value) if value not in (None, -1) else unknown


def _fmt_manuf(value):
    return value.strip() if value and value.strip() else "-"


def _fmt_rxq(value):
    return str(value) if value not in (None, -1) else "-"


def _fmt_rate_part(value):
    if value in (None, -1):
        return "-"
    if value > 100000:
        value = value // 1000000
    return str(value)


def _fmt_client_rate(client):
    return f"{_fmt_rate_part(client.rate_to)}/{_fmt_rate_part(client.rate_from)}"


def _client_frames(client):
    return client.frames or client.packets


def _keep_scan_capture_enabled():
    if os.environ.get("SWCLI_KEEP_SCAN_CAP", "").lower() in ("1", "true", "yes"):
        return True
    return SidewinderConfig.load().keep_scan_captures


def _advanced_scan_info_enabled(config=None):
    if os.environ.get("SWCLI_ADVANCED_SCAN_INFO", "").lower() in ("1", "true", "yes"):
        return True
    return (config or SidewinderConfig.load()).advanced_scan_info


def _fmt_flags(*, wps=False, he=False, eapol=False, color_mode="airodump"):
    flags = Text()
    items = []
    enabled = _scan_colors_enabled(color_mode)
    if eapol:
        items.append(("EAPOL", "bold red" if enabled else ""))
    if wps:
        items.append(("WPS", "yellow" if enabled else ""))
    if he:
        items.append(("HE", "cyan" if enabled else ""))
    if not items:
        flags.append("--", style="dim" if enabled else "")
        return flags
    for idx, (label, style) in enumerate(items):
        if idx:
            flags.append(" ")
        flags.append(label, style=style)
    return flags


def _network_client_counts(clients):
    counts = {}
    eapol = set()
    for client in clients:
        bssid = client.bssid.upper()
        counts[bssid] = counts.get(bssid, 0) + 1
        if client.eapol:
            eapol.add(bssid)
    return counts, eapol


def _fmt_client_ap(client, color_mode="airodump"):
    if client.bssid.upper() == "FF:FF:FF:FF:FF:FF":
        return Text("(not associated)", style="dim" if _scan_colors_enabled(color_mode) else "")
    return _fmt_mac(client.bssid, "cyan", color_mode)


def _fmt_client_essid(client, engine, color_mode="airodump"):
    if client.bssid.upper() == "FF:FF:FF:FF:FF:FF":
        return Text("-", style="dim" if _scan_colors_enabled(color_mode) else "")
    style = "dim" if _scan_colors_enabled(color_mode) else ""
    return Text(_resolve_essid(engine, client.bssid), style=style)


def _build_scan_display(engine, elapsed, band, color_mode="airodump", max_networks=18, max_clients=12):
    color_enabled = _scan_colors_enabled(color_mode)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    show_rxq = bool(getattr(engine, "show_rxq", False))
    show_advanced = bool(getattr(engine, "advanced_info", False))

    if engine.current_channel > 0:
        ch_str = str(engine.current_channel)
    else:
        nets = engine.networks
        if nets:
            channels = sorted(set(n.channel for n in nets.values()))
            ch_str = ",".join(str(c) for c in channels)
        else:
            ch_str = band or "?"

    nets_count = len(engine.networks)
    clis_count = len(engine.clients)
    sorted_nets = sorted(
        engine.networks.values(),
        key=lambda x: x.signal if x.signal != -1 else -999,
        reverse=True,
    )
    sorted_clients = sorted(engine.clients.values(), key=lambda x: x.packets, reverse=True)
    client_counts, eapol_bssids = _network_client_counts(sorted_clients)
    handshake_count = sum(1 for n in sorted_nets if n.eapol or n.bssid.upper() in eapol_bssids)
    active_count = sum(1 for n in sorted_nets if n.data_packets > 0 or client_counts.get(n.bssid.upper(), 0) > 0)

    summary = Table.grid(expand=True)
    summary.add_column()
    left = Text()
    left.append("SWCLI Live Scan", style="bold white")
    left.append(f"  {now_str}", style="dim")
    left.append("  CH ", style="dim")
    left.append(ch_str, style="bold cyan")
    left.append("  BAND ", style="dim")
    left.append(band or "custom", style="bold white")
    left.append("  TIME ", style="dim")
    left.append(f"{int(elapsed):>4}s", style="bold white")
    left.append("\n")
    left.append(f"iface activity: {nets_count} APs / {clis_count} clients", style="cyan")
    left.append(f"  active: {active_count}", style="green" if active_count else "dim")
    left.append(f"  handshakes: {handshake_count}", style="bold red" if handshake_count else "dim")
    summary.add_row(left)
    header = Panel(summary, border_style="bright_blue", box=box.ROUNDED, padding=(0, 1))

    ap_table = Table(
        show_header=True,
        header_style="bold bright_cyan" if color_enabled else "none",
        border_style="bright_black",
        box=box.SIMPLE_HEAVY,
        padding=(0, 0),
        pad_edge=False,
        collapse_padding=True,
        show_edge=False,
        expand=False,
    )
    ap_table.add_column("#", justify="right", style="dim", width=3)
    ap_table.add_column("ESSID", ratio=3, min_width=12, overflow="fold")
    ap_table.add_column("BSSID", style="cyan" if color_enabled else "none", width=17, no_wrap=True)
    ap_table.add_column("MANUF", ratio=1, min_width=10, overflow="fold")
    if show_rxq:
        ap_table.add_column("RXQ", justify="right", width=4)
    ap_table.add_column("PWR", justify="right", width=5)
    ap_table.add_column("Beacons", justify="right", width=7)
    ap_table.add_column("#Data", justify="right", width=6)
    ap_table.add_column("#/s", justify="right", width=4)
    ap_table.add_column("CH", justify="right", width=4)
    ap_table.add_column("MB", justify="right", width=4)
    ap_table.add_column("HE", justify="center", width=4)
    ap_table.add_column("ENC", justify="center", width=6)
    ap_table.add_column("CIPHER", justify="center", width=7)
    ap_table.add_column("AUTH", justify="center", width=6)
    ap_table.add_column("CL", justify="right", width=3)
    ap_table.add_column("FLAGS", justify="center", width=6)

    hidden_nets = max(0, len(sorted_nets) - max_networks)
    for idx, n in enumerate(sorted_nets[:max_networks], 1):
        clients_for_ap = client_counts.get(n.bssid.upper(), 0)
        is_mb = len(engine.get_related_networks(n.bssid)) > 0 if hasattr(engine, "get_related_networks") else False
        ap_table.add_row(
            str(idx),
            _fmt_essid(n.display_name(), color_mode, is_mb),
            _fmt_mac(n.bssid, "cyan", color_mode),
            _fmt_manuf(n.manuf),
            *([_fmt_rxq(n.rxq)] if show_rxq else []),
            _fmt_signal(n.signal, color_mode),
            _fmt_count(n.beacons, "white", color_mode),
            _fmt_count(n.data_packets, "green", color_mode),
            _fmt_count(n.data_per_sec, "green", color_mode),
            _fmt_channel(n.channel, color_mode),
            _fmt_int(n.speed),
            _fmt_yes(n.he, color_mode, "cyan"),
            _fmt_privacy(n.privacy, color_mode),
            n.cipher or "-",
            n.auth or "-",
            _fmt_count(clients_for_ap, "green", color_mode),
            _fmt_flags(wps=n.wps, eapol=(n.eapol or n.bssid.upper() in eapol_bssids), color_mode=color_mode),
        )

    cli_table = Table(
        show_header=True,
        header_style="bold bright_magenta" if color_enabled else "none",
        border_style="bright_black",
        box=box.SIMPLE_HEAVY,
        padding=(0, 0),
        pad_edge=False,
        collapse_padding=True,
        show_edge=False,
        expand=False,
    )
    cli_table.add_column("#", justify="right", style="dim", width=3)
    cli_table.add_column("ESSID", ratio=2, min_width=12, overflow="fold")
    cli_table.add_column("STATION", style="magenta" if color_enabled else "none", width=17, no_wrap=True)
    cli_table.add_column("MANUF", ratio=1, min_width=10, overflow="fold")
    cli_table.add_column("BSSID", style="cyan" if color_enabled else "none", width=17, no_wrap=True)
    cli_table.add_column("PWR", justify="right", width=5)
    if show_advanced:
        cli_table.add_column("RATE", justify="right", width=7)
        cli_table.add_column("LOST", justify="right", width=5)
        cli_table.add_column("FRAMES", justify="right", width=7)
    cli_table.add_column("PROBE", ratio=2, min_width=12, overflow="fold")
    cli_table.add_column("HE", justify="center", width=4)
    cli_table.add_column("FLAGS", justify="center", width=6)

    hidden_clients = max(0, len(sorted_clients) - max_clients)
    for idx, c in enumerate(sorted_clients[:max_clients], 1):
        cli_table.add_row(
            str(idx),
            _fmt_client_essid(c, engine, color_mode),
            _fmt_mac(c.mac, "magenta", color_mode),
            _fmt_manuf(c.manuf),
            _fmt_client_ap(c, color_mode),
            _fmt_signal(c.signal, color_mode),
            *([_fmt_client_rate(c), str(c.lost), str(_client_frames(c))] if show_advanced else []),
            c.probe or "-",
            _fmt_yes(c.he, color_mode, "cyan"),
            _fmt_flags(eapol=c.eapol, color_mode=color_mode),
        )

    footer = Text(style="dim" if color_enabled else "none")
    recent = engine.get_recent_counts() if hasattr(engine, "get_recent_counts") else {"networks": 0, "clients": 0}
    if recent["networks"] or recent["clients"]:
        footer.append(
            f"\n Recently seen but not in the current frame: "
            f"{recent['networks']} APs / {recent['clients']} clients."
        )
    if hidden_nets or hidden_clients:
        footer.append(f"\n Showing top {min(len(sorted_nets), max_networks)} APs")
        if hidden_nets:
            footer.append(f" ({hidden_nets} more hidden)")
        footer.append(f" and top {min(len(sorted_clients), max_clients)} clients")
        if hidden_clients:
            footer.append(f" ({hidden_clients} more hidden)")
        footer.append(". Run /scan results for the full table.")
    footer.append("\n Press Ctrl+C to stop and keep results. Use /target after scan to choose an AP.\n")

    return Group(header, Text(""), ap_table, Text(""), cli_table, footer)



async def cmd_scan(repl):
    monitor_ifaces = []
    for iface_name in list_interfaces():
        mode = get_interface_mode(iface_name)
        if mode == "monitor":
            chip = await detect_adapter(iface_name)
            chip_str = f" ({chip.chipset})" if (chip and chip.chipset) else ""
            monitor_ifaces.append((iface_name, chip_str))

    if not monitor_ifaces:
        repl.print("[red]No monitor interfaces found.[/red]")
        repl.print("[dim]Run /monitor first to enter monitor mode.[/dim]")
        return

    if len(monitor_ifaces) == 1:
        iface = monitor_ifaces[0][0]
        repl.print(f"  Using [cyan]{iface}[/cyan]{monitor_ifaces[0][1]}")
    else:
        choices = [f"{name}{chip}" for name, chip in monitor_ifaces]
        res = prompt_choice("Select monitor interface:", choices)
        if res.cancelled:
            repl.print("[yellow]Scan cancelled while selecting monitor interface.[/yellow]")
            return
        iface = res.value.split(" ")[0]

    band_res = prompt_choice("Select band:", ["All (2.4+5GHz)", "2.4GHz (bg)", "5GHz (a)", "Custom channels"])
    if band_res.cancelled:
        repl.print("[yellow]Scan cancelled while selecting band.[/yellow]")
        return

    band_val = band_res.value
    channels = None
    if band_val == "2.4GHz (bg)":
        band = "bg"
        preset_res = prompt_choice("Channel preset:", ["All 2.4GHz", "1, 6, 11 (non-overlapping)", "Custom"])
        if preset_res.cancelled:
            repl.print("[yellow]Scan cancelled while selecting channels.[/yellow]")
            return
        if "1, 6, 11" in preset_res.value:
            channels = [1, 6, 11]
        elif "Custom" in preset_res.value:
            ch_str = prompt_text("Enter channels (comma-separated)", default="1,6,11")
            if ch_str.cancelled:
                repl.print("[yellow]Scan cancelled while entering channels.[/yellow]")
                return
            channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]
    elif band_val == "5GHz (a)":
        band = "a"
        preset_res = prompt_choice("Channel preset:", ["All 5GHz", "UNII-1 (36-48)", "UNII-2 (52-64)", "UNII-3 (100-144)", "UNII-4 (149-165)", "Custom"])
        if preset_res.cancelled:
            repl.print("[yellow]Scan cancelled while selecting channels.[/yellow]")
            return
        p = preset_res.value
        if "UNII-1" in p: channels = list(range(36, 49))
        elif "UNII-2" in p: channels = list(range(52, 65))
        elif "UNII-3" in p: channels = list(range(100, 145))
        elif "UNII-4" in p: channels = list(range(149, 166))
        elif "Custom" in p:
            ch_str = prompt_text("Enter channels (comma-separated)", default="36,40,44,48")
            if ch_str.cancelled:
                repl.print("[yellow]Scan cancelled while entering channels.[/yellow]")
                return
            channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]
    elif band_val == "All (2.4+5GHz)":
        band = "abg"
        channels = None
    else:  # "Custom channels"
        band = ""
        ch_str = prompt_text("Enter channels (comma-separated)", default="1,6,11,36,40,44,48")
        if ch_str.cancelled:
            repl.print("[yellow]Scan cancelled while entering channels.[/yellow]")
            return
        channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]

    timing_res = prompt_choice("Refresh rate:", list(TIMING_PRESETS.keys()) + ["Custom"])
    if timing_res.cancelled:
        repl.print("[yellow]Scan cancelled while selecting refresh rate.[/yellow]")
        return

    preset_name = timing_res.value
    if preset_name == "Custom":
        repl.print("  [dim]Configure timing (press Enter for defaults)[/dim]")
        update_res = prompt_text("  UI Refresh rate in seconds", default="0.1")
        if update_res.cancelled:
            repl.print("[yellow]Scan cancelled while entering refresh rate.[/yellow]")
            return
        update_secs = float(update_res.value) if update_res.value else 0.1
        hop_res = prompt_text("  Channel hop interval in ms", default="250")
        if hop_res.cancelled:
            repl.print("[yellow]Scan cancelled while entering hop interval.[/yellow]")
            return
        hop_ms = int(hop_res.value) if hop_res.value else 250
        write_interval_secs = 0
        poll_ms = max(10, int(update_secs * 1000))
    else:
        update_secs, hop_ms, write_interval_secs, poll_ms = TIMING_PRESETS[preset_name]

    conf = prompt_confirm("Start Scan?")
    if conf.cancelled or not conf.value:
        repl.print("[yellow]Cancelled.[/yellow]")
        return

    scan_config = SidewinderConfig.load()
    advanced_info = _advanced_scan_info_enabled(scan_config)
    write_capture = _keep_scan_capture_enabled()
    color_mode = _scan_color_mode()

    engine = ScanEngine()
    start_time = time.time()

    init_printed = False
    def on_init(status):
        nonlocal init_printed
        if status.startswith("init:"):
            remaining = status.split(":")[1]
            if not init_printed:
                repl.print(f"  [dim]Starting scan... ({remaining}s)[/dim]")
                init_printed = True

    capture_prefix = scan_prefix()
    scan_task = asyncio.create_task(engine.scan(
        mon_iface=iface,
        capture_prefix=capture_prefix,
        band=band,
        channels=channels,
        update_secs=update_secs,
        hop_ms=hop_ms,
        write_interval_secs=write_interval_secs,
        write_capture=write_capture,
        advanced_info=advanced_info,
        poll_ms=poll_ms,
        on_init=on_init,
    ))

    repl.print("  [dim]Initializing scan engine, warm-up in progress...[/dim]")
    for i in range(2, 0, -1):
        repl.print(f"  [dim]Launching live dump screen in {i}s...[/dim]")
        await asyncio.sleep(1.0)
    await asyncio.sleep(0.5)
    console.clear()

    try:
        refresh_fps = max(1, int(1000 / poll_ms))
        with Live(console=console, refresh_per_second=refresh_fps, screen=True, vertical_overflow="crop") as live:
            while engine._running:
                elapsed = time.time() - start_time
                display = _build_scan_display(engine, elapsed, band, color_mode=color_mode)
                live.update(display, refresh=True)
                await asyncio.sleep(poll_ms / 1000.0)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        try:
            await scan_task
        except (asyncio.CancelledError, Exception):
            pass
        await engine.stop_and_wait()

        elapsed = time.time() - start_time
        nets = engine.get_networks()
        clients = engine.get_clients()

        # Render final display onto normal scrollback buffer
        final_display = _build_scan_display(engine, elapsed, band, color_mode=color_mode)
        console.print(final_display)

        cap_file = f"{capture_prefix}-01.cap"
        cap_exists = os.path.exists(cap_file)
        handshake = validate_handshake(cap_file) if cap_exists else None
        has_eapol = bool(handshake and handshake.eapol_count)
        repl.session.scan_results = nets
        repl.session.clients = clients
        repl.session.last_iface = iface
        repl.session.last_scan_show_rxq = engine.show_rxq
        repl.session.last_scan_advanced_info = engine.advanced_info

        if cap_exists and (has_eapol or scan_config.save_captures_without_eapol):
            repl.session.last_cap_file = cap_file
            if cap_file not in repl.session.captures:
                repl.session.captures.append(cap_file)
        elif cap_exists:
            delete_capture_segments(cap_file)

        if has_eapol:
            repl.session.handshake = handshake
        repl.print(f"\n  [green]Scan complete.[/green] Found {len(nets)} networks, {len(clients)} clients in {elapsed:.0f}s.")
        if cap_exists and (has_eapol or scan_config.save_captures_without_eapol):
            repl.print(f"  [dim]Capture saved: {cap_file}[/dim]")
        elif not write_capture:
            repl.print("  [dim]Raw scan capture writing is off to save disk. Use /capture for handshakes.[/dim]")
        else:
            repl.print(
                "  [yellow]No EAPOL detected; scan .cap was not saved. "
                "Toggle save_captures_without_eapol in /config set to keep these files.[/yellow]"
            )
        if has_eapol:
            repl.print(f"  [green]EAPOL detected:[/green] {handshake.status.upper()} ({handshake.eapol_count} frames). Run /handshake.")
        repl.print("  Run /scan results to view them in a table.")



async def cmd_scan_results(repl):
    nets = repl.session.scan_results
    if not nets:
        repl.print("  [yellow]No scan results in session. Run /scan first.[/yellow]")
        return

    clients = repl.session.clients
    color_mode = _scan_color_mode()
    color_enabled = _scan_colors_enabled(color_mode)
    client_counts, eapol_bssids = _network_client_counts(clients)
    show_rxq = bool(getattr(repl.session, "last_scan_show_rxq", False))
    show_advanced = bool(getattr(repl.session, "last_scan_advanced_info", False))
    active_count = sum(1 for n in nets if n.data_packets > 0 or client_counts.get(n.bssid.upper(), 0) > 0)
    handshake_count = sum(1 for n in nets if n.eapol or n.bssid.upper() in eapol_bssids)

    summary = Table.grid(expand=True)
    summary.add_column(ratio=2)
    summary.add_column(justify="right")
    left = Text()
    left.append("Last scan results", style="bold white")
    left.append(f"\n{len(nets)} APs / {len(clients)} clients", style="cyan")
    left.append(f"  active: {active_count}", style="green" if active_count else "dim")
    left.append(f"  handshakes: {handshake_count}", style="bold red" if handshake_count else "dim")
    right = Text("Use /target to select an AP", style="dim")
    summary.add_row(left, right)
    console.print(Panel(summary, border_style="bright_blue", box=box.ROUNDED, padding=(0, 1)))

    ap_table = Table(
        title="Access Points",
        title_style="bold cyan",
        show_header=True,
        header_style="bold bright_cyan",
        border_style="bright_black",
        box=box.SIMPLE_HEAVY,
        padding=(0, 0),
        pad_edge=False,
        collapse_padding=True,
        expand=False,
    )
    ap_table.add_column("#", justify="right", style="dim", width=3)
    ap_table.add_column("ESSID", ratio=3, min_width=12, overflow="fold")
    ap_table.add_column("BSSID", style="cyan" if color_enabled else "none", width=17, no_wrap=True)
    ap_table.add_column("MANUF", ratio=1, min_width=10, overflow="fold")
    if show_rxq:
        ap_table.add_column("RXQ", justify="right", width=4)
    ap_table.add_column("PWR", justify="right", width=5)
    ap_table.add_column("Beacons", justify="right", width=7)
    ap_table.add_column("#Data", justify="right", width=6)
    ap_table.add_column("#/s", justify="right", width=4)
    ap_table.add_column("CH", justify="right", width=4)
    ap_table.add_column("MB", justify="right", width=4)
    ap_table.add_column("HE", justify="center", width=4)
    ap_table.add_column("ENC", justify="center", width=6)
    ap_table.add_column("CIPHER", justify="center", width=7)
    ap_table.add_column("AUTH", justify="center", width=6)
    ap_table.add_column("CL", justify="right", width=3)
    ap_table.add_column("FLAGS", justify="center", width=6)

    # Group by ESSID to check for multiband in results table
    essid_counts = {}
    for net in nets:
        if net.essid and net.display_name() not in ("[HIDDEN]", "[MANUAL]"):
            name = net.display_name().strip()
            essid_counts[name] = essid_counts.get(name, 0) + 1

    for i, n in enumerate(nets, 1):
        name = n.display_name().strip()
        is_mb = (n.essid and essid_counts.get(name, 0) > 1 and n.display_name() not in ("[HIDDEN]", "[MANUAL]"))
        ap_table.add_row(
            str(i),
            _fmt_essid(n.display_name(), color_mode, is_mb),
            _fmt_mac(n.bssid, "cyan", color_mode),
            _fmt_manuf(n.manuf),
            *([_fmt_rxq(n.rxq)] if show_rxq else []),
            _fmt_signal(n.signal, color_mode),
            _fmt_count(n.beacons, "white", color_mode),
            _fmt_count(n.data_packets, "green", color_mode),
            _fmt_count(n.data_per_sec, "green", color_mode),
            _fmt_channel(n.channel, color_mode),
            _fmt_int(n.speed),
            _fmt_yes(n.he, color_mode, "cyan"),
            _fmt_privacy(n.privacy, color_mode),
            n.cipher or "-",
            n.auth or "-",
            _fmt_count(client_counts.get(n.bssid.upper(), 0), "green", color_mode),
            _fmt_flags(wps=n.wps, eapol=(n.eapol or n.bssid.upper() in eapol_bssids), color_mode=color_mode),
        )
    console.print(ap_table)
    repl.print("  [dim]Use /target to set the active AP. Commands still ask for confirmation before capture or attack.[/dim]")

    if clients:
        cli_table = Table(
            title="Clients",
            title_style="bold magenta",
            show_header=True,
            header_style="bold bright_magenta",
            border_style="bright_black",
            box=box.SIMPLE_HEAVY,
            padding=(0, 0),
            pad_edge=False,
            collapse_padding=True,
            expand=False,
        )
        cli_table.add_column("#", justify="right", style="dim", width=3)
        cli_table.add_column("ESSID", ratio=2, min_width=12, overflow="fold")
        cli_table.add_column("STATION", style="magenta" if color_enabled else "none", width=17, no_wrap=True)
        cli_table.add_column("MANUF", ratio=1, min_width=10, overflow="fold")
        cli_table.add_column("BSSID", style="cyan" if color_enabled else "none", width=17, no_wrap=True)
        cli_table.add_column("PWR", justify="right", width=5)
        if show_advanced:
            cli_table.add_column("RATE", justify="right", width=7)
            cli_table.add_column("LOST", justify="right", width=5)
            cli_table.add_column("FRAMES", justify="right", width=7)
        cli_table.add_column("PROBE", ratio=2, min_width=12, overflow="fold")
        cli_table.add_column("HE", justify="center", width=4)
        cli_table.add_column("FLAGS", justify="center", width=6)

        engine_like = type("ScanResultView", (), {"networks": {n.bssid: n for n in nets}})()
        for i, c in enumerate(clients, 1):
            cli_table.add_row(
                str(i),
                _fmt_client_essid(c, engine_like, color_mode),
                _fmt_mac(c.mac, "magenta", color_mode),
                _fmt_manuf(c.manuf),
                _fmt_client_ap(c, color_mode),
                _fmt_signal(c.signal, color_mode),
                *([_fmt_client_rate(c), str(c.lost), str(_client_frames(c))] if show_advanced else []),
                c.probe or "-",
                _fmt_yes(c.he, color_mode, "cyan"),
                _fmt_flags(eapol=c.eapol, color_mode=color_mode),
            )
        console.print(cli_table)


def register_commands(palette: CommandPalette):
    palette.register(Command("/scan", "Start WiFi scan", "Scan", cmd_scan, requires_iface=True))
    palette.register(Command("/scan results", "Show last scan", "Scan", cmd_scan_results, requires_root=False))
    from swcli.repl.commands.capture import cmd_handshake
    palette.register(Command("/scan handshakes", "Show M1-M4 key-info bits", "Scan", cmd_handshake, requires_root=False))
