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
from sidewinder.core.capture import validate_handshake
from sidewinder.core.paths import scan_prefix
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


def _fmt_signal(signal):
    if signal == -1:
        return Text("UNK", style="dim")
    return Text(f"{signal:>4}", style=_signal_style(signal))


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


def _fmt_privacy(privacy):
    privacy = privacy or "-"
    return Text(privacy, style=_sec_style(privacy))


def _fmt_int(value, unknown="-"):
    return str(value) if value not in (None, -1) else unknown


def _fmt_flags(*, wps=False, he=False, eapol=False):
    flags = Text()
    items = []
    if eapol:
        items.append(("EAPOL", "bold red"))
    if wps:
        items.append(("WPS", "yellow"))
    if he:
        items.append(("HE", "cyan"))
    if not items:
        flags.append("--", style="dim")
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


def _fmt_client_ap(client):
    if client.bssid.upper() == "FF:FF:FF:FF:FF:FF":
        return Text("(not associated)", style="dim")
    return Text(client.bssid, style="cyan")


def _fmt_client_essid(client, engine):
    if client.bssid.upper() == "FF:FF:FF:FF:FF:FF":
        return Text("-", style="dim")
    return Text(_resolve_essid(engine, client.bssid), style="dim")


def _build_scan_display(engine, elapsed, band, color_enabled=True, max_networks=18, max_clients=12):
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

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
    ap_table.add_column("BSSID", style="cyan", width=17, no_wrap=True)
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
        ap_table.add_row(
            str(idx),
            n.display_name(),
            n.bssid,
            _fmt_signal(n.signal),
            str(n.beacons),
            str(n.data_packets),
            str(n.data_per_sec),
            str(n.channel),
            _fmt_int(n.speed),
            "YES" if n.he else "--",
            _fmt_privacy(n.privacy),
            n.cipher or "-",
            n.auth or "-",
            str(clients_for_ap),
            _fmt_flags(wps=n.wps, eapol=(n.eapol or n.bssid.upper() in eapol_bssids)),
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
    cli_table.add_column("BSSID", style="cyan" if color_enabled else "none", width=17, no_wrap=True)
    cli_table.add_column("PWR", justify="right", width=5)
    cli_table.add_column("PKTS", justify="right", width=5)
    cli_table.add_column("PROBE", ratio=2, min_width=12, overflow="fold")
    cli_table.add_column("HE", justify="center", width=4)
    cli_table.add_column("FLAGS", justify="center", width=6)

    hidden_clients = max(0, len(sorted_clients) - max_clients)
    for idx, c in enumerate(sorted_clients[:max_clients], 1):
        cli_table.add_row(
            str(idx),
            _fmt_client_essid(c, engine),
            c.mac,
            _fmt_client_ap(c),
            _fmt_signal(c.signal),
            str(c.packets),
            c.probe or "-",
            "YES" if c.he else "--",
            _fmt_flags(eapol=c.eapol),
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
            return
        iface = res.value.split(" ")[0]

    band_res = prompt_choice("Select band:", ["All (2.4+5GHz)", "2.4GHz (bg)", "5GHz (a)", "Custom channels"])
    if band_res.cancelled:
        return

    band_val = band_res.value
    channels = None
    if band_val == "2.4GHz (bg)":
        band = "bg"
        preset_res = prompt_choice("Channel preset:", ["All 2.4GHz", "1, 6, 11 (non-overlapping)", "Custom"])
        if preset_res.cancelled: return
        if "1, 6, 11" in preset_res.value:
            channels = [1, 6, 11]
        elif "Custom" in preset_res.value:
            ch_str = prompt_text("Enter channels (comma-separated)", default="1,6,11")
            if ch_str.cancelled: return
            channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]
    elif band_val == "5GHz (a)":
        band = "a"
        preset_res = prompt_choice("Channel preset:", ["All 5GHz", "UNII-1 (36-48)", "UNII-2 (52-64)", "UNII-3 (100-144)", "UNII-4 (149-165)", "Custom"])
        if preset_res.cancelled: return
        p = preset_res.value
        if "UNII-1" in p: channels = list(range(36, 49))
        elif "UNII-2" in p: channels = list(range(52, 65))
        elif "UNII-3" in p: channels = list(range(100, 145))
        elif "UNII-4" in p: channels = list(range(149, 166))
        elif "Custom" in p:
            ch_str = prompt_text("Enter channels (comma-separated)", default="36,40,44,48")
            if ch_str.cancelled: return
            channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]
    elif band_val == "All (2.4+5GHz)":
        band = "abg"
        channels = None
    else:  # "Custom channels"
        band = ""
        ch_str = prompt_text("Enter channels (comma-separated)", default="1,6,11,36,40,44,48")
        if ch_str.cancelled: return
        channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]

    timing_res = prompt_choice("Refresh rate:", list(TIMING_PRESETS.keys()) + ["Custom"])
    if timing_res.cancelled:
        return

    preset_name = timing_res.value
    if preset_name == "Custom":
        repl.print("  [dim]Configure timing (press Enter for defaults)[/dim]")
        update_res = prompt_text("  UI Refresh rate in seconds", default="0.1")
        if update_res.cancelled: return
        update_secs = float(update_res.value) if update_res.value else 0.1
        hop_res = prompt_text("  Channel hop interval in ms", default="250")
        if hop_res.cancelled: return
        hop_ms = int(hop_res.value) if hop_res.value else 250
        write_interval_secs = 0
        poll_ms = max(10, int(update_secs * 1000))
    else:
        update_secs, hop_ms, write_interval_secs, poll_ms = TIMING_PRESETS[preset_name]

    conf = prompt_confirm("Start Scan?")
    if conf.cancelled or not conf.value:
        repl.print("[yellow]Cancelled.[/yellow]")
        return

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
                display = _build_scan_display(engine, elapsed, band)
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
        final_display = _build_scan_display(engine, elapsed, band)
        console.print(final_display)

        cap_file = f"{capture_prefix}-01.cap"
        repl.session.scan_results = nets
        repl.session.clients = clients
        repl.session.last_iface = iface
        repl.session.last_cap_file = cap_file
        if cap_file not in repl.session.captures:
            repl.session.captures.append(cap_file)
        handshake = validate_handshake(cap_file) if os.path.exists(cap_file) else None
        if handshake and handshake.eapol_count:
            repl.session.handshake = handshake
        repl.print(f"\n  [green]Scan complete.[/green] Found {len(nets)} networks, {len(clients)} clients in {elapsed:.0f}s.")
        repl.print(f"  [dim]Capture saved: {cap_file}[/dim]")
        if handshake and handshake.eapol_count:
            repl.print(f"  [green]EAPOL detected:[/green] {handshake.status.upper()} ({handshake.eapol_count} frames). Run /handshake.")
        repl.print("  Run /scan results to view them in a table.")



async def cmd_scan_results(repl):
    nets = repl.session.scan_results
    if not nets:
        repl.print("  [yellow]No scan results in session. Run /scan first.[/yellow]")
        return

    clients = repl.session.clients
    client_counts, eapol_bssids = _network_client_counts(clients)
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
    ap_table.add_column("BSSID", style="cyan", width=17, no_wrap=True)
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

    for i, n in enumerate(nets, 1):
        ap_table.add_row(
            str(i),
            n.display_name(),
            n.bssid,
            _fmt_signal(n.signal),
            str(n.beacons),
            str(n.data_packets),
            str(n.data_per_sec),
            str(n.channel),
            _fmt_int(n.speed),
            "YES" if n.he else "--",
            _fmt_privacy(n.privacy),
            n.cipher or "-",
            n.auth or "-",
            str(client_counts.get(n.bssid.upper(), 0)),
            _fmt_flags(wps=n.wps, eapol=(n.eapol or n.bssid.upper() in eapol_bssids)),
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
        cli_table.add_column("STATION", style="magenta", width=17, no_wrap=True)
        cli_table.add_column("BSSID", style="cyan", width=17, no_wrap=True)
        cli_table.add_column("PWR", justify="right", width=5)
        cli_table.add_column("PKTS", justify="right", width=5)
        cli_table.add_column("PROBE", ratio=2, min_width=12, overflow="fold")
        cli_table.add_column("HE", justify="center", width=4)
        cli_table.add_column("FLAGS", justify="center", width=6)

        engine_like = type("ScanResultView", (), {"networks": {n.bssid: n for n in nets}})()
        for i, c in enumerate(clients, 1):
            cli_table.add_row(
                str(i),
                _fmt_client_essid(c, engine_like),
                c.mac,
                _fmt_client_ap(c),
                _fmt_signal(c.signal),
                str(c.packets),
                c.probe or "-",
                "YES" if c.he else "--",
                _fmt_flags(eapol=c.eapol),
            )
        console.print(cli_table)


def register_commands(palette: CommandPalette):
    palette.register(Command("/scan", "Start WiFi scan", "Scan", cmd_scan, requires_iface=True))
    palette.register(Command("/scan results", "Show last scan", "Scan", cmd_scan_results, requires_root=False))
    from swcli.repl.commands.capture import cmd_handshake
    palette.register(Command("/scan handshakes", "Show M1-M4 key-info bits", "Scan", cmd_handshake, requires_root=False))
