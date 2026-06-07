import asyncio
import os
import sys
import select
import time
import tty
import termios
import threading
from rich.live import Live
from rich.table import Table
from rich.console import Group
from rich.text import Text
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_confirm, prompt_choice
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.core.scanner import ScanEngine
from sidewinder.core.adapter import list_interfaces, get_interface_mode, detect_adapter
from swcli.repl.renderer import print_table, console

# Timing presets: (update_secs, hop_ms, write_interval_secs, poll_ms)
TIMING_PRESETS = {
    "Fast":     (0.1,  150, 0, 50),
    "Default":  (0.1,  250, 0, 100),
    "Thorough": (0.2,  400, 0, 200),
}

BG_CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
A_CHANNELS = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
ABG_CHANNELS = BG_CHANNELS + A_CHANNELS


class _KeyReader:
    """Background thread that reads keypresses from stdin in raw mode."""

    def __init__(self):
        self._last_key = ""
        self._lock = threading.Lock()
        self._running = False
        self._old_settings = None

    def start(self):
        self._old_settings = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while self._running:
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if r:
                ch = sys.stdin.read(1)
                with self._lock:
                    self._last_key = ch

    def get_key(self):
        with self._lock:
            k = self._last_key
            self._last_key = ""
            return k

    def stop(self):
        self._running = False
        if self._old_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._old_settings)


def _resolve_essid(engine, bssid):
    if bssid in engine.networks:
        return engine.networks[bssid].display_name()
    return "[UNKNOWN]"


def _get_channel_choices(band):
    if band == "a":
        return A_CHANNELS, "5GHz"
    elif band == "bg":
        return BG_CHANNELS, "2.4GHz"
    return ABG_CHANNELS, "All"


def _build_scan_display(engine, elapsed, band, show_probes_only=False):
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
    filter_tag = " [PROBES]" if show_probes_only else " [P]robe"
    header = Text(
        f" CH {ch_str} ][ Elapsed: {int(elapsed)} s ][ {now_str} "
        f"][ {nets_count} networks, {clis_count} clients ]{filter_tag}",
        style="bold cyan",
    )

    ap_table = Table(
        show_header=True, header_style="bold",
        box=None, padding=(0, 2),
        show_edge=False,
    )
    ap_table.add_column("ESSID")
    ap_table.add_column("BSSID", style="bold")
    ap_table.add_column("PWR", justify="right")
    ap_table.add_column("Beacons", justify="right")
    ap_table.add_column("#Data", justify="right")
    ap_table.add_column("#/s", justify="right")
    ap_table.add_column("CH", justify="right")
    ap_table.add_column("MB", justify="right")
    ap_table.add_column("HE", style="green")
    ap_table.add_column("ENC")
    ap_table.add_column("CIPHER")
    ap_table.add_column("AUTH")
    ap_table.add_column("EAPOL", style="red")

    for n in sorted(engine.networks.values(), key=lambda x: x.signal, reverse=True):
        ap_table.add_row(
            n.display_name(),
            n.bssid,
            str(n.signal) if n.signal != -1 else "UKNWN",
            str(n.beacons),
            str(n.data_packets),
            str(n.data_per_sec),
            str(n.channel),
            str(n.speed),
            "Yes" if n.he else "-",
            n.privacy,
            n.cipher,
            n.auth,
            "Yes" if n.eapol else "-",
        )

    cli_table = Table(
        show_header=True, header_style="bold",
        box=None, padding=(0, 2),
        show_edge=False,
    )
    cli_table.add_column("ESSID")
    cli_table.add_column("BSSID", style="bold")
    cli_table.add_column("STATION", style="bold")
    cli_table.add_column("PWR", justify="right")
    cli_table.add_column("Packets", justify="right")
    cli_table.add_column("EAPOL", style="red")
    cli_table.add_column("Probes")

    clients = engine.clients.values()
    if show_probes_only:
        clients = [c for c in clients if c.probe]

    for c in sorted(clients, key=lambda x: x.packets, reverse=True):
        essid = _resolve_essid(engine, c.bssid)
        cli_table.add_row(
            essid,
            c.bssid,
            c.mac,
            str(c.signal) if c.signal != -1 else "UKNWN",
            str(c.packets),
            "Yes" if c.eapol else "-",
            c.probe or "",
        )

    return Group(header, ap_table, Text(""), cli_table)


async def cmd_scan(repl):
    monitor_ifaces = []
    for iface_name in list_interfaces():
        mode = get_interface_mode(iface_name)
        if mode == "monitor":
            chip = detect_adapter(iface_name)
            chip_str = f" ({chip})" if chip else ""
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
    if "2.4GHz" in band_val:
        band = "bg"
        preset_res = prompt_choice("Channel preset:", ["All 2.4GHz", "1, 6, 11 (non-overlapping)", "Custom"])
        if preset_res.cancelled: return
        if "1, 6, 11" in preset_res.value:
            channels = [1, 6, 11]
        elif "Custom" in preset_res.value:
            ch_str = prompt_text("Enter channels (comma-separated)", default="1,6,11")
            if ch_str.cancelled: return
            channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]
    elif "5GHz" in band_val:
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
    else:
        band = ""
        preset_res = prompt_choice("Channel preset:", ["All channels", "1, 6, 11", "Custom"])
        if preset_res.cancelled: return
        if "1, 6, 11" in preset_res.value:
            channels = [1, 6, 11]
        elif "Custom" in preset_res.value:
            ch_str = prompt_text("Enter channels (comma-separated)", default="1,6,11,36,40,44,48")
            if ch_str.cancelled: return
            channels = [int(c.strip()) for c in ch_str.value.split(",") if c.strip().isdigit()]

    timing_res = prompt_choice("Timing preset:", list(TIMING_PRESETS.keys()) + ["Custom"])
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
        poll_ms = 100
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

    scan_task = asyncio.create_task(engine.scan(
        mon_iface=iface,
        band=band,
        channels=channels,
        update_secs=update_secs,
        hop_ms=hop_ms,
        write_interval_secs=write_interval_secs,
        poll_ms=poll_ms,
        on_init=on_init,
    ))

    await asyncio.sleep(3.5)
    console.clear()

    key_reader = _KeyReader()
    key_reader.start()

    show_probes_only = False
    try:
        with Live(console=console, refresh_per_second=10, screen=False) as live:
            while engine._running:
                elapsed = time.time() - start_time
                display = _build_scan_display(engine, elapsed, band, show_probes_only)
                live.update(display)
                key = key_reader.get_key()
                if key and key.lower() == 'p':
                    show_probes_only = not show_probes_only
                await asyncio.sleep(0)
    except KeyboardInterrupt:
        pass
    finally:
        key_reader.stop()
        engine.stop()
        try:
            await scan_task
        except (asyncio.CancelledError, Exception):
            pass
        await engine.stop_and_wait()

        elapsed = time.time() - start_time
        nets = engine.get_networks()
        clients = engine.get_clients()
        cap_file = "/tmp/swcli_scan-01.cap"
        repl.session.scan_results = nets
        repl.session.clients = clients
        repl.session.last_iface = iface
        repl.session.last_cap_file = cap_file
        if cap_file not in repl.session.captures:
            repl.session.captures.append(cap_file)
        repl.print(f"\n  [green]Scan complete.[/green] Found {len(nets)} networks, {len(clients)} clients in {elapsed:.0f}s.")
        repl.print(f"  [dim]Capture saved: {cap_file}[/dim]")
        repl.print("  Run /scan results to view them in a table.")


async def cmd_scan_results(repl):
    nets = repl.session.scan_results
    if not nets:
        repl.print("  [yellow]No scan results in session. Run /scan first.[/yellow]")
        return

    headers = ["#", "ESSID", "BSSID", "CH", "PWR", "ENC", "CIPHER", "AUTH", "WPS", "EAPOL"]
    rows = []
    for i, n in enumerate(nets, 1):
        rows.append([
            str(i),
            n.display_name(),
            n.bssid,
            str(n.channel),
            str(n.signal) if n.signal != -1 else "UKNWN",
            n.privacy,
            n.cipher,
            n.auth,
            "Yes" if n.wps else "No",
            "Yes" if n.eapol else "-",
        ])
    print_table(headers, rows, "Scan Results")

    clients = repl.session.clients
    if clients:
        cli_headers = ["ESSID", "STATION", "BSSID", "PWR", "Packets", "EAPOL", "Probes"]
        cli_rows = []
        for c in clients:
            essid = "[UNKNOWN]"
            for n in nets:
                if n.bssid == c.bssid:
                    essid = n.display_name()
                    break
            cli_rows.append([
                essid,
                c.mac,
                c.bssid,
                str(c.signal) if c.signal != -1 else "UKNWN",
                str(c.packets),
                "Yes" if c.eapol else "-",
                c.probe or "",
            ])
        print_table(cli_headers, cli_rows, "Clients")


async def cmd_scan_handshakes(repl):
    clients = repl.session.clients
    cap_file = repl.session.last_cap_file
    if not clients:
        repl.print("  [yellow]No scan results. Run /scan first.[/yellow]")
        return

    eapol_clients = [c for c in clients if c.eapol]
    repl.print(f"\n  [bold]Handshake Status[/bold]")
    repl.print(f"  Capture file: [cyan]{cap_file}[/cyan]" if cap_file else "  [dim]No capture file[/dim]")
    repl.print(f"  EAPOL frames detected: [red]{len(eapol_clients)}[/red] clients\n")

    if not eapol_clients:
        repl.print("  [dim]No EAPOL handshakes observed in this scan.[/dim]")
        repl.print("  [dim]Tip: run /scan for longer on busy networks to capture handshakes.[/dim]")
        return

    nets = repl.session.scan_results
    essid_map = {n.bssid: n.display_name() for n in nets}

    headers = ["ESSID", "Station", "BSSID", "PWR", "Packets"]
    rows = []
    for c in eapol_clients:
        rows.append([
            essid_map.get(c.bssid, c.bssid),
            c.mac,
            c.bssid,
            str(c.signal) if c.signal != -1 else "UKNWN",
            str(c.packets),
        ])
    print_table(headers, rows, "EAPOL Handshakes")

    if cap_file and os.path.exists(cap_file):
        size = os.path.getsize(cap_file)
        repl.print(f"\n  [dim]Cap file size: {size:,} bytes -- usable for handshake cracking.[/dim]")
    else:
        repl.print(f"\n  [yellow]Capture file not found at {cap_file}[/yellow]")


def register_commands(palette: CommandPalette):
    palette.register(Command("/scan", "Start WiFi scan", "Scan", cmd_scan, requires_iface=True))
    palette.register(Command("/scan results", "Show last scan", "Scan", cmd_scan_results, requires_root=False))
    palette.register(Command("/scan handshakes", "Show EAPOL handshake status", "Scan", cmd_scan_handshakes, requires_root=False))
