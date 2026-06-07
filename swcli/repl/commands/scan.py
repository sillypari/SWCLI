import asyncio
import time
from rich.live import Live
from rich.table import Table
from rich.console import Group
from rich.text import Text
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_text, prompt_confirm, prompt_choice
from swcli.repl.session_ui import auto_fill_prompt
from sidewinder.core.scanner import ScanEngine
from swcli.repl.renderer import print_table, console

# Timing presets: (update_secs, hop_ms, write_interval_secs, poll_ms)
TIMING_PRESETS = {
    "Fast":     (0.1,  250, 0, 100),
    "Balanced": (0.5,  500, 0, 250),
    "Slow":     (1.0, 1000, 0, 500),
}

def _build_scan_display(engine, elapsed, band):
    """Build the live display: header + AP table + client table."""
    # Header — show band or detected channels
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    nets = engine.networks
    if nets:
        channels = sorted(set(n.channel for n in nets.values()))
        ch_str = ",".join(str(c) for c in channels)
    else:
        ch_str = band or "?"
    header = Text(f" CH {ch_str} ][ Elapsed: {int(elapsed)} s ][ {now_str}", style="bold cyan")

    # AP table
    ap_table = Table(
        show_header=True, header_style="bold",
        box=None, padding=(0, 2),
        show_edge=False,
    )
    ap_table.add_column("BSSID", style="bold")
    ap_table.add_column("PWR", justify="right")
    ap_table.add_column("Beacons", justify="right")
    ap_table.add_column("#Data", justify="right")
    ap_table.add_column("#/s", justify="right")
    ap_table.add_column("CH", justify="right")
    ap_table.add_column("MB", justify="right")
    ap_table.add_column("ENC")
    ap_table.add_column("CIPHER")
    ap_table.add_column("AUTH")
    ap_table.add_column("ESSID")

    for n in sorted(engine.networks.values(), key=lambda x: x.signal, reverse=True):
        prev = engine._data_rate_prev.get(n.bssid)
        now = time.time()
        rate = 0
        if prev and now - prev[1] > 0:
            rate = int((n.data_packets - prev[0]) / (now - prev[1]))
        engine._data_rate_prev[n.bssid] = (n.data_packets, now)

        ap_table.add_row(
            n.bssid,
            str(n.signal),
            str(n.beacons),
            str(n.data_packets),
            str(rate),
            str(n.channel),
            str(n.speed),
            n.privacy,
            n.cipher,
            n.auth,
            n.display_name(),
        )

    # Client table
    cli_table = Table(
        show_header=True, header_style="bold",
        box=None, padding=(0, 2),
        show_edge=False,
    )
    cli_table.add_column("BSSID", style="bold")
    cli_table.add_column("STATION", style="bold")
    cli_table.add_column("PWR", justify="right")
    cli_table.add_column("Packets", justify="right")
    cli_table.add_column("Probes")

    for c in engine.clients.values():
        cli_table.add_row(
            c.bssid,
            c.mac,
            str(c.signal),
            str(c.packets),
            c.probe or "",
        )

    # Separator + count
    nets_count = len(engine.networks)
    clis_count = len(engine.clients)
    separator = Text("─" * 80, style="dim")
    count_line = Text(f" {nets_count} networks, {clis_count} clients", style="dim")

    return Group(header, separator, ap_table, Text(""), cli_table, count_line)


async def cmd_scan(repl):
    msg, default = auto_fill_prompt(repl.session, "iface", "Monitor Interface")
    iface_res = prompt_text(msg, default=default)
    if iface_res.cancelled: return
    iface = iface_res.value
    
    band_res = prompt_choice("Band", ["bg (2.4GHz)", "a (5GHz)", "abg (Both)"], default=0)
    if band_res.cancelled: return
    band = band_res.value.split(" ")[0]

    # --- Timing: single preset choice ---
    timing_res = prompt_choice(
        "Scan Speed",
        ["Fast (recommended)", "Balanced", "Slow", "Custom"],
        default=0,
    )
    if timing_res.cancelled: return

    preset_name = timing_res.value.split(" ")[0]
    if preset_name == "Custom":
        repl.print("  [dim]Configure timing (press Enter for defaults)[/dim]")
        update_res = prompt_text("  Update rate in seconds", default="0.1")
        if update_res.cancelled: return
        update_secs = float(update_res.value) if update_res.value else 0.1
        hop_res = prompt_text("  Channel hop interval in ms", default="250")
        if hop_res.cancelled: return
        hop_ms = int(hop_res.value) if hop_res.value else 250
        write_res = prompt_text("  CSV write interval in seconds (0 = auto)", default="0")
        if write_res.cancelled: return
        write_interval_secs = int(write_res.value) if write_res.value else 0
        poll_res = prompt_text("  Poll interval in ms", default="100")
        if poll_res.cancelled: return
        poll_ms = int(poll_res.value) if poll_res.value else 100
    else:
        update_secs, hop_ms, write_interval_secs, poll_ms = TIMING_PRESETS[preset_name]
    
    conf = prompt_confirm("Start Scan?")
    if conf.cancelled or not conf.value:
        repl.print("[yellow]Cancelled.[/yellow]")
        return
        
    engine = ScanEngine()
    start_time = time.time()

    # Init callback — show countdown before Live starts
    init_printed = False
    def on_init(status):
        nonlocal init_printed
        if status.startswith("init:"):
            remaining = status.split(":")[1]
            repl.print(f"  [dim]  Initializing... {remaining}s remaining[/dim]")
        elif status == "ready" and not init_printed:
            init_printed = True
            repl.print(f"  [green]  Ready! Starting live display...[/green]")

    # Start scan in background
    scan_task = asyncio.create_task(engine.scan(
        mon_iface=iface,
        capture_prefix="/tmp/swcli_scan",
        band=band,
        update_secs=update_secs,
        hop_ms=hop_ms,
        write_interval_secs=write_interval_secs,
        poll_ms=poll_ms,
        on_init=on_init,
    ))

    # Wait for init, then start Live display
    await asyncio.sleep(3.5)

    try:
        with Live(console=console, refresh_per_second=2, screen=False) as live:
            while engine._running:
                elapsed = time.time() - start_time
                display = _build_scan_display(engine, elapsed, band)
                live.update(display)
                await asyncio.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        await scan_task
        await engine.stop_and_wait()
        
    # Final results
    elapsed = time.time() - start_time
    nets = engine.get_networks()
    repl.session.scan_results = nets
    repl.session.last_iface = iface
    repl.print(f"\n  [green]Scan complete.[/green] Found {len(nets)} networks in {elapsed:.0f}s.")
    repl.print("  Run /scan results to view them in a table.")

async def cmd_scan_results(repl):
    nets = repl.session.scan_results
    if not nets:
        repl.print("  [yellow]No scan results in session. Run /scan first.[/yellow]")
        return
        
    headers = ["#", "BSSID", "CH", "PWR", "MB", "ENC", "CIPHER", "AUTH", "ESSID", "WPS"]
    rows = []
    for i, n in enumerate(nets, 1):
        rows.append([
            str(i),
            n.bssid,
            str(n.channel),
            str(n.signal),
            str(n.speed),
            n.privacy,
            n.cipher,
            n.auth,
            n.display_name(),
            "Yes" if n.wps else "No"
        ])
    print_table(headers, rows, "Scan Results")

def register_commands(palette: CommandPalette):
    palette.register(Command("/scan", "Start WiFi scan", "Scan", cmd_scan, requires_iface=True))
    palette.register(Command("/scan results", "Show last scan", "Scan", cmd_scan_results, requires_root=False))
