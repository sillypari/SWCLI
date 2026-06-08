import os
import shutil
from datetime import datetime
from swcli.repl.palette import Command, CommandPalette
from swcli.repl.prompts import prompt_choice
from swcli.repl.renderer import print_table, print_success, print_error, yes_no

REQUIRED_BINS = ["airodump-ng", "aireplay-ng", "aircrack-ng", "iw", "ip"]
OPTIONAL_BINS = ["hashcat", "hcxpcapngtool", "airbase-ng", "reaver", "dnsmasq"]


def _yes(value: bool) -> str:
    return yes_no(value)


def _path_state(path: str) -> str:
    if not path:
        return "[dim]none[/dim]"
    if os.path.exists(path):
        return f"[green]{path}[/green]"
    return f"[yellow]{path} (missing)[/yellow]"


async def cmd_status(repl):
    """Show current operator-controlled session state."""
    target = getattr(repl.session, "selected_target", None)
    target_label = "[dim]none[/dim]"
    if target:
        target_label = f"{target.display_name()} ({target.bssid}) ch {target.channel}"
    elif repl.session.last_bssid:
        target_label = f"{repl.session.last_bssid} ch {repl.session.last_channel or '?'} [dim](manual)[/dim]"

    rows = [
        ["Monitor interface", repl.session.monitor_iface or repl.session.last_iface or "[dim]none[/dim]"],
        ["Monitor tracked", _yes(bool(repl.session.monitor_mode))],
        ["Selected target", target_label],
        ["Selected client", getattr(repl.session, "selected_client", "") or "broadcast/manual"],
        ["Networks in session", str(len(repl.session.scan_results))],
        ["Clients in session", str(len(repl.session.clients))],
        ["Last capture", _path_state(repl.session.last_cap_file)],
        ["Captures tracked", str(len(repl.session.captures))],
        ["Last wordlist", repl.session.last_wordlist or "[dim]none[/dim]"],
    ]
    print_table(["Item", "Value"], rows, "SWCLI Status")
    repl.print("\n  [dim]User control: this screen does not start, stop, kill, or modify anything.[/dim]")


async def cmd_doctor(repl):
    """Preflight checks without changing system state."""
    rows = []
    is_root = os.name == "nt" or os.geteuid() == 0
    rows.append(["Root privileges", _yes(is_root), "Required for monitor/capture/attack commands"])

    for name in REQUIRED_BINS:
        path = shutil.which(name)
        rows.append([name, _yes(bool(path)), path or "required binary not found"])
    for name in OPTIONAL_BINS:
        path = shutil.which(name)
        rows.append([name, _yes(bool(path)), path or "optional feature unavailable"])

    try:
        from sidewinder.core.adapter import list_interfaces, get_interface_mode, discover_all_adapters
        interfaces = list_interfaces()
        monitor = [iface for iface in interfaces if get_interface_mode(iface) == "monitor"]
        rows.append(["Wireless interfaces", _yes(bool(interfaces)), ", ".join(interfaces) or "none detected"])
        rows.append(["Monitor interfaces", _yes(bool(monitor)), ", ".join(monitor) or "run /monitor"])
        adapters = await discover_all_adapters()
        for adapter in adapters:
            chipset = adapter.chipset or adapter.driver or "unknown"
            rows.append([
                f"{adapter.iface} monitor report",
                _yes(adapter.monitor_capable),
                f"{chipset} reports monitor={adapter.monitor_capable}; runtime test not run",
            ])
            rows.append([
                f"{adapter.iface} injection report",
                _yes(adapter.injection_capable),
                f"{chipset} reports injection={adapter.injection_capable}; runtime test not run",
            ])
    except Exception as e:
        rows.append(["Interface check", "[red]NO[/red]", str(e)])

    try:
        import scapy.all  # noqa: F401
        rows.append(["Scapy import", "[green]YES[/green]", "EAPOL validation available"])
    except Exception as e:
        rows.append(["Scapy import", "[red]NO[/red]", str(e)])

    tmp_ok = os.access("/tmp", os.W_OK)
    rows.append(["/tmp writable", _yes(tmp_ok), "capture output location"])
    print_table(["Check", "OK", "Detail"], rows, "Preflight Doctor")
    repl.print("\n  [dim]Doctor is read-only. Adapter support rows are reported capability, not proof; use /adapters test injection for an explicit active test.[/dim]")


async def cmd_target(repl):
    """Select an active target from scan results."""
    nets = repl.session.scan_results
    if not nets:
        repl.print("  [yellow]No scan results in session. Run /scan first, or use capture commands to enter a BSSID manually.[/yellow]")
        return

    sorted_nets = sorted(nets, key=lambda n: (n.eapol, n.wps, n.signal), reverse=True)
    choices = []
    target_map = {}
    for i, n in enumerate(sorted_nets, 1):
        clients = [c for c in repl.session.clients if c.bssid.upper() == n.bssid.upper()]
        flags = []
        if clients:
            flags.append(f"{len(clients)} clients")
        if n.eapol:
            flags.append("EAPOL")
        if n.wps:
            flags.append("WPS")
        label = f"{i}. {n.display_name()} ({n.bssid}) ch {n.channel} signal {n.signal}"
        if flags:
            label += " [" + ", ".join(flags) + "]"
        choices.append(label)
        target_map[label] = n
    choices.append("Clear selected target")

    res = prompt_choice("Select active target", choices)
    if res.cancelled:
        return
    if res.value == "Clear selected target":
        repl.session.selected_target = None
        repl.session.last_bssid = ""
        repl.session.last_channel = 0
        print_success("Selected target cleared.")
        return

    target = target_map[res.value]
    repl.session.selected_target = target
    repl.session.last_bssid = target.bssid
    repl.session.last_channel = target.channel
    print_success(f"Selected target: {target.display_name()} ({target.bssid}) on channel {target.channel}")

    clients = [c for c in repl.session.clients if c.bssid.upper() == target.bssid.upper()]
    if clients:
        rows = [[str(i), c.mac, str(c.signal), str(c.packets), "Yes" if c.eapol else "-"] for i, c in enumerate(clients, 1)]
        print_table(["#", "Client", "PWR", "Packets", "EAPOL"], rows, "Associated Clients")
    repl.print("\n  [dim]Next options: /capture passive, /capture deauth, /scan handshakes, /crack aircrack[/dim]")


async def cmd_next(repl):
    """Show suggested next actions without running them."""
    suggestions = []
    if not repl.session.monitor_iface and not repl.session.last_iface:
        suggestions.append(["1", "/adapters", "Inspect adapters"])
        suggestions.append(["2", "/monitor", "Enter monitor mode after choosing adapter"])
    elif not repl.session.scan_results:
        suggestions.append(["1", "/scan", "Discover APs and clients"])
    elif not getattr(repl.session, "selected_target", None) and not repl.session.last_bssid:
        suggestions.append(["1", "/target", "Choose active target from scan results"])
    elif not repl.session.last_cap_file:
        suggestions.append(["1", "/capture passive", "Try passive handshake capture"])
        suggestions.append(["2", "/capture deauth", "User-confirmed deauth capture"])
    else:
        suggestions.append(["1", "/validate", "Validate latest capture"])
        suggestions.append(["2", "/crack aircrack", "Try wordlist cracking"])
        suggestions.append(["3", "/cleanup", "Clean up when finished"])
    print_table(["#", "Command", "Why"], suggestions, "Suggested Next Actions")
    repl.print("\n  [dim]These are suggestions only. Nothing runs until you choose a command and confirm prompts.[/dim]")


def register_commands(palette: CommandPalette):
    palette.register(Command("/status", "Show current session state", "Control", cmd_status, requires_root=False))
    palette.register(Command("/doctor", "Read-only readiness checks", "Control", cmd_doctor, requires_root=False))
    palette.register(Command("/target", "Select active target", "Control", cmd_target, requires_root=False))
    palette.register(Command("/next", "Suggest next actions", "Control", cmd_next, requires_root=False))
