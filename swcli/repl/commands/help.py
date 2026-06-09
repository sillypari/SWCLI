from swcli.repl.palette import Command, CommandPalette
from swcli.repl.renderer import APP_DEVELOPER, APP_GITHUB, APP_VERSION, console
from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


SCAN_FIELD_GROUPS = [
    (
        "Access points",
        [
            ("ESSID", "Network name. [HIDDEN] means the SSID was not visible in the scan data."),
            ("BSSID", "Access point MAC address."),
            ("MANUF", "Manufacturer from the MAC OUI lookup when available."),
            ("RXQ", "Receive quality. Shown only when advanced scan info is enabled and the scan is fixed to one channel."),
            ("PWR", "Signal strength reported by the adapter. Closer to zero is stronger; -1 means unknown."),
            ("Beacons", "Beacon frames seen from the AP. Healthy APs usually send these steadily."),
            ("#Data", "Captured data packets for the AP. For WEP this is effectively the IV count."),
            ("#/s", "Recent data packet rate per second. Higher values mean current traffic."),
            ("CH", "Channel advertised by the AP."),
            ("MB", "Maximum AP data rate in Mbit/s reported by airodump-ng."),
            ("HE", "High Efficiency / 802.11ax capability indicator when detected."),
            ("ENC", "Encryption family: OPN, WEP, WPA, WPA2, or WPA3 when detected."),
            ("CIPHER", "Traffic cipher such as CCMP or TKIP."),
            ("AUTH", "Authentication method such as PSK or MGT."),
            ("CL", "SWCLI client count associated with this AP."),
            ("FLAGS", "SWCLI highlights such as WPS or EAPOL/handshake activity."),
        ],
    ),
    (
        "Clients",
        [
            ("ESSID", "Network name of the associated AP when known."),
            ("STATION", "Client device MAC address."),
            ("MANUF", "Client manufacturer from the MAC OUI lookup when available."),
            ("BSSID", "Associated AP MAC address, or not associated when the client is probing."),
            ("PWR", "Client signal strength. -1 often means only AP-to-client traffic was heard."),
            ("RATE", "AP-to-client and client-to-AP data rates in Mbit/s. Hidden unless advanced scan info is enabled."),
            ("LOST", "Airodump estimated missed packets from that client. Hidden unless advanced scan info is enabled."),
            ("FRAMES", "Frames seen from that client. Hidden unless advanced scan info is enabled."),
            ("PROBE", "SSID requested by a client while searching for networks."),
            ("HE", "High Efficiency / 802.11ax capability indicator when detected."),
            ("FLAGS", "Client-side notes such as EAPOL activity."),
        ],
    ),
]


ATTACK_FIELD_GROUPS = [
    (
        "Evil Twin",
        [
            ("What it does", "Starts a rogue AP using airbase-ng with a chosen ESSID and channel."),
            ("Commands", "/attack evil-twin and /attack evil-twin-simple run Simple logging; /attack evil-twin-pass runs the password-validation lab flow."),
            ("Target", "Select from the current scan/session target, then confirm the ESSID to broadcast."),
            ("Clone BSSID", "Optional. Uses airbase-ng -a to beacon with the target BSSID when requested."),
            ("Client network", "Configures at0 and starts one dnsmasq instance for DHCP plus wildcard DNS capture."),
            ("Portal modes", "Simple supports notice or captive-trigger logging. Pass uses the password-validation portal flow."),
            ("Captive trigger", "Captive/password modes serve the portal for OS probe URLs so phones open the sign-in flow."),
            ("Required", "Monitor interface, ESSID, channel, airbase-ng, dnsmasq, and authorization for the test scope."),
        ],
    ),
    (
        "WPS Pixie-Dust",
        [
            ("What it does", "Runs reaver in Pixie-Dust mode against a WPS-capable AP."),
            ("Target", "Prefers networks marked WPS in scan results; manual BSSID/channel entry remains available."),
            ("Result", "Reports recovered WPS PIN and WPA PSK when reaver returns them."),
            ("Required", "Monitor interface, target BSSID, channel, WPS support, and authorization."),
        ],
    ),
]


def _scan_field_guide():
    tables = []
    for title, rows in SCAN_FIELD_GROUPS:
        table = Table(
            title=title,
            title_style="bold cyan",
            show_header=True,
            header_style="bold bright_cyan",
            border_style="bright_black",
            box=box.SIMPLE_HEAVY,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Field", style="bold white", no_wrap=True)
        table.add_column("Meaning", ratio=1, overflow="fold")
        for field, meaning in rows:
            table.add_row(field, meaning)
        tables.append(table)

    note = Text()
    note.append("Reading tip: ", style="bold white")
    note.append("sort attention by strong PWR, rising #/s or #Data, visible clients, and EAPOL flags.", style="dim")

    return Panel(
        Group(*tables, Text(""), note),
        title="Scan Field Guide",
        border_style="bright_blue",
        padding=(0, 1),
    )


def _attack_field_guide():
    tables = []
    for title, rows in ATTACK_FIELD_GROUPS:
        table = Table(
            title=title,
            title_style="bold red",
            show_header=True,
            header_style="bold bright_red",
            border_style="bright_black",
            box=box.SIMPLE_HEAVY,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Item", style="bold white", no_wrap=True)
        table.add_column("Meaning", ratio=1, overflow="fold")
        for field, meaning in rows:
            table.add_row(field, meaning)
        tables.append(table)

    note = Text()
    note.append("Workflow tip: ", style="bold white")
    note.append("run /scan, select a target with /target, then start the attack command and choose from the list.", style="dim")

    return Panel(
        Group(*tables, Text(""), note),
        title="Attack Guide",
        border_style="red",
        padding=(0, 1),
    )


async def cmd_help_scan(repl):
    """Explain scan table fields."""
    console.print(_scan_field_guide())


async def cmd_help_attack(repl):
    """Explain attack command workflows."""
    console.print(_attack_field_guide())


async def cmd_about(repl):
    """Show project and developer information."""
    github = Text("@sillypari", style=f"link {APP_GITHUB} cyan underline")
    info = Table.grid(padding=(0, 2))
    info.add_column(style="cyan", no_wrap=True)
    info.add_column(style="white")
    info.add_row("Application", "SWCLI")
    info.add_row("Version", APP_VERSION)
    info.add_row("Purpose", "Sidewinder wireless audit console")
    info.add_row("Developer", APP_DEVELOPER)
    info.add_row("GitHub", github)

    note = Text()
    note.append("Operator-controlled workflows for scanning, capture, validation, and cracking.", style="dim")

    console.print(Panel(
        Group(info, Text(""), note),
        title="About SWCLI",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 1),
    ))


async def cmd_help(repl):
    """Show help for commands."""
    repl.print("\n  [bold cyan]Available Commands[/bold cyan]")
    
    # We can group them by category
    categories = {}
    for cmd in repl.palette.commands:
        if cmd.category not in categories:
            categories[cmd.category] = []
        categories[cmd.category].append(cmd)
        
    for cat, cmds in categories.items():
        repl.print(f"\n  [bold]{cat}[/bold]")
        for c in cmds:
            repl.print(f"    {c.name.ljust(20)} {c.description}")
            
    repl.print("\n  Type / to open the interactive command palette.")
    repl.print("  Use /help scan to show only the scan table field guide.\n")
    console.print(_scan_field_guide())

def register_commands(palette: CommandPalette):
    palette.register(Command("/help", "List all commands and scan field meanings", "System", cmd_help, requires_root=False))
    palette.register(Command("/help scan", "Explain /scan table fields", "System", cmd_help_scan, requires_root=False))
    palette.register(Command("/help attack", "Explain attack workflows", "System", cmd_help_attack, requires_root=False))
    palette.register(Command("/about", "Show SWCLI version and developer info", "System", cmd_about, requires_root=False))
