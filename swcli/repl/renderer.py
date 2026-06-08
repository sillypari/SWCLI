from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.align import Align
import time

APP_VERSION = "0.1.0"
APP_DEVELOPER = "Parikshit Singh Bais"
APP_GITHUB = "https://github.com/sillypari"

console = Console(force_terminal=True)

TONE_STYLES = {
    "success": "bold bright_green",
    "error": "bold red",
    "warning": "bold yellow",
    "info": "bold cyan",
    "muted": "dim",
    "active": "bold green",
    "danger": "bold red",
}


def badge(label: str, tone: str = "info") -> str:
    style = TONE_STYLES.get(tone, "bold cyan")
    return f"[{style}][ {label} ][/{style}]"


def yes_no(value: bool) -> str:
    return badge("YES", "success") if value else badge("NO", "error")


def print_splash(duration: float = 1.8):
    """Show a short startup splash before the REPL prompt."""
    console.clear()
    title = Text()
    title.append("SWCLI\n", style="bold bright_cyan")
    title.append("Sidewinder Wireless Audit Console", style="bold white")

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="cyan", no_wrap=True)
    meta.add_column(style="white")
    meta.add_row("Version", APP_VERSION)
    meta.add_row("Developer", APP_DEVELOPER)
    meta.add_row("GitHub", Text("@sillypari", style=f"link {APP_GITHUB} cyan underline"))
    meta.add_row("Mode", "operator-controlled workflows")

    footer = Text("Preparing command palette...", style="dim")
    panel = Panel(
        Align.center(
            Group(title, Text(""), meta, Text(""), footer),
            vertical="middle",
        ),
        title="SWCLI",
        subtitle="Wireless Toolkit",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(1, 6),
    )
    console.print(Align.center(panel, vertical="middle"))
    time.sleep(duration)
    console.clear()


def print_banner():
    """Print the compact SWCLI header."""
    header = Table.grid(padding=(0, 2))
    header.add_column(justify="left")
    header.add_column(justify="left")
    logo = Text()
    logo.append("SW", style="bold blue")
    logo.append("CLI", style="bold white")
    title = Text()
    title.append("SWCLI", style="bold white")
    title.append(f"\nWireless Audit Console v{APP_VERSION}", style="cyan")
    title.append("\nType / for commands, /status for state, ? for help", style="dim")
    header.add_row(logo, title)
    console.print(Panel(header, border_style="blue", padding=(0, 1)))

def print_table(headers: list[str], rows: list[list[str]], title: str = ""):
    """Print a consistent, high-contrast table for command output."""
    if not rows:
        console.print(f"  {badge('EMPTY', 'muted')} [dim]No data available.[/dim]")
        return

    table = Table(
        title=title,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
        border_style="bright_black",
        box=box.SIMPLE_HEAVY,
        expand=False,
        padding=(0, 1),
    )

    for header in headers:
        h = str(header)
        justify = "right" if h in ("#", "CH", "PWR", "Packets", "Size", "Saved", "Keys") else "left"
        if h.lower() in ("ok", "status", "wps", "eapol", "captured", "pair", "inst", "ack", "mic", "sec"):
            justify = "center"
        table.add_column(h, justify=justify, overflow="fold")

    for row in rows:
        table.add_row(*[str(item) for item in row])

    console.print(table)

def print_success(msg: str):
    """Print success message."""
    console.print(f"  {badge('+', 'success')} {msg}")

def print_error(msg: str):
    """Print error message."""
    console.print(f"  {badge('!', 'error')} [red]{msg}[/red]")

def print_warning(msg: str):
    """Print warning message."""
    console.print(f"  {badge('~', 'warning')} [yellow]{msg}[/yellow]")

def print_info(msg: str):
    """Print info message."""
    console.print(f"  {badge('i', 'info')} {msg}")

def _mark(value: bool) -> Text:
    return Text("YES" if value else "--", style="green bold" if value else "red")


def build_handshake_progress_panel(
    *,
    title: str,
    iface: str,
    bssid: str,
    client: str,
    channel: int,
    count: int,
    m1: bool = False,
    m2: bool = False,
    m3: bool = False,
    m4: bool = False,
    status: str = "waiting",
    elapsed: float = 0.0,
    activity: str = "",
    analysis_passes: int = 0,
) -> Panel:
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="cyan")
    summary.add_column(style="white")
    summary.add_row("Interface", iface)
    summary.add_row("Target", bssid)
    summary.add_row("Client", "broadcast" if client.upper() == "FF:FF:FF:FF:FF:FF" else client)
    summary.add_row("Channel", str(channel))
    summary.add_row("Deauth frames", str(count))
    summary.add_row("Elapsed", _fmt_hms(elapsed))
    if activity:
        detail = f"{activity} waiting for EAPOL"
        if analysis_passes:
            detail += f" ({analysis_passes} UI ticks)"
        summary.add_row("Analysis", detail)

    handshakes = Table(show_header=True, header_style="bold cyan", box=None, show_edge=False)
    handshakes.add_column("Message")
    handshakes.add_column("Captured", justify="center")
    handshakes.add_row("M1", _mark(m1))
    handshakes.add_row("M2", _mark(m2))
    handshakes.add_row("M3", _mark(m3))
    handshakes.add_row("M4", _mark(m4))

    status_text = Text()
    status_text.append("Status: ", style="white")
    status_style = "green bold" if status in ("full", "complete") else "yellow bold"
    status_text.append(status.upper(), style=status_style)
    if activity:
        status_text.append(f"    {activity}", style="cyan bold")
    status_text.append("    Press Ctrl+C to abort", style="dim")

    return Panel(
        Group(summary, Text(""), handshakes, Text(""), status_text),
        title=title,
        border_style="bright_cyan",
        padding=(0, 1),
    )


def _fmt_hms(total_seconds: float) -> str:
    if total_seconds <= 0:
        return "00:00"
    h = int(total_seconds // 3600)
    m = int((total_seconds % 3600) // 60)
    s = int(total_seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h > 0 else f"{m:02d}:{s:02d}"


def build_aircrack_status_panel(
    *,
    method: str,
    cap_file: str,
    bssid: str,
    wordlist: str,
    tested: int,
    total: int,
    keys_per_second: float,
    elapsed: float,
    eta_seconds: float,
    current_key: str = "",
    found_password: str = "",
    status: str = "running",
    activity: str = "",
    percent: float = 0.0,
    eta_text: str = "",
    master_key: str = "",
    transient_key: str = "",
    eapol_hmac: str = "",
) -> Panel:
    actual_percent = percent
    if actual_percent <= 0 and total > 0:
        actual_percent = min(100.0, (tested / total) * 100.0)

    speed = keys_per_second / 1000.0
    eta = eta_text or (_fmt_hms(eta_seconds) if eta_seconds > 0 else "unknown")
    passphrase = current_key or "waiting..."

    body = Text(justify="center")
    body.append(f"{method}\n\n", style="bold white")
    body.append(
        f"[{_fmt_hms(elapsed)}]  {tested}/{total or '?'} keys tested ({speed:,.2f} K/s)\n\n",
        style="white",
    )
    body.append("Time left: ", style="white")
    body.append(eta, style="white")
    body.append(f"{actual_percent:>28.2f}%\n\n", style="white")
    body.append("Current passphrase: ", style="white")
    body.append(f"{passphrase}\n\n", style="white")

    if found_password:
        body.append("KEY FOUND! [ ", style="green bold")
        body.append(found_password, style="bright_green bold")
        body.append(" ]\n\n", style="green bold")
    elif status in ("exhausted", "failed", "error"):
        body.append(f"{status.upper()}\n\n", style="red bold")

    def append_key(label: str, value: str) -> None:
        body.append(f"{label:<16}: ", style="white")
        body.append((value or "--") + "\n\n", style="white")

    append_key("Master Key", master_key)
    append_key("Transient Key", transient_key)
    append_key("EAPOL HMAC", eapol_hmac)

    footer = Text(justify="center")
    if found_password:
        footer.append("Crack complete", style="green")
    else:
        if activity:
            footer.append(f"{activity} ", style="cyan bold")
        footer.append("Trying passphrases...", style="dim")

    return Panel(
        Align.center(Group(body, footer), vertical="top"),
        border_style="bright_black",
        padding=(1, 3),
    )
