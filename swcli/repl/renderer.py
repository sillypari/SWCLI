from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich import box
from rich.align import Align
import time

APP_VERSION = "0.1.0"
APP_DEVELOPER = "Parikshit Singh Bais"
APP_GITHUB = "https://github.com/sillypari"

console = Console(force_terminal=True)

# Color constants
COLORS = {
    "primary":    "green",        # Success, active, selected
    "secondary":  "cyan",         # Info, headers
    "accent":     "magenta",      # Special actions
    "error":      "red",          # Errors, danger
    "warning":    "yellow",       # Warnings
    "success":    "bright_green", # Passwords found
    "info":       "blue",         # Informational
    "muted":      "dim",          # Secondary text
    "dim":        "dark_gray",    # Dimmed text
    "text":       "white",        # Primary text
}

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


def state_text(value: str) -> str:
    lowered = str(value).lower()
    if lowered in ("yes", "ok", "active", "full", "found", "success", "running"):
        return f"[bold bright_green]{value}[/bold bright_green]"
    if lowered in ("no", "failed", "invalid", "missing", "error", "exhausted"):
        return f"[bold red]{value}[/bold red]"
    if lowered in ("partial", "waiting", "inactive", "unknown"):
        return f"[bold yellow]{value}[/bold yellow]"
    return str(value)

SW_LOGO = """[bold blue]
   ███████╗██╗    ██╗[/bold blue][bold white] ██████╗██╗     ██╗[/bold white]
[bold blue]   ██╔════╝██║    ██║[/bold blue][bold white]██╔════╝██║     ██║[/bold white]
[bold blue]   ███████╗██║ █╗ ██║[/bold blue][bold white]██║     ██║     ██║[/bold white]
[bold blue]   ╚════██║██║███╗██║[/bold blue][bold white]██║     ██║     ██║[/bold white]
[bold blue]   ███████║╚███╔███╔╝[/bold blue][bold white]╚██████╗███████╗██║[/bold white]
[bold blue]   ╚══════╝ ╚══╝╚══╝ [/bold blue][bold white] ╚═════╝╚══════╝╚═╝[/bold white]
"""

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

def print_progress(line: str):
    """Print progress line (overwrites previous)."""
    console.file.write(f"\r {line}\x1b[K")
    console.file.flush()


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


_SPEED_UNITS = ((1_000_000_000, "G/s"), (1_000_000, "M/s"), (1_000, "K/s"), (1, "keys/s"))


def _format_speed(h_per_sec: float) -> str:
    for threshold, unit in _SPEED_UNITS:
        if h_per_sec >= threshold:
            value = h_per_sec / threshold
            return f"{value:,.2f} {unit}"
    return f"{h_per_sec:,.0f} keys/s"


def _fmt_hms(total_seconds: float) -> str:
    if total_seconds <= 0:
        return "00:00"
    h = int(total_seconds // 3600)
    m = int((total_seconds % 3600) // 60)
    s = int(total_seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h > 0 else f"{m:02d}:{s:02d}"


def build_crack_progress_panel(
    *,
    title: str,
    target: str,
    tested: int,
    total: int,
    keys_per_second: float,
    elapsed: float,
    eta_seconds: float,
) -> Panel:
    t = Text()

    t.append(title + "\n", style="cyan bold")
    t.append("Target       : ", style="white")
    t.append(target + "\n", style="yellow")
    t.append("Keys tested  : ", style="white")
    t.append(f"{tested:,}\n", style="green")
    t.append("Speed        : ", style="white")
    t.append(f"{_format_speed(keys_per_second)}\n", style="magenta")
    t.append("Elapsed      : ", style="white")
    t.append(f"{_fmt_hms(elapsed)}\n", style="white")
    t.append("ETA          : ", style="white")
    t.append(
        _fmt_hms(eta_seconds) if eta_seconds > 0 else "unknown",
        style="blue",
    )

    return Panel(t, title="", border_style="bright_cyan", padding=(0, 1))



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
) -> Panel:
    header = Text()
    header.append(f"{method}\n", style="cyan bold")
    header.append("WPA handshake crack status", style="dim")

    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="cyan")
    stats.add_column(style="white")
    stats.add_row("BSSID", bssid or "unknown")
    stats.add_row("Capture", cap_file)
    if found_password:
        status_style = "green"
    elif status in ("exhausted", "failed", "error"):
        status_style = "red"
    else:
        status_style = "yellow"
    stats.add_row("Wordlist", wordlist)
    stats.add_row("Status", Text(status.upper(), style=status_style))
    stats.add_row("Keys tested", f"{tested:,}" if tested else "0")
    stats.add_row("Speed", _format_speed(keys_per_second))
    stats.add_row("Elapsed", _fmt_hms(elapsed))
    stats.add_row("ETA", _fmt_hms(eta_seconds) if eta_seconds > 0 else "unknown")
    if current_key:
        stats.add_row("Current key", current_key)

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=38),
        TextColumn("[progress.percentage]{task.percentage:>5.1f}%"),
        expand=False,
    )
    task_total = total if total > 0 else 100
    task_completed = min(tested, total) if total > 0 else 0
    progress.add_task("Progress", total=task_total, completed=task_completed)

    footer = Text()
    if found_password:
        footer.append("KEY FOUND! [ ", style="green bold")
        footer.append(found_password, style="bright_green bold")
        footer.append(" ]", style="green bold")
    else:
        if activity:
            footer.append(f"{activity} ", style="cyan bold")
        footer.append("Trying passphrases...", style="yellow")

    return Panel(
        Group(header, Text(""), stats, Text(""), progress, Text(""), footer),
        title="Crack",
        border_style="bright_cyan",
        padding=(0, 1),
    )
